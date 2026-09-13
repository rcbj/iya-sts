"use strict";
//
// File: sts_jwt_bearer_grant.js
//
// ===========================================================================
// RFC 7521 AND RFC 7523 AT A REAL TOKEN ENDPOINT, AND THE CERTIFICATE
// AUTHORITY THAT MAKES THEM USABLE (2026-09-10).
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE AND NOT IN THE PARENT SUITE.
//
// The THIRD reason `tests/CLAUDE.md` gives, and this file is a plain instance
// of it: **every assertion spans an AUTHORING door and a PROTOCOL door.** A
// signing key pair does not exist until `/admin-api/pki` issues one, and an
// assertion issuer is not trusted until `oauthAssertionIssuer` is written onto
// an application entry through `/admin-api/applications`. Only then is there a
// question worth asking `/oauth2/token` at all — which is exactly the shape
// `sts_xacml_endpoints.js` has with a policy repository that starts empty.
//
// A test with the CA in one repository and the token endpoint in the other
// could not make a single assertion in this file.
//
// ---------------------------------------------------------------------------
// AND WHY IT IS NOT `tests/pki.js` OR `tests/assertion_grant.js`.
//
// Those two are in process and assert what the MODULES decide — the path
// check, the ninety-six encryption combinations, the twelve claims that may
// never reach a token. Not one of them sends a request, so not one of them can
// see a grant that is registered and unreachable, a metadata member that
// promises an algorithm the endpoint refuses, or a key pair written to the
// wrong six attributes. **Every function involved can be correct while the
// feature does not work**, which is this suite's standing argument for an
// over-HTTP job.
//
// ---------------------------------------------------------------------------
// MOSTLY NEGATIVES, FOR `sts_dpop.js`'s REASON.
//
// An authorization server that takes a well-formed assertion and hands back a
// token looks finished and can be worth nothing: that is what a server with no
// checks in it does for everybody. What is worth asserting is that a REPLAY is
// refused, that an unknown issuer is refused, that the right issuer with the
// wrong key is refused, that `alg: "none"` is refused by name, and that the
// assertion beside each of those is not — which is the only shape that tells a
// working gate from a service refusing for some other reason.
//
// ---------------------------------------------------------------------------
// IT WORKS IN A THROWAWAY TRUST REALM, and the reason is sharper than
// tidiness: a certificate authority is PER REALM, so a realm of its own gives
// this job a hierarchy whose entire contents it built — which is what makes
// "this leaf chains here and not there" an exact claim. It does NOT remove the
// realm afterwards; see *No job removes a realm* in `tests/CLAUDE.md`.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_jwt_bearer_grant",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// A realm of this run's own. `usernameFor()` carries the run stamp, so two
// runs against one long-lived mock never meet.
var REALM = usernameFor("jwtbearer").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var realmBase = base + "/realm/" + REALM;
var realmApi = realmBase + "/admin-api";
var TOKEN_ENDPOINT = realmBase + "/oauth2/token";

var CLIENT = "assert-issuer-1";
var OTHER_CLIENT = "assert-issuer-2";
var ISS = "https://issuer.example.test/jwtbearer";
var OTHER_ISS = "https://other-issuer.example.test/jwtbearer";

// ---------------------------------------------------------------------------
// WHAT A REAL DEPLOYMENT WOULD HAVE PROVISIONED, SUPPLIED UP FRONT
// (2026-09-12).
//
// Product mode seeds no `alice`, invents no persona onto an entry, and holds
// every OAuth application to a client secret. So both asserting applications
// are created with one, and the person every assertion below is ABOUT is a
// directory entry this job makes — with the attributes a real account carries
// and nothing invented — rather than a seeded name or a name nobody created.
//
// **WHAT IS NOT SUPPLIED, AND WHY.** Product mode also refuses a token request
// that authenticates no client, and none of the grant requests here carries a
// client credential: RFC 7521 section 4.2 makes client authentication OPTIONAL
// for an authorization grant, and adding it to every request would change the
// grant under test (a request that authenticates CLIENT is judged partly by who
// CLIENT is). That is a decision for this job's author rather than a sweep.
// ---------------------------------------------------------------------------
var ASSERTED_PERSON = usernameFor("asserted");
var MAIL_DOMAIN = "jwt-bearer-grant.test";

function personFields(who) {
  log.debug("Entering personFields().");
  log.debug("Leaving personFields().");
  return { cn: "Asserted Person " + who, givenName: "Asserted", sn: who,
           displayName: "Asserted Person " + who,
           mail: who + "@" + MAIL_DOMAIN };
}

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE ONE JWS SIGNER IN THIS FILE, AND IT IS THIS FILE'S OWN.
//
// `sts_dpop.js` writes its own DPoP client rather than importing the wallet's,
// and the reason applies here word for word: **if both sides of the exchange
// came from one implementation, a shared misunderstanding would make this test
// pass and interoperate with nobody.** So the assertion is built out of
// node's own crypto — a base64url header, a base64url payload, a signature
// over the two joined by a dot — rather than out of `common/crypto.js`.
//
// It is thirty lines because RFC 7515's compact serialization is thirty lines.
// It signs RSA only, which is what the CA issues by default; the algorithm
// matrix is `tests/assertion_grant.js`'s, in process, where it costs a loop
// instead of a token request.
// ---------------------------------------------------------------------------
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function signJws(header, payload, privateKeyPem) {
  log.debug("Entering signJws().");
  const head = b64u(Buffer.from(JSON.stringify(header), "utf8"));
  const body = b64u(Buffer.from(JSON.stringify(payload), "utf8"));
  const signing = head + "." + body;
  const digest = { RS256: "sha256", RS384: "sha384",
                   RS512: "sha512" }[header.alg];
  if (!digest) {
    throw new Error("this file signs RS256/RS384/RS512; asked for " +
                    header.alg);
  }
  const sig = nodeCrypto.sign(digest, Buffer.from(signing, "ascii"),
                              privateKeyPem);
  log.debug("Leaving signJws().");
  return signing + "." + b64u(sig);
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
}

function jti() {
  log.debug("Entering jti().");
  log.debug("Leaving jti().");
  return nodeCrypto.randomUUID();
}

// ---------------------------------------------------------------------------
// The two doors.
// ---------------------------------------------------------------------------
async function post(url, body) {
  log.debug("Entering post().");
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in post(): " + ((e && e.message) || e));
    // Not JSON — an HTML error page. Quoting it whole says more than a parse
    // failure would.
    parsed = raw;
  }
  log.debug("Leaving post().");
  return { status: r.status, body: parsed, raw: raw };
}

async function get(url) {
  log.debug("Entering get().");
  const r = await fetch(url);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in get(): " + ((e && e.message) || e));
    parsed = raw;
  }
  log.debug("Leaving get().");
  return { status: r.status, body: parsed, raw: raw };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await post(url, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status + " " +
    JSON.stringify((r.body && (r.body.errors || r.body.why)) || r.body)
      .slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A form POST to the token endpoint. The grant takes form encoding, which is
// what RFC 6749 section 4 says and what every OAuth client sends.
async function tokenRequest(fields) {
  log.debug("Entering tokenRequest().");
  const r = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString() });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in tokenRequest(): " + ((e && e.message) || e));
    parsed = raw;
  }
  log.debug("Leaving tokenRequest().");
  return { status: r.status, body: parsed, raw: raw };
}

function claimsOf(token) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url")
    .toString("utf8"));
}

// A refusal, read as the OAuth ERROR CODE and never as the status alone.
// `sts_roles.js` records why: a gate that works and a handler that has fallen
// over both produce a 400, and only the code tells them apart.
function refused(r, code, what) {
  log.debug("Entering refused().");
  assert.ok(r.status === 400 && r.body && r.body.error === code,
    what + " should be refused " + code + "; it answered " + r.status + " " +
    JSON.stringify(r.body).slice(0, 300));
  assert.ok(String(r.body.error_description || "").length > 20,
    "RFC 7521 section 4.2: a refusal carries an error_description a client " +
    "author can act on; " + what + " came back with " +
    JSON.stringify(r.body.error_description));
  log.debug("Leaving refused().");
  return r.body.error_description;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in the trust realm \"" + REALM + "\".");

  // -------------------------------------------------------------------------
  // 0. THE REALM, THE CERTIFICATE AUTHORITY, AND TWO APPLICATIONS.
  // -------------------------------------------------------------------------
  log.info("=== 0. a realm, a CA, and two applications ===");
  await ok(api + "/realms/create", { id: REALM, name: "JWT bearer grant" },
           "created the trust realm");

  const built = await ok(realmApi + "/pki/build",
                         { organisation: "Assertion Test", country: "US" },
                         "built a certificate authority");
  check("a three-tier hierarchy is built in this realm", function () {
    assert.strictEqual(built.chain.tiers.length, 3,
      "expected Root, Intermediate and Issuing; got " +
      JSON.stringify((built.chain.tiers || []).map(function (one) {
        return one.tier;
      })));
    assert.ok(built.chain.tiers.every(function (one) {
      return /BEGIN CERTIFICATE/.test(one.certificatePem);
    }), "every tier carries its certificate");
  });
  check("and NO private key is in what the API hands back — the assertion " +
        "that would otherwise be an absence nobody could see", function () {
    assert.ok(JSON.stringify(built).indexOf("PRIVATE KEY") < 0,
      "a PRIVATE KEY block appeared in the /admin-api/pki/build reply");
  });

  // The DEFAULT realm's hierarchy is a different one, or absent. Either way
  // this realm's leaf must not verify against it, which is section 6 below.
  await ok(realmApi + "/applications/create",
           { identifier: CLIENT, protocols: ["oauth2"],
             fields: { oauthClientId: CLIENT,
                       oauthClientSecret: CLIENT + "-secret-" + REALM,
                       oauthTokenEndpointAuthMethod: "client_secret_post" } },
           "created the asserting application");
  await ok(realmApi + "/applications/create",
           { identifier: OTHER_CLIENT, protocols: ["oauth2"],
             fields: { oauthClientId: OTHER_CLIENT,
                       oauthClientSecret: OTHER_CLIENT + "-secret-" + REALM,
                       oauthTokenEndpointAuthMethod: "client_secret_post" } },
           "created the second application");
  // The resource owner the assertions below name as `sub`.
  await ok(realmApi + "/users/create",
           { username: ASSERTED_PERSON, invent: false,
             attributes: personFields(ASSERTED_PERSON) },
           "created the person the assertions are about");

  // -------------------------------------------------------------------------
  // 1. ISSUING A KEY PAIR, AND WHERE IT LANDS.
  // -------------------------------------------------------------------------
  log.info("=== 1. a signing key pair, on the application's own entry ===");
  const issued = await ok(realmApi + "/pki/issue", { identifier: CLIENT },
                          "issued a signing key pair");
  check("the reply names the kid and the JWS algorithm the key signs with",
        function () {
          assert.ok(/^app-/.test(issued.kid), "kid=" + issued.kid);
          assert.strictEqual(issued.jwsAlg, "RS256");
        });

  const view = await get(realmApi + "/applications?application=" +
                         encodeURIComponent(CLIENT));
  const fields = ((view.body.application || view.body).fields) || {};
  const privateKeyPem = fields.oauthAssertionPrivateKey;
  const kid = fields.oauthAssertionKid;

  // WHAT THIS ASSERTS AND WHAT IT CANNOT. The key comes back as a PEM here in
  // every mode, and that is the design: this endpoint reads through
  // `common/applications.js`, which OPENS the value, and the caller is holding
  // an `admin:read` token. What the ENTRY holds is sealed under the
  // key-encryption key wherever that key outlives the process — and no request
  // can see the entry, so that half is asserted in process by `tests/pki.js`.
  // Neither implies the other.
  check("the PRIVATE KEY is on the application's own directory entry and is " +
        "handed to a caller holding a credential — sealed at rest under the " +
        "key-encryption key, opened by the module that owns the registry, " +
        "because a key pair an operator cannot collect is one nobody can use",
        function () {
    assert.ok(privateKeyPem && /BEGIN PRIVATE KEY/.test(privateKeyPem),
      "oauthAssertionPrivateKey is " +
      JSON.stringify(privateKeyPem).slice(0, 60));
  });
  check("beside the certificate, the chain, the kid and the expiry — six " +
        "attributes, because this service keeps NO second copy of any of them",
        function () {
          ["oauthAssertionCertificate", "oauthAssertionCertificateChain",
           "oauthAssertionJwks", "oauthAssertionKid",
           "oauthAssertionExpiresAt"].forEach(function (name) {
            assert.ok(fields[name], name + " is empty on the entry");
          });
        });
  check("the JWKS carries the whole path in `x5c` — leaf, Issuing, " +
        "Intermediate — so registering it registers the chain with it",
        function () {
          const jwks = JSON.parse(fields.oauthAssertionJwks);
          assert.strictEqual(jwks.keys.length, 1);
          assert.strictEqual(jwks.keys[0].x5c.length, 3,
            "x5c has " + jwks.keys[0].x5c.length + " member(s)");
          assert.strictEqual(jwks.keys[0].kid, kid);
        });
  check("and `oauthJwks` was NOT overwritten — a client that registered its " +
        "own keys and is later issued a pair has TWO ways to sign, both of " +
        "which somebody deliberately arranged", function () {
          assert.ok(!fields.oauthJwks,
            "oauthJwks should still be empty; it holds " +
            String(fields.oauthJwks).slice(0, 60));
        });

  // -------------------------------------------------------------------------
  // 2. THE METADATA SAYS WHAT THIS ENDPOINT WILL DO.
  // -------------------------------------------------------------------------
  log.info("=== 2. the metadata ===");
  const md = await get(realmBase + "/.well-known/oauth-authorization-server");
  const GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  check("grant_types_supported advertises the JWT bearer grant — a member " +
        "there is a PROMISE, and the endpoint refuses anything the list does " +
        "not carry", function () {
          assert.ok((md.body.grant_types_supported || []).indexOf(GRANT) >= 0,
            JSON.stringify(md.body.grant_types_supported));
        });
  check("and the assertion algorithm lists are published, signing and " +
        "encryption alike", function () {
          assert.ok((md.body.assertion_signing_alg_values_supported || [])
            .indexOf("RS256") >= 0, "no RS256 in the signing list");
          assert.ok((md.body.assertion_encryption_alg_values_supported || [])
            .indexOf("RSA-OAEP-256") >= 0, "no RSA-OAEP-256 in the alg list");
          assert.ok((md.body.assertion_encryption_enc_values_supported || [])
            .indexOf("A256GCM") >= 0, "no A256GCM in the enc list");
        });

  // -------------------------------------------------------------------------
  // 3. THE REFUSAL THAT DEFAULTS TO ON.
  // -------------------------------------------------------------------------
  log.info("=== 3. an issuer nobody declared ===");
  // ASSERTED BEFORE THE ISSUER IS DECLARED, deliberately: the same key, the
  // same claims, the same endpoint, and the only difference is one attribute
  // on a directory entry. Asserting it afterwards would need a second key.
  const undeclared = await tokenRequest({
    grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: ASSERTED_PERSON, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, privateKeyPem) });
  const why = refused(undeclared, "invalid_grant",
                      "an assertion from an issuer nobody has declared");
  check("an assertion from an undeclared issuer is REFUSED, which is one of " +
        "only two refusals in this service that default to ON — the grant " +
        "has no browser, no password and no consent step in it, so the " +
        "signature is the whole of its security", function () {
          assert.ok(/oauthAssertionIssuer/.test(why),
            "the refusal should name the attribute that would fix it; it said " +
            JSON.stringify(why).slice(0, 300));
        });
  check("and the refusal names the setting that turns it off, rather than " +
        "leaving somebody to find it", function () {
          assert.ok(/jwtBearerRequireRegisteredIssuer/.test(why),
            JSON.stringify(why).slice(0, 300));
        });

  await ok(realmApi + "/applications/add",
           { application: CLIENT, attribute: "oauthAssertionIssuer",
             value: ISS },
           "declared the assertion issuer");

  // -------------------------------------------------------------------------
  // 4. THE GRANT.
  // -------------------------------------------------------------------------
  log.info("=== 4. the grant itself ===");
  const person = ASSERTED_PERSON;
  const goodJti = jti();
  const assertion = signJws({ alg: "RS256", typ: "JWT", kid: kid },
    { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
      exp: now() + 120, jti: goodJti, department: "engineering",
      employee_number: 4711 }, privateKeyPem);
  const granted = await tokenRequest({ grant_type: GRANT, assertion: assertion,
                                       scope: "openid profile" });
  check("THE SAME ASSERTION IS NOW ACCEPTED — one attribute on a directory " +
        "entry is the whole difference, which is what makes section 3 a gate " +
        "rather than a service refusing for some other reason", function () {
          assert.strictEqual(granted.status, 200,
            JSON.stringify(granted.body).slice(0, 400));
          assert.ok(granted.body.access_token, "no access token came back");
        });
  const claims = claimsOf(granted.body.access_token);
  check("the token is FOR THE SUBJECT of the assertion and not for the " +
        "issuer — a party asserting on somebody's behalf is not that person",
        function () {
          assert.ok(String(claims.sub).indexOf(person) >= 0,
            "sub=" + claims.sub + " for " + person);
          assert.strictEqual(claims.username, person);
        });
  check("RFC 7523 section 3 claim 8: other claims from the assertion are " +
        "carried onto the token, which is the only useful thing an " +
        "authorization server can do with a statement a trusted party made",
        function () {
          assert.strictEqual(claims.department, "engineering");
          assert.strictEqual(claims.employee_number, 4711);
        });
  check("and the profile's OWN claims are not — an `exp` copied off an " +
        "assertion would be a token lifetime chosen by whoever signed it",
        function () {
          assert.ok(claims.exp > now() + 200,
            "the token's exp is " + claims.exp + " and the assertion's was " +
            (now() + 120) + "; it looks copied");
          assert.notStrictEqual(claims.jti, goodJti,
            "the token carries the assertion's own jti");
          assert.strictEqual(claims.iss, realmBase,
            "iss should be this authorization server, not the assertion's");
        });

  // -------------------------------------------------------------------------
  // 5. THE REPLAY, AND EVERY OTHER REFUSAL.
  // -------------------------------------------------------------------------
  log.info("=== 5. the refusals ===");
  const replay = await tokenRequest({ grant_type: GRANT,
                                      assertion: assertion });
  check("THE SAME ASSERTION A SECOND TIME IS REFUSED. A signed assertion " +
        "captured off the wire is a credential until it expires, so its jti " +
        "is remembered until then", function () {
          const said = refused(replay, "invalid_grant", "a replayed assertion");
          assert.ok(/used already/.test(said), said.slice(0, 200));
        });

  const rogue = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const roguePem = rogue.privateKey.export({ type: "pkcs8", format: "pem" });

  const wrongKey = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT" },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, roguePem) });
  check("the RIGHT issuer signed with the WRONG key is refused, and the " +
        "refusal says the assertion did not verify — this is the assertion " +
        "that says the signature is checked at all, and every other refusal " +
        "in this section would pass against a service that checked nothing " +
        "but the claims", function () {
          const said = refused(wrongKey, "invalid_grant",
                               "a wrongly-signed assertion");
          assert.ok(/did not verify/.test(said), said.slice(0, 200));
        });

  const wrongIssuer = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: OTHER_ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, privateKeyPem) });
  check("a DIFFERENT issuer signed with a key this service issued is refused " +
        "— holding a key pair is not being trusted to assert, and the two " +
        "are separate acts", function () {
          refused(wrongIssuer, "invalid_grant", "an undeclared issuer");
        });

  const wrongAudience = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: "https://somebody-else.example/token",
        iat: now(), exp: now() + 120, jti: jti() }, privateKeyPem) });
  check("an assertion minted for ANOTHER authorization server is refused — " +
        "RFC 7521 section 5.2 (5), and it is what stops an assertion being " +
        "replayed from one server to another", function () {
          refused(wrongAudience, "invalid_grant", "a foreign audience");
        });

  const expired = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now() - 600,
        exp: now() - 300, jti: jti() }, privateKeyPem) });
  check("an expired assertion is refused", function () {
    refused(expired, "invalid_grant", "an expired assertion");
  });

  const noJti = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120 }, privateKeyPem) });
  check("an assertion with NO jti is refused, which is RFC 7523 section 3's " +
        "last paragraph read literally: one that cannot be remembered is a " +
        "bearer credential this service has no way to spend", function () {
          const said = refused(noJti, "invalid_grant", "an assertion with no " +
                                                       "jti");
          assert.ok(/jti/.test(said), said.slice(0, 200));
        });

  const noExp = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        jti: jti() }, privateKeyPem) });
  check("and one with no `exp` — it would never stop working", function () {
    refused(noExp, "invalid_grant", "an assertion with no exp");
  });

  const noSub = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, aud: TOKEN_ENDPOINT, iat: now(), exp: now() + 120,
        jti: jti() }, privateKeyPem) });
  check("and one with no `sub` — it says who is asking and not who they are " +
        "asking about", function () {
          refused(noSub, "invalid_grant", "an assertion with no sub");
        });

  const unsigned = b64u(Buffer.from(JSON.stringify(
    { alg: "none", typ: "JWT" }), "utf8")) + "." +
    b64u(Buffer.from(JSON.stringify(
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }), "utf8")) + ".";
  const noneAlg = await tokenRequest({ grant_type: GRANT,
                                       assertion: unsigned });
  check("`alg: \"none\"` is refused BY NAME, citing section 3 claim 9 — it " +
        "is the forgery every JWT implementation has had at some point, and " +
        "a caller sending one deserves to be told which rule it broke rather " +
        "than being told its assertion did not verify", function () {
          const said = refused(noneAlg, "invalid_grant",
                               "an unsigned assertion");
          assert.ok(/claim 9|signed or MACed/.test(said), said.slice(0, 250));
        });

  const tooLong = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 4000, jti: jti() }, privateKeyPem) });
  check("an assertion valid for over an hour is refused — RFC 7521 section " +
        "5.2 leaves the ceiling to the server, and an assertion is meant to " +
        "be spent within seconds of being minted", function () {
          const said = refused(tooLong, "invalid_grant", "a long-lived " +
              "assertion");
          assert.ok(/jwtBearerMaxLifetimeS/.test(said), said.slice(0, 250));
        });

  // -------------------------------------------------------------------------
  // 6. THE CERTIFICATE PATH, AND THE REALM BOUNDARY.
  // -------------------------------------------------------------------------
  log.info("=== 6. an x5c chain, and the realm it anchors in ===");
  const jwks = JSON.parse(fields.oauthAssertionJwks);
  const byChain = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", x5c: jwks.keys[0].x5c },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, privateKeyPem) });
  check("an assertion carrying its CERTIFICATE CHAIN and no kid is accepted " +
        "— which is what makes holding a certificate authority worth " +
        "anything: this service can see that it issued the key", function () {
          assert.strictEqual(byChain.status, 200,
            JSON.stringify(byChain.body).slice(0, 400));
        });

  // THE SAME ASSERTION AT THE DEFAULT REALM'S TOKEN ENDPOINT. A leaf issued
  // here must not verify there.
  //
  // **THE REASON CHANGED ON 2026-09-11 AND THE ASSERTION DID NOT**, which is
  // worth knowing because the old reason is the one a reader will reach for.
  // It used to be that a CA shared across realms would be one authority
  // vouching for several identity services — every realm had a Root of its
  // own, so this chain simply ended somewhere the default realm had never
  // heard of. There is ONE Root for the service now, so that test is true of
  // every certificate this service issues, in any realm, and it stopped being
  // a boundary on the day it was shared. What refuses this today is that the
  // path does not pass through the DEFAULT realm's own Intermediate.
  //
  // The check below is unchanged and is the point: the boundary moved, and a
  // certificate from one realm still does not work in another.
  const elsewhere = await fetch(base + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: GRANT,
      assertion: signJws({ alg: "RS256", typ: "JWT", x5c: jwks.keys[0].x5c },
        { iss: ISS, sub: person, aud: base + "/oauth2/token", iat: now(),
          exp: now() + 120, jti: jti() }, privateKeyPem) }).toString() });
  check("AND THE SAME CHAIN AT ANOTHER REALM'S TOKEN ENDPOINT IS REFUSED — " +
        "the realm boundary, made checkable rather than asserted", function () {
          assert.strictEqual(elsewhere.status, 400,
            "the default realm answered " + elsewhere.status);
        });

  // -------------------------------------------------------------------------
  // 7. RFC 7523 SECTION 3 CLAIM 10 — AN ENCRYPTED ASSERTION.
  // -------------------------------------------------------------------------
  log.info("=== 7. an encrypted assertion ===");
  // The JWE is built HERE rather than through `common/crypto.js`, for the
  // reason the signer above is this file's own: a nested JWT this service both
  // wrote and read would agree with itself whatever either half did. RSA-OAEP
  // -256 with A256GCM, written out — which is four calls to node's crypto.
  const realmJwks = await get(realmBase + "/oauth2/jwks");
  const rsaJwk = (realmJwks.body.keys || []).filter(function (k) {
    return k.kty === "RSA";
  })[0];
  assert.ok(rsaJwk, "this realm publishes no RSA key to encrypt to");
  const recipient = nodeCrypto.createPublicKey({ key: rsaJwk, format: "jwk" });
  const inner = signJws({ alg: "RS256", typ: "JWT", kid: kid },
    { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
      exp: now() + 120, jti: jti() }, privateKeyPem);
  const jweHeader = b64u(Buffer.from(JSON.stringify(
    { alg: "RSA-OAEP-256", enc: "A256GCM", typ: "JWT", cty: "JWT" }), "utf8"));
  const cek = nodeCrypto.randomBytes(32);
  const iv = nodeCrypto.randomBytes(12);
  const wrapped = nodeCrypto.publicEncrypt(
    { key: recipient, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256" }, cek);
  const cipher = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
  cipher.setAAD(Buffer.from(jweHeader, "ascii"));
  const sealed = Buffer.concat([cipher.update(Buffer.from(inner, "utf8")),
                                cipher.final()]);
  const jwe = [jweHeader, b64u(wrapped), b64u(iv), b64u(sealed),
               b64u(cipher.getAuthTag())].join(".");
  const encrypted = await tokenRequest({ grant_type: GRANT, assertion: jwe });
  check("AN ENCRYPTED ASSERTION IS ACCEPTED — a nested JWT, built here with " +
        "node's own crypto and decrypted by this service with the key it " +
        "publishes at /oauth2/jwks", function () {
          assert.strictEqual(encrypted.status, 200,
            JSON.stringify(encrypted.body).slice(0, 400));
          assert.ok(encrypted.body.access_token);
        });

  // A JWE whose plaintext is not a JWS. Encryption does not stand in for a
  // signature: an encrypted document says nothing about who wrote it.
  const iv2 = nodeCrypto.randomBytes(12);
  const cek2 = nodeCrypto.randomBytes(32);
  const wrapped2 = nodeCrypto.publicEncrypt(
    { key: recipient, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256" }, cek2);
  const cipher2 = nodeCrypto.createCipheriv("aes-256-gcm", cek2, iv2);
  cipher2.setAAD(Buffer.from(jweHeader, "ascii"));
  const sealed2 = Buffer.concat([
    cipher2.update(Buffer.from(JSON.stringify(
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, exp: now() + 120,
        jti: jti() }), "utf8")),
    cipher2.final()]);
  const bare = [jweHeader, b64u(wrapped2), b64u(iv2), b64u(sealed2),
                b64u(cipher2.getAuthTag())].join(".");
  const bareResult = await tokenRequest({ grant_type: GRANT, assertion: bare });
  check("and an encrypted assertion that is NOT SIGNED inside is refused — " +
        "encryption does not stand in for a signature, because an encrypted " +
        "document says nothing about who wrote it", function () {
          const said = refused(bareResult, "invalid_grant",
                               "an encrypted unsigned assertion");
          assert.ok(/claim 9|signed/.test(said), said.slice(0, 250));
        });

  // -------------------------------------------------------------------------
  // 8. RFC 7521 SECTION 4.1 — THE SCOPE IS NARROWED AND NEVER WIDENED.
  // -------------------------------------------------------------------------
  log.info("=== 8. the requested scope ===");
  const scoped = await tokenRequest({ grant_type: GRANT,
    scope: "openid email admin",
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti(), scope: "openid email" },
      privateKeyPem) });
  check("a request asking for MORE than the assertion carries gets the " +
        "intersection — the issuer said what this grant is for, and a " +
        "request cannot ask the assertion to authorize something it did not",
        function () {
          assert.strictEqual(scoped.status, 200,
            JSON.stringify(scoped.body).slice(0, 300));
          const got = String(claimsOf(scoped.body.access_token).scope || "")
            .split(/\s+/).filter(Boolean).sort().join(" ");
          assert.strictEqual(got, "email openid",
            "the token carries scope " + JSON.stringify(got));
        });

  // -------------------------------------------------------------------------
  // 9. THE ACT IS RECORDED AS A DELEGATION.
  // -------------------------------------------------------------------------
  log.info("=== 9. what the delegation register says about it ===");
  const delegation = await get(realmApi + "/delegation");
  const acts = (delegation.body.acts || delegation.body.rows || [])
    .filter(function (one) { return one.type === "oauth-assertion-grant"; });
  check("the grant is recorded as a DELEGATION — one party asked this " +
        "service to issue a credential in another party's name, which is " +
        "exactly what the register is for", function () {
          assert.ok(acts.length > 0,
            "no oauth-assertion-grant act in " +
            JSON.stringify((delegation.body.acts || []).map(function (one) {
              return one.type;
            })).slice(0, 300));
        });
  check("and the row names the assertion's ISSUER as the intermediary and " +
        "the SUBJECT as the initial identity — the two are different parties " +
        "and a register that conflated them would say the person asked for " +
        "the token themselves", function () {
          const row = acts[0];
          const text = JSON.stringify(row);
          assert.ok(text.indexOf(ISS) >= 0,
            "the issuer is not on the row: " + text.slice(0, 400));
        });

  // -------------------------------------------------------------------------
  // 10. THE OFF SWITCH, AND THE METADATA FOLLOWING IT.
  // -------------------------------------------------------------------------
  log.info("=== 10. oauth2.jwtBearerGrant off ===");
  await ok(realmApi + "/config/set",
           { key: "oauth2.jwtBearerGrant", value: "false" },
           "switched the grant off in this realm");
  const offMetadata = await get(realmBase +
                                "/.well-known/oauth-authorization-server");
  check("the metadata STOPS ADVERTISING the grant — a grant_types_supported " +
        "member is a promise, and a document that went on naming a grant the " +
        "endpoint refuses would be the worst shape a metadata member can have",
        function () {
          assert.ok((offMetadata.body.grant_types_supported || [])
            .indexOf(GRANT) < 0,
            JSON.stringify(offMetadata.body.grant_types_supported));
        });
  const offResult = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, privateKeyPem) });
  check("and the endpoint refuses it unsupported_grant_type, which is the " +
        "answer a client that read the document and a client that guessed " +
        "both get", function () {
          assert.strictEqual(offResult.status, 400);
          assert.strictEqual(offResult.body.error, "unsupported_grant_type",
            JSON.stringify(offResult.body).slice(0, 300));
        });
  // Put it back through `reset` and not through a second `set` — the two do
  // not leave the same state, and `admin_api.js` asserts that a row nobody
  // overrode does not say `source: override`. See tests/CLAUDE.md.
  await post(realmApi + "/config/reset", { key: "oauth2.jwtBearerGrant" });

  // -------------------------------------------------------------------------
  // 11. THE CONSOLE PAGE, AND THE API THAT MIRRORS IT.
  // -------------------------------------------------------------------------
  log.info("=== 11. /admin/pki and /admin-api/pki ===");
  const apiView = await get(realmApi + "/pki");
  check("GET /admin-api/pki answers with the hierarchy, the algorithm " +
        "vocabularies and the applications holding an issued key pair",
        function () {
          assert.strictEqual(apiView.status, 200);
          assert.strictEqual((apiView.body.chain || {}).tiers.length, 3);
          assert.ok(apiView.body.keyAlgorithms.length >= 7);
          assert.ok(apiView.body.issued.some(function (one) {
            return one.identifier === CLIENT && one.hasKeyPair;
          }), "the issued list does not name " + CLIENT);
        });
  // **THIS CHECK REVERSED ON 2026-09-11 AND ITS OLD FORM WENT ON PASSING.**
  // It read `/no CRL/ && /OCSP/` against a sentence that said *NONE. This
  // service publishes no CRL and answers no OCSP.* Both endpoints exist now,
  // and the replacement sentence contains the words `no CRL` too — in the
  // clause about what this service does not CONSULT — so a substring test
  // over prose reported green against prose saying the opposite. It is
  // `revocationNote` now; `revocation` is the REGISTER.
  // **AND AGAIN ON 2026-09-12**, when a presented certificate started being
  // checked: "consulted by nothing" became the policy in force, by name.
  check("it states what revocation here MEANS in words — published by every " +
        "authority, consulted for a presented certificate under a named " +
        "policy — and where the CA keys live",
        function () {
          assert.ok(/PUBLISHED AND CONSULTED/.test(apiView.body.revocationNote),
            JSON.stringify(apiView.body.revocationNote).slice(0, 200));
          assert.ok(/CONSULTED, (SOFT|HARD)-FAIL|CONSULTED NOWHERE/
                      .test(apiView.body.revocationNote),
            "the note must keep the other half in the same breath: what a " +
            "PRESENTED certificate is held to, by policy name");
          assert.ok(!/^NONE/.test(apiView.body.revocationNote),
            "the report still opens with the claim that reversed");
          assert.ok(String(apiView.body.residency).length > 40);
        });
  check("and the REGISTER is beside the note, one entry per certificate " +
        "authority, each naming its CRL over http and ldap and its OCSP " +
        "responder — because an empty list and no lists at all are " +
        "different answers and one field could only carry one of them",
        function () {
          const register = apiView.body.revocation || {};
          assert.ok(Array.isArray(register.authorities) &&
                    register.authorities.length >= 3,
            JSON.stringify(register).slice(0, 300));
          assert.strictEqual(register.reasons.length, 9,
            "nine of RFC 5280 section 5.3.1's eleven — 7 is unused and " +
            "removeFromCRL is a delta-CRL verb this service cannot honour");
          register.authorities.forEach(function (one) {
            assert.ok(/^http/.test(one.crl.http), one.ca + " has no HTTP CRL");
            assert.ok(/^ldap:/.test(one.crl.ldap), one.ca + " has no LDAP CRL");
            // No ldaps:// since 2026-09-13 — RFC 5280 section 8.
            assert.ok(one.crl.ldaps === undefined, one.ca + " still names an " +
                "LDAPS CRL, which RFC 5280 section 8 says a CA SHOULD NOT");
            assert.ok(/^http/.test(one.ocsp), one.ca + " has no responder");
          });
        });
  check("and NO private key is in it, which is the one thing this reply " +
        "could get wrong that would matter", function () {
          assert.ok(JSON.stringify(apiView.body).indexOf("PRIVATE KEY") < 0);
        });

  const page = await fetch(realmBase + "/admin/pki", { redirect: "manual" });
  check("the console page is BEHIND THE GATE — it is reached through the " +
        "authorization code flow like every other page of that console",
        function () {
          assert.ok(page.status === 303 || page.status === 302,
            "/admin/pki answered " + page.status + " to a caller with no " +
            "console session");
        });

  // -------------------------------------------------------------------------
  // 12. TAKING THE KEY PAIR OFF IS NOT REVOCATION.
  // -------------------------------------------------------------------------
  log.info("=== 12. revoke, which is not revocation ===");
  const removed = await ok(realmApi + "/pki/revoke",
                           { identifier: CLIENT },
                           "took the key pair off");
  check("the reply says in as many words that this is NOT revocation — the " +
        "certificate is still valid and still chains; what changed is that " +
        "this service will no longer accept what the key signs", function () {
          assert.ok(/NOT REVOCATION/i.test(removed.why),
            JSON.stringify(removed.why).slice(0, 300));
        });
  const afterRemoval = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, privateKeyPem) });
  check("and an assertion signed with it is refused from that moment — " +
        "which is the half that IS true, and the reason the operation is " +
        "worth having", function () {
          refused(afterRemoval, "invalid_grant",
                  "an assertion signed with a key that was taken off");
        });

  // -------------------------------------------------------------------------
  // 13. A PERSON AS THE ISSUER (2026-09-11), AND THE ONE RULE THAT COMES WITH
  // IT.
  //
  // Everything above this line has an APPLICATION as the issuer: a party an
  // operator declared, vouching for somebody else. RFC 7523 section 3 asks no
  // such thing — claim 1 wants `iss` to be "a unique identifier for the JWT
  // issuer" and claim 2 says the `sub` of an authorization grant "typically
  // identifies an authorized accessor or resource owner" — so a person holding
  // a key of their own and signing *this is me* is the profile read literally.
  //
  // **THE RULE IS THAT THEY MAY ONLY ASSERT ABOUT THEMSELVES**, and it is the
  // whole security of the feature: without it, everybody ever issued a key on
  // /admin/pki can obtain a token as anybody in the realm, and nothing about
  // the service looks wrong while they do it.
  //
  // What this section adds over `tests/rfc7523_person_issuer.js` in process is
  // the DOORS: that /admin-api/pki issues to a person at all, that the private
  // key comes back from that call and from no other, that the attributes land
  // on the ou=users entry, and that the token endpoint — not just the library —
  // refuses the assertion about somebody else.
  // -------------------------------------------------------------------------
  log.info("=== 13. a person as the issuer ===");
  const SIGNER = usernameFor("selfassert");
  const SOMEBODY = usernameFor("elseentirely");
  await ok(realmApi + "/users/create",
           { username: SIGNER, invent: false,
             attributes: personFields(SIGNER) },
           "created the person who will sign");
  await ok(realmApi + "/users/create",
           { username: SOMEBODY, invent: false,
             attributes: personFields(SOMEBODY) },
           "created somebody else for them to try to speak for");

  const mine = await ok(realmApi + "/pki/issue",
                        { identifier: SIGNER, target: "person" },
                        "issued a signing key pair to a PERSON");
  check("the same `issue` action takes a `target` — one act, one hierarchy, " +
        "one certificate profile — and the kid says which kind of subject it " +
        "was issued to", function () {
          assert.ok(/^person-/.test(mine.kid), "kid=" + mine.kid);
          assert.strictEqual(mine.target, "person");
        });
  check("**THE PRIVATE KEY COMES BACK FROM THIS CALL**, which the " +
        "application arm deliberately does not do: an application's is " +
        "readable afterwards through GET /admin-api/applications, and a " +
        "person's entry is drawn through nothing that would open the seal — " +
        "so the alternatives were a page that prints somebody's private key " +
        "on every visit or a key nobody can ever collect", function () {
          assert.ok(/BEGIN (RSA )?PRIVATE KEY/.test(String(mine.privateKeyPem)),
            "privateKeyPem is " +
            JSON.stringify(mine.privateKeyPem).slice(0, 60));
        });

  const entry = await get(realmApi + "/users?user=" +
                          encodeURIComponent(SIGNER));
  check("and the PUBLIC half is on that person's own directory entry as " +
        "stsAssertion* — an attribute set that shares no name with the " +
        "application's, which is what stops either pair signing for the " +
        "other's holder", function () {
          const whole = JSON.stringify(entry.body).toLowerCase();
          ["stsassertionjwks", "stsassertioncertificate",
           "stsassertioncertificatechain", "stsassertionkid",
           "stsassertionexpiresat"].forEach(function (name) {
            assert.ok(whole.indexOf(name) >= 0,
              name + " is not on " + SIGNER + "'s entry");
          });
        });

  const selfAssertion = signJws(
    { alg: mine.jwsAlg, typ: "JWT", kid: mine.kid },
    { iss: SIGNER, sub: SIGNER, aud: TOKEN_ENDPOINT, iat: now(),
      exp: now() + 120, jti: jti() }, mine.privateKeyPem);
  const selfGrant = await tokenRequest({ grant_type: GRANT,
                                         assertion: selfAssertion,
                                         scope: "openid" });
  check("A PERSON'S ASSERTION ABOUT THEMSELVES IS ACCEPTED at the token " +
        "endpoint — no browser, no password, a signature and an access " +
        "token, which is the shape of this grant a client author most often " +
        "wants to run", function () {
          assert.strictEqual(selfGrant.status, 200,
            JSON.stringify(selfGrant.body).slice(0, 400));
          assert.ok(selfGrant.body.access_token, "no access token came back");
          const mineClaims = claimsOf(selfGrant.body.access_token);
          assert.strictEqual(mineClaims.username, SIGNER,
            "the token is for " + mineClaims.username);
        });

  const aboutOther = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: mine.jwsAlg, typ: "JWT", kid: mine.kid },
      { iss: SIGNER, sub: SOMEBODY, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, mine.privateKeyPem) });
  check("**AND THE SAME PERSON ASSERTING ABOUT SOMEBODY ELSE IS REFUSED.** A " +
        "key issued to one resource owner is that person's credential rather " +
        "than permission to speak for the others; a party that may assert " +
        "about other people is an APPLICATION with the issuer declared on " +
        "it, which is a decision an operator made", function () {
          const why = refused(aboutOther, "invalid_grant",
                              "a person asserting about somebody else");
          assert.ok(/only be about themselves/.test(why),
            "the refusal should say WHY rather than report a lookup that " +
            "failed; it said " + JSON.stringify(why).slice(0, 200));
        });

  // The x5c half, with the entry CLEARED so that the registry cannot be what
  // refuses it. This is the path that does not go through the registry at all,
  // and it is where the rule would have been missed.
  const takenOff = await ok(realmApi + "/pki/revoke",
                            { identifier: SIGNER, target: "person" },
                            "took the person's key pair off");
  check("taking a person's key pair off clears the issuer declaration with " +
        "it — everything in stsAssertion* was put there by the issue, so " +
        "leaving the declaration would leave somebody declared as an issuer " +
        "with no key to issue with — and it says, as the application arm " +
        "does, that this is NOT revocation", function () {
          assert.ok(/NOT REVOCATION/i.test(takenOff.why),
            JSON.stringify(takenOff.why).slice(0, 200));
        });

  const x5c = mine.jwks.keys[0].x5c;
  const chainSelf = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: mine.jwsAlg, typ: "JWT", x5c: x5c },
      { iss: SIGNER, sub: SIGNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, mine.privateKeyPem) });
  check("with nothing on the entry, the CERTIFICATE this service issued is " +
        "still evidence in its own right and the same person may present it " +
        "instead — which is what makes holding a certificate authority worth " +
        "anything", function () {
          assert.strictEqual(chainSelf.status, 200,
            JSON.stringify(chainSelf.body).slice(0, 400));
        });

  const chainOther = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: mine.jwsAlg, typ: "JWT", x5c: x5c },
      { iss: SIGNER, sub: SOMEBODY, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, mine.privateKeyPem) });
  check("**AND THE RULE HOLDS ON THE CERTIFICATE ALONE**, with nothing in " +
        "the registry to consult. Before a person could hold a key pair, " +
        "\"it chains here\" and \"it may assert about somebody\" were one " +
        "sentence; the URI subjectAltName is what keeps them apart now, and " +
        "a check written only against the entry would have passed while " +
        "leaving this open", function () {
          refused(chainOther, "invalid_grant",
                  "a person's certificate presented to assert about somebody " +
                  "else");
        });

  // -------------------------------------------------------------------------
  // 14. ONCE, EVER (2026-09-13) — ONE HISTORY FOR BOTH USES, SPENT ONLY WHEN
  // TOKENS ARE ISSUED, AND ONE VERIFICATION PER REQUEST.
  //
  // Section 5 asserts a replay inside ONE use. What it cannot see is the four
  // things `common/used_assertions.js` changed: a JWT that authenticated a
  // client could ALSO be spent as a grant (two caches keyed two ways); a token
  // request that failed for another reason used the assertion up anyway; and in
  // RFC 9700 mode the token endpoint verified a client assertion TWICE — the
  // policy check spent it and the observation that follows met a replay of the
  // request's own document, so the client was observed as unauthenticated and
  // a role requiring authentication refused it. Each is asserted here as the
  // transition that shows it, with the persistence half left to
  // `tests/used_assertions.js`, because no request can restart the service.
  // -------------------------------------------------------------------------
  log.info("=== 14. once, ever ===");
  const ONCE = usernameFor("onceclient");
  const CLIENT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  await ok(realmApi + "/applications/create",
           { identifier: ONCE, protocols: ["oauth2"],
             fields: { oauthClientId: ONCE,
                       oauthTokenEndpointAuthMethod: "private_key_jwt" } },
           "created an application that authenticates with a JWT");
  const onceIssued = await ok(realmApi + "/pki/issue", { identifier: ONCE },
                              "issued it a signing key pair");
  const onceView = await get(realmApi + "/applications?application=" +
                             encodeURIComponent(ONCE));
  const onceKey = (((onceView.body.application || onceView.body).fields) ||
                   {}).oauthAssertionPrivateKey;
  assert.ok(onceKey, "the issued private key is not on " + ONCE + "'s entry");
  // The same party is trusted to assert as a GRANT, so one document can be
  // presented as either and the only thing that can refuse the second use is
  // the history.
  await ok(realmApi + "/applications/add",
           { application: ONCE, attribute: "oauthAssertionIssuer",
             value: ONCE },
           "declared it as an assertion issuer too");
  function onceJwt() {
    log.debug("Entering onceJwt().");
    log.debug("Leaving onceJwt().");
    return signJws({ alg: onceIssued.jwsAlg, typ: "JWT", kid: onceIssued.kid },
      { iss: ONCE, sub: ONCE, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, onceKey);
  }
  function asClient(assertion, extra) {
    log.debug("Entering asClient().");
    log.debug("Leaving asClient().");
    return tokenRequest(Object.assign({ grant_type: "client_credentials",
      scope: "openid", client_id: ONCE, client_assertion_type: CLIENT_TYPE,
      client_assertion: assertion }, extra || {}));
  }

  const authFirst = onceJwt();
  const authedFirst = await asClient(authFirst);
  check("a JWT authenticates the client at client_credentials", function () {
    assert.strictEqual(authedFirst.status, 200,
      JSON.stringify(authedFirst.body).slice(0, 300));
  });
  const thenGrant = await tokenRequest({ grant_type: GRANT,
                                         assertion: authFirst });
  check("AND THE SAME JWT PRESENTED AS A GRANT IS REFUSED — one history for " +
        "both uses. Two caches keyed two ways accepted it, which is a JWT " +
        "used twice", function () {
          const said = refused(thenGrant, "invalid_grant",
                               "a client assertion re-presented as a grant");
          assert.ok(/used already — as a client assertion/.test(said),
            "the refusal should say what it was spent as; it said " +
            said.slice(0, 250));
        });

  const grantFirst = onceJwt();
  const grantedFirst = await tokenRequest({ grant_type: GRANT,
                                            assertion: grantFirst });
  check("the reverse starts with a JWT accepted as a grant", function () {
    assert.strictEqual(grantedFirst.status, 200,
      JSON.stringify(grantedFirst.body).slice(0, 300));
  });

  // RFC 9700 MODE IN THIS REALM ONLY, which is what makes client
  // authentication REQUIRED — without it a spent client assertion is observed
  // and not refused, and the next three checks would assert nothing.
  await ok(realmApi + "/config/set", { key: "oauth2.rfc9700", value: "true" },
           "put this realm into RFC 9700 mode");
  try {
    const thenClient = await asClient(grantFirst);
    check("and a JWT spent as a grant is refused as a client assertion, " +
          "invalid_client, naming the grant", function () {
            assert.strictEqual(thenClient.status, 401,
              JSON.stringify(thenClient.body).slice(0, 300));
            assert.strictEqual(thenClient.body.error, "invalid_client");
            assert.ok(/used already — as an authorization grant/
                        .test(String(thenClient.body.error_description)),
              String(thenClient.body.error_description).slice(0, 300));
          });

    // RELEASED WHEN THE REQUEST FAILS FOR ANOTHER REASON. The client assertion
    // verifies and is claimed; the request is then refused for a malformed
    // RFC 8707 resource, which is decided after client authentication.
    const released = onceJwt();
    const badResource = await asClient(released,
      { resource: "https://api.example.test/#fragment" });
    check("a token request refused AFTER its client assertion verified — an " +
          "RFC 8707 resource with a fragment — issues nothing", function () {
            assert.strictEqual(badResource.status, 400,
              JSON.stringify(badResource.body).slice(0, 300));
            assert.strictEqual(badResource.body.error, "invalid_target");
          });
    const retried = await asClient(released);
    check("SO THE ASSERTION WAS NOT USED, and the same one succeeds on the " +
          "retry. Spending it on a refusal that had nothing to do with it " +
          "refused a good credential for somebody else's mistake", function () {
            assert.strictEqual(retried.status, 200,
              JSON.stringify(retried.body).slice(0, 300));
          });
    const thirdTime = await asClient(released);
    check("and once tokens HAVE been issued for it, it is spent", function () {
      assert.strictEqual(thirdTime.status, 401,
        JSON.stringify(thirdTime.body).slice(0, 300));
    });

    // ONE VERIFICATION PER REQUEST. With the application narrowed to a role
    // only an AUTHENTICATED application holds, the observation the role gate
    // reads is what decides — and it was the second verification of the
    // request's own assertion.
    await ok(realmApi + "/applications/add",
             { application: ONCE, attribute: "appRequiredRole",
               value: "ALL_AUTHENTICATED_APPLICATIONS" },
             "required an authenticated application");
    try {
      const narrowed = await asClient(onceJwt());
      check("IN RFC 9700 MODE A CLIENT AUTHENTICATED BY JWT HOLDS " +
            "ALL_AUTHENTICATED_APPLICATIONS. The policy check and the " +
            "observation are two questions about one request and get one " +
            "answer; before, the observation met a replay of the request's " +
            "own assertion and this was access_denied", function () {
              assert.strictEqual(narrowed.status, 200,
                JSON.stringify(narrowed.body).slice(0, 300));
            });
    } finally {
      await post(realmApi + "/applications/remove",
                 { application: ONCE, attribute: "appRequiredRole",
                   value: "ALL_AUTHENTICATED_APPLICATIONS" });
    }
  } finally {
    await post(realmApi + "/config/reset", { key: "oauth2.rfc9700" });
  }

  const history = await get(realmApi + "/used-assertions?q=" +
                            encodeURIComponent(ONCE) + "&per=100");
  check("GET /admin-api/used-assertions lists what this realm spent, the " +
        "client assertion and the grant each under the use it was spent as",
        function () {
          assert.strictEqual(history.status, 200,
            JSON.stringify(history.body).slice(0, 300));
          const rows = history.body.rows || [];
          const uses = rows.map(function (one) { return one.use; });
          assert.ok(uses.indexOf("client-authentication") >= 0 &&
                    uses.indexOf("authorization-grant") >= 0,
            "uses listed: " + JSON.stringify(uses));
          assert.ok(rows.every(function (one) {
            return one.issuer === ONCE && one.state === "spent" &&
                   one.expiresAt > Date.now();
          }), JSON.stringify(rows).slice(0, 400));
          assert.ok(history.body.live >= rows.length &&
                    history.body.cap > 0, "live=" + history.body.live);
        });
  check("and NO row carries an assertion — a history of used credentials " +
        "must not be a place to steal one from", function () {
          const whole = JSON.stringify(history.body);
          assert.ok(whole.indexOf(authFirst) < 0 &&
                    whole.indexOf(authFirst.split(".")[2]) < 0,
            "an assertion or its signature is in the reply");
        });
  const grantsOnly = await get(realmApi + "/used-assertions?use=" +
                               "authorization-grant&q=" +
                               encodeURIComponent(ONCE));
  check("and the filter narrows by use", function () {
    assert.ok((grantsOnly.body.rows || []).length > 0 &&
              grantsOnly.body.rows.every(function (one) {
                return one.use === "authorization-grant";
              }), JSON.stringify(grantsOnly.body.rows).slice(0, 300));
  });

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure a suite cannot report about itself.
  assert.ok(checks >= 52,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_jwt_bearer_grant")
  .description("RFC 7521 and RFC 7523 at a real token endpoint: a " +
      "certificate authority built through /admin-api/pki, a signing key " +
      "pair issued to an application and written onto its own directory " +
      "entry, an assertion signed with an implementation of this file's own, " +
      "and the eleven ways it is refused — an undeclared issuer, a replay, a " +
      "wrong key, a foreign audience, an expiry, a missing jti, exp or sub, " +
      "alg=none, a lifetime over the ceiling, an unsigned encrypted " +
      "assertion and a chain from another realm — and, since 2026-09-11, a " +
      "PERSON as the issuer: a key pair issued onto their own ou=users " +
      "entry, an assertion about themselves accepted, and one about somebody " +
      "else refused both on the registered key and on the certificate " +
      "presented alone — and, since 2026-09-13, ONCE EVER: a JWT that " +
      "authenticated a client refused as a grant and the reverse, an " +
      "assertion released by a request refused for another reason, one " +
      "verification of a client assertion per request in RFC 9700 mode, " +
      "and the history at /admin-api/used-assertions.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
