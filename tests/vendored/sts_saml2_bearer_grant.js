"use strict";
//
// File: sts_saml2_bearer_grant.js
//
// ===========================================================================
// RFC 7521 AND RFC 7522 AT A REAL TOKEN ENDPOINT, AND THE TWO KEY PAIRS THAT
// MAY NOT SIGN FOR EACH OTHER (2026-09-11).
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE AND NOT IN THE PARENT SUITE.
//
// `sts_jwt_bearer_grant.js`'s reason, word for word, because it is the same
// reason: **every assertion spans an AUTHORING door and a PROTOCOL door.** A
// signing key pair does not exist until `/admin-api/pki` issues one — and for
// this profile it has to be issued with `purpose: "saml"`, which is a control
// on this repository's own console — and an assertion issuer is not trusted
// until `oauthSamlAssertionIssuer` is written through
// `/admin-api/applications`. Only then is there a question worth asking
// `/oauth2/token`.
//
// ---------------------------------------------------------------------------
// AND WHY IT IS NOT `tests/saml_assertion_grant.js`.
//
// That file is in process and asserts what the MODULE decides: the eleven
// items of section 3 as a table, the two attribute sets being disjoint read
// out of the source, the grammar `read()` applies. It sends no request, so it
// cannot see a grant that is registered and unreachable, a
// `grant_types_supported` member that promises something the endpoint refuses,
// a key pair written to the wrong six attributes, or a console control that
// issues for the wrong profile. **Every function involved can be correct while
// the feature does not work.**
//
// ---------------------------------------------------------------------------
// THE ONE THING THIS JOB EXISTS FOR THAT NEITHER OF THOSE COVERS.
//
// **THE TWO PROFILES' KEY PAIRS MUST NOT BE ABLE TO SIGN FOR EACH OTHER, AND
// THAT IS A CLAIM ABOUT TWO ENDPOINTS RATHER THAN ABOUT ONE MODULE.** Section
// 1 below issues both to ONE application through the real console API, and
// section 6 then presents each key pair at the OTHER profile's grant — a JWT
// signed with the SAML key, and a SAML assertion signed with the JWT key. Both
// are refused, and both are refused while the correct key pair works at the
// same endpoint in the same realm seconds earlier, which is the only shape
// that tells a rule from a service failing for some other reason.
//
// ---------------------------------------------------------------------------
// MOSTLY NEGATIVES, FOR `sts_dpop.js`'s REASON, and with more force here: a
// SAML verifier that does not really check the signature looks exactly like
// one that does, because XML Signature is complicated enough that "it worked"
// is what everybody reports right up until somebody sends a document with the
// digest changed. The assertions are made with an XML Signature implementation
// of this suite's own (`saml_xmldsig.js`), for the reason that file's header
// gives.
//
// ---------------------------------------------------------------------------
// IT WORKS IN A THROWAWAY TRUST REALM, for `sts_jwt_bearer_grant.js`'s sharper
// reason: a certificate authority is PER REALM, so a realm of its own gives
// this job a hierarchy whose entire contents it built. It does NOT remove the
// realm afterwards; see *No job removes a realm* in `tests/CLAUDE.md`.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const saml = require("./saml_xmldsig.js");

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
var log = bunyan.createLogger({ name: "sts_saml2_bearer_grant",
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

var REALM = usernameFor("saml2bearer").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var realmBase = base + "/realm/" + REALM;
var realmApi = realmBase + "/admin-api";
var TOKEN_ENDPOINT = realmBase + "/oauth2/token";

var CLIENT = "saml-assert-issuer-1";
var AUTH_CLIENT = "saml-auth-client-1";
var ISS = "https://issuer.example.test/saml2bearer";
var OTHER_ISS = "https://other-issuer.example.test/saml2bearer";

// ---------------------------------------------------------------------------
// WHAT A REAL DEPLOYMENT WOULD HAVE PROVISIONED, SUPPLIED UP FRONT
// (2026-09-12).
//
// Product mode seeds no `alice`, invents no persona onto an entry, and holds
// every OAuth application to a client credential. So the asserting
// application is created with a client secret (the SAML-authenticating one
// already holds an asymmetric credential, issued in section 8), and the person
// every assertion below is ABOUT is a directory entry this job makes, with the
// attributes a real account carries, rather than a seeded name.
//
// **WHAT IS NOT SUPPLIED**: product mode also refuses a token request that
// authenticates no client, and the grant requests here carry none. RFC 7521
// section 4.2 makes client authentication OPTIONAL for an authorization grant,
// and adding it would change the grant under test — the same decision
// `sts_jwt_bearer_grant.js` records.
// ---------------------------------------------------------------------------
var ASSERTED_PERSON = usernameFor("samlasserted");

var GRANT = "urn:ietf:params:oauth:grant-type:saml2-bearer";
var JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
var CLIENT_TYPE = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";
var JWT_CLIENT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// A JWS SIGNER, for sections 6 and 12 ALONE — where a JWT has to be presented
// at the RFC 7523 grant signed with the SAML profile's key, or with the JWT
// profile's own to show that one still works. Thirty lines because RFC
// 7515's compact serialization is thirty lines, and this file's own for
// `saml_xmldsig.js`'s reason.
// ---------------------------------------------------------------------------
function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString("base64url");
}

function signJws(header, payload, privateKeyPem) {
  log.debug("Entering signJws().");
  const signing = b64u(Buffer.from(JSON.stringify(header), "utf8")) + "." +
                  b64u(Buffer.from(JSON.stringify(payload), "utf8"));
  const sig = nodeCrypto.sign("sha256", Buffer.from(signing, "ascii"),
                              privateKeyPem);
  log.debug("Leaving signJws().");
  return signing + "." + b64u(sig);
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
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
  // 0. THE REALM, THE CERTIFICATE AUTHORITY, AND THE APPLICATIONS.
  // -------------------------------------------------------------------------
  log.info("=== 0. a realm, a CA, and two applications ===");
  await ok(api + "/realms/create", { id: REALM,
                                     domain: REALM + ".example.net",
                                     name: "SAML bearer grant" },
           "created the trust realm");
  const built = await ok(realmApi + "/pki/build",
                         { organisation: "SAML Assertion Test", country: "US" },
                         "built a certificate authority");
  check("a three-tier hierarchy is built in this realm", function () {
    assert.strictEqual(built.chain.tiers.length, 3,
      "expected Root, Intermediate and Issuing; got " +
      JSON.stringify((built.chain.tiers || []).map(function (one) {
        return one.tier;
      })));
  });
  await ok(realmApi + "/applications/create",
           { identifier: CLIENT, protocols: ["oauth2"],
             fields: { oauthClientId: CLIENT,
                       oauthClientSecret: CLIENT + "-secret-" + REALM,
                       oauthTokenEndpointAuthMethod: "client_secret_post" } },
           "created the asserting application");
  await ok(realmApi + "/users/create",
           { username: ASSERTED_PERSON, invent: false,
             attributes: { cn: "SAML Asserted " + ASSERTED_PERSON,
                           givenName: "SAML", sn: ASSERTED_PERSON,
                           displayName: "SAML Asserted " + ASSERTED_PERSON,
                           mail: ASSERTED_PERSON +
                                 "@saml2-bearer-grant.test" } },
           "created the person the assertions are about");
  await ok(realmApi + "/applications/create",
           { identifier: AUTH_CLIENT, protocols: ["oauth2"],
             fields: { oauthClientId: AUTH_CLIENT,
                       oauthTokenEndpointAuthMethod: "saml2_bearer" } },
           "created the application that authenticates by SAML assertion");

  // -------------------------------------------------------------------------
  // 1. TWO KEY PAIRS, ONE APPLICATION, AND WHERE EACH ONE LANDS.
  // -------------------------------------------------------------------------
  log.info("=== 1. both profiles' key pairs, on one application ===");
  const jwtIssued = await ok(realmApi + "/pki/issue", { identifier: CLIENT },
                             "issued the RFC 7523 key pair");
  const samlIssued = await ok(realmApi + "/pki/issue",
                              { identifier: CLIENT, purpose: "saml" },
                              "issued the RFC 7522 key pair");
  check("the purpose DEFAULTS to the JWT profile, which is what every caller " +
        "written before this field existed sends", function () {
          assert.strictEqual(jwtIssued.purpose, "jwt");
          assert.strictEqual(samlIssued.purpose, "saml");
        });
  // ONE FEWER THAN THE JWT PROFILE'S, which is the claim; the numbers moved
  // from five and six on 2026-09-13, when both sets gained the provenance
  // attribute (`…KeySource`) that records an issue from an upload.
  check("and the SAML reply names the attributes it wrote — ONE FEWER than " +
        "the JWT profile's, because SAML has no JWKS: what a party registers " +
        "for that profile IS a certificate", function () {
          assert.strictEqual(samlIssued.attributes.length,
            jwtIssued.attributes.length - 1,
            JSON.stringify(samlIssued.attributes) + " against " +
            JSON.stringify(jwtIssued.attributes));
          assert.ok(jwtIssued.attributes.indexOf("oauthAssertionJwks") >= 0 &&
                    samlIssued.attributes.every(function (name) {
                      return !/Jwks/.test(name);
                    }), "the difference is not the JWKS");
          assert.ok(samlIssued.attributes.every(function (name) {
            return /^oauthSamlAssertion/.test(name);
          }), JSON.stringify(samlIssued.attributes));
          assert.ok(samlIssued.thumbprint,
            "the reply carries no certificate thumbprint");
        });

  const view = await get(realmApi + "/applications?application=" +
                         encodeURIComponent(CLIENT));
  const fields = ((view.body.application || view.body).fields) || {};
  const samlKey = fields.oauthSamlAssertionPrivateKey;
  const samlCert = fields.oauthSamlAssertionCertificate;
  const jwtKey = fields.oauthAssertionPrivateKey;
  const jwtKid = fields.oauthAssertionKid;

  check("the RFC 7522 private key and certificate are on the application's " +
        "own entry, beside the RFC 7523 ones and not instead of them — which " +
        "is the whole of the separation, stated as two attributes that are " +
        "both there at once", function () {
          assert.ok(samlKey && /BEGIN PRIVATE KEY/.test(samlKey),
            "oauthSamlAssertionPrivateKey is " +
            JSON.stringify(samlKey).slice(0, 60));
          assert.ok(samlCert && /BEGIN CERTIFICATE/.test(samlCert),
            "oauthSamlAssertionCertificate is empty");
          assert.ok(jwtKey && /BEGIN PRIVATE KEY/.test(jwtKey),
            "issuing the SAML pair took the JWT one off");
          assert.ok(fields.oauthAssertionJwks, "the JWT JWKS went missing");
        });
  check("and they are DIFFERENT KEYS — the requirement in one comparison",
        function () {
          assert.notStrictEqual(samlKey, jwtKey,
            "one key pair is serving both profiles");
        });
  check("the chain and the expiry came with it, and the handle is a " +
        "THUMBPRINT where the JWT profile's is a kid — because those are the " +
        "handles the two formats actually carry", function () {
          assert.ok(fields.oauthSamlAssertionCertificateChain,
            "oauthSamlAssertionCertificateChain is empty");
          assert.ok(fields.oauthSamlAssertionExpiresAt,
            "oauthSamlAssertionExpiresAt is empty");
          assert.strictEqual(fields.oauthSamlAssertionThumbprint,
                             samlIssued.thumbprint);
          assert.notStrictEqual(fields.oauthSamlAssertionThumbprint, jwtKid);
        });

  // The assertion builder every section below goes through.
  function assertionFor(o) {
    log.debug("Entering assertionFor().");
    const options = o || {};
    const doc = saml.buildAssertion(Object.assign(
      { issuer: ISS, subject: options.person || ASSERTED_PERSON,
        audience: TOKEN_ENDPOINT, recipient: TOKEN_ENDPOINT },
      options.build || {}));
    const xml = saml.sign(doc, options.key || samlKey,
                          options.cert === null ? "" :
                          (options.cert || samlCert),
                          options.signOpts || {});
    log.debug("Leaving assertionFor().");
    return options.encode === "base64" ? saml.b64(xml) : saml.b64u(xml);
  }

  // -------------------------------------------------------------------------
  // 2. THE METADATA SAYS WHAT THIS ENDPOINT WILL DO.
  // -------------------------------------------------------------------------
  log.info("=== 2. the metadata ===");
  const md = await get(realmBase + "/.well-known/oauth-authorization-server");
  check("grant_types_supported advertises the SAML 2.0 bearer grant BESIDE " +
        "the JWT one — two profiles of one framework, and a document naming " +
        "only one of them would be a client author concluding the other is " +
        "not offered", function () {
          const grants = md.body.grant_types_supported || [];
          assert.ok(grants.indexOf(GRANT) >= 0, JSON.stringify(grants));
          assert.ok(grants.indexOf(JWT_GRANT) >= 0, JSON.stringify(grants));
        });
  check("the SAML client_assertion_type is published, which is the one thing " +
        "a client author needs to know before writing any code against this " +
        "profile: the assertion is XML rather than a JWT", function () {
          assert.strictEqual(
            md.body[CLIENT_TYPE + "_supported"], true,
            JSON.stringify(Object.keys(md.body).filter(function (k) {
              return /client-assertion-type/.test(k);
            })));
        });
  check("and `saml2_bearer` is in token_endpoint_auth_methods_supported — " +
        "THIS SERVICE'S OWN NAME for a method RFC 7522 registers none for, " +
        "published so that a client discovers it rather than reading it in a " +
        "comment", function () {
          assert.ok((md.body.token_endpoint_auth_methods_supported || [])
            .indexOf("saml2_bearer") >= 0,
            JSON.stringify(md.body.token_endpoint_auth_methods_supported));
        });

  // -------------------------------------------------------------------------
  // 3. THE REFUSAL THAT DEFAULTS TO ON.
  // -------------------------------------------------------------------------
  log.info("=== 3. an Issuer nobody declared ===");
  // ASSERTED BEFORE THE ISSUER IS DECLARED, deliberately: the same key, the
  // same document, the same endpoint, and the only difference from section 4
  // is one attribute on a directory entry.
  const undeclared = await tokenRequest({ grant_type: GRANT,
                                          assertion: assertionFor({}) });
  const why = refused(undeclared, "invalid_grant",
                      "an assertion from an Issuer nobody has declared");
  check("an assertion from an undeclared Issuer is REFUSED — the grant has " +
        "no browser, no password and no consent step in it, so the signature " +
        "is the whole of its security", function () {
          assert.ok(/oauthSamlAssertionIssuer/.test(why),
            "the refusal should name the attribute that would fix it; it said " +
            JSON.stringify(why).slice(0, 300));
        });
  check("and it names the setting that turns it off, and the SEPARATE " +
        "attribute — declaring an issuer for RFC 7523 must not silently " +
        "declare it for RFC 7522", function () {
          assert.ok(/saml2BearerRequireRegisteredIssuer/.test(why),
            JSON.stringify(why).slice(0, 300));
        });

  // The JWT profile's declaration, written FIRST and deliberately: it must not
  // be enough. This is the cheapest possible statement that the two
  // declarations are two.
  await ok(realmApi + "/applications/add",
           { application: CLIENT, attribute: "oauthAssertionIssuer",
             value: ISS },
           "declared the issuer for the JWT profile");
  const stillRefused = await tokenRequest({ grant_type: GRANT,
                                            assertion: assertionFor({}) });
  check("DECLARING THE ISSUER FOR RFC 7523 DOES NOT DECLARE IT FOR RFC 7522 " +
        "— being trusted to assert in one format is not being trusted to " +
        "assert in the other, and an operator who wrote one attribute has " +
        "not accidentally written two", function () {
          refused(stillRefused, "invalid_grant",
                  "a SAML assertion whose issuer is declared only for JWTs");
        });

  await ok(realmApi + "/applications/add",
           { application: CLIENT, attribute: "oauthSamlAssertionIssuer",
             value: ISS },
           "declared the assertion issuer for the SAML profile");

  // -------------------------------------------------------------------------
  // 4. THE GRANT.
  // -------------------------------------------------------------------------
  log.info("=== 4. the grant itself ===");
  const person = ASSERTED_PERSON;
  const granted = await tokenRequest({
    grant_type: GRANT, scope: "openid profile",
    assertion: assertionFor({ person: person,
      build: { attributes: { department: "engineering",
                             employee_number: "4711" },
               authnStatement: true } }) });
  check("THE SAME ASSERTION IS NOW ACCEPTED — one attribute on a directory " +
        "entry is the whole difference, which is what makes that refusal a " +
        "gate rather than a service refusing for some other reason",
        function () {
          assert.strictEqual(granted.status, 200,
            JSON.stringify(granted.body).slice(0, 400));
          assert.ok(granted.body.access_token, "no access token came back");
        });
  const claims = claimsOf(granted.body.access_token);
  // A person's `sub` is `urn:uuid:<entryUUID>` since 2026-09-14
  // (`authn/CLAUDE.md`), so it is not built from the name: the job asks the
  // realm's /admin-api/users what this person's subject is and compares.
  const subjectAnswer = await get(realmApi + "/users?user=" +
                                  encodeURIComponent(person));
  const expectedSub = String((subjectAnswer.body &&
                              subjectAnswer.body.subject) || "");
  check("the token is FOR THE <Subject> of the assertion and not for its " +
        "<Issuer> — a party asserting on somebody's behalf is not that person",
        function () {
          assert.ok(/^urn:uuid:[0-9a-f-]{36}$/.test(expectedSub),
            "the subject of " + person + " from /admin-api/users: " +
            String(subjectAnswer.raw).slice(0, 200));
          assert.strictEqual(claims.sub, expectedSub,
            "sub=" + claims.sub + " for " + person);
          assert.strictEqual(claims.username, person);
        });
  check("RFC 7522 section 3 item 8: the <AttributeStatement> is carried onto " +
        "the token, which is the only useful thing an authorization server " +
        "can do with a statement a trusted party made", function () {
          assert.strictEqual(claims.department, "engineering");
          assert.strictEqual(claims.employee_number, "4711");
        });
  check("and the token is this authorization server's own — its `iss` is " +
        "this realm and its expiry is this service's, not the assertion's",
        function () {
          assert.strictEqual(claims.iss, realmBase,
            "iss should be this authorization server, not the assertion's");
          assert.ok(claims.exp > now() + 200,
            "the token's exp is " + claims.exp +
            " and the assertion's was about " + (now() + 120) +
            "; it looks copied");
        });

  // STANDARD base64, which the specification does not ask for and several
  // widely-deployed stacks send. Accepted and warned about, which is this
  // service's usual shape — and asserted here because a client author whose
  // stack does it needs to know it works.
  const standard = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person, encode: "base64" }) });
  check("an assertion in STANDARD base64 is accepted, though RFC 7522 " +
        "section 2.1 asks for base64url — a mock that refused it would send " +
        "a client author to look at their signature code", function () {
          assert.strictEqual(standard.status, 200,
            JSON.stringify(standard.body).slice(0, 300));
        });

  // -------------------------------------------------------------------------
  // 5. THE REFUSALS.
  // -------------------------------------------------------------------------
  log.info("=== 5. the refusals ===");
  const replayable = saml.buildAssertion({ issuer: ISS, subject: person,
    audience: TOKEN_ENDPOINT, recipient: TOKEN_ENDPOINT });
  const replayableXml = saml.b64u(saml.sign(replayable, samlKey, samlCert));
  const spent = await tokenRequest({ grant_type: GRANT,
                                     assertion: replayableXml });
  check("an assertion is spent once", function () {
    assert.strictEqual(spent.status, 200,
      JSON.stringify(spent.body).slice(0, 300));
  });
  const replay = await tokenRequest({ grant_type: GRANT,
                                      assertion: replayableXml });
  check("AND THE SAME ASSERTION A SECOND TIME IS REFUSED. RFC 7522 section 3 " +
        "item 6 makes the replay cache a MAY; a signed assertion captured " +
        "off the wire is a credential until it expires, so \"may\" is not " +
        "the useful reading", function () {
          const said = refused(replay, "invalid_grant", "a replayed assertion");
          assert.ok(/used already/.test(said), said.slice(0, 200));
        });

  const rogue = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const roguePem = rogue.privateKey.export({ type: "pkcs8", format: "pem" });
  const wrongKey = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person, key: roguePem, cert: null }) });
  check("the RIGHT Issuer signed with the WRONG key is refused, and the " +
        "refusal says the signature did not verify — THIS IS THE ASSERTION " +
        "THAT SAYS THE SIGNATURE IS CHECKED AT ALL, and every other refusal " +
        "in this section would pass against a service that checked nothing " +
        "but the elements", function () {
          const said = refused(wrongKey, "invalid_grant",
                               "a wrongly-signed assertion");
          assert.ok(/did not verify/.test(said), said.slice(0, 200));
        });

  const tampered = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
                              signOpts: { breakDigest: true } }) });
  check("and an assertion whose REFERENCE DIGEST does not match its own " +
        "document is refused — which is the half of an XML Signature that a " +
        "verifier checking only the SignatureValue would wave through, and " +
        "is how a signature-wrapping attack gets in", function () {
          refused(tampered, "invalid_grant", "a tampered assertion");
        });

  const wrongIssuer = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
                              build: { issuer: OTHER_ISS } }) });
  check("a DIFFERENT Issuer signed with a key this service issued is refused " +
        "— holding a key pair is not being trusted to assert, and the two " +
        "are separate acts", function () {
          refused(wrongIssuer, "invalid_grant", "an undeclared issuer");
        });

  const wrongAudience = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
      build: { audience: "https://somebody-else.example/token" } }) });
  check("an assertion whose <AudienceRestriction> names another " +
        "authorization server is refused — RFC 7522 section 3 item 2, and " +
        "the ONE refusal in this profile that has no off switch at all",
        function () {
          const said = refused(wrongAudience, "invalid_grant",
                               "a foreign audience");
          assert.ok(/item 2/.test(said), said.slice(0, 200));
        });

  const wrongRecipient = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
      build: { recipient: "https://somebody-else.example/token" } }) });
  check("and one whose <SubjectConfirmationData> Recipient names another " +
        "token endpoint is refused — item 5, which is the check that stops " +
        "an assertion being relayed from the endpoint it was delivered to",
        function () {
          refused(wrongRecipient, "invalid_grant", "a foreign recipient");
        });

  const expired = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
      build: { notBefore: saml.iso(-600000),
               notOnOrAfter: saml.iso(-300000) } }) });
  check("an expired assertion is refused", function () {
    refused(expired, "invalid_grant", "an expired assertion");
  });

  const noExpiry = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
      build: { notOnOrAfter: null, confirmationNotOnOrAfter: null } }) });
  check("and one with NO expiry on either element is refused — item 4; it " +
        "would be a credential anybody who captured it could use for ever",
        function () {
          const said = refused(noExpiry, "invalid_grant",
                               "an assertion with no expiry");
          assert.ok(/item 4/.test(said), said.slice(0, 200));
        });

  const noSubject = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
                              build: { omitSubject: true } }) });
  check("one with no <Subject> is refused — it says who is asking and not " +
        "who they are asking about", function () {
          refused(noSubject, "invalid_grant", "an assertion with no subject");
        });

  const unsigned = saml.b64u(saml.buildAssertion({ issuer: ISS,
    subject: person, audience: TOKEN_ENDPOINT,
    recipient: TOKEN_ENDPOINT }).xml);
  const noSignature = await tokenRequest({ grant_type: GRANT,
                                           assertion: unsigned });
  check("AN UNSIGNED ASSERTION IS REFUSED BY NAME, citing item 9 — it is " +
        "this profile's `alg: \"none\"`, and a caller sending one deserves " +
        "to be told which rule it broke rather than being told its assertion " +
        "did not verify", function () {
          const said = refused(noSignature, "invalid_grant",
                               "an unsigned assertion");
          assert.ok(/item 9|signed or have a MAC/.test(said),
                    said.slice(0, 250));
        });

  const tooLong = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
      build: { notOnOrAfter: saml.iso(4000 * 1000),
               confirmationNotOnOrAfter: saml.iso(4000 * 1000) } }) });
  check("an assertion valid for over an hour is refused — item 6 leaves " +
        "\"unreasonably far in the future\" to the server, and an assertion " +
        "is meant to be spent within seconds of being minted", function () {
          const said = refused(tooLong, "invalid_grant",
                               "a long-lived assertion");
          assert.ok(/saml2BearerMaxLifetimeS/.test(said), said.slice(0, 250));
        });

  const unknownCondition = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person,
      build: { unknownCondition: "ProhibitedByLaw" } }) });
  check("and one carrying a <Condition> this service does not understand is " +
        "refused rather than IGNORED — item 11 by way of SAML core section " +
        "2.5.1, and the item most implementations skip because ignoring an " +
        "unknown element is what every other XML reader does", function () {
          refused(unknownCondition, "invalid_grant", "an unknown condition");
        });

  const notXml = await tokenRequest({ grant_type: GRANT,
    assertion: "this is not an assertion" });
  check("something that is not an assertion at all is refused " +
        "invalid_request, because there is nothing yet to be an invalid " +
        "GRANT", function () {
          assert.strictEqual(notXml.status, 400);
          assert.ok(notXml.body.error === "invalid_request" ||
                    notXml.body.error === "invalid_grant",
            JSON.stringify(notXml.body).slice(0, 200));
        });

  // -------------------------------------------------------------------------
  // 6. THE CROSSING. The one thing this job exists for.
  // -------------------------------------------------------------------------
  log.info("=== 6. neither key pair may sign for the other profile ===");
  const samlSignedWithJwtKey = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person, key: jwtKey,
                              cert: fields.oauthAssertionCertificate }) });
  check("A SAML ASSERTION SIGNED WITH THE SAME APPLICATION'S RFC 7523 KEY " +
        "PAIR IS REFUSED — the certificate is a real one this realm's own CA " +
        "issued minutes ago, so it is not being refused for failing to chain",
        function () {
          const said = refused(samlSignedWithJwtKey, "invalid_grant",
                               "a SAML assertion signed with the JWT key");
          assert.ok(/KeyInfo|registered/.test(said), said.slice(0, 250));
        });
  check("and the refusal explains WHY a chain is not enough for this profile " +
        "— it proves the REALM issued a key and says nothing about which " +
        "application holds it, which is the one place this service is " +
        "stricter here than for RFC 7523", function () {
          const said = String(samlSignedWithJwtKey.body.error_description);
          assert.ok(/chain/.test(said), said.slice(0, 250));
        });

  // AND THE OTHER WAY ROUND. The RFC 7523 grant reads `oauthAssertionJwks`
  // and `oauthAssertionIssuer` — both of which this application HAS — so a JWT
  // signed with the SAML profile's private key is a document from a declared
  // issuer signed with a key that is registered for the wrong profile. If the
  // JWT verifier ever learned to read the SAML certificate, this is the
  // assertion that would go red.
  const jwtSignedWithSamlKey = await tokenRequest({ grant_type: JWT_GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT" },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: nodeCrypto.randomUUID() }, samlKey) });
  check("AND A JWT SIGNED WITH THE RFC 7522 KEY PAIR IS REFUSED AT THE RFC " +
        "7523 GRANT — the same claim from the other side, and the one that " +
        "would go red if the JWT verifier ever learned to read the SAML " +
        "certificate. The issuer is declared for both profiles by now, so " +
        "the ONLY thing refusing it is which key signed it", function () {
          refused(jwtSignedWithSamlKey, "invalid_grant",
                  "a JWT signed with the SAML key pair");
        });
  const jwtSignedProperly = await tokenRequest({ grant_type: JWT_GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: jwtKid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: nodeCrypto.randomUUID() }, jwtKey) });
  check("while the JWT signed with its OWN key pair is accepted at the same " +
        "endpoint in the same realm — which is what turns the two refusals " +
        "above into a rule rather than a service that has stopped working",
        function () {
          assert.strictEqual(jwtSignedProperly.status, 200,
            JSON.stringify(jwtSignedProperly.body).slice(0, 300));
        });

  // -------------------------------------------------------------------------
  // 7. RFC 7521 SECTION 4.1 — THE SCOPE IS NARROWED AND NEVER WIDENED.
  // -------------------------------------------------------------------------
  log.info("=== 7. the requested scope ===");
  // The extra scope is `profile` — one every client may ask for — and not a
  // word of the job's own: in product mode an undeclared scope is refused
  // invalid_scope before the grant is read (#110), and what this section is
  // about is the ASSERTION narrowing a request, not the client's list.
  const scoped = await tokenRequest({ grant_type: GRANT,
    scope: "openid email profile",
    assertion: assertionFor({ person: person,
      build: { attributes: { scope: "openid email" } } }) });
  check("a request asking for MORE than the assertion's <Attribute " +
        "Name=\"scope\"> carries gets the intersection — the issuer said " +
        "what this grant is for, and a request cannot ask the assertion to " +
        "authorize something it did not", function () {
          assert.strictEqual(scoped.status, 200,
            JSON.stringify(scoped.body).slice(0, 300));
          const got = String(claimsOf(scoped.body.access_token).scope || "")
            .split(/\s+/).filter(Boolean).sort().join(" ");
          assert.strictEqual(got, "email openid",
            "the token carries scope " + JSON.stringify(got));
        });

  // -------------------------------------------------------------------------
  // 8. RFC 7522 SECTION 2.2 — CLIENT AUTHENTICATION.
  // -------------------------------------------------------------------------
  log.info("=== 8. the same document authenticating a client ===");
  const authIssued = await ok(realmApi + "/pki/issue",
                              { identifier: AUTH_CLIENT, purpose: "saml" },
                              "issued the client's SAML key pair");
  assert.ok(authIssued.thumbprint, "no thumbprint on the issue reply");
  const authView = await get(realmApi + "/applications?application=" +
                             encodeURIComponent(AUTH_CLIENT));
  const authFields = ((authView.body.application ||
                       authView.body).fields) || {};
  const authKey = authFields.oauthSamlAssertionPrivateKey;
  const authCert = authFields.oauthSamlAssertionCertificate;

  // RFC 9700 MODE IN THIS REALM ONLY, which is what makes client
  // authentication REQUIRED rather than merely observed — without it a bad
  // assertion is not refused, and the section would assert nothing. A realm
  // may be in that mode while the process is not; see `common/CLAUDE.md`.
  await ok(realmApi + "/config/set", { key: "oauth2.rfc9700", value: "true" },
           "put this realm into RFC 9700 mode");

  function clientAssertion(o) {
    log.debug("Entering clientAssertion().");
    const options = o || {};
    const doc = saml.buildAssertion(Object.assign(
      { issuer: AUTH_CLIENT, subject: AUTH_CLIENT, audience: TOKEN_ENDPOINT,
        recipient: TOKEN_ENDPOINT }, options.build || {}));
    log.debug("Leaving clientAssertion().");
    return saml.b64u(saml.sign(doc, options.key || authKey,
                               options.cert === null ? "" :
                                 (options.cert || authCert)));
  }

  const authed = await tokenRequest({ grant_type: "client_credentials",
    scope: "openid", client_id: AUTH_CLIENT,
    client_assertion_type: CLIENT_TYPE,
    client_assertion: clientAssertion({}) });
  check("A CLIENT AUTHENTICATES WITH A SAML 2.0 ASSERTION (section 2.2) and " +
        "gets a token, in a realm where authentication is REQUIRED — which " +
        "is the only state in which this section asserts anything",
        function () {
          assert.strictEqual(authed.status, 200,
            JSON.stringify(authed.body).slice(0, 400));
          assert.ok(authed.body.access_token);
        });

  const noClientId = await tokenRequest({ grant_type: "client_credentials",
    scope: "openid", client_assertion_type: CLIENT_TYPE,
    client_assertion: clientAssertion({}) });
  check("and with NO client_id at all — RFC 7521 section 6.2: the assertion " +
        "identifies the client, and item 3B makes its <Subject> the " +
        "client_id, so the parameter carries nothing the document does not",
        function () {
          assert.strictEqual(noClientId.status, 200,
            JSON.stringify(noClientId.body).slice(0, 300));
        });

  const wrongSubject = await tokenRequest({ grant_type: "client_credentials",
    scope: "openid", client_id: AUTH_CLIENT,
    client_assertion_type: CLIENT_TYPE,
    client_assertion: clientAssertion({ build: {
      subject: "somebody-else" } }) });
  check("an assertion whose <Subject> is not the client_id is refused — item " +
        "3B, and it is the check that stops one client authenticating as " +
        "another with a perfectly valid signature of its own", function () {
          assert.strictEqual(wrongSubject.status, 401,
            JSON.stringify(wrongSubject.body).slice(0, 300));
          assert.strictEqual(wrongSubject.body.error, "invalid_client");
        });

  const wrongType = await tokenRequest({ grant_type: "client_credentials",
    scope: "openid", client_id: AUTH_CLIENT,
    client_assertion_type: JWT_CLIENT_TYPE,
    client_assertion: clientAssertion({}) });
  check("and the RIGHT document under the WRONG client_assertion_type is " +
        "refused with a message naming the expected one — the two profiles " +
        "put different documents in one parameter, and \"your assertion is " +
        "invalid\" would be the least useful true sentence available",
        function () {
          assert.strictEqual(wrongType.status, 401);
          assert.ok(/saml2-bearer/.test(
            String(wrongType.body.error_description)),
            String(wrongType.body.error_description).slice(0, 250));
        });

  await post(realmApi + "/config/reset", { key: "oauth2.rfc9700" });

  // -------------------------------------------------------------------------
  // 9. THE ACT IS RECORDED AS A DELEGATION, AND AS ITS OWN MECHANISM.
  // -------------------------------------------------------------------------
  log.info("=== 9. what the delegation register says about it ===");
  const delegation = await get(realmApi + "/delegation");
  const rows = (delegation.body.acts || delegation.body.rows || []);
  const samlActs = rows.filter(function (one) {
    return one.type === "oauth-saml-assertion-grant";
  });
  check("the grant is recorded as a DELEGATION — one party asked this " +
        "service to issue a credential in another party's name, which is " +
        "exactly what the register is for", function () {
          assert.ok(samlActs.length > 0,
            "no oauth-saml-assertion-grant act in " +
            JSON.stringify(rows.map(function (one) { return one.type; }))
              .slice(0, 300));
        });
  check("and it is a MECHANISM OF ITS OWN rather than the JWT one with a " +
        "format noted on it — a reader asking how a token was authorized has " +
        "to be told which document was spent and which declaration allowed " +
        "it, and those are different for the two profiles", function () {
          const jwtActs = rows.filter(function (one) {
            return one.type === "oauth-assertion-grant";
          });
          assert.ok(jwtActs.length > 0,
            "the JWT grant in section 6 left no act, so this comparison " +
            "proves nothing");
          assert.ok(samlActs[0].type !== jwtActs[0].type);
        });

  // -------------------------------------------------------------------------
  // 10. THE OFF SWITCH, AND THE METADATA FOLLOWING IT.
  // -------------------------------------------------------------------------
  log.info("=== 10. oauth2.saml2BearerGrant off ===");
  await ok(realmApi + "/config/set",
           { key: "oauth2.saml2BearerGrant", value: "false" },
           "switched the SAML grant off in this realm");
  const offMetadata = await get(realmBase +
                                "/.well-known/oauth-authorization-server");
  check("the metadata STOPS ADVERTISING the SAML grant and GOES ON " +
        "advertising the JWT one — two settings rather than one, because a " +
        "deployment legitimately offers one profile and not the other",
        function () {
          const grants = offMetadata.body.grant_types_supported || [];
          assert.ok(grants.indexOf(GRANT) < 0, JSON.stringify(grants));
          assert.ok(grants.indexOf(JWT_GRANT) >= 0, JSON.stringify(grants));
        });
  const offResult = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person }) });
  check("and the endpoint refuses it unsupported_grant_type, which is the " +
        "answer a client that read the document and a client that guessed " +
        "both get", function () {
          assert.strictEqual(offResult.status, 400);
          assert.strictEqual(offResult.body.error, "unsupported_grant_type",
            JSON.stringify(offResult.body).slice(0, 300));
        });
  // Put it back through `reset` and not through a second `set` — the two do
  // not leave the same state. See tests/CLAUDE.md.
  await post(realmApi + "/config/reset", { key: "oauth2.saml2BearerGrant" });

  // -------------------------------------------------------------------------
  // 11. THE CONSOLE PAGE, AND THE API THAT MIRRORS IT.
  // -------------------------------------------------------------------------
  log.info("=== 11. /admin/pki and /admin-api/pki ===");
  const apiView = await get(realmApi + "/pki");
  check("GET /admin-api/pki publishes the two PROFILES a key pair may be " +
        "issued for, with the attributes each writes — a caller learns the " +
        "vocabulary from the service rather than from a copy of this list",
        function () {
          const purposes = (apiView.body.purposes || []).map(function (one) {
            return one.id;
          });
          assert.deepStrictEqual(purposes.sort(), ["jwt", "saml"],
            JSON.stringify(apiView.body.purposes));
        });
  check("and there is ONE ROW PER APPLICATION PER PROFILE, so an application " +
        "holding both key pairs appears twice — every fact on such a row is " +
        "per profile, so a single row would have had to say which of two " +
        "things each of its columns meant", function () {
          const mine = (apiView.body.issued || []).filter(function (one) {
            return one.identifier === CLIENT;
          });
          assert.strictEqual(mine.length, 2,
            JSON.stringify(mine.map(function (one) { return one.purpose; })));
          assert.ok(mine.every(function (one) { return one.hasKeyPair; }),
            "a row says there is no key pair: " + JSON.stringify(mine));
          const saml2 = mine.filter(function (one) {
            return one.purpose === "saml";
          })[0];
          assert.strictEqual(saml2.handleLabel, "thumbprint");
          assert.ok(saml2.assertionIssuers.indexOf(ISS) >= 0,
            "the SAML row does not carry the declared issuer: " +
            JSON.stringify(saml2.assertionIssuers));
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
  // 12. TAKING ONE KEY PAIR OFF LEAVES THE OTHER WORKING.
  // -------------------------------------------------------------------------
  log.info("=== 12. revoke, which is per profile and is not revocation ===");
  const removed = await ok(realmApi + "/pki/revoke",
                           { identifier: CLIENT, purpose: "saml" },
                           "took the SAML key pair off");
  check("the reply says in as many words that this is NOT revocation — the " +
        "certificate is still valid and still chains; what changed is that " +
        "this service will no longer accept what the key signs", function () {
          assert.ok(/NOT REVOCATION/i.test(removed.why),
            JSON.stringify(removed.why).slice(0, 300));
        });
  const afterRemoval = await tokenRequest({ grant_type: GRANT,
    assertion: assertionFor({ person: person }) });
  check("and a SAML assertion signed with it is refused from that moment — " +
        "the half that IS true, and the reason the operation is worth having",
        function () {
          refused(afterRemoval, "invalid_grant",
                  "an assertion signed with a key that was taken off");
        });
  const jwtStillWorks = await tokenRequest({ grant_type: JWT_GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: jwtKid },
      { iss: ISS, sub: person, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: nodeCrypto.randomUUID() }, jwtKey) });
  check("WHILE THE RFC 7523 KEY PAIR ON THE SAME APPLICATION GOES ON " +
        "WORKING. Taking one profile's credential off must not take the " +
        "other's, and a control that cleared both would be a button whose " +
        "label said one thing and did two", function () {
          assert.strictEqual(jwtStillWorks.status, 200,
            JSON.stringify(jwtStillWorks.body).slice(0, 300));
        });
  const after = await get(realmApi + "/applications?application=" +
                          encodeURIComponent(CLIENT));
  const afterFields = ((after.body.application || after.body).fields) || {};
  check("and the entry says the same thing: the RFC 7522 attributes are " +
        "empty and the RFC 7523 ones are untouched", function () {
          assert.ok(!afterFields.oauthSamlAssertionPrivateKey,
            "oauthSamlAssertionPrivateKey survived the take-off");
          assert.ok(afterFields.oauthAssertionPrivateKey,
            "oauthAssertionPrivateKey was taken off too");
        });

  // -------------------------------------------------------------------------
  // 13. ONCE, EVER, ACROSS THE TWO SECTIONS (2026-09-13).
  //
  // Both RFC 7522 sections always shared one cache here — a document that
  // would authenticate a client would also grant for it. What changed is that
  // the cache became `common/used_assertions.js`, persisted and shared with the
  // JWT profile, and that an assertion is spent only when tokens are issued.
  // This section keeps the cross-section rule honest against that module over
  // HTTP, in both directions, and reads the history back.
  // -------------------------------------------------------------------------
  log.info("=== 13. once, ever, across both sections ===");
  await ok(realmApi + "/applications/add",
           { application: AUTH_CLIENT, attribute: "oauthSamlAssertionIssuer",
             value: AUTH_CLIENT },
           "declared the authenticating client as a SAML assertion issuer too");
  // AND A PERSON OF THE SAME NAME (2026-09-14). A client assertion's
  // <Subject> is the client_id, so the one document presented both ways names
  // AUTH_CLIENT — and a grant for somebody with no directory entry is refused
  // `invalid_grant` since that date (`oauth-oidc/CLAUDE.md`), for a reason
  // that is not the history this section is about.
  await ok(realmApi + "/users/create",
           { username: AUTH_CLIENT, invent: false,
             attributes: { cn: "SAML client " + AUTH_CLIENT, givenName: "SAML",
                           sn: AUTH_CLIENT,
                           displayName: "SAML client " + AUTH_CLIENT,
                           mail: AUTH_CLIENT + "@saml-grant.test" } },
           "created the person the grant half names");
  const bothWays = clientAssertion({});
  const authFirst = await tokenRequest({ grant_type: "client_credentials",
    scope: "openid", client_id: AUTH_CLIENT, client_assertion_type: CLIENT_TYPE,
    client_assertion: bothWays });
  check("a SAML assertion authenticates the client (section 2.2)",
        function () {
          assert.strictEqual(authFirst.status, 200,
            JSON.stringify(authFirst.body).slice(0, 300));
        });
  const thenGrant = await tokenRequest({ grant_type: GRANT,
                                         assertion: bothWays });
  check("AND THE SAME DOCUMENT AS A GRANT (section 2.1) IS REFUSED, naming " +
        "the section it was spent under", function () {
          const said = refused(thenGrant, "invalid_grant",
                               "a client assertion re-presented as a grant");
          assert.ok(/used already — under RFC 7522 section 2\.2/.test(said),
            said.slice(0, 250));
        });

  const grantFirst = clientAssertion({});
  const grantedFirst = await tokenRequest({ grant_type: GRANT,
                                            assertion: grantFirst });
  check("the reverse starts with a document accepted as a grant", function () {
    assert.strictEqual(grantedFirst.status, 200,
      JSON.stringify(grantedFirst.body).slice(0, 300));
  });
  // RFC 9700 mode, for the reason section 8 gives: without it a spent client
  // assertion is observed and not refused.
  await ok(realmApi + "/config/set", { key: "oauth2.rfc9700", value: "true" },
           "put this realm into RFC 9700 mode");
  try {
    const thenClient = await tokenRequest({ grant_type: "client_credentials",
      scope: "openid", client_id: AUTH_CLIENT,
      client_assertion_type: CLIENT_TYPE, client_assertion: grantFirst });
    check("and a document spent as a grant is refused as a client " +
          "assertion, invalid_client, naming section 2.1", function () {
            assert.strictEqual(thenClient.status, 401,
              JSON.stringify(thenClient.body).slice(0, 300));
            assert.ok(/used already — under RFC 7522 section 2\.1/
                        .test(String(thenClient.body.error_description)),
              String(thenClient.body.error_description).slice(0, 300));
          });
  } finally {
    await post(realmApi + "/config/reset", { key: "oauth2.rfc9700" });
  }
  const samlHistory = await get(realmApi + "/used-assertions?format=saml&q=" +
                                encodeURIComponent(AUTH_CLIENT) + "&per=100");
  check("GET /admin-api/used-assertions lists both documents under the " +
        "SAML format with the Issuer and the section each was spent under",
        function () {
          assert.strictEqual(samlHistory.status, 200);
          const rows = samlHistory.body.rows || [];
          assert.ok(rows.length >= 2 && rows.every(function (one) {
            return one.format === "saml" && one.issuer === AUTH_CLIENT;
          }), JSON.stringify(rows).slice(0, 400));
          const uses = rows.map(function (one) { return one.use; });
          assert.ok(uses.indexOf("client-authentication") >= 0 &&
                    uses.indexOf("authorization-grant") >= 0,
            JSON.stringify(uses));
          assert.ok(JSON.stringify(samlHistory.body).indexOf("Signature") < 0,
            "an XML Signature — part of an assertion — is in the reply");
        });

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure a suite cannot report about itself.
  assert.ok(checks >= 45,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_saml2_bearer_grant")
  .description("RFC 7521 and RFC 7522 at a real token endpoint: a " +
      "certificate authority built through /admin-api/pki, TWO signing key " +
      "pairs issued to one application — one per assertion profile — a SAML " +
      "2.0 assertion signed with an XML Signature implementation of this " +
      "suite's own, the fourteen ways it is refused, the same document " +
      "authenticating a client under section 2.2, and the claim the whole " +
      "design rests on: neither key pair can sign for the other profile, at " +
      "either grant — and, since 2026-09-13, one document spent once across " +
      "both sections, read back from /admin-api/used-assertions.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
