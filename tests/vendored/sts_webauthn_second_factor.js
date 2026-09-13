"use strict";
//
// File: sts_webauthn_second_factor.js
//
// ===========================================================================
// A SECURITY KEY ENROLLED HERE IS DEMANDED HERE AFTERWARDS (2026-09-10).
//
// **THIS JOB EXISTS BECAUSE IT WAS NOT TRUE.** `authn/authn.js` kept a
// credential store of its own — a per-realm map of ONE key per person — while
// `common/credentials.js` kept the security keys on the person's directory
// entry, multi-valued, each with the ROLE it was enrolled in. Two stores, and
// the role model was wired to the one nothing wrote:
//
//   * `credentials.addKey()` had **no caller anywhere in the service**, so
//     `mechanismsFor()` answered `mfaKeys: 0` for everybody, for ever.
//   * `mfaRequired` could therefore never become true from a key, so a key
//     enrolled at the sign-in screen was **never asked for again** — the next
//     sign-in had the checkbox unticked and a password alone was accepted.
//   * `GET /authn/webauthn`'s gate (*does this person hold an `mfa` key?*)
//     refused everybody, so the *use your security key instead* link could
//     never be followed.
//   * `/portal/keys` listed and removed keys that could not exist.
//
// Every one of those is invisible to a test that ticks the box, completes a
// ceremony and asserts that it worked — which is what the coverage was. **The
// assertion that finds it is the SECOND sign-in**, and section 3 is the whole
// reason this file is here.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE AND NOT IN THE PARENT SUITE.
//
// It spans two doors, which is `sts_consent.js`'s third reason. The ceremony is
// a protocol surface and would sit happily over there; what makes the claim
// worth anything is reading the credential back out of **`GET
// /admin-api/users`** — this repository's own API, whose `factors` block is the
// register the sign-in screen consults. A test with the ceremony in one
// repository and the register in the other could not assert that enrolling
// wrote to the store the door reads.
//
// ---------------------------------------------------------------------------
// THE AUTHENTICATOR IS THIS FILE'S OWN, AND THAT IS `sts_dpop.js`'s RULE.
//
// It signs over the real `authenticatorData || SHA-256(clientDataJSON)` with a
// real P-256 key and emits real CBOR. It does NOT import `authn/webauthn.js`:
// if both ends of the exchange came from one implementation, a shared
// misunderstanding would make this pass and interoperate with nothing.
// `tests/webauthn_session.js` holds the same fixture in process against the
// verifier directly; this one drives the DOORS, and the duplication is the
// point rather than a cost.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_webauthn_second_factor",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// THE ORIGIN AND THE RP ID ARE COMPUTED FROM THE SERVICE'S OWN BASE, not
// written down. A `clientDataJSON.origin` is compared byte for byte and an RP
// ID hash is compared byte for byte, so a fixture with `localhost` in it passes
// only on the stack that happens to use that name — and fails on the other two
// with a message about a rejected ceremony rather than about a wrong fixture.
var ORIGIN = new URL(base).origin;
var RP_ID = new URL(base).hostname;

var PERSON = usernameFor("wa-second-factor");

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  ✓ " + what);
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR. See the header for why it is this file's own.
// ---------------------------------------------------------------------------
function sha256(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest();
}
function cborBytes(buf) {
  const head = buf.length < 24 ? Buffer.from([0x40 + buf.length])
    : Buffer.concat([Buffer.from([0x58]), Buffer.from([buf.length])]);
  return Buffer.concat([head, buf]);
}
function cborText(text) {
  const body = Buffer.from(text, "utf8");
  return Buffer.concat([Buffer.from([0x60 + body.length]), body]);
}
function cborMapHeader(n) { return Buffer.from([0xa0 + n]); }
function cborInt(n) { return Buffer.from([n]); }
function cborNegInt(n) { return Buffer.from([0x20 + (Math.abs(n) - 1)]); }

function coseKey(jwk) {
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  return Buffer.concat([
    cborMapHeader(5),
    cborInt(0x01), cborInt(0x02),          // kty: EC2
    cborInt(0x03), cborNegInt(-7),         // alg: ES256
    cborNegInt(-1), cborInt(0x01),         // crv: P-256
    cborNegInt(-2), cborBytes(x),
    cborNegInt(-3), cborBytes(y)
  ]);
}

function authenticatorData(opts) {
  const flags = Buffer.from([opts.flags]);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(opts.signCount >>> 0, 0);
  const parts = [sha256(Buffer.from(RP_ID, "utf8")), flags, count];
  if (opts.attested) {
    const aaguid = Buffer.alloc(16);                 // all-zero: no attestation
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(opts.credentialId.length, 0);
    parts.push(aaguid, idLen, opts.credentialId, opts.cose);
  }
  return Buffer.concat(parts);
}

function clientData(type, challenge) {
  return Buffer.from(JSON.stringify({
    type: type, challenge: challenge, origin: ORIGIN, crossOrigin: false
  }), "utf8");
}

// `flags` 0x45 is UP | UV | AT on registration and 0x05 is UP | UV on an
// assertion — user present AND user verified, because a fixture that never set
// UV could not be run against a realm with `webauthn.userVerification:
// required` and the difference would look like a broken key.
function makeAuthenticator() {
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const credentialId = nodeCrypto.randomBytes(32);
  let signCount = 0;

  return {
    credentialId: credentialId,
    idB64: credentialId.toString("base64url"),
    counter: function () { return signCount; },
    register: function (challenge) {
      const authData = authenticatorData({
        flags: 0x45, signCount: signCount, attested: true,
        credentialId: credentialId, cose: coseKey(jwk)
      });
      const length = Buffer.alloc(2);
      length.writeUInt16BE(authData.length, 0);
      const attestationObject = Buffer.concat([
        cborMapHeader(3),
        cborText("fmt"), cborText("none"),
        cborText("attStmt"), cborMapHeader(0),
        cborText("authData"),
        Buffer.concat([Buffer.from([0x59]), length, authData])
      ]);
      return {
        id: credentialId.toString("base64url"),
        rawId: credentialId.toString("base64url"),
        type: "public-key",
        authenticatorAttachment: "cross-platform",
        clientExtensionResults: { credProps: { rk: false } },
        response: {
          attestationObject: attestationObject.toString("base64url"),
          clientDataJSON: clientData("webauthn.create", challenge).toString("base64url")
        }
      };
    },
    assert: function (challenge) {
      signCount += 1;
      const authData = authenticatorData({ flags: 0x05, signCount: signCount });
      const cdj = clientData("webauthn.get", challenge);
      const signature = nodeCrypto.sign(
        "sha256", Buffer.concat([authData, sha256(cdj)]), pair.privateKey);
      return {
        id: credentialId.toString("base64url"),
        rawId: credentialId.toString("base64url"),
        type: "public-key",
        authenticatorAttachment: "cross-platform",
        response: {
          authenticatorData: authData.toString("base64url"),
          clientDataJSON: cdj.toString("base64url"),
          signature: signature.toString("base64url"),
          userHandle: null
        }
      };
    }
  };
}

// ---------------------------------------------------------------------------
// THE VERBS. Manual redirects and a cookie jar, because every claim here is
// about a session and about WHICH page came back.
// ---------------------------------------------------------------------------
function form(o) { return new URLSearchParams(o).toString(); }

function absolute(location) {
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

function browser() {
  const self = {
    cookie: "",
    async go(method, path, body) {
      const headers = {};
      if (self.cookie) { headers.cookie = self.cookie; }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method, redirect: "manual",
                                              headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) { self.cookie = String(one).split(";")[0]; });
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  return self;
}

async function get(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // An HTML error page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function post(path, payload) {
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

function attr(html, name) {
  const m = String(html).match(new RegExp(name + '="([^"]*)"'));
  return m ? m[1] : "";
}

function hidden(html, name) {
  const m = String(html)
    .match(new RegExp('name="' + name + '"[^>]*value="([^"]*)"'));
  return m ? m[1] : "";
}

// Start an authorization request and get as far as the sign-in screen, which is
// where a pending record exists. `/authn/login` cannot be reached directly —
// it draws a form for a PENDING RECORD and answers 400 to a request naming
// none, which `sts_portal_sessions.js` asserts of every page in this service.
async function reachTheSignInScreen(b) {
  const started = await b.go("GET",
    "/oauth2/authorize?" + form({
      client_id: "wa-probe", redirect_uri: "http://localhost:9999/cb",
      response_type: "code", scope: "openid"
    }));
  assert.ok(/\/authn\/login\?authn=/.test(started.location),
    "the authorization endpoint did not send us to the sign-in screen: " +
    started.status + " " + started.location);
  return started.location.replace(/.*authn=/, "").replace(/&.*/, "");
}

// Complete whichever ceremony the security-key page is drawing. Returns the
// page's own answer, so a caller can assert what came back.
async function completeCeremony(b, page, authenticator) {
  const mode = attr(page, "data-mode");
  const challenge = attr(page, "data-challenge");
  const mfaId = hidden(page, "mfa_id");
  assert.ok(mfaId, "the security-key page carried no mfa_id: " +
    String(page).slice(0, 300));
  assert.ok(challenge, "the security-key page carried no challenge.");
  const credential = mode === "create"
    ? authenticator.register(challenge) : authenticator.assert(challenge);
  return b.go("POST", "/authn/webauthn",
              form({ mfa_id: mfaId, mode: mode,
                     credential: JSON.stringify(credential) }));
}

// ---------------------------------------------------------------------------
// THE PERSON IS CREATED FIRST, WITH A PASSWORD AND THE ATTRIBUTES A REAL
// ACCOUNT CARRIES (2026-09-12). In product mode this service creates nobody
// because a sign-in named them, invents no persona onto an entry, and verifies
// the password — so every password step below presents the one set here, of at
// least twelve characters, rather than a word nothing checks.
// ---------------------------------------------------------------------------
var PASSWORD = "webauthn-second-factor-Passw0rd!-" + String(Date.now()).slice(-6);

async function createThePerson() {
  log.debug("Entering createThePerson().");
  const r = await post("/users/create", {
    username: PERSON, invent: false,
    attributes: { cn: "Security Key Person " + PERSON, givenName: "Security",
                  sn: PERSON, displayName: "Security Key Person " + PERSON,
                  mail: PERSON + "@webauthn-second-factor.test" },
    credential: "password", password: PASSWORD
  });
  assert.ok(r.status === 200 && r.body && r.body.ok && r.body.passwordSet,
    "POST /admin-api/users/create should create " + PERSON + " with a " +
    "password; it answered " + r.status + " " + String(r.raw).slice(0, 300));
  log.debug("Leaving createThePerson().");
}

async function factorsFor(who) {
  const r = await get("/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/users?user=" + who + " answered " + r.status + " " +
    String(r.raw).slice(0, 200));
  return r.body.factors || {};
}

// ---------------------------------------------------------------------------
// 1. ENROLLING ONE. The box is ticked, the page offers a REGISTRATION, and the
//    ceremony this job performs is accepted by the real verifier.
// ---------------------------------------------------------------------------
async function enrollingAKeyAtTheSignInScreen(authenticator) {
  log.info("=== enrolling a security key at the sign-in screen ===");
  const b = browser();
  const authnId = await reachTheSignInScreen(b);

  const page = await b.go("POST", "/authn/login",
    form({ authn_id: authnId, username: PERSON, password: PASSWORD,
           use_webauthn: "1", action: "login" }));
  check("a person holding no key is offered the ENROLMENT ceremony — which is " +
        "this service's enrol-on-first-use behaviour and is unchanged",
    function () {
      assert.strictEqual(page.status, 200,
        "the sign-in answered " + page.status + " " +
        String(page.text).slice(0, 300));
      assert.strictEqual(attr(page.text, "data-mode"), "create",
        "the page is not drawing a registration: " +
        String(page.text).slice(0, 400));
    });

  const done = await completeCeremony(b, page.text, authenticator);
  check("AND THE CEREMONY IS ACCEPTED BY THE REAL VERIFIER — a real P-256 " +
        "signature over the real authenticatorData || SHA-256(clientDataJSON), " +
        "from an implementation that shares no code with the one checking it",
    function () {
      assert.ok(done.status === 302 || done.status === 303,
        "the registration was refused: " + done.status + " " +
        String(done.text).slice(0, 500));
      assert.ok(/oauth2\/authorize/.test(done.location),
        "it did not return to the interrupted request: " + done.location);
    });
  check("and the browser is signed in, so the session was minted on the " +
        "ceremony rather than on the password step alone", function () {
    assert.ok(b.cookie, "no session cookie came back.");
  });
  return b;
}

// ---------------------------------------------------------------------------
// 2. IT REACHED THE STORE THE DOORS READ. **This is the assertion the whole
//    fix is for**, and before it every one of these was 0, false or empty:
//    the ceremony wrote to a map in `authn.js` that nothing else could see.
// ---------------------------------------------------------------------------
async function theKeyIsInTheStoreEverythingElseReads(authenticator) {
  log.info("=== the key reached the credential store ===");
  const factors = await factorsFor(PERSON);

  check("THE KEY IS ON THE PERSON'S OWN ENTRY, where /portal/keys, " +
        "/admin/users, removeKey()'s last-way-in refusal and the sign-in " +
        "screen's own mfaRequired check all read — it was written to a map " +
        "none of them could see", function () {
    assert.strictEqual(factors.mfaKeys, 1,
      "the credential store holds " + factors.mfaKeys + " second-factor " +
      "key(s): " + JSON.stringify(factors));
    assert.strictEqual((factors.keys || []).length, 1,
      "and " + (factors.keys || []).length + " key(s) are listed.");
  });

  check("IT CARRIES THE ROLE IT WAS ENROLLED IN. The ceremony cannot say " +
        "which — the POST is the browser's result and nothing in it says what " +
        "was chosen a screen ago — so the role comes off the pending record, " +
        "and a key with no role is a key no policy can decide anything about",
    function () {
      assert.strictEqual(factors.keys[0].role, "mfa",
        "the key is stored as " + factors.keys[0].role);
    });

  check("and it names the credential the browser sent, so an assertion can be " +
        "matched to it later", function () {
      assert.strictEqual(factors.keys[0].credentialId, authenticator.idB64,
        "the stored credential id is not the one enrolled.");
    });

  check("AND `mfaRequired` IS TRUE NOW, which is the flag the sign-in screen " +
        "reads and which no security key could ever set before", function () {
    assert.strictEqual(factors.mfaRequired, true,
      "a second factor is not being required of them: " +
      JSON.stringify(factors));
    assert.strictEqual(factors.secondFactor, "webauthn",
      "and the wrong factor will be asked for: " + factors.secondFactor);
  });
}

// ---------------------------------------------------------------------------
// 3. THE SECOND SIGN-IN. **THE ASSERTION THIS FILE EXISTS FOR.**
//
// The box is NOT ticked. A person who has enrolled a second factor must be
// asked for it anyway — otherwise the enrolment is a per-sign-in opt-in, and
// anybody who knows the password signs in without ever meeting it.
// ---------------------------------------------------------------------------
async function theSecondSignInDemandsItWithoutBeingAsked(authenticator) {
  log.info("=== the second sign-in demands the key with the box UNTICKED ===");
  const b = browser();
  const authnId = await reachTheSignInScreen(b);

  const page = await b.go("POST", "/authn/login",
    form({ authn_id: authnId, username: PERSON, password: PASSWORD,
           action: "login" }));
  check("A PASSWORD ALONE NO LONGER SIGNS THEM IN. The checkbox is untouched " +
        "and the security-key step is demanded anyway, because the account is " +
        "CONFIGURED for two factors — which is what `mfaRequired` means and " +
        "what nothing at this door read", function () {
    assert.strictEqual(page.status, 200,
      "the sign-in answered " + page.status + " — a redirect here is a " +
      "session minted on one factor, which is the bypass this asserts is " +
      "closed: " + page.location);
    assert.ok(/wa-data/.test(page.text),
      "the security-key page was not drawn: " + String(page.text).slice(0, 400));
  });

  check("AND IT IS AN ASSERTION, NOT ANOTHER ENROLMENT — the ceremony is " +
        "against the key they hold. A `create` here would let anybody who " +
        "knows the password register an authenticator of their own and be " +
        "signed in claiming two factors, which is not a weaker second factor " +
        "but none at all", function () {
    assert.strictEqual(attr(page.text, "data-mode"), "get",
      "the page is drawing a " + attr(page.text, "data-mode") + " ceremony.");
    assert.ok(attr(page.text, "data-allow").indexOf(authenticator.idB64) >= 0,
      "allowCredentials does not name the enrolled key: " +
      attr(page.text, "data-allow"));
  });

  const done = await completeCeremony(b, page.text, authenticator);
  check("and the key they actually hold completes it", function () {
    assert.ok(done.status === 302 || done.status === 303,
      "the assertion was refused: " + done.status + " " +
      String(done.text).slice(0, 500));
  });

  const factors = await factorsFor(PERSON);
  check("THE SIGNATURE COUNTER ADVANCED, so WebAuthn's replay defence has " +
        "something to check against next time — it is recorded through " +
        "credentials.noteKeyUsed(), and a counter that never moves is a " +
        "defence that never defends", function () {
    assert.ok(factors.keys[0].signCount > 0,
      "the stored counter is still " + factors.keys[0].signCount);
  });
}

// ---------------------------------------------------------------------------
// 4. AN ASSERTION FROM AN AUTHENTICATOR THIS PERSON NEVER ENROLLED.
//
// The negative that matters, for `sts_dpop.js`'s reason: a service that
// accepts the right key looks finished. This one signs a perfectly valid
// ceremony with a DIFFERENT key and requires a refusal.
// ---------------------------------------------------------------------------
async function somebodyElsesAuthenticatorIsRefused() {
  log.info("=== an authenticator this person never enrolled is refused ===");
  const stranger = makeAuthenticator();
  const b = browser();
  const authnId = await reachTheSignInScreen(b);
  const page = await b.go("POST", "/authn/login",
    form({ authn_id: authnId, username: PERSON, password: PASSWORD,
           action: "login" }));
  assert.ok(/wa-data/.test(page.text),
    "the security-key page was not drawn for the refusal case.");

  const done = await completeCeremony(b, page.text, stranger);
  check("A VALID CEREMONY FROM THE WRONG KEY IS REFUSED. The signature is " +
        "real and the challenge is right; what is wrong is that the " +
        "credential is not one of this person's — which is the check that " +
        "makes several keys per person safe", function () {
    assert.strictEqual(done.status, 200,
      "the stranger's authenticator was ACCEPTED (" + done.status + " " +
      done.location + ").");
    assert.ok(/could not be checked|did not verify|not one of/.test(done.text),
      "it was refused without saying why: " + String(done.text).slice(0, 400));
  });
  check("and no session came out of it", function () {
    assert.ok(!b.cookie || !/oauth2/.test(done.location),
      "a session was established on a refused ceremony.");
  });
}

// ---------------------------------------------------------------------------
// 5. THE LINK THAT COULD NEVER BE FOLLOWED.
//
// `GET /authn/webauthn?mfa=…` gates on *does this person hold an `mfa` key*,
// which was `mechanismsFor().mfaKeys` — always 0 — so the *use your security
// key instead* link refused everybody. It is reachable now, and the gate still
// refuses somebody who holds nothing.
// ---------------------------------------------------------------------------
async function theUseYourKeyInsteadLinkWorks() {
  log.info("=== the use-your-key-instead link is reachable ===");
  const b = browser();
  const authnId = await reachTheSignInScreen(b);
  const page = await b.go("POST", "/authn/login",
    form({ authn_id: authnId, username: PERSON, password: PASSWORD,
           action: "login" }));
  const mfaId = hidden(page.text, "mfa_id");
  const drawn = await b.go("GET", "/authn/webauthn?mfa=" +
                           encodeURIComponent(mfaId));
  check("GET /authn/webauthn draws the ceremony for somebody who HOLDS a key " +
        "— its own gate asks the credential store, which answered `nobody " +
        "holds one` for everybody until the two stores became one", function () {
    assert.strictEqual(drawn.status, 200,
      "it answered " + drawn.status + " " + String(drawn.text).slice(0, 300));
    assert.strictEqual(attr(drawn.text, "data-mode"), "get",
      "and it is not drawing an assertion.");
  });
}

// ---------------------------------------------------------------------------
// 6. THE OPERATOR'S REMOVE, AND WHAT IT UNDOES.
//
// The other half of the store being real: a key that can be enrolled can be
// cleared, and clearing it stops the demand. Before this, the Clear button on
// `/admin/users` could only ever answer "no security key of that id is
// enrolled".
// ---------------------------------------------------------------------------
async function anOperatorCanClearItAndTheDemandStops(authenticator) {
  log.info("=== an operator clears it and the demand stops ===");
  const r = await post("/users/clear-key",
    { user: PERSON, credentialId: authenticator.idB64 });
  check("POST /admin-api/users/clear-key removes a key that really exists — " +
        "the console's Clear button could only ever answer `no security key " +
        "of that id is enrolled`, because none could", function () {
    assert.strictEqual(r.status, 200,
      "it answered " + r.status + " " + String(r.raw).slice(0, 300));
  });

  const factors = await factorsFor(PERSON);
  check("and the account is back to one factor", function () {
    assert.strictEqual(factors.mfaKeys, 0,
      "the key is still on the entry: " + JSON.stringify(factors.keys));
    assert.strictEqual(factors.mfaRequired, false,
      "a second factor is still being demanded of them.");
  });

  const b = browser();
  const authnId = await reachTheSignInScreen(b);
  const page = await b.go("POST", "/authn/login",
    form({ authn_id: authnId, username: PERSON, password: PASSWORD,
           action: "login" }));
  check("SO A PASSWORD ALONE SIGNS THEM IN AGAIN, which is what makes the " +
        "clear the way back for somebody who lost their key rather than a " +
        "button that reports success and changes nothing", function () {
    assert.ok(page.status === 302 || page.status === 303,
      "the sign-in answered " + page.status + " rather than completing: " +
      String(page.text).slice(0, 300));
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " as " + PERSON +
           " (origin " + ORIGIN + ", rpId " + RP_ID + ").");
  const authenticator = makeAuthenticator();

  await createThePerson();
  await enrollingAKeyAtTheSignInScreen(authenticator);
  await theKeyIsInTheStoreEverythingElseReads(authenticator);
  await theSecondSignInDemandsItWithoutBeingAsked(authenticator);
  await somebodyElsesAuthenticatorIsRefused();
  await theUseYourKeyInsteadLinkWorks();
  await anOperatorCanClearItAndTheDemandStops(authenticator);

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure a suite cannot report about itself.
  assert.ok(checks >= 14,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_webauthn_second_factor")
  .description("Drive a real WebAuthn ceremony against the sign-in screen and " +
      "assert the credential reaches the store every other door reads: that " +
      "enrolling writes a key with its ROLE to the person's directory entry, " +
      "that the SECOND sign-in demands it with the checkbox untouched, that " +
      "an assertion from an authenticator they never enrolled is refused, " +
      "that the signature counter advances, and that an operator's clear " +
      "stops the demand.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
