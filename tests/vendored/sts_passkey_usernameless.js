// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// sts_passkey_usernameless.js — PASSKEYS AS DISCOVERABLE CREDENTIALS (#474),
// over HTTP, in every mode the suite runs.
//
// `tests/passkey_discoverable.js` holds the same design in process; this is
// the protocol half, so the product mode, the cluster and an AWS target see
// it too (tests/CLAUDE.md, *where a new test goes*). It is `local: true`:
// written here, never vendored from the parent.
//
// The passkey is registered the way product allows a PRIMARY key to be —
// through an activation link (`/portal/activate`), never at the sign-in
// screen — by a software authenticator that keeps the user handle it was
// created under and hands it back on every assertion, as a discoverable
// credential does.
//
// **ALL OF IT IN A THROWAWAY REALM OF ITS OWN**, because the suite runs jobs
// side by side (the main, bulk and conformance lanes): `webauthn.usernameless`
// changes what `/authn/login` draws, and turned on in the DEFAULT realm it
// would be on for every job loading that screen meanwhile. A realm's setting
// is its own. The realm is left behind afterwards, as every job's is.
//
// The setting is off at first (G), then on for the rest:
//
//   A. the page created the credential under a minted 64-byte handle, never
//      the username's bytes, and the person's key list says it signs in with
//      no username;
//   B. the sign-in screen draws the real button, the autofill token and the
//      script, under `script-src 'self'` with the framing clause kept;
//   C. a usernameless assertion signs its owner in, and the session says
//      `amr ["hwk","user"]`, `acr "mfa"`;
//   D. one without user verification is refused;
//   E. one under a handle nobody holds is refused;
//   F. the real button with the script blocked is told it needs JavaScript;
//   G. with the setting at its default, off, nothing is drawn and the door
//      refuses — asserted first.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const fixtures = require("./oauth_fixtures.js");

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
var log = bunyan.createLogger({ name: "sts_passkey_usernameless",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
// THE REALM (see the header): every request below goes to it.
var REALM = usernameFor("pknouser").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var DOMAIN = REALM + ".example.net";
var serviceApi = base + "/admin-api";
base = base + "/realm/" + REALM;
var api = base + "/admin-api";

// The origin and RP ID from the service's own base (the realm's is on the
// same host), for
// `sts_webauthn_second_factor.js`'s reason: both are compared byte for byte.
var ORIGIN = new URL(base).origin;
var RP_ID = new URL(base).hostname;

var PERSON = usernameFor("passkey-nouser");
var CLIENT = "pk-nouser-probe";
var REDIRECT = "http://localhost:9999/cb";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR, `sts_webauthn_second_factor.js`'s, holding its user
// handle.
// ---------------------------------------------------------------------------
function sha256(buf) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash("sha256").update(buf).digest();
}

function cborBytes(buf) {
  log.debug("Entering cborBytes().");
  const head = buf.length < 24 ? Buffer.from([0x40 + buf.length])
    : Buffer.concat([Buffer.from([0x58]), Buffer.from([buf.length])]);
  log.debug("Leaving cborBytes().");
  return Buffer.concat([head, buf]);
}

function cborText(text) {
  log.debug("Entering cborText().");
  const body = Buffer.from(text, "utf8");
  log.debug("Leaving cborText().");
  return Buffer.concat([Buffer.from([0x60 + body.length]), body]);
}

function cborMapHeader(n) {
  log.debug("Entering cborMapHeader().");
  log.debug("Leaving cborMapHeader().");
  return Buffer.from([0xa0 + n]);
}

function cborInt(n) {
  log.debug("Entering cborInt().");
  log.debug("Leaving cborInt().");
  return Buffer.from([n]);
}

function cborNegInt(n) {
  log.debug("Entering cborNegInt().");
  log.debug("Leaving cborNegInt().");
  return Buffer.from([0x20 + (Math.abs(n) - 1)]);
}

function coseKey(jwk) {
  log.debug("Entering coseKey().");
  log.debug("Leaving coseKey().");
  return Buffer.concat([
    cborMapHeader(5),
    cborInt(0x01), cborInt(0x02),          // kty: EC2
    cborInt(0x03), cborNegInt(-7),         // alg: ES256
    cborNegInt(-1), cborInt(0x01),         // crv: P-256
    cborNegInt(-2), cborBytes(Buffer.from(jwk.x, "base64url")),
    cborNegInt(-3), cborBytes(Buffer.from(jwk.y, "base64url"))
  ]);
}

function authenticatorData(opts) {
  log.debug("Entering authenticatorData().");
  const count = Buffer.alloc(4);
  count.writeUInt32BE(opts.signCount >>> 0, 0);
  const parts = [sha256(Buffer.from(RP_ID, "utf8")), Buffer.from([opts.flags]),
                 count];
  if (opts.attested) {
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(opts.credentialId.length, 0);
    parts.push(Buffer.alloc(16), idLen, opts.credentialId, opts.cose);
  }
  log.debug("Leaving authenticatorData().");
  return Buffer.concat(parts);
}

function clientData(type, challenge) {
  log.debug("Entering clientData().");
  log.debug("Leaving clientData().");
  return Buffer.from(JSON.stringify({
    type: type, challenge: challenge, origin: ORIGIN, crossOrigin: false
  }), "utf8");
}

// Registration 0x45 (UP | UV | AT); an assertion 0x05 (UP | UV), or 0x01 —
// user presence alone — where `uv` is false.
function makeAuthenticator() {
  log.debug("Entering makeAuthenticator().");
  const pair = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const credentialId = nodeCrypto.randomBytes(32);
  let signCount = 0;
  let userHandle = "";
  log.debug("Leaving makeAuthenticator().");
  return {
    idB64: credentialId.toString("base64url"),
    handle: function () {
      log.debug("Entering handle().");
      log.debug("Leaving handle().");
      return userHandle;
    },
    register: function (challenge, handle) {
      log.debug("Entering register().");
      userHandle = handle;
      const authData = authenticatorData({
        flags: 0x45, signCount: signCount, attested: true,
        credentialId: credentialId, cose: coseKey(jwk) });
      const length = Buffer.alloc(2);
      length.writeUInt16BE(authData.length, 0);
      const attestationObject = Buffer.concat([
        cborMapHeader(3),
        cborText("fmt"), cborText("none"),
        cborText("attStmt"), cborMapHeader(0),
        cborText("authData"),
        Buffer.concat([Buffer.from([0x59]), length, authData])
      ]);
      log.debug("Leaving register().");
      return {
        id: credentialId.toString("base64url"),
        rawId: credentialId.toString("base64url"),
        type: "public-key", authenticatorAttachment: "platform",
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          attestationObject: attestationObject.toString("base64url"),
          clientDataJSON: clientData("webauthn.create", challenge)
            .toString("base64url"),
          transports: ["internal", "hybrid"] } };
    },
    assert: function (challenge, opts) {
      log.debug("Entering assert().");
      const o = opts || {};
      signCount += 1;
      const authData = authenticatorData({
        flags: o.uv === false ? 0x01 : 0x05, signCount: signCount });
      const cdj = clientData("webauthn.get", challenge);
      const signature = nodeCrypto.sign(
        "sha256", Buffer.concat([authData, sha256(cdj)]), pair.privateKey);
      log.debug("Leaving assert().");
      return {
        id: credentialId.toString("base64url"),
        rawId: credentialId.toString("base64url"),
        type: "public-key", authenticatorAttachment: "platform",
        response: {
          authenticatorData: authData.toString("base64url"),
          clientDataJSON: cdj.toString("base64url"),
          signature: signature.toString("base64url"),
          userHandle: o.handle === undefined ? userHandle : o.handle } };
    }
  };
}

// ---------------------------------------------------------------------------
// THE VERBS.
// ---------------------------------------------------------------------------
function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  // A path this job writes is the realm's ("/authn/login"); a Location the
  // service answers already carries the realm's prefix ("/realm/<id>/...").
  const text = String(location || "");
  return /^https?:\/\//i.test(text) ? text
    : (/^\/realm\//.test(text) ? ORIGIN + text : base + text);
}

function browser() {
  log.debug("Entering browser().");
  const self = {
    cookie: "",
    async go(method, path, body) {
      log.debug("Entering go().");
      const headers = {};
      if (self.cookie) {
        headers.cookie = self.cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path),
                            { method: method, redirect: "manual",
                              headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        self.cookie = String(one).split(";")[0];
      });
      log.debug("Leaving go().");
      return { status: r.status, location: r.headers.get("location") || "",
               csp: r.headers.get("content-security-policy") || "",
               text: await r.text() };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

async function call(method, path, payload) {
  log.debug("Entering call().");
  const r = await fetch(api + path, method === "GET" ? {} : {
    method: method, headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  log.debug("Leaving call().");
  return { status: r.status, body: body, raw: raw };
}

function attr(html, name, within) {
  log.debug("Entering attr().");
  let text = String(html);
  if (within) {
    const at = text.indexOf('id="' + within + '"');
    text = at < 0 ? "" : text.slice(at, text.indexOf(">", at));
  }
  const m = text.match(new RegExp(" data-" + name + '="([^"]*)"'));
  log.debug("Leaving attr().");
  return m ? m[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&") : "";
}

function hidden(html, name) {
  log.debug("Entering hidden().");
  const m = String(html)
    .match(new RegExp('name="' + name + '"[^>]*value="([^"]*)"'));
  log.debug("Leaving hidden().");
  return m ? m[1] : "";
}

// The sign-in screen of an authorization request: a pending record exists
// only there (`/authn/login` cannot be reached directly).
async function theSignInScreen() {
  log.debug("Entering theSignInScreen().");
  const b = browser();
  const challenge = fixtures.pkce();
  const started = await b.go("GET", "/oauth2/authorize?" + form({
    client_id: CLIENT, redirect_uri: REDIRECT, response_type: "code",
    scope: "openid", code_challenge: challenge.challenge,
    code_challenge_method: challenge.method }));
  assert.ok(/\/authn\/login\?authn=/.test(started.location),
    "the authorization endpoint did not send us to the sign-in screen: " +
    started.status + " " + started.location);
  const screen = await b.go("GET", started.location);
  log.debug("Leaving theSignInScreen().");
  return { b: b, screen: screen };
}

// The screen's usernameless door, posted with an assertion (or none).
async function withoutAUsername(s, credential) {
  log.debug("Entering withoutAUsername().");
  const r = await s.b.go("POST", "/authn/login", form({
    authn_id: hidden(s.screen.text, "authn_id"), action: "passkey",
    passkey_credential: credential ? JSON.stringify(credential) : "" }));
  log.debug("Leaving withoutAUsername().");
  return r;
}

async function sessionOf(who) {
  log.debug("Entering sessionOf().");
  const r = await call("GET", "/sessions?q=" + encodeURIComponent(who));
  const rows = (r.body && (r.body.rows || r.body.sessions)) || [];
  const found = rows.filter(function (row) {
    return JSON.stringify(row).indexOf('"' + who + '"') >= 0 &&
           Array.isArray(row.amr) && row.amr.indexOf("user") >= 0;
  })[0] || null;
  log.debug("Leaving sessionOf().");
  return found;
}

// ---------------------------------------------------------------------------
// A. THE PASSKEY, registered through an activation link.
// ---------------------------------------------------------------------------
async function registerThePasskey(authenticator) {
  log.debug("Entering registerThePasskey().");
  log.info("=== a passkey registered through an activation link ===");
  const created = await call("POST", "/users/create", {
    username: PERSON, invent: false, credential: "none",
    attributes: { cn: "Passkey Person " + PERSON, givenName: "Passkey",
                  sn: PERSON, displayName: "Passkey Person " + PERSON,
                  mail: PERSON + "@passkey-nouser.test" } });
  assert.ok(created.status === 200 || created.status === 201,
    "creating " + PERSON + " answered " + created.status + " " +
    String(created.raw).slice(0, 300));
  const issued = await call("POST", "/users/issue-activation",
                            { username: PERSON });
  // The absolute link carries the realm's prefix; the bare path does not.
  const url = (issued.body && (issued.body.activationLink ||
                               (issued.body.activationUrl
                                 ? base + issued.body.activationUrl : ""))) ||
              "";
  assert.ok(issued.status === 200 && url,
    "issuing an activation link answered " + issued.status + " " +
    String(issued.raw).slice(0, 300));
  const b = browser();
  const setup = await b.go("GET", url);
  const token = hidden(setup.text, "token");
  const armed = await b.go("POST", "/portal/activate",
    form({ user: PERSON, token: token, key_role: "primary",
           kind: "passkey" }));
  const handle = attr(armed.text, "userid");
  check("THE PAGE CREATES THE CREDENTIAL UNDER A MINTED 64-BYTE USER HANDLE " +
        "(WebAuthn Level 3 section 5.4.3) — never the username's bytes, " +
        "which it was until #474", function () {
    assert.strictEqual(attr(armed.text, "mode"), "create",
      "no registration ceremony: " + String(armed.text).slice(0, 300));
    assert.ok(/^[A-Za-z0-9_-]{86}$/.test(handle), "the handle is " + handle);
    assert.notStrictEqual(handle, Buffer.from(PERSON).toString("base64url"),
      "the handle is the username.");
  });
  const done = await b.go("POST", "/portal/activate",
    form({ user: PERSON, token: token, key_role: "primary", step: "key",
           enrolment_id: hidden(armed.text, "enrolment_id"),
           credential: JSON.stringify(authenticator.register(
             attr(armed.text, "challenge"), handle)) }));
  assert.ok(done.status === 200 && /Your account is ready/.test(done.text),
    "the activation did not finish: " + done.status + " " +
    String(done.text).slice(0, 300));
  const users = await call("GET", "/users?user=" + encodeURIComponent(PERSON));
  const key = ((users.body && users.body.factors &&
                users.body.factors.keys) || [])[0] || {};
  check("and the person's key list says it signs in with no username",
    function () {
      assert.ok(key.withoutUsername && key.withoutUsername.ready === true,
        "the key reports " + JSON.stringify(key).slice(0, 400));
    });
  log.debug("Leaving registerThePasskey().");
}

// ---------------------------------------------------------------------------
// B–F. WITH THE SETTING ON.
// ---------------------------------------------------------------------------
async function signingInWithNoUsername(authenticator) {
  log.debug("Entering signingInWithNoUsername().");
  log.info("=== signing in with a passkey and no username ===");
  let s = await theSignInScreen();
  check("THE SCREEN DRAWS A REAL SUBMIT BUTTON, THE AUTOFILL TOKEN AND THE " +
        "CEREMONY SCRIPT, under script-src 'self' with frame-ancestors kept, " +
        "and asks for user verification", function () {
    assert.ok(/id="wa-passkey-go"[^>]*value="passkey"/.test(s.screen.text),
      "no passkey button: " + String(s.screen.text).slice(0, 400));
    assert.ok(/autocomplete="username webauthn"/.test(s.screen.text),
      "the username field offers no passkeys.");
    // Under the realm's prefix: the service rewrites every root-relative
    // src on a realm's page as it is sent (`app.js`'s withRealmLinks()).
    assert.ok(/<script src="(\/realm\/[^/"]+)?\/authn\/webauthn\.js">/
      .test(s.screen.text), "the ceremony script is not loaded.");
    assert.ok(/script-src 'self'/.test(s.screen.csp) &&
              /frame-ancestors/.test(s.screen.csp), s.screen.csp);
    assert.strictEqual(JSON.parse(attr(s.screen.text, "options",
                                       "wa-passkey") || "{}")
      .userVerification, "required");
  });

  let r = await withoutAUsername(s, authenticator.assert(
    attr(s.screen.text, "challenge", "wa-passkey")));
  const session = await sessionOf(PERSON);
  check("A USERNAMELESS ASSERTION SIGNS ITS OWNER IN — the user handle named " +
        "the account — and the session records amr [\"hwk\",\"user\"] and " +
        "acr \"mfa\": the key and the verification that unlocked it",
    function () {
      assert.ok(r.status === 302 || r.status === 303,
        "the sign-in answered " + r.status + " " +
        String(r.text).slice(0, 400));
      assert.ok(/oauth2\/authorize/.test(r.location),
        "it did not return to the interrupted request: " + r.location);
      assert.ok(session, "no session for " + PERSON + " carries amr user.");
      assert.deepStrictEqual(session.amr, ["hwk", "user"]);
      assert.strictEqual(session.acr, "mfa");
    });

  s = await theSignInScreen();
  r = await withoutAUsername(s, authenticator.assert(
    attr(s.screen.text, "challenge", "wa-passkey"), { uv: false }));
  check("AN ASSERTION WITHOUT USER VERIFICATION IS REFUSED, whatever " +
        "webauthn.userVerification says", function () {
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.ok(/could not sign you in/.test(r.text),
      String(r.text).slice(0, 300));
  });

  s = await theSignInScreen();
  r = await withoutAUsername(s, authenticator.assert(
    attr(s.screen.text, "challenge", "wa-passkey"),
    { handle: nodeCrypto.randomBytes(64).toString("base64url") }));
  check("a user handle nobody holds signs nobody in", function () {
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.ok(/could not sign you in/.test(r.text),
      String(r.text).slice(0, 300));
  });

  s = await theSignInScreen();
  r = await withoutAUsername(s, null);
  check("THE REAL BUTTON WITH THE SCRIPT BLOCKED is told the ceremony needs " +
        "JavaScript, rather than the page doing nothing", function () {
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.ok(/needs JavaScript/.test(r.text), String(r.text).slice(0, 300));
  });
  log.debug("Leaving signingInWithNoUsername().");
}

// ---------------------------------------------------------------------------
// G. OFF, which is the default.
// ---------------------------------------------------------------------------
async function offByDefault(authenticator) {
  log.debug("Entering offByDefault().");
  log.info("=== webauthn.usernameless off, its default ===");
  const s = await theSignInScreen();
  const r = await withoutAUsername(s, authenticator.assert(
    attr(s.screen.text, "challenge") || "none"));
  check("OFF, THE SCREEN DRAWS NO PASSKEY BUTTON AND THE DOOR REFUSES, " +
        "naming the setting", function () {
    assert.ok(!/id="wa-passkey"/.test(s.screen.text),
      "the passkey button is drawn with the setting off.");
    assert.strictEqual(r.status, 200, "it answered " + r.status);
    assert.ok(/webauthn\.usernameless/.test(r.text),
      String(r.text).slice(0, 300));
  });
  log.debug("Leaving offByDefault().");
}

async function test() {
  log.debug("Entering test().");
  const made = await fetch(serviceApi + "/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: DOMAIN,
                           name: "usernameless passkeys (#474)" }) });
  assert.strictEqual(made.status, 200, "creating the realm " + REALM +
    " answered " + made.status + " " + (await made.text()).slice(0, 300));
  await fixtures.publicClient(api, CLIENT, [REDIRECT]);
  const authenticator = makeAuthenticator();
  await registerThePasskey(authenticator);
  // OFF FIRST, which is the default; then on, in this realm alone.
  await offByDefault(authenticator);
  const set = await call("POST", "/config/set-many",
                         { "webauthn.usernameless": true });
  assert.ok(set.status === 200 && set.body && set.body.ok !== false,
    "turning webauthn.usernameless on in " + REALM + " answered " +
    set.status + " " + String(set.raw).slice(0, 300));
  await signingInWithNoUsername(authenticator);
  assert.ok(checks >= 8, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_usernameless")
  .description("Register a passkey through an activation link and sign in " +
      "with it and no username (#474): the minted user handle, the screen's " +
      "button, autofill and script, the session's amr and acr, user " +
      "verification required, an unknown handle refused, and the setting " +
      "off by default.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
