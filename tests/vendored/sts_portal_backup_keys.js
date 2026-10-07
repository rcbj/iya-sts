// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_portal_backup_keys.js
//
// ===========================================================================
// A BACKUP SECURITY KEY: ENROLLING A SECOND ONE, AND LOSING THE FIRST
// (2026-09-10).
//
// **THE POINT OF A SECOND KEY IS THE DAY THE FIRST ONE IS GONE**, and that is
// the shape of this job: enrol two, take the first away, and require that the
// second still signs the person in and that they can tidy up after themselves
// without asking an operator for anything.
//
// It exists because none of that was possible. `/portal/keys` said, in a
// paragraph of its own, *there is no enrol button here, because a WebAuthn
// ceremony belongs to a sign-in and this page is not one* — and the sign-in
// screen's checkbox is enrol-on-first-use, reserved for people who hold NO
// second factor yet, because enrolling there for somebody who already holds
// one is a bypass. So there was exactly one key per person, no door to add
// another, and a lost key meant an operator clearing it.
//
// ---------------------------------------------------------------------------
// THE FOUR ASSERTIONS THAT CARRY IT.
//
//   1. **A SECOND KEY CAN BE ENROLLED AT ALL**, by a signed-in person, with no
//      operator involved.
//   2. **THE SAME AUTHENTICATOR IS REFUSED TWICE.** `excludeCredentials` is
//      WebAuthn's own mechanism for it and a browser enforces it; this service
//      checks again at the write, because a second row for one device is a
//      backup that is lost with the original — which is the failure this whole
//      feature is against.
//   3. **EITHER KEY SIGNS THEM IN.** Not just the newest: an assertion names
//      the credential that produced it, and a service that checked whichever
//      key it found first would refuse every assertion from the others while
//      looking perfectly correct with one key enrolled.
//   4. **REMOVING THE LOST ONE IS SELF-SERVICE, AND SO IS REMOVING THE LAST
//      `mfa` KEY.** The first is what makes a backup useful; the second is
//      allowed because a second-factor key was never a way IN, so taking the
//      last one drops the account to one factor rather than to none. The
//      refusal that stops somebody locking themselves out with one click is
//      for a `primary` key, and `tests/portal_access.js` asserts it at the
//      layer that decides it (section 4 below).
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE AND NOT IN THE PARENT SUITE — `sts_consent.js`'s third
// reason, twice over: the ceremony is driven at `/portal/keys`, which is this
// repository's own surface, and the credential is read back out of `GET
// /admin-api/users`, which is this repository's own API.
//
// THE AUTHENTICATOR IS THIS FILE'S OWN, on `sts_dpop.js`'s rule — two ends of
// one exchange from one implementation would let a shared misunderstanding
// pass. `sts_webauthn_second_factor.js` beside it carries the same fixture for
// the same reason and drives the SIGN-IN door; this one drives the PORTAL.
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
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_portal_backup_keys",
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

// Computed from the service's own base rather than written down: a
// clientDataJSON origin and an RP ID hash are both compared byte for byte, so
// a fixture naming `localhost` passes on one stack and fails on the others
// with a message about a rejected ceremony rather than a wrong fixture.
var ORIGIN = new URL(base).origin;
var RP_ID = new URL(base).hostname;

var PERSON = usernameFor("backup-keys");

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR, and this job needs THREE of them: the original, the
// backup, and one that is never enrolled at all.
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
    cborInt(0x01), cborInt(0x02),
    cborInt(0x03), cborNegInt(-7),
    cborNegInt(-1), cborInt(0x01),
    cborNegInt(-2), cborBytes(Buffer.from(jwk.x, "base64url")),
    cborNegInt(-3), cborBytes(Buffer.from(jwk.y, "base64url"))
  ]);
}

function authenticatorData(opts) {
  log.debug("Entering authenticatorData().");
  const flags = Buffer.from([opts.flags]);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(opts.signCount >>> 0, 0);
  const parts = [sha256(Buffer.from(RP_ID, "utf8")), flags, count];
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

// `opts.backup` (#470) makes a passkey in a credential manager: BE and BS set
// at registration and on every assertion, reached over hybrid — which a
// browser reports as `cross-platform` — so the page must group it by the
// backup flag and not by the attachment.
function makeAuthenticator(name, opts) {
  log.debug("Entering makeAuthenticator().");
  const backup = !!(opts && opts.backup);
  const pair = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const credentialId = nodeCrypto.randomBytes(32);
  let signCount = 0;
  log.debug("Leaving makeAuthenticator().");
  return {
    name: name,
    idB64: credentialId.toString("base64url"),
    register: function (challenge) {
      log.debug("Entering register().");
      const authData = authenticatorData({
        flags: backup ? 0x5d : 0x45, signCount: signCount, attested: true,
        credentialId: credentialId, cose: coseKey(jwk)
      });
      const length = Buffer.alloc(2);
      length.writeUInt16BE(authData.length, 0);
      log.debug("Leaving register().");
      return {
        id: credentialId.toString("base64url"),
        rawId: credentialId.toString("base64url"),
        type: "public-key",
        authenticatorAttachment: "cross-platform",
        clientExtensionResults: { credProps: { rk: backup } },
        response: {
          transports: backup ? ["hybrid", "internal"] : ["usb", "nfc"],
          attestationObject: Buffer.concat([
            cborMapHeader(3),
            cborText("fmt"), cborText("none"),
            cborText("attStmt"), cborMapHeader(0),
            cborText("authData"),
            Buffer.concat([Buffer.from([0x59]), length, authData])
          ]).toString("base64url"),
          clientDataJSON: clientData("webauthn.create", challenge).toString(
              "base64url")
        }
      };
    },
    assert: function (challenge) {
      log.debug("Entering assert().");
      signCount += 1;
      const authData = authenticatorData({ flags: backup ? 0x1d : 0x05,
                                           signCount: signCount });
      const cdj = clientData("webauthn.get", challenge);
      log.debug("Leaving assert().");
      return {
        id: credentialId.toString("base64url"),
        rawId: credentialId.toString("base64url"),
        type: "public-key",
        response: {
          authenticatorData: authData.toString("base64url"),
          clientDataJSON: cdj.toString("base64url"),
          signature: nodeCrypto.sign("sha256",
            Buffer.concat([authData, sha256(cdj)]), pair.privateKey)
            .toString("base64url"),
          userHandle: null
        }
      };
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

function absolute(l) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(l || "")) ? String(l) :
         base + String(l || "");
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

function attr(html, name) {
  log.debug("Entering attr().");
  const m = String(html).match(new RegExp(name + '="([^"]*)"'));
  log.debug("Leaving attr().");
  return m ? m[1] : "";
}

function hidden(html, name) {
  log.debug("Entering hidden().");
  const m = String(html).match(new RegExp('name="' + name +
                                          '"[^>]*value="([^"]*)"'));
  log.debug("Leaving hidden().");
  return m ? m[1] : "";
}

// ---------------------------------------------------------------------------
// A JAR THAT KEEPS COOKIES BY NAME, AND THE ONE-LINE VERSION DOES NOT.
//
// The shape used elsewhere in this directory is `self.cookie = <the last
// Set-Cookie>`, which is right for a job that only ever holds ONE — and this
// one holds TWO. `/portal` is an OpenID Connect relying party of this service's
// own authorization server, so a signed-in browser carries the SIGN-ON cookie
// (`sts_session`) and the portal's own (`sts_portal`), and whichever
// arrived last would silently evict the other.
//
// **IT COSTS AN HOUR AND IT LOOKS LIKE A SERVER BUG.** With the portal cookie
// evicted, `GET /portal/keys` succeeded — it had been fetched before the
// eviction — and the POST beside it was redirected to the authorization
// endpoint, which reads exactly like a handler that forgot to check its
// session. The service was right and the jar was wrong.
// ---------------------------------------------------------------------------
function browser() {
  log.debug("Entering browser().");
  const jar = new Map();
  const self = {
    get cookie() {
      log.debug("Entering cookie().");
      log.debug("Leaving cookie().");
      return Array.from(jar.entries()).map(function (pair) {
        return pair[0] + "=" + pair[1];
      }).join("; ");
    },
    async go(method, path, body) {
      log.debug("Entering go().");
      const headers = {};
      const sending = self.cookie;
      if (sending) { headers.cookie = sending; }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path),
                            { method: method, redirect: "manual",
                                              headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const eq = pair.indexOf("=");
        if (eq < 0) return;
        const name = pair.slice(0, eq);
        const value = pair.slice(eq + 1);
        // An empty value is a CLEAR — how a sign-out takes a cookie away — and
        // keeping it would send `name=` for ever, which the service reads as a
        // session id it has never heard of rather than as no cookie at all.
        if (!value) { jar.delete(name); } else { jar.set(name, value); }
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

// A BARE `/portal` OR `/admin` DRAWS THE REALM CHOOSER once a service has
// trust realms (2026-09-14, #32), and the suite nearly always has some. The
// chooser's own `?realm=default` is what a script names to skip it, so every
// door this file signs in through, or asks whether a browser is anybody, names
// it. `sts_realm_administrators.js` asserts the chooser itself.
const PORTAL_DOOR = "/portal?realm=default";

async function get(path) {
  log.debug("Entering get().");
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in get(): " + ((e && e.message) || e));
    // An HTML page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  log.debug("Leaving get().");
  return { status: r.status, body: body, raw: raw };
}

// The management API taking JSON, for the one thing no browser door here does:
// creating the person before they sign in.
async function apiPost(path, payload) {
  log.debug("Entering apiPost().");
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    // An HTML page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  log.debug("Leaving apiPost().");
  return { status: r.status, body: body, raw: raw };
}

// ---------------------------------------------------------------------------
// EVERY PERSON THIS JOB SIGNS IN IS CREATED FIRST, WITH A PASSWORD AND THE
// ATTRIBUTES A REAL ACCOUNT CARRIES (2026-09-12).
//
// In product mode this service invents no persona for a name that signs in,
// creates nobody because a sign-in named them, and verifies the password
// against the person's own entry. The suite runs in development, where none of
// that is enforced — which is why a job leaning on it would go on passing
// while testing the invention. So `ensurePerson()` makes each account through
// `/admin-api/users/create` with `invent: false`, its own `cn`, `sn`,
// `givenName`, `displayName` and `mail`, and a password of at least twelve
// characters, and that password is what the sign-in screen is sent.
// ---------------------------------------------------------------------------
var PASSWORD = "portal-backup-keys-Passw0rd!-" + String(Date.now()).slice(-6);
var MAIL_DOMAIN = "portal-backup-keys.test";

function personAttributes(who) {
  log.debug("Entering personAttributes().");
  log.debug("Leaving personAttributes().");
  return { cn: "Backup Keys Person " + who, givenName: "Backup", sn: who,
           displayName: "Backup Keys Person " + who,
           mail: who + "@" + MAIL_DOMAIN };
}

// Create `who` with a password and real attributes, once per run.
var createdPeople = {};
async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). who=" + who);
  if (createdPeople[who]) {
    log.debug("Leaving ensurePerson(). Already created by this run.");
    return;
  }
  const r = await apiPost("/users/create", {
    username: who, invent: false, attributes: personAttributes(who),
    credential: "password", password: PASSWORD
  });
  assert.ok(r.status === 200 && r.body && r.body.ok && r.body.passwordSet,
    "POST /admin-api/users/create should create " + who + " with a password " +
    "before they sign in; it answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  createdPeople[who] = true;
  log.debug("Leaving ensurePerson(). Created " + who + ".");
}

async function factorsFor(who) {
  log.debug("Entering factorsFor().");
  const r = await get("/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/users?user=" + who + " answered " + r.status);
  log.debug("Leaving factorsFor().");
  return r.body.factors || {};
}

// Sign in at a portal door through the code flow, answering a security-key
// step with `authenticator` when one is asked for.
async function signIn(door, authenticator) {
  log.debug("Entering signIn().");
  const b = browser();
  let r = await b.go("GET", door);
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    door + " did not send an unauthenticated browser to the authorization " +
    "endpoint: " + r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    "the authorization endpoint did not ask for a sign-in: " + r.location);
  r = await b.go("GET", r.location);
  const authnId = hidden(r.text, "authn_id");
  assert.ok(authnId, "the sign-in screen carries no authn_id.");
  r = await b.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: PERSON,
                        password: PASSWORD, action: "login",
                        csrf_token: csrfOf(r.text) }));
  if (r.status === 200) {
    assert.ok(authenticator,
      "a second factor was asked for and this call brought no authenticator: " +
      String(r.text).slice(0, 300));
    const mode = attr(r.text, "data-mode");
    const credential = mode === "create"
      ? authenticator.register(attr(r.text, "data-challenge"))
      : authenticator.assert(attr(r.text, "data-challenge"));
    r = await b.go("POST", "/authn/webauthn",
                   form({ mfa_id: hidden(r.text, "mfa_id"), mode: mode,
                          credential: JSON.stringify(credential) }));
  }
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in did not complete: " + r.status + " " +
    String(r.text).slice(0, 400));
  r = await b.go("GET",
                 r.location);   // the authorization endpoint, with a code
  r = await b.go("GET", r.location);   // the callback, which mints the session
  assert.ok(b.cookie, "completing the flow established no session cookie.");
  log.debug("Leaving signIn().");
  return b;
}

// Drive `/portal/keys`'s two-step enrolment with one authenticator.
// Since #470 there is no name before the ceremony: the button pressed is the
// kind, and a `label` is given afterwards through `/portal/rename-key`, the
// way the nickname prompt does it.
async function enrolAt(b, authenticator, role, label, kind) {
  log.debug("Entering enrolAt().");
  let page = await b.go("GET", "/portal/keys");
  const begun = await b.go("POST", "/portal/keys",
    form({ action: "begin", role: role, kind: kind || "security-key",
           csrf_token: csrfOf(page.text) }));
  assert.ok(begun.status === 303,
    "beginning the enrolment answered " + begun.status + " " +
    String(begun.text).slice(0, 400));
  page = await b.go("GET", "/portal/keys");
  const challenge = attr(page.text, "data-challenge");
  assert.ok(challenge, "the armed page carries no challenge: " +
    String(page.text).slice(0, 400));
  const done = await b.go("POST", "/portal/keys",
    form({ action: "finish", enrolment_id: hidden(page.text, "enrolment_id"),
           credential: JSON.stringify(authenticator.register(challenge)),
           csrf_token: csrfOf(page.text) }));
  let prompt = null;
  let renamed = null;
  if (done.status === 303) {
    prompt = await b.go("GET", done.location);
    if (label) {
      renamed = await b.go("POST", "/portal/rename-key",
        form({ credentialId: authenticator.idB64, label: label,
               csrf_token: csrfOf(prompt.text) }));
    }
  }
  log.debug("Leaving enrolAt().");
  return { armed: page, done: done, prompt: prompt, renamed: renamed };
}

// ---------------------------------------------------------------------------
// 1a. TWO CALLS TO ACTION (#470), AND A BROWSER THAT HAS NOTHING BUILT IN.
//
// The passkey management guidelines ask for *Create a passkey* and *Use a
// security key* as two buttons, replacing 2026-09-26's three-way radio. That
// radio's lesson still holds and is asserted here: a hard `platform` refused
// outright on a browser with nothing built in (Linux Firefox), so *Create a
// passkey* sends NO attachment — it hints `client-device` then `hybrid` and
// prefers a discoverable credential — and a browser's refusal hands the form
// back rather than re-arming the same ceremony on every reload.
// ---------------------------------------------------------------------------
async function twoCallsToAction(b) {
  log.debug("Entering twoCallsToAction().");
  log.info("=== /portal/keys offers Create a passkey and Use a security key ===");
  let page = await b.go("GET", "/portal/keys");
  check("the page is headed Passkeys and offers the two calls to action, " +
        "Create a passkey first", function () {
    assert.ok(/<title>Passkeys/.test(page.text) || />Passkeys</.test(page.text),
      "the page is not headed Passkeys: " + String(page.text).slice(0, 600));
    const create = page.text.indexOf('name="kind" value="passkey"');
    const key = page.text.indexOf('name="kind" value="security-key"');
    assert.ok(create >= 0 && key >= 0,
      "a call to action is missing: " + String(page.text).slice(0, 600));
    assert.ok(create < key, "Create a passkey is not the first");
    assert.ok(/Create a passkey/.test(page.text) &&
              /Use a security key/.test(page.text),
      "the buttons do not say what they do");
    assert.ok(!/name="kind" value="(any|platform|roaming)"/.test(page.text),
      "the old three-way choice is still drawn");
  });

  const asked = {};
  for (const kind of ["passkey", "security-key"]) {
    page = await b.go("GET", "/portal/keys");
    const begun = await b.go("POST", "/portal/keys",
      form({ action: "begin", role: "mfa", kind: kind,
             csrf_token: csrfOf(page.text) }));
    assert.strictEqual(begun.status, 303, "arming answered " + begun.status);
    const armed = await b.go("GET", "/portal/keys");
    // The attribute is HTML-escaped JSON.
    const options = JSON.parse((attr(armed.text, "data-options") || "{}")
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
      .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&"));
    asked[kind] = options;
    if (kind !== "passkey") {
      await b.go("POST", "/portal/keys",
        form({ action: "cancel", csrf_token: csrfOf(armed.text) }));
      continue;
    }
    // THE BROWSER REFUSES, as one with nothing built in and no phone does.
    const refused = await b.go("POST", "/portal/keys",
      form({ action: "finish",
             enrolment_id: hidden(armed.text, "enrolment_id"),
             credential: JSON.stringify({ error: "NotAllowedError",
               message: "The operation either timed out or was not " +
                        "allowed." }),
             csrf_token: csrfOf(armed.text) }));
    const after = await b.go("GET", "/portal/keys");
    check("A BROWSER THAT CANNOT CREATE A PASSKEY gets the form BACK with " +
          "its error and what to try, rather than the same ceremony re-armed " +
          "on every reload", function () {
      assert.strictEqual(refused.status, 400,
        "it answered " + refused.status);
      assert.ok(/NotAllowedError/.test(refused.text) &&
                /Use a security key/.test(refused.text),
        "the page does not say why or what to try: " +
        String(refused.text).slice(0, 600));
      assert.ok(!attr(after.text, "data-challenge") &&
                /name="action" value="begin"/.test(after.text),
        "the ceremony is still armed after the browser refused it");
    });
  }
  check("the button reaches the ceremony: Create a passkey sends no " +
        "attachment, prefers a discoverable credential and hints the device " +
        "then hybrid; Use a security key asks for cross-platform and hints " +
        "a security key (WebAuthn Level 3 section 5.4.8)", function () {
    const passkey = asked.passkey.authenticatorSelection || {};
    const key = asked["security-key"].authenticatorSelection || {};
    assert.ok(!("authenticatorAttachment" in passkey), JSON.stringify(passkey));
    assert.ok(passkey.residentKey === "preferred" ||
              passkey.residentKey === "required", JSON.stringify(passkey));
    assert.deepStrictEqual(asked.passkey.hints, ["client-device", "hybrid"]);
    assert.strictEqual(key.authenticatorAttachment, "cross-platform",
      JSON.stringify(key));
    assert.deepStrictEqual(asked["security-key"].hints, ["security-key"]);
  });
  log.debug("Leaving twoCallsToAction().");
}

// ---------------------------------------------------------------------------
// 1. THE FIRST KEY, AND THE PAGE THAT COULD NOT ENROL ONE.
// ---------------------------------------------------------------------------
async function thePortalCanEnrolAKey(first) {
  log.debug("Entering thePortalCanEnrolAKey().");
  log.info("=== /portal/keys enrols a key at all ===");
  const b = await signIn("/portal/keys", null);

  const page = await b.go("GET", "/portal/keys");
  check("THE PAGE OFFERS AN ENROL CONTROL. It said `there is no enrol button " +
        "here, because a WebAuthn ceremony belongs to a sign-in and this " +
        "page is not one` — and the premise is false: a ceremony belongs to " +
        "whoever is asking, and a signed-in person registering a credential " +
        "is the ordinary WebAuthn flow", function () {
    assert.strictEqual(page.status, 200,
      "/portal/keys answered " + page.status);
    assert.ok(/name="action" value="begin"/.test(page.text),
      "there is no enrolment form on the page: " +
      String(page.text).slice(0, 500));
  });

  check("AND IT RELAXES `script-src` TO `'self'` WHILE KEEPING " +
        "`frame-ancestors` — the seventh scripted page in this service and " +
        "the first in this portal. A ceremony is a browser API call and " +
        "there is no markup that makes one; the relaxation goes through " +
        "app.contentSecurityPolicy(), which is what stops the framing clause " +
        "being lost with the page still working", function () {
    assert.ok(/script-src 'self'/.test(page.csp),
      "the policy does not allow the ceremony script: " + page.csp);
    assert.ok(/frame-ancestors/.test(page.csp),
      "and the framing clause is GONE, which is the failure the builder " +
      "exists to prevent: " + page.csp);
    // THE `script-src` DIRECTIVE AND NOT THE WHOLE HEADER. `style-src
    // 'unsafe-inline'` is the service-wide default — every page here carries
    // its stylesheet inline — and asserting against the whole policy reads it
    // as a script hole, which is a check that fails on a correct service.
    const scriptSrc = (String(page.csp).match(/script-src ([^;]*)/) ||
                       [])[1] || "";
    assert.ok(!/unsafe-inline/.test(scriptSrc),
      "script-src was relaxed with 'unsafe-inline', which is a hole rather " +
      "than an exception: " + scriptSrc);
  });

  // THE CEREMONY IS BOUND TO THE ENROLMENT THAT ARMED IT, and this assertion
  // exists because a mutant survived without it: removing the id check changes
  // nothing for a job that always posts the right one. What it stops is a
  // `finish` from one tab completing the ceremony another tab armed — the same
  // rule the sign-in screen's `mfa_id` follows, and the reason the challenge
  // is held against an id rather than only against a name.
  const armed = await b.go("POST", "/portal/keys",
    form({ action: "begin", role: "mfa",
           csrf_token: csrfOf((await b.go("GET", "/portal/keys")).text) }));
  assert.strictEqual(armed.status, 303, "arming answered " + armed.status);
  const armedPage = await b.go("GET", "/portal/keys");
  const wrongId = await b.go("POST", "/portal/keys",
    form({ action: "finish", enrolment_id: "not-the-one-in-progress",
           credential: JSON.stringify(
             first.register(attr(armedPage.text, "data-challenge"))),
           csrf_token: csrfOf(armedPage.text) }));
  check("A `finish` NAMING A DIFFERENT ENROLMENT IS REFUSED — the challenge " +
        "is held against an id, so a ceremony armed in one tab cannot be " +
        "completed by another", function () {
    assert.strictEqual(wrongId.status, 400,
      "it answered " + wrongId.status + " " +
      String(wrongId.text).slice(0, 300));
    assert.ok(/not the one in progress/i.test(wrongId.text),
      "and not for the reason expected: " + String(wrongId.text).slice(0, 300));
  });
  await b.go("POST", "/portal/keys",
    form({ action: "cancel",
           csrf_token: csrfOf((await b.go("GET", "/portal/keys")).text) }));

  await twoCallsToAction(b);

  const enrolled = await enrolAt(b, first, "mfa", "the one at my desk");
  check("and a real ceremony against it enrols the key", function () {
    assert.strictEqual(enrolled.done.status, 303,
      "the enrolment answered " + enrolled.done.status + " " +
      String(enrolled.done.text).slice(0, 500));
  });

  check("THE NICKNAME IS ASKED FOR AFTER THE CEREMONY (#470): the redirect " +
        "names the new passkey and the page opens its rename form, filled " +
        "with the default name — a security key's, since this one cannot be " +
        "backed up and is cross-platform", function () {
    assert.ok(/[?&]named=/.test(String(enrolled.done.location)),
      "the redirect names no passkey: " + enrolled.done.location);
    assert.ok(/Give your security key a nickname/.test(enrolled.prompt.text),
      "no nickname prompt: " + String(enrolled.prompt.text).slice(0, 600));
    assert.ok(/name="label"[^>]*value="Security key"/.test(
      enrolled.prompt.text), "the prompt does not hold the default name");
    assert.strictEqual(enrolled.renamed && enrolled.renamed.status, 303,
      "the rename answered " + (enrolled.renamed && enrolled.renamed.status));
  });

  const factors = await factorsFor(PERSON);
  check("which reaches the person's own entry, with the nickname they gave " +
        "it, the role they chose, and what the passkey pages group it by " +
        "(#470): BE clear, the transports, not discoverable", function () {
    assert.strictEqual(factors.mfaKeys, 1,
      "the store holds " + factors.mfaKeys + " key(s).");
    assert.strictEqual(factors.keys[0].label, "the one at my desk",
      "the label did not survive: " + JSON.stringify(factors.keys[0]));
    assert.strictEqual(factors.keys[0].name, "the one at my desk");
    assert.strictEqual(factors.keys[0].role, "mfa",
      "the role did not survive.");
    assert.strictEqual(factors.keys[0].group, "security-key",
      JSON.stringify(factors.keys[0]));
    assert.strictEqual(factors.keys[0].backupEligible, false);
    assert.deepStrictEqual(factors.keys[0].transports, ["usb", "nfc"]);
    assert.strictEqual(factors.keys[0].discoverable, false);
    assert.strictEqual(factors.keys[0].lastUsedAt, 0,
      "a passkey nobody has used yet says it was used");
  });

  const listed = await b.go("GET", "/portal/keys");
  check("the list draws it under PASSKEYS ON SECURITY KEYS, with its name, " +
        "Created, Not used yet, a Rename and a Details fold", function () {
    assert.ok(/Passkeys on security keys/.test(listed.text),
      String(listed.text).slice(0, 800));
    assert.ok(!/Passkeys on your devices/.test(listed.text),
      "an empty group is drawn");
    assert.ok(/the one at my desk/.test(listed.text) &&
              /Created \d{4}-\d\d-\d\d/.test(listed.text) &&
              /Not used yet/.test(listed.text),
      "the row does not say what it is and when");
    assert.ok(/<summary>Rename<\/summary>/.test(listed.text) &&
              /<summary>Details<\/summary>/.test(listed.text),
      "the row has no Rename or Details");
  });

  // RENAME'S REFUSALS (#470): `credentials.renameKey()` is the one writer,
  // and it is held to `remove-key`'s A01 rule — an id that is not one of
  // THIS person's keys matches nothing.
  const tooLong = await b.go("POST", "/portal/rename-key",
    form({ credentialId: first.idB64, label: "x".repeat(61),
           csrf_token: csrfOf(listed.text) }));
  const notTheirs = await b.go("POST", "/portal/rename-key",
    form({ credentialId: makeAuthenticator("nobody's").idB64, label: "mine",
           csrf_token: csrfOf(listed.text) }));
  const noCsrf = await b.go("POST", "/portal/rename-key",
    form({ credentialId: first.idB64, label: "forged" }));
  check("a rename is refused for a name over 60 characters, for an id that " +
        "is not one of theirs, and without the CSRF token", function () {
    assert.strictEqual(tooLong.status, 400, "too long: " + tooLong.status);
    assert.ok(/at most 60 characters/.test(tooLong.text),
      String(tooLong.text).slice(0, 300));
    assert.strictEqual(notTheirs.status, 400, "not theirs: " +
      notTheirs.status);
    assert.strictEqual(noCsrf.status, 403, "no CSRF token: " + noCsrf.status);
  });
  const restored = await b.go("POST", "/portal/rename-key",
    form({ credentialId: first.idB64, label: "",
           csrf_token: csrfOf(listed.text) }));
  const afterRestore = await factorsFor(PERSON);
  check("an EMPTY name restores the default", function () {
    assert.strictEqual(restored.status, 303, "it answered " + restored.status);
    assert.strictEqual(afterRestore.keys[0].label, "Security key",
      JSON.stringify(afterRestore.keys[0]));
  });
  const back = await b.go("POST", "/portal/rename-key",
    form({ credentialId: first.idB64, label: "the one at my desk",
           csrf_token: csrfOf(listed.text) }));
  assert.strictEqual(back.status, 303, "renaming back answered " +
    back.status);
  log.debug("Leaving thePortalCanEnrolAKey().");
  return b;
}

// ---------------------------------------------------------------------------
// 2. THE BACKUP, AND THE MISTAKE IT HAS TO REFUSE.
// ---------------------------------------------------------------------------
async function aSecondKeyIsABackupAndTheSameOneIsNot(first, second) {
  log.debug("Entering aSecondKeyIsABackupAndTheSameOneIsNot().");
  log.info("=== a second key, and the same one refused ===");
  const b = await signIn("/portal/keys", first);

  const again = await enrolAt(b, first, "mfa", "the same one again");
  check("PRESSING ADD AND TOUCHING THE KEY ALREADY PLUGGED IN IS REFUSED. " +
        "That is the commonest way to get this wrong, and a second row for " +
        "one device is a backup that is lost with the original — WebAuthn's " +
        "excludeCredentials asks the browser to refuse and this service " +
        "checks again at the write, because the list is a request like every " +
        "other ceremony option", function () {
    assert.strictEqual(again.done.status, 400,
      "the same authenticator was enrolled twice (" + again.done.status + ").");
    assert.ok(/already enrolled/i.test(again.done.text),
      "it was refused without saying why: " +
      String(again.done.text).slice(0, 400));
  });
  check("and the excluded list on the armed page names the key they hold, so " +
        "a conforming browser refuses before the person touches anything",
    function () {
      assert.ok(attr(again.armed.text, "data-exclude").indexOf(
          first.idB64) >= 0,
        "the ceremony did not exclude the enrolled key: " +
        attr(again.armed.text, "data-exclude"));
    });

  const backup = await enrolAt(b, second, "mfa", "the one on my keyring",
                               "passkey");
  check("A DIFFERENT AUTHENTICATOR IS ACCEPTED, which is the whole feature",
    function () {
      assert.strictEqual(backup.done.status, 303,
        "the backup was refused: " + backup.done.status + " " +
        String(backup.done.text).slice(0, 400));
    });

  const factors = await factorsFor(PERSON);
  check("so they hold TWO, each with its own label and credential id — which " +
        "is what the multi-valued attribute, the credential id and " +
        "webauthn.maxKeysPerPerson have all been for since before any door " +
        "could produce this state", function () {
      assert.strictEqual(factors.mfaKeys, 2,
        "the store holds " + factors.mfaKeys + " key(s): " +
        JSON.stringify(factors.keys));
      const ids = factors.keys.map(function (k) { return k.credentialId; });
      assert.ok(ids.indexOf(first.idB64) >= 0 && ids.indexOf(second.idB64) >= 0,
        "the two enrolled keys are not the two stored: " + ids.join(", "));
    });
  const synced = factors.keys.filter(function (k) {
    return k.credentialId === second.idB64;
  })[0] || {};
  const page = await b.go("GET", "/portal/keys");
  check("A PASSKEY IN A CREDENTIAL MANAGER IS ON YOUR DEVICES even reached " +
        "over hybrid, which a browser reports as cross-platform: the BACKUP " +
        "ELIGIBILITY flag decides first (#470), and the page draws both " +
        "groups", function () {
    assert.strictEqual(synced.backupEligible, true, JSON.stringify(synced));
    assert.strictEqual(synced.backupState, true, JSON.stringify(synced));
    assert.strictEqual(synced.group, "device", JSON.stringify(synced));
    assert.strictEqual(synced.discoverable, true, JSON.stringify(synced));
    const devices = page.text.indexOf("Passkeys on your devices");
    const keys = page.text.indexOf("Passkeys on security keys");
    assert.ok(devices >= 0 && keys > devices,
      "the two groups are not both drawn, devices first");
    assert.ok(page.text.indexOf("the one on my keyring") > devices &&
              page.text.indexOf("the one on my keyring") < keys,
      "the synced passkey is not under passkeys on your devices");
  });
  log.debug("Leaving aSecondKeyIsABackupAndTheSameOneIsNot().");
}

// ---------------------------------------------------------------------------
// 3. EITHER KEY SIGNS THEM IN. **The assertion the backup is FOR.**
// ---------------------------------------------------------------------------
async function eitherKeySignsThemIn(first, second) {
  log.debug("Entering eitherKeySignsThemIn().");
  log.info("=== either key signs them in ===");
  for (const one of [first, second]) {
    const b = await signIn(PORTAL_DOOR, one);
    check("the key called `" + one.name + "` completes the second-factor " +
          "step on its own — a service that checked whichever key it found " +
          "FIRST would refuse every assertion from the others and look " +
          "perfectly correct with one key enrolled", function () {
      assert.ok(b.cookie, "no session came out of it.");
    });
  }

  const stranger = makeAuthenticator("never enrolled");
  const b = browser();
  let r = await b.go("GET", PORTAL_DOOR);
  r = await b.go("GET", r.location);
  r = await b.go("GET", r.location);
  r = await b.go("POST", "/authn/login",
    form({ authn_id: hidden(r.text, "authn_id"), username: PERSON,
           password: PASSWORD, action: "login",
           csrf_token: csrfOf(r.text) }));
  const refused = await b.go("POST", "/authn/webauthn",
    form({ mfa_id: hidden(r.text, "mfa_id"), mode: "get",
           credential: JSON.stringify(
             stranger.assert(attr(r.text, "data-challenge"))) }));
  check("AND A THIRD AUTHENTICATOR NOBODY ENROLLED IS STILL REFUSED. Holding " +
        "two keys must not mean holding the door open — the assertion is " +
        "matched to a credential id on this person's own entry", function () {
    assert.strictEqual(refused.status, 200,
      "a stranger's authenticator was accepted (" + refused.status + ").");
  });
  log.debug("Leaving eitherKeySignsThemIn().");
}

// ---------------------------------------------------------------------------
// 4. LOSING ONE. Self-service for the lost key, refused for the last.
// ---------------------------------------------------------------------------
async function theLostKeyIsRemovedWithoutAnOperator(first, second) {
  log.debug("Entering theLostKeyIsRemovedWithoutAnOperator().");
  log.info("=== the lost key is removed, and the last one is not ===");
  const b = await signIn("/portal/keys", second);
  let page = await b.go("GET", "/portal/keys");

  const used = await factorsFor(PERSON);
  check("EACH PASSKEY NOW SAYS WHEN IT WAS LAST USED (#470) — recorded by " +
        "every assertion, and drawn on the list", function () {
    used.keys.forEach(function (k) {
      assert.ok(k.lastUsedAt > 0, "never used: " + JSON.stringify(k));
    });
    assert.ok(/Last used \d{4}-\d\d-\d\d/.test(page.text),
      "the list does not say when: " + String(page.text).slice(0, 800));
  });

  const removed = await b.go("POST", "/portal/remove-key",
    form({ credentialId: first.idB64, csrf_token: csrfOf(page.text) }));
  check("THE PERSON REMOVES THE LOST KEY THEMSELVES, signed in with the " +
        "backup. That is what a backup is for and it is the conversation " +
        "with an operator that no longer has to happen", function () {
    assert.ok(removed.status === 303 || removed.status === 200,
      "the removal answered " + removed.status + " " +
      String(removed.text).slice(0, 400));
  });

  let factors = await factorsFor(PERSON);
  check("and the backup is the one that is left", function () {
    assert.strictEqual(factors.mfaKeys, 1,
      "the store holds " + factors.mfaKeys + " key(s).");
    assert.strictEqual(factors.keys[0].credentialId, second.idB64,
      "the wrong key was removed.");
  });

  page = await b.go("GET", "/portal/keys");
  const lastOne = await b.go("POST", "/portal/remove-key",
    form({ credentialId: second.idB64, csrf_token: csrfOf(page.text) }));
  check("AND REMOVING THE LAST ONE IS ALLOWED HERE ONLY BECAUSE IT IS A " +
        "SECOND FACTOR — an `mfa` key was never a way IN, so taking it away " +
        "drops the account to one factor rather than to none. A `primary` " +
        "key in the same position is refused, which tests/portal_access.js " +
        "asserts at the layer that decides it", function () {
    assert.ok(lastOne.status === 303 || lastOne.status === 200,
      "removing the last second factor answered " + lastOne.status + " " +
      String(lastOne.text).slice(0, 300));
  });

  factors = await factorsFor(PERSON);
  check("and the account is back to a password alone", function () {
    assert.strictEqual(factors.mfaKeys, 0,
      "keys remain: " + JSON.stringify(factors.keys));
    assert.strictEqual(factors.mfaRequired, false,
      "a second factor is still being demanded.");
  });
  log.debug("Leaving theLostKeyIsRemovedWithoutAnOperator().");
}

// ---------------------------------------------------------------------------
// 5. A KEY INSTEAD OF A PASSWORD, SET UP BY AN ACTIVATION LINK (2026-10-01).
//
// Reported by rcbj: a new person following their registration link chose to
// use a passkey as their primary sign-in and still had to set a password.
// `/portal/activate`'s `key_role` radio enrolled nothing — it spent the link
// and sent the person to the sign-in screen to enrol on first use, which
// product mode refuses. The key is registered on the activation page now,
// authorised by the link, and this drives that whole road: no password typed
// anywhere, the key on the entry in the `primary` role, the link spent only
// once the key is registered, and a passwordless sign-in with it afterwards.
// ---------------------------------------------------------------------------
var NEWCOMER = usernameFor("passkey-newcomer");

async function aKeyInsteadOfAPasswordAtActivation(authenticator) {
  log.debug("Entering aKeyInsteadOfAPasswordAtActivation().");
  log.info("=== 5. a key instead of a password, at activation ===");
  const created = await apiPost("/users/create",
    { username: NEWCOMER, invent: false, credential: "none",
      attributes: personAttributes(NEWCOMER) });
  assert.ok(created.status === 200 || created.status === 201,
    "creating " + NEWCOMER + " answered " + created.status + " " +
    String(created.raw).slice(0, 300));
  const issued = await apiPost("/users/issue-activation",
                               { username: NEWCOMER });
  assert.strictEqual(issued.status, 200,
    "issuing an activation link answered " + issued.status + " " +
    String(issued.raw).slice(0, 300));
  const url = issued.body.activationUrl || issued.body.url || "";
  assert.ok(url,
            "no activation URL came back: " + String(issued.raw).slice(0, 300));

  const b = browser();
  const setup = await b.go("GET", url);
  const token = hidden(setup.text, "token");
  assert.ok(token, "the setup form carries no token: " +
    String(setup.text).slice(0, 300));

  // NO PASSWORD FIELD IS SENT AT ALL — what a person who leaves both boxes
  // empty posts is the same as this.
  const armed = await b.go("POST", "/portal/activate",
    form({ user: NEWCOMER, token: token, key_role: "primary",
           kind: "passkey" }));
  check("CHOOSING A KEY INSTEAD OF A PASSWORD DRAWS THE CEREMONY rather than " +
        "finishing — the activation page registers the key, authorised by " +
        "the link, with script-src relaxed to 'self' and frame-ancestors " +
        "kept", function () {
    assert.strictEqual(armed.status, 200,
      "it answered " + armed.status + " " + String(armed.text).slice(0, 400));
    assert.strictEqual(attr(armed.text, "data-mode"), "create",
      "no registration ceremony on the page: " +
      String(armed.text).slice(0, 400));
    assert.ok(attr(armed.text, "data-challenge"), "no challenge on the page.");
    assert.ok(!/Your account is ready/.test(armed.text),
      "the activation finished before any key was registered.");
    assert.ok(/script-src 'self'/.test(armed.csp),
      "the policy does not allow the ceremony script: " + armed.csp);
    assert.ok(/frame-ancestors/.test(armed.csp),
      "the framing clause is gone: " + armed.csp);
  });

  // THE BROWSER RAN NO CEREMONY: the real button under the script. The step
  // is drawn again with a fresh challenge and the link is not spent.
  const noCeremony = await b.go("POST", "/portal/activate",
    form({ user: NEWCOMER, token: token, key_role: "primary",
           step: "key", enrolment_id: hidden(armed.text, "enrolment_id"),
           credential: "" }));
  check("a `key` step with no credential is answered by saying why, and the " +
        "ceremony is drawn again rather than the account finished",
        function () {
    assert.strictEqual(noCeremony.status, 400,
      "it answered " + noCeremony.status);
    assert.ok(/did not run the ceremony/.test(noCeremony.text),
      "not for the reason expected: " + String(noCeremony.text).slice(0, 300));
    assert.strictEqual(attr(noCeremony.text, "data-mode"), "create",
      "the ceremony was not drawn again.");
    assert.notStrictEqual(attr(noCeremony.text, "data-challenge"),
      attr(armed.text, "data-challenge"), "the challenge was not fresh.");
  });

  const done = await b.go("POST", "/portal/activate",
    form({ user: NEWCOMER, token: token, key_role: "primary", step: "key",
           enrolment_id: hidden(noCeremony.text, "enrolment_id"),
           credential: JSON.stringify(authenticator.register(
             attr(noCeremony.text, "data-challenge"))) }));
  check("A REAL CEREMONY FINISHES THE ACTIVATION, and the page says the key " +
        "is how they sign in", function () {
    assert.strictEqual(done.status, 200,
      "it answered " + done.status + " " + String(done.text).slice(0, 400));
    assert.ok(/Your account is ready/.test(done.text),
      "not the account-ready page: " + String(done.text).slice(0, 400));
    assert.ok(/registered and is how you sign in/.test(done.text),
      "the page does not say the key is registered.");
  });

  const factors = await factorsFor(NEWCOMER);
  check("THE ENTRY HOLDS ONE `primary` KEY AND NO PASSWORD — the reported " +
        "defect was a password still being required", function () {
    assert.strictEqual(factors.primaryKeys, 1,
      "the entry holds " + factors.primaryKeys + " primary key(s): " +
      JSON.stringify(factors.keys));
    assert.strictEqual(factors.password, false,
      "a password was set, and none was asked for.");
  });
  check("AND THE KEY'S SIGNATURE ALGORITHM IS RECORDED AND REPORTED " +
        "(2026-10-01) — the authenticator here signs with ES256 (-7)",
        function () {
    const algorithm = (factors.keys[0] || {}).algorithm || {};
    assert.strictEqual(algorithm.name, "ES256",
      "the key's algorithm: " + JSON.stringify(algorithm));
    assert.strictEqual(algorithm.coseAlg, -7,
      "the key's COSE identifier: " + JSON.stringify(algorithm));
  });

  const again = await b.go("GET", url);
  check("and the link is spent only now, once the key is registered",
        function () {
    assert.strictEqual(again.status, 400,
      "re-opening the link answered " + again.status);
  });

  // A PASSWORDLESS SIGN-IN WITH THE KEY: the box ticked, no password.
  const s = browser();
  let r = await s.go("GET", PORTAL_DOOR);
  r = await s.go("GET", r.location);
  r = await s.go("GET", r.location);
  const authnId = hidden(r.text, "authn_id");
  assert.ok(authnId, "the sign-in screen carries no authn_id.");
  r = await s.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: NEWCOMER,
                        webauthn_only: "1", action: "login",
                        csrf_token: csrfOf(r.text) }));
  const mode = attr(r.text, "data-mode");
  check("THE SIGN-IN SCREEN ASKS FOR THE KEY THEY HOLD rather than enrolling " +
        "one or asking for a password", function () {
    assert.strictEqual(r.status, 200,
      "the passwordless sign-in answered " + r.status + " " +
      String(r.text).slice(0, 400));
    assert.strictEqual(mode, "get",
      "the ceremony is not an assertion: " + mode);
  });
  r = await s.go("POST", "/authn/webauthn",
                 form({ mfa_id: hidden(r.text, "mfa_id"), mode: mode,
                        credential: JSON.stringify(authenticator.assert(
                          attr(r.text, "data-challenge"))) }));
  check("and the key alone signs them in", function () {
    assert.ok(r.status === 303 || r.status === 302,
      "the assertion answered " + r.status + " " +
      String(r.text).slice(0, 400));
  });

  // THE EVENT LOG NAMES THE ALGORITHM (2026-10-01): the enrolment and the
  // sign-in it verified, each read one action at a time for
  // sts_portal_backup_codes.js's reason.
  const rowsFor = async function (action) {
    const answer = await get("/audit?per=200&action=" +
                             encodeURIComponent(action));
    return ((answer.body && (answer.body.events || answer.body.rows)) || [])
      .filter(function (e) {
        return e.actor === NEWCOMER;
      });
  };
  const enrolRows = await rowsFor("portal.activate.key.enrolled");
  const signInRows = await rowsFor("session.start");
  check("the audit log records the algorithm the key was registered with " +
        "and the one the sign-in was verified with", function () {
    assert.ok(enrolRows.some(function (e) {
      return String((e.detail || {}).algorithm) === "ES256 (-7)";
    }), "no portal.activate.key.enrolled row naming ES256 (-7): " +
      JSON.stringify(enrolRows).slice(0, 400));
    assert.ok(signInRows.some(function (e) {
      return String((e.detail || {}).credentialAlgorithm) === "ES256 (-7)";
    }), "no session.start row naming ES256 (-7): " +
      JSON.stringify(signInRows).slice(0, 400));
  });
  log.debug("Leaving aKeyInsteadOfAPasswordAtActivation().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " as " + PERSON +
           " (origin " + ORIGIN + ", rpId " + RP_ID + ").");
  const first = makeAuthenticator("at my desk");
  const second = makeAuthenticator("on my keyring");
  await ensurePerson(PERSON);

  await thePortalCanEnrolAKey(first);
  await aSecondKeyIsABackupAndTheSameOneIsNot(first, second);
  await eitherKeySignsThemIn(first, second);
  await theLostKeyIsRemovedWithoutAnOperator(first, second);
  await aKeyInsteadOfAPasswordAtActivation(makeAuthenticator("my passkey"));

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed".
  assert.ok(checks >= 21,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_portal_backup_keys")
  .description("Enrol two security keys from /portal/keys, lose the first, " +
      "and require that the second still signs the person in: that the " +
      "portal can enrol at all, that the SAME authenticator is refused a " +
      "second time, that either key completes a sign-in, that a third nobody " +
      "enrolled is refused, and that the lost one is removed without an " +
      "operator.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
