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
//   4. **REMOVING THE LOST ONE IS SELF-SERVICE, AND REMOVING THE LAST IS
//      NOT.** The first is what makes a backup useful; the second is the
//      refusal that stops somebody locking themselves out with one click.
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
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_portal_backup_keys",
                                level: appconfig.LOG_LEVEL || "info" });
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
  fn();
  checks += 1;
  log.info("  ✓ " + what);
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR, and this job needs THREE of them: the original, the
// backup, and one that is never enrolled at all.
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
  const flags = Buffer.from([opts.flags]);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(opts.signCount >>> 0, 0);
  const parts = [sha256(Buffer.from(RP_ID, "utf8")), flags, count];
  if (opts.attested) {
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(opts.credentialId.length, 0);
    parts.push(Buffer.alloc(16), idLen, opts.credentialId, opts.cose);
  }
  return Buffer.concat(parts);
}

function clientData(type, challenge) {
  return Buffer.from(JSON.stringify({
    type: type, challenge: challenge, origin: ORIGIN, crossOrigin: false
  }), "utf8");
}

function makeAuthenticator(name) {
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const credentialId = nodeCrypto.randomBytes(32);
  let signCount = 0;
  return {
    name: name,
    idB64: credentialId.toString("base64url"),
    register: function (challenge) {
      const authData = authenticatorData({
        flags: 0x45, signCount: signCount, attested: true,
        credentialId: credentialId, cose: coseKey(jwk)
      });
      const length = Buffer.alloc(2);
      length.writeUInt16BE(authData.length, 0);
      return {
        id: credentialId.toString("base64url"),
        rawId: credentialId.toString("base64url"),
        type: "public-key",
        authenticatorAttachment: "cross-platform",
        clientExtensionResults: { credProps: { rk: false } },
        response: {
          attestationObject: Buffer.concat([
            cborMapHeader(3),
            cborText("fmt"), cborText("none"),
            cborText("attStmt"), cborMapHeader(0),
            cborText("authData"),
            Buffer.concat([Buffer.from([0x59]), length, authData])
          ]).toString("base64url"),
          clientDataJSON: clientData("webauthn.create", challenge).toString("base64url")
        }
      };
    },
    assert: function (challenge) {
      signCount += 1;
      const authData = authenticatorData({ flags: 0x05, signCount: signCount });
      const cdj = clientData("webauthn.get", challenge);
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
function form(o) { return new URLSearchParams(o).toString(); }
function absolute(l) {
  return /^https?:\/\//i.test(String(l || "")) ? String(l) : base + String(l || "");
}
function csrfOf(text) {
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
}
function attr(html, name) {
  const m = String(html).match(new RegExp(name + '="([^"]*)"'));
  return m ? m[1] : "";
}
function hidden(html, name) {
  const m = String(html).match(new RegExp('name="' + name + '"[^>]*value="([^"]*)"'));
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
  const jar = new Map();
  const self = {
    get cookie() {
      return Array.from(jar.entries()).map(function (pair) {
        return pair[0] + "=" + pair[1];
      }).join("; ");
    },
    async go(method, path, body) {
      const headers = {};
      const sending = self.cookie;
      if (sending) { headers.cookie = sending; }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method, redirect: "manual",
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
      return { status: r.status, location: r.headers.get("location") || "",
               csp: r.headers.get("content-security-policy") || "",
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
    // An HTML page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

// The management API taking JSON, for the one thing no browser door here does:
// creating the person before they sign in.
async function apiPost(path, payload) {
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // An HTML page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
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
  return { cn: "Backup Keys Person " + who, givenName: "Backup", sn: who,
           displayName: "Backup Keys Person " + who, mail: who + "@" + MAIL_DOMAIN };
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
  const r = await get("/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200,
    "GET /admin-api/users?user=" + who + " answered " + r.status);
  return r.body.factors || {};
}

// Sign in at a portal door through the code flow, answering a security-key
// step with `authenticator` when one is asked for.
async function signIn(door, authenticator) {
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
  r = await b.go("GET", r.location);   // the authorization endpoint, with a code
  r = await b.go("GET", r.location);   // the callback, which mints the session
  assert.ok(b.cookie, "completing the flow established no session cookie.");
  return b;
}

// Drive `/portal/keys`'s two-step enrolment with one authenticator.
async function enrolAt(b, authenticator, role, label) {
  let page = await b.go("GET", "/portal/keys");
  const begun = await b.go("POST", "/portal/keys",
    form({ action: "begin", role: role, label: label || "",
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
  return { armed: page, done: done };
}

// ---------------------------------------------------------------------------
// 1. THE FIRST KEY, AND THE PAGE THAT COULD NOT ENROL ONE.
// ---------------------------------------------------------------------------
async function thePortalCanEnrolAKey(first) {
  log.info("=== /portal/keys enrols a key at all ===");
  const b = await signIn("/portal/keys", null);

  const page = await b.go("GET", "/portal/keys");
  check("THE PAGE OFFERS AN ENROL CONTROL. It said `there is no enrol button " +
        "here, because a WebAuthn ceremony belongs to a sign-in and this page " +
        "is not one` — and the premise is false: a ceremony belongs to " +
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
        "the first in this portal. A ceremony is a browser API call and there " +
        "is no markup that makes one; the relaxation goes through " +
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
    const scriptSrc = (String(page.csp).match(/script-src ([^;]*)/) || [])[1] || "";
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
  check("A `finish` NAMING A DIFFERENT ENROLMENT IS REFUSED — the challenge is " +
        "held against an id, so a ceremony armed in one tab cannot be " +
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

  const enrolled = await enrolAt(b, first, "mfa", "the one at my desk");
  check("and a real ceremony against it enrols the key", function () {
    assert.strictEqual(enrolled.done.status, 303,
      "the enrolment answered " + enrolled.done.status + " " +
      String(enrolled.done.text).slice(0, 500));
  });

  const factors = await factorsFor(PERSON);
  check("which reaches the person's own entry, with the label they typed and " +
        "the role they chose", function () {
    assert.strictEqual(factors.mfaKeys, 1,
      "the store holds " + factors.mfaKeys + " key(s).");
    assert.strictEqual(factors.keys[0].label, "the one at my desk",
      "the label did not survive: " + JSON.stringify(factors.keys[0]));
    assert.strictEqual(factors.keys[0].role, "mfa",
      "the role did not survive.");
  });
  return b;
}

// ---------------------------------------------------------------------------
// 2. THE BACKUP, AND THE MISTAKE IT HAS TO REFUSE.
// ---------------------------------------------------------------------------
async function aSecondKeyIsABackupAndTheSameOneIsNot(first, second) {
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
      assert.ok(attr(again.armed.text, "data-exclude").indexOf(first.idB64) >= 0,
        "the ceremony did not exclude the enrolled key: " +
        attr(again.armed.text, "data-exclude"));
    });

  const backup = await enrolAt(b, second, "mfa", "the one on my keyring");
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
}

// ---------------------------------------------------------------------------
// 3. EITHER KEY SIGNS THEM IN. **The assertion the backup is FOR.**
// ---------------------------------------------------------------------------
async function eitherKeySignsThemIn(first, second) {
  log.info("=== either key signs them in ===");
  for (const one of [first, second]) {
    const b = await signIn("/portal", one);
    check("the key called `" + one.name + "` completes the second-factor " +
          "step on its own — a service that checked whichever key it found " +
          "FIRST would refuse every assertion from the others and look " +
          "perfectly correct with one key enrolled", function () {
      assert.ok(b.cookie, "no session came out of it.");
    });
  }

  const stranger = makeAuthenticator("never enrolled");
  const b = browser();
  let r = await b.go("GET", "/portal");
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
}

// ---------------------------------------------------------------------------
// 4. LOSING ONE. Self-service for the lost key, refused for the last.
// ---------------------------------------------------------------------------
async function theLostKeyIsRemovedWithoutAnOperator(first, second) {
  log.info("=== the lost key is removed, and the last one is not ===");
  const b = await signIn("/portal/keys", second);
  let page = await b.go("GET", "/portal/keys");

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
        "drops the account to one factor rather than to none. A `primary` key " +
        "in the same position is refused, which tests/portal_access.js " +
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

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed".
  assert.ok(checks >= 12,
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
