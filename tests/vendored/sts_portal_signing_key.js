// File: sts_portal_signing_key.js
//
// ===========================================================================
// /portal/signing-key: A PERSON ISSUING THEMSELVES AN RFC 7523 SIGNING KEY,
// AND THEN USING IT.
//
// `/admin/pki` could issue a person a key pair from 2026-09-11 and an operator
// had to do it. This page is the person's own door onto the same act, and the
// claim it makes is one nothing else in either suite can check:
//
//   **the private key this page shows once, in a browser, to somebody who
//   typed a password, actually obtains an access token as them at
//   `/oauth2/token` — and obtains nothing at all as anybody else.**
//
// Every half of that sentence is a different subsystem. The portal renders and
// writes; `common/pki.js` issues; `common/person_assertions.js` seals and
// resolves; `oauth-oidc/assertion_grant.js` verifies and refuses. They are
// asserted apart in `tests/rfc7523_person_issuer.js`, in process, where the
// refusals are cheap to reach. **What is here is the seam**: a PEM read off a
// rendered HTML page and presented to a token endpoint by a signer this file
// wrote itself.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE, WHICH IS THE FIRST QUESTION tests/CLAUDE.md ASKS.
//
// `local: true`. It drives this service's own `/portal` and its `/admin-api`,
// which is the OWNERSHIP argument rather than a capability one: the tree that
// adds a control to those surfaces is the tree that should go red when the
// control loses its endpoint.
//
// **AND IT IS NOT COVERED BY `tests/rfc7523_person_issuer.js` NEXT DOOR**,
// which is the trap this feature invites — that file proves every rule the
// grant enforces and touches no route, so a page that never renders the key, a
// form that posts to nothing, a CSRF check that was never wired, a private key
// that leaks onto the account page, and a second person's entry written by a
// body parameter are all invisible to it and pass it perfectly.
//
// ---------------------------------------------------------------------------
// THE SIGNER BELOW IS THIS FILE'S OWN, and that is deliberate rather than
// lazy. `sts_dpop.js` states the rule: if both sides of the exchange came from
// one implementation, a shared misunderstanding of RFC 7515 would make this
// test pass and interoperate with nobody. Twelve lines of compact
// serialization, RSA only, which is what the certificate authority issues by
// default.
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
var log = bunyan.createLogger({ name: "sts_portal_signing_key",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";
var TOKEN_ENDPOINT = base + "/oauth2/token";
var GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

// Suffixed per run: the directory is append-only in practice, and two runs
// against one long-lived mock must not see each other's people.
var OWNER = usernameFor("signkey-owner");
var OTHER = usernameFor("signkey-other");

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  [ok] " + what);
}

// ---------------------------------------------------------------------------
// THIS FILE'S OWN JWS SIGNER. See the header.
// ---------------------------------------------------------------------------
function b64u(buf) {
  return Buffer.from(buf).toString("base64url");
}

function signJws(header, payload, privateKeyPem) {
  const head = b64u(Buffer.from(JSON.stringify(header), "utf8"));
  const body = b64u(Buffer.from(JSON.stringify(payload), "utf8"));
  const signing = head + "." + body;
  const digest = { RS256: "sha256", RS384: "sha384", RS512: "sha512" }[header.alg];
  if (!digest) {
    throw new Error("this file signs RS256/RS384/RS512; asked for " + header.alg);
  }
  return signing + "." +
    b64u(nodeCrypto.sign(digest, Buffer.from(signing, "ascii"), privateKeyPem));
}

function now() {
  return Math.floor(Date.now() / 1000);
}

function jti() {
  return nodeCrypto.randomUUID();
}

// ---------------------------------------------------------------------------
// ONE BROWSER, with manual redirects and a cookie jar of its own — every
// assertion here is about WHICH page came back, and a fetch that followed the
// redirects would answer the question by hiding it.
// ---------------------------------------------------------------------------
function formBody(o) {
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

function browser(name) {
  const self = {
    name: name,
    cookie: "",
    jar: {},
    cookieHeader: function () {
      return Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
    },
    async go(method, path, body) {
      const headers = {};
      if (self.cookie) headers.cookie = self.cookie;
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method, redirect: "manual",
                                              headers: headers, body: body });
      // KEYED BY NAME: a browser signed in to a hosted surface holds TWO
      // cookies — the sign-on session and the surface's own — and keeping only
      // the last one seen drops whichever arrived first.
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const key = pair.split("=")[0];
        const value = pair.slice(key.length + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[key];
        } else {
          self.jar[key] = value;
        }
        self.cookie = self.cookieHeader();
      });
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text(), headers: r.headers };
    }
  };
  return self;
}

async function apiPost(path, body) {
  const r = await fetch(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {})
  });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    // An HTML error page from a door that answers JSON is worth quoting whole.
    parsed = raw;
  }
  return { status: r.status, body: parsed, raw: raw };
}

async function apiGet(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    parsed = raw;
  }
  return { status: r.status, body: parsed, raw: raw };
}

async function tokenRequest(fields) {
  const r = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString() });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    parsed = raw;
  }
  return { status: r.status, body: parsed, raw: raw };
}

function claimsOf(token) {
  return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url")
    .toString("utf8"));
}

function csrfOf(text) {
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
}

// The PEM as the page prints it. Anchored on the BEGIN line rather than on the
// block, because the page carries a second <pre> holding a curl command and a
// regex that matched any <pre> would read that one on the day the order
// changed.
function privateKeyOn(text) {
  const found = String(text).match(
    /(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC )?PRIVATE KEY-----)/);
  return found ? found[1] : "";
}

function kidOn(text) {
  const found = String(text).match(/<th>Key<\/th><td><code>(person-[^<]+)<\/code>/);
  return found ? found[1] : "";
}

// A refusal read as the OAuth ERROR CODE and never as the status alone:
// `sts_roles.js` records why — a gate that works and a handler that has fallen
// over both produce a 400, and only the code tells them apart.
function refused(r, code, what) {
  assert.ok(r.status === 400 && r.body && r.body.error === code,
    what + " should be refused " + code + "; it answered " + r.status + " " +
    JSON.stringify(r.body).slice(0, 300));
  return String(r.body.error_description || "");
}

// ---------------------------------------------------------------------------
// SIGN IN AT A PORTAL DOOR. `/portal` is an OpenID Connect relying party of
// this service's own authorization server, so this is a code flow: the browser
// goes to `/oauth2/authorize`, meets the sign-in screen because the
// AUTHORIZATION ENDPOINT decides it needs one, and comes back with a code.
// ---------------------------------------------------------------------------
async function signIn(door, who) {
  log.debug("Entering signIn(). door=" + door + " who=" + who);
  const b = browser(who);
  let r = await b.go("GET", door);
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    door + " should send an unauthenticated browser to the authorization " +
    "endpoint; it answered " + r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    "the authorization endpoint should ask for a sign-in; it answered " +
    r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");
  r = await b.go("POST", "/authn/login",
                 formBody({ authn_id: authnId, username: who,
                            password: "any-password", action: "login",
                            csrf_token: csrfOf(r.text) }));
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in should end in a redirect; got " + r.status + " " +
    String(r.text).slice(0, 300));
  r = await b.go("GET", r.location);   // the authorization endpoint, with a code
  r = await b.go("GET", r.location);   // the callback, which mints the session
  assert.ok(b.cookie, "completing the flow should establish a session cookie.");
  log.debug("Leaving signIn().");
  return b;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + ".");

  // -------------------------------------------------------------------------
  // 0. TWO PEOPLE. The second one exists to be asserted ABOUT rather than to
  //    act: every refusal in this job is about what the first one cannot do to
  //    the second.
  // -------------------------------------------------------------------------
  log.info("=== 0. two people ===");
  const made = await apiPost("/users/create", { username: OWNER });
  const madeOther = await apiPost("/users/create", { username: OTHER });
  check("both people are created through the management API", function () {
    assert.strictEqual(made.status, 200, JSON.stringify(made.body).slice(0, 300));
    assert.strictEqual(madeOther.status, 200,
      JSON.stringify(madeOther.body).slice(0, 300));
  });

  // -------------------------------------------------------------------------
  // 1. THE PAGE BEFORE ANYTHING IS ISSUED.
  // -------------------------------------------------------------------------
  log.info("=== 1. the page, holding nothing ===");
  const b = await signIn("/portal/signing-key", OWNER);
  const empty = await b.go("GET", "/portal/signing-key");
  check("the page is drawn for a signed-in person and says they hold no key",
        function () {
          assert.strictEqual(empty.status, 200,
            "it answered " + empty.status + " -> " + empty.location);
          assert.ok(/You have no signing key/.test(empty.text),
            "the page does not say the key is missing: " +
            String(empty.text).slice(0, 400));
        });
  check("and offers to issue one, with the CSRF token every form here carries",
        function () {
          assert.ok(/name="action" value="generate"/.test(empty.text),
            "there is no generate control on the page");
          assert.ok(csrfOf(empty.text), "the form carries no CSRF token");
        });
  check("and the account column marks it as the page being read, so it is a " +
        "page in this application rather than a URL somebody has to be told",
        function () {
          assert.ok(/aria-current="page">Signing key</.test(empty.text),
            "the navigation does not carry this page: " +
            (String(empty.text).match(/<nav[\s\S]*?<\/nav>/) || [""])[0]
              .slice(0, 400));
        });

  // -------------------------------------------------------------------------
  // 2. GENERATING IT, AND THE ONE MOMENT THE KEY EXISTS IN THE OPEN.
  // -------------------------------------------------------------------------
  log.info("=== 2. generating ===");
  const issued = await b.go("POST", "/portal/signing-key",
                            formBody({ action: "generate",
                                       csrf_token: csrfOf(empty.text) }));
  const pem = privateKeyOn(issued.text);
  const kid = kidOn(issued.text);
  check("**the POST ANSWERS WITH A PAGE and the private key is on it.** A 303 " +
        "has nowhere to put a credential, and a query string would write this " +
        "key into a browser history entry and every log between here and the " +
        "person", function () {
          assert.strictEqual(issued.status, 200,
            "it answered " + issued.status + " -> " + issued.location + " " +
            String(issued.text).slice(0, 300));
          assert.ok(/BEGIN (RSA )?PRIVATE KEY/.test(pem),
            "no private key block on the page: " +
            String(issued.text).slice(0, 600));
        });
  check("the page says it is the only time it will be shown, which is the " +
        "whole contract — nothing in this service opens the stored copy again",
        function () {
          assert.ok(/only time it will be shown/i.test(issued.text),
            "the page does not say the key is shown once");
        });
  check("and it is served no-store, like every page in this portal",
        function () {
          assert.ok(/no-store/.test(
            String(issued.headers.get("cache-control") || "")),
            "cache-control is " + issued.headers.get("cache-control"));
        });
  check("the key handle says the certificate was issued to a PERSON — the " +
        "prefix is what `common/pki.js` puts on a subject of that kind, and " +
        "it is the visible half of the URN that holds this key to asserting " +
        "about its own holder", function () {
          assert.ok(/^person-/.test(kid), "kid=" + JSON.stringify(kid));
        });

  // -------------------------------------------------------------------------
  // 3. THE CLAIM THE WHOLE PAGE IS FOR: the key works.
  // -------------------------------------------------------------------------
  log.info("=== 3. the key obtains a token ===");
  const selfAssertion = signJws(
    { alg: "RS256", typ: "JWT", kid: kid },
    { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
      exp: now() + 120, jti: jti() }, pem);
  const granted = await tokenRequest({ grant_type: GRANT,
                                       assertion: selfAssertion,
                                       scope: "openid" });
  check("**A PEM READ OFF A RENDERED PAGE OBTAINS AN ACCESS TOKEN** at " +
        "/oauth2/token as its own holder — no browser, no password and no " +
        "consent step in the request", function () {
          assert.strictEqual(granted.status, 200,
            JSON.stringify(granted.body).slice(0, 400));
          assert.ok(granted.body.access_token, "no access token came back");
          assert.strictEqual(claimsOf(granted.body.access_token).username,
                             OWNER,
            "the token is for " + claimsOf(granted.body.access_token).username);
        });

  const aboutOther = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: OWNER, sub: OTHER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, pem) });
  check("**AND OBTAINS NOTHING AS ANYBODY ELSE.** A key a person issued " +
        "themselves is their credential rather than permission to speak for " +
        "the others; without this refusal the button on that page would hand " +
        "every signed-in person a token as anybody in the realm", function () {
          const why = refused(aboutOther, "invalid_grant",
                              "an assertion about somebody else");
          assert.ok(/only be about themselves/.test(why),
            "the refusal should say why; it said " +
            JSON.stringify(why).slice(0, 200));
        });

  // -------------------------------------------------------------------------
  // 4. SHOWN ONCE MEANS SHOWN ONCE.
  // -------------------------------------------------------------------------
  log.info("=== 4. what the page says afterwards ===");
  const after = await b.go("GET", "/portal/signing-key");
  check("**the private key is NOT on the page again** — the stored copy is " +
        "sealed and nothing here opens it, so a person who closed the tab has " +
        "to generate a new pair", function () {
          assert.strictEqual(privateKeyOn(after.text), "",
            "a private key block is still on the page");
        });
  check("what IS there is the public half: the key handle, what they assert " +
        "as, and the certificate — which is the half anybody may hold",
        function () {
          assert.strictEqual(kidOn(after.text), kid,
            "the page no longer names the key");
          assert.ok(/BEGIN CERTIFICATE/.test(after.text),
            "the certificate is not on the page");
        });

  const overview = await b.go("GET", "/portal");
  check("and NONE of it is on the Overview, by name or by value — that page " +
        "draws a FIXED LIST of standard attributes, so a credential this " +
        "service invents cannot arrive on it by accident", function () {
          const whole = String(overview.text);
          ["stsAssertionPrivateKey", "stsassertionprivatekey",
           "stsAssertionJwks", "stsassertionjwks"].forEach(function (name) {
            assert.ok(whole.indexOf(name) < 0,
              "the Overview mentions " + name);
          });
          assert.strictEqual(privateKeyOn(whole), "",
            "the Overview carries a private key block");
        });

  // -------------------------------------------------------------------------
  // 5. THE CSRF CHECK, AND THAT A REFUSED POST ISSUES NOTHING.
  // -------------------------------------------------------------------------
  log.info("=== 5. a post with no CSRF token ===");
  const forged = await b.go("POST", "/portal/signing-key",
                            formBody({ action: "generate" }));
  check("a generate with no CSRF token is refused 403 — the token is what " +
        "stops another origin's form pressing this button in a live session",
        function () {
          assert.strictEqual(forged.status, 403,
            "it answered " + forged.status + " " +
            String(forged.text).slice(0, 200));
        });
  check("and NOTHING was issued by the refusal: the key handle on the page is " +
        "still the one from before, which is the half a status code cannot " +
        "show", function () {
          const still = kidOn(forged.text);
          assert.ok(!still || still === kid,
            "the refused post seems to have replaced the key: " + still +
            " where " + kid + " was held");
        });

  // -------------------------------------------------------------------------
  // 6. THE RULE THIS PORTAL IS BUILT ON: the identity is the session's.
  // -------------------------------------------------------------------------
  log.info("=== 6. a username in the body changes nothing ===");
  const smuggled = await b.go("POST", "/portal/signing-key",
                              formBody({ action: "generate",
                                         username: OTHER, user: OTHER,
                                         identifier: OTHER,
                                         csrf_token: csrfOf(after.text) }));
  check("a generate carrying somebody else's name in every parameter a " +
        "future author might plausibly read still issues to the SIGNED-IN " +
        "person", function () {
          assert.strictEqual(smuggled.status, 200,
            "it answered " + smuggled.status);
          assert.ok(privateKeyOn(smuggled.text), "no key came back");
        });
  const theirs = await apiGet("/users?user=" + encodeURIComponent(OTHER));
  check("**and the other person's entry holds NOTHING** — which is the " +
        "assertion that matters: a body parameter that wrote a key pair onto " +
        "somebody else's entry would be a takeover rather than a leak",
        function () {
          const whole = JSON.stringify(theirs.body).toLowerCase();
          assert.ok(whole.indexOf("stsassertionjwks") < 0,
            OTHER + " has been given a signing key by " + OWNER + "'s post");
        });

  const replacedKid = kidOn(smuggled.text);
  check("generating again REPLACED the pair rather than adding one — a person " +
        "holds one signing key, and two would mean a verifier trying both",
        function () {
          assert.ok(replacedKid && replacedKid !== kid,
            "the key handle did not change: " + replacedKid);
        });
  const oldKey = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, pem) });
  check("and the key it replaced stops working that moment, which is what the " +
        "page warns before the button is pressed", function () {
          refused(oldKey, "invalid_grant", "an assertion signed with the " +
                  "replaced key");
        });

  // -------------------------------------------------------------------------
  // 7. TAKING IT OFF.
  // -------------------------------------------------------------------------
  log.info("=== 7. taking it off ===");
  const newPem = privateKeyOn(smuggled.text);
  const removed = await b.go("POST", "/portal/signing-key",
                             formBody({ action: "remove",
                                        csrf_token: csrfOf(smuggled.text) }));
  check("the remove answers 303 with a message rather than a page — there is " +
        "nothing to hand back, which is why this half is a redirect and the " +
        "generate is not", function () {
          assert.strictEqual(removed.status, 303,
            "it answered " + removed.status);
          assert.ok(/\/portal\/signing-key\?done=/.test(removed.location),
            "it redirected to " + removed.location);
        });
  const afterRemoval = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: replacedKid },
      { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, newPem) });
  check("and an assertion signed with the key that was taken off is refused " +
        "from that moment — which is the half that IS true of it, since the " +
        "certificate itself is on no revocation list", function () {
          refused(afterRemoval, "invalid_grant",
                  "an assertion signed with a key that was taken off");
        });

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure a suite cannot report about itself.
  assert.ok(checks >= 17,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_portal_signing_key")
  .description("/portal/signing-key: a person issues themselves an RFC 7523 " +
      "key pair, the private half is shown once on the page that comes back, " +
      "it obtains an access token as them at /oauth2/token and obtains " +
      "nothing as anybody else, it never appears again, a post with no CSRF " +
      "token is refused, a username in the body changes nothing, generating " +
      "replaces and taking it off stops it being accepted.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
