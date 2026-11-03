// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_portal_signing_key.js
//
// ===========================================================================
// /portal/signing-key: A PERSON ISSUING THEMSELVES AN RFC 7523 SIGNING KEY,
// AND THEN USING IT — and since 2026-09-13 an RFC 7522 one beside it, on a
// set of its own that neither signs for the other nor comes off with it.
// SINCE #1290 (2026-11-03) several of each: Generate adds, each key pair is
// revoked on its own row, and at `pki.personSigningKeyMax` the Generate
// control becomes a note.
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
// **SINCE #568 THE PORTAL IS A STATIC APPLICATION** over `/account-api`: the
// page is `GET /account-api/signing-key` drawn by the portal's own
// renderers, and the PEM is read off the VIEW the generate answers, drawn in
// place — still the page a person reads it from. The CSRF checks became the
// token's: a request without the person's token issues nothing.
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
const portal = require("./portal_signin.js");
// RFC 7522's signer is this suite's own XML Signature, for the reason the JWS
// signer below is this file's own: see `saml_xmldsig.js`'s header.
const samlSigner = require("./saml_xmldsig.js");

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
var log = bunyan.createLogger({ name: "sts_portal_signing_key",
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
var TOKEN_ENDPOINT = base + "/oauth2/token";
var GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
var SAML_GRANT = "urn:ietf:params:oauth:grant-type:saml2-bearer";

// Suffixed per run: the directory is append-only in practice, and two runs
// against one long-lived mock must not see each other's people.
var OWNER = usernameFor("signkey-owner");
var OTHER = usernameFor("signkey-other");

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THIS FILE'S OWN JWS SIGNER. See the header.
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
  log.debug("Leaving signJws().");
  return signing + "." +
    b64u(nodeCrypto.sign(digest, Buffer.from(signing, "ascii"), privateKeyPem));
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

async function apiPost(path, body) {
  log.debug("Entering apiPost().");
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
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting whole.
    parsed = raw;
  }
  log.debug("Leaving apiPost().");
  return { status: r.status, body: parsed, raw: raw };
}

async function apiGet(path) {
  log.debug("Entering apiGet().");
  const r = await fetch(api + path);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiGet(): " + ((e && e.message) || e));
    parsed = raw;
  }
  log.debug("Leaving apiGet().");
  return { status: r.status, body: parsed, raw: raw };
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

// ---------------------------------------------------------------------------
// BOTH PEOPLE ARE CREATED WITH THE ATTRIBUTES A REAL ACCOUNT CARRIES
// (2026-09-12), and the one who signs in with a password of at least twelve
// characters — which is what the sign-in screen is then sent. In product mode
// this service invents no persona onto an entry and verifies the password
// against it; a job that leaned on either would be testing the invention.
// ---------------------------------------------------------------------------
var PASSWORD = "portal-signing-key-Passw0rd!-" + String(Date.now()).slice(-6);
var MAIL_DOMAIN = "portal-signing-key.test";

function personAttributes(who) {
  log.debug("Entering personAttributes().");
  log.debug("Leaving personAttributes().");
  return { cn: "Signing Key Person " + who, givenName: "Signing", sn: who,
           displayName: "Signing Key Person " + who,
           mail: who + "@" + MAIL_DOMAIN };
}

// A `download` link's file, by the end of its name and its media type. The
// link carries a `title` between `download` and `href` since #671, so other
// attributes may sit between the two.
function dataLink(text, suffix, mime) {
  log.debug("Entering dataLink().");
  const pattern = new RegExp('download="([^"]*' + suffix.replace(/\./g,
    "\\.") + ')"[^>]*? href="data:' + mime.replace(/[/+.]/g, "\\$&") +
    ';base64,([A-Za-z0-9+/=]+)"');
  const found = pattern.exec(String(text || ""));
  log.debug("Leaving dataLink().");
  return found ? { name: found[1],
                   bytes: Buffer.from(found[2], "base64") } : null;
}

// The private key a page offers. SINCE #671 (2026-11-03) it is a download
// link in the certificate's row, `<name>-<profile>-signing-key.pem`, and not
// a printed block; a PEM printed anywhere in the text is still found, so the
// checks that a page carries NO key stay as strict as they were. Anchored on
// the BEGIN line rather than on the block, because the page carries a <pre>
// holding a curl command.
function privateKeyOn(text) {
  log.debug("Entering privateKeyOn().");
  const pemOf = function (one) {
    const found = String(one).match(
      /(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC )?PRIVATE KEY-----)/);
    return found ? found[1] : "";
  };
  const printed = pemOf(text);
  const link = dataLink(text, "-key.pem", "application/x-pem-file");
  log.debug("Leaving privateKeyOn().");
  return printed || (link ? pemOf(link.bytes.toString("utf8")) : "");
}

// ONE PROFILE'S CARD (#1290): from its heading to the next card's. Each
// card lists every key pair the person holds, one row each, the handle in
// the row's second cell.
function cardOf(text, id) {
  log.debug("Entering cardOf(). " + id);
  const after = String(text || "").split('<h2 id="' + id + '">')[1] || "";
  log.debug("Leaving cardOf().");
  return after.split('<div class="card">')[0];
}

// Every handle a card lists, newest first (the order the page draws).
function handlesOn(text, id) {
  log.debug("Entering handlesOn(). " + id);
  const out = [];
  const pattern = /<\/td><td><code>([A-Za-z0-9_-]+)<\/code>/g;
  const card = cardOf(text, id);
  let found = pattern.exec(card);
  while (found) {
    out.push(found[1]);
    found = pattern.exec(card);
  }
  log.debug("Leaving handlesOn(). " + out.length);
  return out;
}

// The state a card's row for one handle says: `valid`, `revoked`, ….
function stateOn(text, id, handle) {
  log.debug("Entering stateOn().");
  const rows = cardOf(text, id).split("<tr");
  const row = rows.filter(function (one) {
    return one.indexOf("<code>" + handle + "</code>") >= 0;
  })[0] || "";
  const found = /<span class="state-([a-z]+)">/.exec(row);
  log.debug("Leaving stateOn().");
  return found ? found[1] : "";
}

// The handle in the row a generation marked as the new one (#671, #1290).
function freshHandleOn(text) {
  log.debug("Entering freshHandleOn().");
  const row = (String(text || "")
    .match(/<tr class="fresh-row">[\s\S]*?<\/tr>/) || [""])[0];
  const found = /<\/td><td><code>([A-Za-z0-9_-]+)<\/code>/.exec(row);
  log.debug("Leaving freshHandleOn().");
  return found ? found[1] : "";
}

function thumbprintOn(text) {
  log.debug("Entering thumbprintOn().");
  log.debug("Leaving thumbprintOn().");
  return handlesOn(text, "saml")[0] || "";
}

// An RFC 7522 grant: an assertion built and signed by `saml_xmldsig.js`,
// base64url-encoded, presented at the token endpoint.
async function samlGrant(iss, sub, privateKeyPem) {
  log.debug("Entering samlGrant().");
  const built = samlSigner.buildAssertion({ issuer: iss, subject: sub,
                                            audience: TOKEN_ENDPOINT,
                                            recipient: TOKEN_ENDPOINT });
  const r = await tokenRequest({ grant_type: SAML_GRANT,
    assertion: samlSigner.b64u(samlSigner.sign(built, privateKeyPem, "", {})),
    scope: "openid" });
  log.debug("Leaving samlGrant().");
  return r;
}

// The newest RFC 7523 key pair's kid on the page.
function kidOn(text) {
  log.debug("Entering kidOn().");
  log.debug("Leaving kidOn().");
  return handlesOn(text, "jwt")[0] || "";
}

// A refusal read as the OAuth ERROR CODE and never as the status alone:
// `sts_roles.js` records why — a gate that works and a handler that has fallen
// over both produce a 400, and only the code tells them apart.
function refused(r, code, what) {
  log.debug("Entering refused().");
  assert.ok(r.status === 400 && r.body && r.body.error === code,
    what + " should be refused " + code + "; it answered " + r.status + " " +
    JSON.stringify(r.body).slice(0, 300));
  log.debug("Leaving refused().");
  return String(r.body.error_description || "");
}

// ---------------------------------------------------------------------------
// SIGN IN AS THE STATIC PORTAL DOES (#568): the code flow with PKCE as the
// public client `sts-user-portal`, a DPoP-bound token for `/account-api`
// (`portal_signin.js`). `door` is the page the person came for.
// ---------------------------------------------------------------------------
async function signIn(door, who) {
  log.debug("Entering signIn(). door=" + door + " who=" + who);
  const b = { portal: await portal.signInToThePortal(base, who, null,
                                                     { password: PASSWORD }) };
  await knowMe(b);
  log.debug("Leaving signIn().");
  return b;
}

// ---------------------------------------------------------------------------
// THE PORTAL, AS ITS PAGES ARE DRAWN SINCE #568. A page is its operation's
// view drawn by the portal's own renderers (`portal/portal.bundle.js`), and
// a form is the operation that mirrors it, sent as JSON; an act that shows
// something once answers a VIEW, drawn in place.
// ---------------------------------------------------------------------------
function drawView(b, path, view) {
  log.debug("Entering drawView(). " + path);
  const table = portal.portalBundle();
  const row = table.PAGES.filter(function (one) {
    return one.path === path;
  })[0];
  assert.ok(row, "the portal draws no page at " + path);
  const t = table.messages.WebTranslator.fromData(b.me && b.me.locale);
  log.debug("Leaving drawView().");
  return row.render(view, { t: t, query: {}, prefix: "", origin: base,
                            me: b.me, locale: b.me && b.me.locale,
                            version: b.me && b.me.version, here: path });
}

async function knowMe(b) {
  log.debug("Entering knowMe().");
  if (!b.me) {
    b.me = (await b.portal.api("GET", "/account-api/me")).json;
  }
  log.debug("Leaving knowMe().");
}

// The page at `path`: `{ status, json, text, headers }`.
async function pageOf(b, path) {
  log.debug("Entering pageOf(). " + path);
  await knowMe(b);
  const table = portal.portalBundle();
  const row = table.PAGES.filter(function (one) {
    return one.path === path;
  })[0];
  assert.ok(row, "the portal draws no page at " + path);
  const answer = await b.portal.api("GET", row.operation);
  log.debug("Leaving pageOf().");
  return { status: answer.status, json: answer.json, headers: answer.headers,
           text: answer.status === 200 && answer.json
             ? drawView(b, path, answer.json) : "" };
}

// The form at `path`, acted on: `{ status, json, text, said, headers }` —
// `text` the view it answered drawn (or its raw text), `said` its message or
// its refusal.
async function act(b, path, fields) {
  log.debug("Entering act(). " + path);
  await knowMe(b);
  const r = await b.portal.act(path, fields);
  const json = r.json || {};
  log.debug("Leaving act().");
  return { status: r.status, json: r.json, headers: r.headers,
           said: String(json.message || "") + " " +
                 (json.errors || []).join(" "),
           text: json.view ? drawView(b, path, json.view)
                           : String(r.text || "") };
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
  const made = await apiPost("/users/create",
    { username: OWNER, invent: false, attributes: personAttributes(OWNER),
      credential: "password", password: PASSWORD });
  const madeOther = await apiPost("/users/create",
    { username: OTHER, invent: false, attributes: personAttributes(OTHER),
      credential: "password", password: PASSWORD });
  check("both people are created through the management API, with their " +
        "attributes and a password, and nothing invented", function () {
    assert.strictEqual(made.status, 200,
                       JSON.stringify(made.body).slice(0, 300));
    assert.strictEqual(madeOther.status, 200,
      JSON.stringify(madeOther.body).slice(0, 300));
    assert.ok(made.body.passwordSet && madeOther.body.passwordSet,
      "a password was not set: " + JSON.stringify(made.body).slice(0, 300));
    assert.strictEqual(made.body.invented, false,
      "the create invented attributes: " +
      JSON.stringify(made.body).slice(0, 300));
  });

  // -------------------------------------------------------------------------
  // 1. THE PAGE BEFORE ANYTHING IS ISSUED.
  // -------------------------------------------------------------------------
  log.info("=== 1. the page, holding nothing ===");
  const b = await signIn("/portal/signing-key", OWNER);
  const empty = await pageOf(b, "/portal/signing-key");
  check("the page is drawn for a signed-in person and says they hold no key",
        function () {
          assert.strictEqual(empty.status, 200,
            "it answered " + empty.status);
          assert.ok(/You have no RFC 7523 signing key/.test(empty.text) &&
                    /You have no RFC 7522 signing key/.test(empty.text),
            "the page does not say either key is missing: " +
            String(empty.text).slice(0, 400));
        });
  check("and offers to issue one, one control per profile",
        function () {
          assert.ok(/name="action" value="generate"/.test(empty.text),
            "there is no generate control on the page");
          assert.ok(/name="purpose" value="jwt"/.test(empty.text) &&
                    /name="purpose" value="saml"/.test(empty.text),
            "the page does not offer one control per profile");
        });
  // THE COLUMN IS THE PORTAL'S FRAME, drawn in the browser around the
  // page's cards (#568); what can be asked over HTTP is that the path is a
  // page of the portal, answered by its shell.
  const shell = await fetch(base + "/portal/signing-key");
  check("the path is a page in this application rather than a URL somebody " +
        "has to be told: the portal's shell answers it", function () {
          assert.strictEqual(shell.status, 200,
            "it answered " + shell.status);
          assert.ok(/text\/html/.test(String(shell.headers.get(
            "content-type") || "")), "the shell is not a page");
        });

  // -------------------------------------------------------------------------
  // 2. GENERATING IT, AND THE ONE MOMENT THE KEY EXISTS IN THE OPEN.
  // -------------------------------------------------------------------------
  log.info("=== 2. generating ===");
  const issued = await act(b, "/portal/signing-key", { action: "generate" });
  const pem = privateKeyOn(issued.text);
  const kid = kidOn(issued.text);
  check("**the act ANSWERS WITH THE PAGE'S VIEW and the private key is on " +
        "it**, drawn in place: a query string would write this key into a " +
        "browser history entry and every log between here and the person",
        function () {
          assert.strictEqual(issued.status, 200,
            "it answered " + issued.status + " " +
            String(issued.text).slice(0, 300));
          assert.ok(/BEGIN (RSA )?PRIVATE KEY/.test(pem),
            "no private key block on the page: " +
            String(issued.text).slice(0, 600));
        });
  check("the page says it is the only time it can be downloaded, which is " +
        "the whole contract — nothing in this service opens the stored copy " +
        "again", function () {
          assert.ok(/only time it can be downloaded/i.test(issued.text),
            "the page does not say the key is offered once");
        });
  // THE TWO FILES ARE IN THE CERTIFICATE'S ROW (#671), the same pair the
  // TLS client certificate's row carries: the key, and the chain whose leaf
  // is the certificate that key belongs to.
  const issuedChain = dataLink(issued.text, "-jwt-signing-chain.pem",
                               "application/x-pem-file");
  check("the key and the certificate chain are download links in the new " +
        "key pair's own row, and the chain's leaf holds the key's public " +
        "half", function () {
          const row = (String(issued.text)
            .match(/<tr class="fresh-row">[\s\S]*?<\/tr>/) || [""])[0];
          assert.ok(/-jwt-signing-key\.pem"/.test(row) &&
                    /-jwt-signing-chain\.pem"/.test(row),
            "the two downloads are not in the certificate's row");
          assert.ok(issuedChain, "no chain download on the page");
          const leaf = new nodeCrypto.X509Certificate((/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/
            .exec(issuedChain.bytes.toString("utf8")) || [""])[0]);
          assert.ok(nodeCrypto.createPublicKey(pem)
            .export({ type: "spki", format: "der" })
            .equals(leaf.publicKey.export({ type: "spki", format: "der" })),
            "the chain's leaf is not the key's certificate");
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
  const after = await pageOf(b, "/portal/signing-key");
  check("**the private key is NOT on the page again** — the stored copy is " +
        "sealed and nothing here opens it, so a person who closed the tab " +
        "has to generate a new pair", function () {
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

  const overview = await pageOf(b, "/portal");
  check("and NONE of it is on the Overview, by name or by value — that page " +
        "draws a FIXED LIST of standard attributes, so a credential this " +
        "service invents cannot arrive on it by accident", function () {
          const whole = String(overview.text) +
                        JSON.stringify(overview.json || {});
          ["stsAssertionPrivateKey", "stsassertionprivatekey",
           "stsAssertionKeyPair", "stsassertionkeypair"].forEach(function (name) {
            assert.ok(whole.indexOf(name) < 0,
              "the Overview mentions " + name);
          });
          assert.strictEqual(privateKeyOn(whole), "",
            "the Overview carries a private key block");
        });

  // -------------------------------------------------------------------------
  // 5. THE CSRF CHECK, AND THAT A REFUSED POST ISSUES NOTHING.
  // -------------------------------------------------------------------------
  // THE CSRF TOKEN WENT WITH THE COOKIE IT GUARDED (#568): what stops
  // another origin's form pressing this button is that the act takes the
  // person's DPoP-bound token and a proof by a key only their page holds.
  log.info("=== 5. a post with no access token ===");
  const forgedRaw = await fetch(base + "/account-api/signing-key", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "generate" }) });
  const forgedText = await forgedRaw.text();
  check("a generate with no access token is refused 401 — the token is what " +
        "stops another origin's form pressing this button", function () {
          assert.strictEqual(forgedRaw.status, 401,
            "it answered " + forgedRaw.status + " " +
            forgedText.slice(0, 200));
          assert.strictEqual(privateKeyOn(forgedText), "",
            "the refusal carried a key");
        });
  const stillPage = await pageOf(b, "/portal/signing-key");
  check("and NOTHING was issued by the refusal: the key handle on the page " +
        "is still the one from before, which is the half a status code " +
        "cannot show", function () {
          assert.strictEqual(kidOn(stillPage.text), kid,
            "the refused post seems to have replaced the key");
        });

  // -------------------------------------------------------------------------
  // 6. THE RULE THIS PORTAL IS BUILT ON: the identity is the session's.
  // -------------------------------------------------------------------------
  log.info("=== 6. a username in the body changes nothing ===");
  // SINCE 2026-10-12 THE ACCOUNT API REFUSES A FIELD AN OPERATION DOES NOT
  // TAKE, so the names are refused outright and nothing is issued; the same
  // generate with only its own field then issues to the SIGNED-IN person.
  const smuggled = await act(b, "/portal/signing-key",
                             { action: "generate", username: OTHER,
                               user: OTHER, identifier: OTHER });
  check("a generate carrying somebody else's name in every parameter a " +
        "future author might plausibly read is refused 400, naming them",
        function () {
          assert.strictEqual(smuggled.status, 400,
            "it answered " + smuggled.status);
          assert.ok(!privateKeyOn(smuggled.text), "a key came back");
        });
  const generated = await act(b, "/portal/signing-key",
                              { action: "generate" });
  check("and the same generate with only its own field issues to the " +
        "SIGNED-IN person", function () {
          assert.strictEqual(generated.status, 200,
            "it answered " + generated.status);
          assert.ok(privateKeyOn(generated.text), "no key came back");
        });
  const theirs = await apiGet("/users?user=" + encodeURIComponent(OTHER));
  check("**and the other person's entry holds NOTHING** — which is the " +
        "assertion that matters: a body parameter that wrote a key pair onto " +
        "somebody else's entry would be a takeover rather than a leak",
        function () {
          // READ OFF THE CREDENTIALS SECTION'S `held` FLAGS (2026-09-13).
          // This used to search the reply for the attribute NAME, and the
          // person page's Credentials section now lists every attribute
          // name whether or not anything is held — so the search went red
          // about an entry holding nothing.
          assert.strictEqual(theirs.status, 200,
            JSON.stringify(theirs.body).slice(0, 300));
          const pairs = (((theirs.body || {}).credentials || {}).keyPairs ||
                         []);
          assert.ok(pairs.length === 2, "the reply carries no credentials: " +
            JSON.stringify(theirs.body).slice(0, 300));
          pairs.forEach(function (one) {
            assert.ok(!one.held, OTHER + " has been given an " +
              one.purpose + " signing key by " + OWNER + "'s post");
          });
        });

  // SEVERAL KEY PAIRS PER PROFILE (#1290): generating again ADDS one.
  const addedKid = freshHandleOn(generated.text);
  check("generating again ADDS a key pair rather than replacing the one " +
        "held — the page lists both, the new one in the row carrying its " +
        "downloads", function () {
          assert.ok(addedKid && addedKid !== kid,
            "the new row's kid is " + JSON.stringify(addedKid));
          const listed = handlesOn(generated.text, "jwt");
          assert.ok(listed.indexOf(kid) >= 0 && listed.indexOf(addedKid) >= 0,
            "the card lists " + JSON.stringify(listed));
        });
  const oldKey = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, pem), scope: "openid" });
  check("and the first key pair STILL obtains a token: each is found by its " +
        "kid", function () {
          assert.strictEqual(oldKey.status, 200,
            JSON.stringify(oldKey.body).slice(0, 300));
        });

  // -------------------------------------------------------------------------
  // 7. REVOKING ONE, ROW BY ROW (#1290) — which replaced taking it off.
  // -------------------------------------------------------------------------
  log.info("=== 7. revoking one ===");
  const newPem = privateKeyOn(generated.text);
  const listedPage = await pageOf(b, "/portal/signing-key");
  check("every valid row carries its own Revoke, with the two reasons a " +
        "holder may give", function () {
          const card = cardOf(listedPage.text, "jwt");
          assert.strictEqual((card.match(/name="action" value="revoke"/g) ||
                              []).length, 2, "the JWT card's revoke forms");
          assert.ok(card.indexOf('name="handle" value="' + kid + '"') >= 0,
            "no revoke form names " + kid);
          assert.ok(/value="keyCompromise"/.test(card) &&
                    /value="cessationOfOperation"/.test(card),
            "the reasons are not offered");
        });
  const otherSide = await signIn("/portal/signing-key", OTHER);
  const notTheirs = await act(otherSide, "/portal/signing-key",
                              { action: "revoke", purpose: "jwt",
                                handle: kid, reason: "keyCompromise" });
  check("**ANOTHER PERSON NAMING THIS KID REVOKES NOTHING** — the handle is " +
        "looked up among the signed-in person's own key pairs only",
        function () {
          assert.strictEqual(notTheirs.status, 400,
            "it answered " + notTheirs.status + " " + notTheirs.said);
        });
  const revoked = await act(b, "/portal/signing-key",
                            { action: "revoke", purpose: "jwt", handle: kid,
                              reason: "keyCompromise" });
  check("the revoke answers a MESSAGE and no view — nothing secret comes " +
        "back", function () {
          assert.ok(revoked.status === 200 && revoked.json &&
                    revoked.json.ok === true && !revoked.json.view &&
                    /RFC 7523/.test(revoked.said),
            "it answered " + revoked.status + " " +
            String(revoked.text).slice(0, 200));
        });
  const revokedUse = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: kid },
      { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, pem) });
  const otherStill = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: addedKid },
      { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, newPem), scope: "openid" });
  check("**the revoked key is refused from that moment and the other still " +
        "obtains a token**", function () {
          refused(revokedUse, "invalid_grant",
                  "an assertion signed with a revoked key");
          assert.strictEqual(otherStill.status, 200,
            JSON.stringify(otherStill.body).slice(0, 300));
        });
  const revokedPage = await pageOf(b, "/portal/signing-key");
  check("the page draws the revoked row as revoked, with no Revoke on it",
        function () {
          assert.strictEqual(stateOn(revokedPage.text, "jwt", kid),
                             "revoked");
          assert.strictEqual(stateOn(revokedPage.text, "jwt", addedKid),
                             "valid");
          assert.ok(cardOf(revokedPage.text, "jwt").indexOf(
            'name="handle" value="' + kid + '"') < 0,
            "the revoked row still offers Revoke");
        });
  const ownerEntry = await apiGet("/users?user=" + encodeURIComponent(OWNER));
  check("and an administrator reads the same: the key pair revoked with " +
        "its reason, the other valid (GET /admin-api/users?user=)",
        function () {
          const pairs = ((ownerEntry.body || {}).credentials || {})
            .keyPairs || [];
          const jwt = pairs.filter(function (one) {
            return one.purpose === "jwt";
          })[0] || { keys: [] };
          const byHandle = {};
          jwt.keys.forEach(function (one) { byHandle[one.handle] = one; });
          assert.ok(byHandle[kid] && byHandle[kid].state === "revoked" &&
                    byHandle[kid].reason === "keyCompromise",
            JSON.stringify(jwt).slice(0, 400));
          assert.ok(byHandle[addedKid] &&
                    byHandle[addedKid].state === "valid",
            JSON.stringify(jwt).slice(0, 400));
        });

  // THE CAP (#1290): at `pki.personSigningKeyMax` valid key pairs the page
  // replaces Generate with a note and the act is refused.
  const capped = await apiPost("/config/set",
                               { key: "pki.personSigningKeyMax", value: "1" });
  check("the cap can be lowered to 1 for this check", function () {
    assert.strictEqual(capped.status, 200,
      JSON.stringify(capped.body).slice(0, 300));
  });
  try {
    const atCap = await pageOf(b, "/portal/signing-key");
    check("**AT THE CAP THE GENERATE CONTROL IS REPLACED BY A NOTE**",
          function () {
            const card = cardOf(atCap.text, "jwt");
            assert.ok(card.indexOf('name="action" value="generate"') < 0,
              "the JWT card still offers Generate at the cap");
            assert.ok(/the most this service issues to one person/
              .test(card), "the cap note is not on the card");
            assert.ok(cardOf(atCap.text, "saml")
              .indexOf('name="action" value="generate"') >= 0,
              "the cap is per profile, and the SAML card lost Generate");
          });
    const overCap = await act(b, "/portal/signing-key",
                              { action: "generate", purpose: "jwt" });
    check("and a generate posted anyway is refused 400, issuing nothing",
          function () {
            assert.strictEqual(overCap.status, 400,
              "it answered " + overCap.status);
            assert.strictEqual(privateKeyOn(overCap.text), "",
              "a key came back over the cap");
          });
  } finally {
    await apiPost("/config/reset", { key: "pki.personSigningKeyMax" });
  }

  // -------------------------------------------------------------------------
  // 8. RFC 7522: A SECOND KEY PAIR, ON A SET OF ITS OWN (2026-09-13).
  // -------------------------------------------------------------------------
  log.info("=== 8. an RFC 7522 key pair beside the RFC 7523 one ===");
  const jwtAgain = await act(b, "/portal/signing-key",
                             { action: "generate", purpose: "jwt" });
  const jwtPem = privateKeyOn(jwtAgain.text);
  const jwtKid = kidOn(jwtAgain.text);
  const samlIssued = await act(b, "/portal/signing-key",
                               { action: "generate", purpose: "saml" });
  const samlPem = privateKeyOn(samlIssued.text);
  const thumbprint = thumbprintOn(samlIssued.text);
  check("**`purpose=saml` ISSUES AN RFC 7522 KEY PAIR** and the page that " +
        "comes back carries its private key once, with SAML instructions " +
        "rather than JWT ones", function () {
          assert.strictEqual(samlIssued.status, 200,
            "it answered " + samlIssued.status + " " +
            String(samlIssued.text).slice(0, 300));
          assert.ok(/BEGIN (RSA )?PRIVATE KEY/.test(samlPem),
            "no private key block on the page");
          assert.ok(/Save this RFC 7522 private key/.test(samlIssued.text) &&
                    /saml2-bearer/.test(samlIssued.text),
            "the one-time card does not describe the SAML grant");
          assert.ok(jwtPem && samlPem !== jwtPem,
            "the two profiles did not get two private keys");
        });
  check("and the page now shows BOTH: the JWT key by its kid and the SAML " +
        "key by its certificate thumbprint", function () {
          assert.ok(/^[A-Za-z0-9_-]{20,}$/.test(thumbprint),
            "thumbprint=" + JSON.stringify(thumbprint));
          assert.strictEqual(kidOn(samlIssued.text), jwtKid,
            "the newest RFC 7523 key is not the one just issued: " +
            kidOn(samlIssued.text));
        });

  // THE CERTIFICATE ON THE SAML CARD SAYS WHICH PROFILE IT WAS ISSUED FOR.
  // `common/pki.js` puts RFC 7522's grant-type URN in the subjectAltName of
  // an RFC 7522 leaf, so that a certificate read out of context names its
  // profile — and nothing else here can tell a JWT leaf written onto the SAML
  // attributes from a SAML one, since the verifier matches the certificate
  // itself either way.
  const samlCard = String(samlIssued.text).split('<h2 id="saml">')[1] || "";
  const samlCert = (samlCard.match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/) ||
    [""])[0];
  check("the certificate on the RFC 7522 card was issued FOR RFC 7522: its " +
        "subjectAltName carries the saml2-bearer grant-type URN and names " +
        "this person", function () {
          assert.ok(samlCert, "no certificate on the SAML card");
          const san = String(new nodeCrypto.X509Certificate(samlCert)
            .subjectAltName || "");
          assert.ok(/grant-type:saml2-bearer/.test(san),
            "the SAML card's certificate has SAN " + san);
          assert.ok(san.indexOf("urn:sts:person:" + OWNER) >= 0,
            "the SAML card's certificate does not name " + OWNER + ": " + san);
        });

  const samlSelf = await samlGrant(OWNER, OWNER, samlPem);
  check("**THE SAML PRIVATE KEY READ OFF THE PAGE OBTAINS AN ACCESS TOKEN** " +
        "at /oauth2/token as its own holder", function () {
          assert.strictEqual(samlSelf.status, 200,
            JSON.stringify(samlSelf.body).slice(0, 400));
          assert.strictEqual(claimsOf(samlSelf.body.access_token).username,
                             OWNER);
        });
  const samlOther = await samlGrant(OWNER, OTHER, samlPem);
  check("and obtains nothing as anybody else: a <Subject> naming another " +
        "person is refused", function () {
          refused(samlOther, "invalid_grant",
                  "an RFC 7522 assertion about somebody else");
        });
  const samlWithJwtKey = await samlGrant(OWNER, OWNER, jwtPem);
  const jwtWithSamlKey = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: jwtKid },
      { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, samlPem) });
  check("**NEITHER KEY SIGNS FOR THE OTHER PROFILE** — a SAML assertion " +
        "signed with the RFC 7523 key and a JWT signed with the RFC 7522 key " +
        "are both refused", function () {
          refused(samlWithJwtKey, "invalid_grant",
                  "a SAML assertion signed with the JWT key");
          refused(jwtWithSamlKey, "invalid_grant",
                  "a JWT signed with the SAML key");
        });
  const afterSaml = await pageOf(b, "/portal/signing-key");
  check("the SAML private key is not on the page again either", function () {
    assert.strictEqual(privateKeyOn(afterSaml.text), "",
      "a private key block is still on the page");
    assert.strictEqual(thumbprintOn(afterSaml.text), thumbprint);
  });

  const badPurpose = await act(b, "/portal/signing-key",
                               { action: "generate", purpose: "kerberos" });
  check("a profile this page does not know is refused 400 at the form's " +
        "shape, and issues nothing", function () {
          assert.strictEqual(badPurpose.status, 400,
            "it answered " + badPurpose.status);
          assert.strictEqual(privateKeyOn(badPurpose.text), "",
            "a key came back for an unknown profile");
        });

  const samlRemoved = await act(b, "/portal/signing-key",
                                { action: "revoke", purpose: "saml",
                                  handle: thumbprint,
                                  reason: "cessationOfOperation" });
  const samlGone = await samlGrant(OWNER, OWNER, samlPem);
  const jwtStill = await tokenRequest({ grant_type: GRANT,
    assertion: signJws({ alg: "RS256", typ: "JWT", kid: jwtKid },
      { iss: OWNER, sub: OWNER, aud: TOKEN_ENDPOINT, iat: now(),
        exp: now() + 120, jti: jti() }, jwtPem) });
  check("**REVOKING THE RFC 7522 KEY LEAVES THE RFC 7523 ONES WORKING** — " +
        "the SAML key is refused from that moment and the JWT key still " +
        "obtains a token", function () {
          assert.strictEqual(samlRemoved.status, 200,
            "the revoke answered " + samlRemoved.status);
          assert.ok(/RFC 7522/.test(samlRemoved.said),
            "the message does not name the profile: " + samlRemoved.said);
          refused(samlGone, "invalid_grant",
                  "an assertion signed with the revoked SAML key");
          assert.strictEqual(jwtStill.status, 200,
            JSON.stringify(jwtStill.body).slice(0, 300));
        });
  const nothingLeft = await act(b, "/portal/signing-key",
                                { action: "revoke", purpose: "saml",
                                  handle: jwtKid });
  check("and a SAML revoke naming a JWT kid is refused 400 naming the " +
        "profile — the two sets share nothing — while the page still shows " +
        "the RFC 7523 key and the RFC 7522 one as revoked", function () {
          assert.strictEqual(nothingLeft.status, 400);
          assert.ok(/no RFC 7522 signing key/.test(nothingLeft.said),
            nothingLeft.said);
          assert.strictEqual(kidOn(nothingLeft.text), jwtKid);
          assert.strictEqual(stateOn(nothingLeft.text, "saml", thumbprint),
                             "revoked");
        });

  // -------------------------------------------------------------------------
  // 9. A TLS CLIENT CERTIFICATE (2026-09-13), the third card on this page.
  //
  //    What is asserted here is the PORTAL: the files arrive once, on the
  //    response to the POST, and are what they say they are; a mismatched file
  //    password and a missing CSRF token issue nothing; one person cannot
  //    revoke another's certificate by naming its serial; the holder can. The
  //    HANDSHAKE — the holder signed in, in their realm, and signed in no
  //    longer once the certificate is revoked — is
  //    `tests/tls_client_certificates.js`. It was 9443 there, and the reason
  //    it was not here was that no launcher publishes 9443 to a job. **That
  //    reason expired on 2026-09-16**, when 8443 and 9443 were deleted and the
  //    sign-in became `GET /tls/sign-in` on the BASE URL every job already
  //    holds — so this could now be asserted here as well, over a handshake a
  //    launcher's own stack made. It is not yet, and that is the gap rather
  //    than a decision.
  // -------------------------------------------------------------------------
  log.info("=== 9. a TLS client certificate ===");
  const tlsPage = await pageOf(b, "/portal/signing-key");
  check("the page carries a TLS client certificate card with a generate form " +
        "that asks for NO file password (#671)", function () {
          assert.ok(/id="tls-client"/.test(tlsPage.text),
            "no TLS client certificate card on the page");
          assert.ok(/name="action" value="generate-tls-client"/.test(
            tlsPage.text), "the generate form is not on the page");
          assert.ok(!/name="p12_password"|name="p12_confirm"/.test(
            tlsPage.text), "the form still asks for a file password");
          assert.ok(/You have no TLS client certificate/.test(tlsPage.text),
            "the card does not say none is held");
        });
  const withPassword = await act(b, "/portal/signing-key",
    { action: "generate-tls-client", label: "laptop",
      p12_password: "a file password" });
  check("a body still carrying a file password is refused 400 at the form's " +
        "shape and nothing is issued — the field is gone, not ignored",
        function () {
          assert.strictEqual(withPassword.status, 400,
            "it answered " + withPassword.status);
          assert.ok(!dataLink(withPassword.text, "-key.pem",
                              "application/x-pem-file"),
            "a key file came back anyway");
        });
  const noTokenTls = await fetch(base + "/account-api/signing-key", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "generate-tls-client" }) });
  const noTokenText = await noTokenTls.text();
  check("a generate with no access token is refused 401 and issues nothing " +
        "(it was the CSRF check until #568)", function () {
          assert.strictEqual(noTokenTls.status, 401,
            "it answered " + noTokenTls.status);
          assert.ok(!/x-pem-file/i.test(noTokenText), "a file came back");
        });
  const tlsIssued = await act(b, "/portal/signing-key",
    { action: "generate-tls-client", label: "laptop", key_alg: "ec-p256" });
  const keyFile = dataLink(tlsIssued.text, "-key.pem",
                           "application/x-pem-file");
  const chainFile = dataLink(tlsIssued.text, "-chain.pem",
                             "application/x-pem-file");
  check("**THE POST ANSWERS WITH THE TWO FILES**, no-store, as download " +
        "links in the new certificate's own row, and NO PKCS#12 (#671)",
        function () {
          assert.strictEqual(tlsIssued.status, 200,
            "it answered " + tlsIssued.status + " " +
            String(tlsIssued.text).slice(0, 400));
          assert.ok(keyFile && chainFile,
            "the two download links are not both on the page");
          assert.ok(!/\.p12"/.test(tlsIssued.text),
            "a PKCS#12 is still offered");
          const row = (String(tlsIssued.text)
            .match(/<tr class="fresh-row">[\s\S]*?<\/tr>/) || [""])[0];
          assert.ok(row.indexOf(keyFile.name) >= 0 &&
                    row.indexOf(chainFile.name) >= 0,
            "the downloads are not in the certificate's row");
          assert.ok(/no-store/.test(
            String(tlsIssued.headers.get("cache-control") || "")));
          assert.ok(/curl --cert /.test(tlsIssued.text),
            "the page does not say how to use the files");
          assert.ok(/only time these files can be downloaded/.test(
            tlsIssued.text), "the page does not say the files are shown once");
        });
  const chainText = chainFile ? chainFile.bytes.toString("utf8") : "";
  const leafPem = (/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/
    .exec(chainText) || [""])[0];
  const tlsLeaf = leafPem ? new nodeCrypto.X509Certificate(leafPem) : null;
  check("the chain file's leaf is a TLS client certificate for this person " +
        "and nobody else: clientAuth, their CN and their urn:sts:person: name",
        function () {
          assert.ok(tlsLeaf, "the chain file holds no certificate");
          assert.ok((tlsLeaf.keyUsage || []).indexOf("1.3.6.1.5.5.7.3.2") >= 0,
            "no clientAuth: " + JSON.stringify(tlsLeaf.keyUsage));
          assert.ok(new RegExp("(^|\\n)CN=" + OWNER + "(\\n|$)")
            .test(tlsLeaf.subject), tlsLeaf.subject);
          assert.ok(String(tlsLeaf.subjectAltName).indexOf(
            "URI:urn:sts:person:" + OWNER) >= 0, tlsLeaf.subjectAltName);
          assert.strictEqual(chainText.split("BEGIN CERTIFICATE").length - 1,
                             3,
                             "the chain file is not the leaf and two " +
                             "issuers");
        });
  check("the key file is an UNENCRYPTED PKCS#8 block (#671: no file " +
        "password) and holds the certificate's key", function () {
          const keyText = keyFile.bytes.toString("utf8");
          assert.ok(/-----BEGIN PRIVATE KEY-----/.test(keyText) &&
                    !/ENCRYPTED/.test(keyText),
            "the key file is not an unencrypted PKCS#8 block");
          const opened = nodeCrypto.createPrivateKey({ key: keyText,
            format: "pem" });
          assert.ok(nodeCrypto.createPublicKey(opened)
            .export({ type: "spki", format: "der" })
            .equals(tlsLeaf.publicKey.export({ type: "spki", format: "der" })),
            "the key in the file is not the certificate's");
        });
  const tlsSerial = tlsLeaf ? String(tlsLeaf.serialNumber).toLowerCase() : "";
  const tlsListed = await pageOf(b, "/portal/signing-key");
  check("afterwards the page lists it as valid and offers the files NO MORE",
        function () {
          assert.ok(tlsListed.text.toLowerCase()
                      .indexOf(tlsSerial.slice(-16)) >= 0,
                    "the serial is not listed");
          assert.ok(/class="state-valid">valid/.test(tlsListed.text),
            "it is not listed as valid");
          assert.ok(!dataLink(tlsListed.text, "-key.pem",
                              "application/x-pem-file"),
            "the key file is still on the page");
        });
  const otherBrowser = await signIn("/portal/signing-key", OTHER);
  const otherPage = await pageOf(otherBrowser, "/portal/signing-key");
  const otherRevoke = await act(otherBrowser, "/portal/signing-key",
    { action: "revoke-tls-client", serial: tlsSerial,
      reason: "keyCompromise" });
  const ownerStill = await pageOf(b, "/portal/signing-key");
  check("**ANOTHER PERSON NAMING THE SERIAL REVOKES NOTHING** — refused 400, " +
        "and the holder's certificate is still valid", function () {
          assert.ok(otherPage.text.toLowerCase().indexOf(tlsSerial.slice(-16)) <
                    0, "the other person's page lists the owner's certificate");
          assert.strictEqual(otherRevoke.status, 400,
            "it answered " + otherRevoke.status);
          assert.ok(/class="state-valid">valid/.test(ownerStill.text),
            "the owner's certificate is no longer valid");
        });
  const ownRevoke = await act(b, "/portal/signing-key",
    { action: "revoke-tls-client", serial: tlsSerial,
      reason: "cessationOfOperation" });
  const afterRevoke = await pageOf(b, "/portal/signing-key");
  check("the holder revokes it: a message saying so, and the page lists it " +
        "as revoked with no Revoke button left on it", function () {
          assert.strictEqual(ownRevoke.status, 200,
            "it answered " + ownRevoke.status + " " +
            String(ownRevoke.text).slice(0, 300));
          assert.ok(/class="state-revoked">revoked/.test(afterRevoke.text),
            "it is not listed as revoked");
          assert.ok(!/name="action" value="revoke-tls-client"/.test(
            afterRevoke.text), "a Revoke button is still drawn");
        });

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure a suite cannot report about itself.
  assert.ok(checks >= 40,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_portal_signing_key")
  .description("/portal/signing-key: a person issues themselves an RFC 7523 " +
      "key pair, the private half is offered once on the page that comes " +
      "back, " +
      "it obtains an access token as them at /oauth2/token and obtains " +
      "nothing as anybody else, it never appears again, a post with no " +
      "access token is refused, a username in the body changes nothing, " +
      "generating " +
      "replaces and taking it off stops it being accepted; and the same " +
      "for an RFC 7522 key pair beside it, which signs no JWT, is signed " +
      "for by no JWT key, and comes off alone; and a TLS client certificate " +
      "downloaded once as a PKCS#12 and PEM files, refused on a mismatched " +
      "file password or no access token, revocable by its holder and by " +
      "nobody " +
      "else.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
