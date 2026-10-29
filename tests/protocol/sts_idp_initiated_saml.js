// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// WHO MAY START A SAML SIGN-IN, OVER THE WIRE, IN PRODUCT (#715).
//
// `tests/saml_initiation.js` holds #711's contract in process, against a
// child process in DEVELOPMENT mode, and reads each error code off the
// server's own response object. This job is the same contract over HTTP,
// written so that it passes in PRODUCT, because the suite runs it in
// `memory` (development), `single-node` and `cluster` (both product on
// postgres; `cluster` is several nodes behind one address). Two requests in
// a row may land on two nodes there, and that is the point: the session, the
// held request and the setting a step reads were written by another node.
//
//   A. SAML 2.0, /saml2/unsolicited. A registered service provider with no
//      override is REFUSED, 403, with no sign-in screen first, with and
//      without a session. One whose entry sets saml2IdpInitiatedSso TRUE
//      sends a browser with no session to the sign-in screen, and once the
//      person has signed in there with their password is answered with an
//      unsolicited Response: Success, no InResponseTo, Destination the
//      registered ACS, the target as RelayState. The person's logout
//      inventory (`GET /logout?format=json`, the JSON door of
//      logout/CLAUDE.md) then names that service provider in its
//      `saml2-sp` family, and not the refused one — the session's
//      `saml2ServiceProviders`, which /logout and back-channel logout read.
//      The realm setting `saml2.idpInitiatedSso` on (through
//      `/admin-api/config/set`) answers the service provider whose entry
//      says nothing, and once it is reset that one is refused again.
//   B. SAML 2.0, an AuthnRequest. From a service provider whose entry sets
//      saml2SpInitiatedSso FALSE: a RequestDenied Response naming the
//      request, with no sign-in screen. Another service provider's request
//      is still answered.
//   C. SAML 1.1, /saml11/sso/{rp}. A link with only a TARGET is refused by
//      default (403, no screen) and answered with saml11IdpInitiatedSso
//      TRUE, after which the inventory lists the SAML 1.1 assertion issued
//      for that relying party (its `issued` family: SAML 1.1 has no Single
//      Logout, so `saml11RelyingParties` reaches no family of its own). A
//      request carrying `shire` is answered by default and refused with
//      saml11SpInitiatedSso FALSE.
//   E. The mechanism re-prompt on /saml2/unsolicited (#457), set up through
//      `appAuthnMechanism` on the entry: a session signed in on a password,
//      for a service provider that allows only `webauthn`, is sent to sign
//      in again; back from that one trip (`reprompted=1`) still on a
//      password, it is answered RequestDenied rather than sent round again.
//
// NOT HERE, AND WHY: section D of the in-process file, the step-up on risk.
// A session's risk comes from the sign-in's assessment over datasets the
// suite does not load, so nothing over HTTP can hold a session at MEDIUM.
// `tests/saml_initiation.js` runs D a second time in product mode instead.
// And the error codes (STS-SAML-0091, 0111, 0113, 0114, 0099, 0100): they
// are recorded and never sent, so a client cannot read them; this asserts
// what a client sees.
//
// WHAT PRODUCT ASKS, AND HOW THIS PAYS IT: every application and the person
// are created by this run through `/admin-api` with unique names; each
// application registers its entity ID, its assertion consumer service and
// (for SAML 2.0) the signing certificate its AuthnRequests are signed with,
// because product delivers only to a registered address and refuses an
// unsigned AuthnRequest; and the person has a real password and signs in
// with it at the sign-in screen, because product checks it.
//
// IN A REALM OF ITS OWN, left standing (tests/CLAUDE.md, *No job removes a
// realm*), created with no mode override so it runs in the process's mode:
// the realm setting A turns on then reaches no other job, and every
// application and person here is one this run made (*Start from a known
// state*).
//
// OWNED HERE (local: true).
// ===========================================================================

"use strict";

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
const zlib = require("zlib");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");

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
var log = bunyan.createLogger({ name: "sts_idp_initiated_saml",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp();
const REALM = ("sii-" + STAMP).replace(/[^a-z0-9-]/g, "").slice(0, 30);
const PERSON = names.usernameFor("sii-person");
// At least twelve characters with every class, which any password policy
// this service ships accepts; unique per run.
const PASSWORD = "sii-Initiation-Passw0rd!-" + STAMP.slice(-6);
const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
// How long a read that another node's write must reach is retried in
// `cluster`, where a session's change or a setting reaches the other nodes
// through the store. In one process the first read is the answer.
const SETTLE_MS = 15000;

let checks = 0;
const failures = [];

async function check(what, fn) {
  log.debug("Entering check(). " + what);
  try {
    await fn();
    checks += 1;
    log.info("  ✓ " + what);
  } catch (e) {
    log.debug("Caught in check(): " + ((e && e.message) || e));
    failures.push(what + " — " + ((e && e.message) || e));
    log.error("  ✗ " + what + "  — " + ((e && e.message) || e));
  }
  log.debug("Leaving check().");
}

function must(condition, message) {
  log.debug("Entering must().");
  if (!condition) {
    log.debug("Leaving must(). Refused.");
    throw new Error("SETUP: " + message);
  }
  log.debug("Leaving must().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// Asks `probe` until `done(answer)` holds or SETTLE_MS has passed, and
// answers the last answer either way: the check after it is what fails.
async function eventually(probe, done) {
  log.debug("Entering eventually().");
  const started = Date.now();
  let answer = await probe();
  while (!done(answer) && Date.now() - started < SETTLE_MS) {
    await sleep(500);
    answer = await probe();
  }
  log.debug("Leaving eventually(). " + (Date.now() - started) + "ms");
  return answer;
}

function realmBase() {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + REALM;
}

// An application's identifier, and the addresses registered on its entry.
// Nothing listens at any of them: each is read, never followed.
function nameFor(label) {
  log.debug("Entering nameFor().");
  log.debug("Leaving nameFor().");
  return "https://" + label + "-" + STAMP + ".idp-initiated.test/sp";
}

function acsOf(identifier) {
  log.debug("Entering acsOf().");
  log.debug("Leaving acsOf().");
  return identifier.replace(/\/sp$/, "/acs");
}

// The management API in the realm named, or the default realm's for null;
// the run's token is attached by tests/tools/attach-admin-token.js.
async function api(realm, method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = { method: method, redirect: "manual", headers: {} };
  if (payload !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const prefix = realm ? base + "/realm/" + realm : base;
  const r = await fetch(prefix + "/admin-api" + path, options);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; `text` carries the answer into every message quoting it.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

// ---------------------------------------------------------------------------
// A COOKIE JAR, and one request with one body read — sts_global_logout.js's
// harness.
// ---------------------------------------------------------------------------
function jar() {
  log.debug("Entering jar().");
  const store = {};
  log.debug("Leaving jar().");
  return {
    header: function () {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(store).map(function (k) {
        return k + "=" + store[k];
      }).join("; ");
    },
    take: function (res) {
      log.debug("Entering take().");
      (res.headers.getSetCookie ? res.headers.getSetCookie() : []).forEach(
        function (line) {
          const pair = line.split(";")[0];
          const i = pair.indexOf("=");
          store[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
        });
      log.debug("Leaving take().");
    },
    has: function () {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return Object.keys(store).length > 0;
    }
  };
}

async function hop(cookies, url, options) {
  log.debug("Entering hop().");
  const o = Object.assign({ redirect: "manual", headers: {} }, options || {});
  if (cookies && cookies.has()) {
    o.headers.cookie = cookies.header();
  }
  const r = await fetch(url, o);
  if (cookies) {
    cookies.take(r);
  }
  const body = r.status >= 300 && r.status < 400 ? "" : await r.text();
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, location: r.headers.get("location") || "",
           body: body, url: url };
}

// Follows redirects until the browser would LEAVE this service, and
// answers the last response and where it was going.
async function follow(cookies, url) {
  log.debug("Entering follow().");
  const origin = new URL(base).origin;
  let r = await hop(cookies, url);
  for (let n = 0; r.status >= 300 && r.status < 400 && n < 12; n += 1) {
    if (!r.location) {
      break;
    }
    const next = new URL(r.location, r.url).toString();
    if (new URL(next).origin !== origin) {
      log.debug("Leaving follow(). Leaving the service.");
      return { r: r, landed: next };
    }
    r = await hop(cookies, next);
  }
  log.debug("Leaving follow().");
  return { r: r, landed: r.url };
}

// THE SIGN-IN SCREEN, answered with the person's password where it is
// drawn, and the flow followed from where its answer says — the shell of
// the static surface since #571, through the one helper.
async function throughTheScreen(cookies, started) {
  log.debug("Entering throughTheScreen().");
  let done = started;
  if (/\/authn\/signin\.js/.test(started.r.body || "")) {
    const answer = await authnSignin.signIn(realmBase(), started.r.url,
      { action: "login", username: PERSON, password: PASSWORD },
      { cookie: cookies.has() ? cookies.header() : "" });
    cookies.take({ headers: answer.headers });
    if (answer.next !== "redirect") {
      log.debug("Leaving throughTheScreen(). " + answer.next);
      return { r: { status: answer.status, location: "",
                    body: JSON.stringify(answer.json), url: started.r.url },
               landed: started.r.url, refused: answer };
    }
    done = await follow(cookies, answer.location);
  }
  log.debug("Leaving throughTheScreen().");
  return done;
}

// The SAML message in a self-submitting form, decoded. The form escapes
// `+` in the base64.
function messageOf(body, field) {
  log.debug("Entering messageOf().");
  const m = new RegExp('name="' + (field || "SAMLResponse") +
                       '" value="([^"]+)"').exec(String(body || ""));
  log.debug("Leaving messageOf().");
  return m ? Buffer.from(m[1].replace(/&#x2B;|&#43;/g, "+"), "base64")
    .toString("utf8") : "";
}

function fieldOf(body, field) {
  log.debug("Entering fieldOf().");
  const m = new RegExp('name="' + field + '" value="([^"]*)"')
    .exec(String(body || ""));
  log.debug("Leaving fieldOf().");
  return m ? m[1].replace(/&amp;/g, "&").replace(/&#x2F;|&#47;/g, "/")
    .replace(/&#x3D;|&#61;/g, "=") : null;
}

function brief(r) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return "HTTP " + r.status + (r.location ? " -> " + r.location : "") + " " +
         String(r.body || "").replace(/\s+/g, " ").slice(0, 240);
}

// ---------------------------------------------------------------------------
// THE SERVICE PROVIDERS SIGN THEIR AUTHNREQUESTS, as sts_global_logout.js's
// do: a product-mode service refuses an unsigned one
// (saml2.requireSignedAuthnRequests), so every SAML 2.0 application here
// registers this run's certificate and B's requests are signed on the HTTP
// Redirect binding (saml-bindings-2.0-os section 3.4.4.1).
// ---------------------------------------------------------------------------
let spCredential = null;

function samlSpCredential() {
  log.debug("Entering samlSpCredential().");
  if (!spCredential) {
    const forge = require("node-forge");
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
    cert.validity.notBefore = new Date(Date.now() - 60000);
    cert.validity.notAfter = new Date(Date.now() + 3600 * 1000);
    const subject = [{ name: "commonName", value: "idp-initiated SP" }];
    cert.setSubject(subject);
    cert.setIssuer(subject);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    spCredential = {
      certificatePem: forge.pki.certificateToPem(cert),
      privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey) };
  }
  log.debug("Leaving samlSpCredential().");
  return spCredential;
}

// A signed AuthnRequest from `issuer` on the HTTP Redirect binding, and its
// ID, which the Response must name in InResponseTo. A SIGNED message carries
// its Destination — the endpoint it is sent to, here the realm's
// /saml2/sso — because saml-bindings-2.0-os section 3.4.5.2 requires it, and
// the service refuses one without it (STS-SAML-0085, a 400 page: a request
// whose signature cannot be said to be about this endpoint is not yet
// attributed to any service provider, so there is no one to answer).
function authnRequestUrl(issuer) {
  log.debug("Entering authnRequestUrl().");
  const id = "_sii" + nodeCrypto.randomBytes(10).toString("hex");
  const endpoint = realmBase() + "/saml2/sso";
  const xml = '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '" ' +
    'Destination="' + endpoint + '" ' +
    'AssertionConsumerServiceURL="' + acsOf(issuer) + '" ' +
    'ProtocolBinding="' + BINDING_POST + '">' +
    '<saml:Issuer>' + issuer + '</saml:Issuer></samlp:AuthnRequest>';
  const sigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const signed = "SAMLRequest=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64")) +
    "&RelayState=" + encodeURIComponent("sii") +
    "&SigAlg=" + encodeURIComponent(sigAlg);
  const signature = nodeCrypto.sign("sha256", Buffer.from(signed),
    samlSpCredential().privateKeyPem).toString("base64");
  log.debug("Leaving authnRequestUrl().");
  return { id: id, url: endpoint + "?" + signed +
                        "&Signature=" + encodeURIComponent(signature) };
}

function unsolicited(sp, extra) {
  log.debug("Entering unsolicited().");
  log.debug("Leaving unsolicited().");
  return realmBase() + "/saml2/unsolicited?" + new URLSearchParams(
    Object.assign({ providerId: sp, target: "rs-" + STAMP }, extra || {}))
    .toString();
}

function sso11(rp, extra) {
  log.debug("Entering sso11().");
  log.debug("Leaving sso11().");
  return realmBase() + "/saml11/sso/" + encodeURIComponent(rp) + "?" +
    new URLSearchParams(Object.assign({
      TARGET: "https://app.idp-initiated.test/" + STAMP }, extra || {}))
      .toString();
}

// The person's logout inventory, through the JSON door, as the session the
// jar holds sees it (logout/CLAUDE.md).
async function inventory(cookies) {
  log.debug("Entering inventory().");
  const r = await hop(cookies, realmBase() + "/logout?format=json",
                      { headers: { accept: "application/json" } });
  let body = null;
  try {
    body = JSON.parse(r.body);
  } catch (e) {
    log.debug("Caught in inventory(): " + ((e && e.message) || e));
    // Not JSON: the check reads the status and the text instead.
    body = null;
  }
  log.debug("Leaving inventory(). " + r.status);
  return { status: r.status, body: body, text: r.body };
}

function rowsOf(held, family) {
  log.debug("Entering rowsOf(). " + family);
  const one = ((held.body && held.body.families) || []).filter(function (f) {
    return f.id === family;
  })[0];
  log.debug("Leaving rowsOf().");
  return (one && one.rows) || [];
}

// ---------------------------------------------------------------------------
// SETTING THE WORLD UP, before anybody signs in.
// ---------------------------------------------------------------------------
async function createApplication(identifier, protocol, fields) {
  log.debug("Entering createApplication(). " + identifier);
  const registered = { samlEntityId: [identifier],
                       samlAssertionConsumerService: [acsOf(identifier)] };
  if (protocol === "saml2") {
    registered.samlSigningCertificate = [samlSpCredential().certificatePem];
  }
  const r = await api(REALM, "POST", "/applications/create",
    { identifier: identifier, name: "idp-initiated " + identifier,
      protocols: [protocol],
      fields: Object.assign(registered, fields || {}) });
  must(r.status === 200 && r.body && r.body.ok,
       "creating the application " + identifier + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createApplication().");
  return identifier;
}

async function setUp() {
  log.debug("Entering setUp().");
  const made = await api(null, "POST", "/realms/create",
    { id: REALM, domain: REALM + ".example.net",
      name: "identity-provider-initiated SAML " + STAMP });
  must(made.status === 200 ||
       /already/i.test(JSON.stringify(made.body || made.text)),
       "creating the realm " + REALM + " answered " + made.status + " " +
       made.text.slice(0, 300));
  const person = await api(REALM, "POST", "/users/create", {
    username: PERSON, invent: false,
    attributes: { cn: "Initiation " + PERSON, givenName: "Initiation",
                  sn: PERSON, displayName: "Initiation " + PERSON,
                  mail: PERSON + "@" + REALM + ".example.net" },
    credential: "password", password: PASSWORD });
  must(person.status === 200 && person.body && person.body.ok &&
       !person.body.credentialError,
       "creating " + PERSON + " with a password answered " + person.status +
       " " + person.text.slice(0, 300));
  // Said, not asserted: the job is the same in either mode.
  const mode = await facts.setting(realmBase() + "/admin-api", "global.mode");
  log.info("The realm " + REALM + " runs in " + String(mode) + " mode.");
  // THE PASSKEY-ONLY SERVICE PROVIDER'S MECHANISMS are a named
  // authentication policy's since #1148, made in the realm first.
  const passkeyOnly = await api(REALM, "POST",
    "/policies/save-named-authn-policy",
    { name: "passkey-only", mechanisms: ["webauthn"] });
  must(passkeyOnly.status === 200 && passkeyOnly.body && passkeyOnly.body.ok,
       "saving the named authentication policy answered " +
       passkeyOnly.status + " " + passkeyOnly.text.slice(0, 300));
  const w = {
    spOff: await createApplication(nameFor("sp-default"), "saml2"),
    spOn: await createApplication(nameFor("sp-idp-on"), "saml2",
                                  { saml2IdpInitiatedSso: "TRUE" }),
    spClosed: await createApplication(nameFor("sp-sp-off"), "saml2",
                                      { saml2SpInitiatedSso: "FALSE" }),
    spMech: await createApplication(nameFor("sp-mech"), "saml2",
                                    { saml2IdpInitiatedSso: "TRUE",
                                      appAuthnPolicy: "passkey-only" }),
    rpOff: await createApplication(nameFor("rp-default"), "saml11"),
    rpOn: await createApplication(nameFor("rp-idp-on"), "saml11",
                                  { saml11IdpInitiatedSso: "TRUE" }),
    rpClosed: await createApplication(nameFor("rp-sp-off"), "saml11",
                                      { saml11SpInitiatedSso: "FALSE" }),
    cookies: jar()
  };
  log.debug("Leaving setUp().");
  return w;
}

// ---------------------------------------------------------------------------
// A. SAML 2.0, IDENTITY-PROVIDER-INITIATED.
// ---------------------------------------------------------------------------
async function sectionA(w) {
  log.debug("Entering sectionA().");
  log.info("=== A. SAML 2.0, /saml2/unsolicited ===");
  const refused = await hop(null, unsolicited(w.spOff));
  await check("A1. a registered service provider with no override is " +
              "REFUSED by default — 403, and no sign-in screen first",
              async function () {
    assert.strictEqual(refused.status, 403, brief(refused));
    assert.ok(!refused.location, brief(refused));
    assert.ok(!/SAMLResponse|signin\.js/.test(refused.body), brief(refused));
  });

  const toScreen = await hop(w.cookies, unsolicited(w.spOn));
  await check("A2. one whose entry sets saml2IdpInitiatedSso TRUE sends a " +
              "browser with no session to the sign-in screen",
              async function () {
    assert.ok(toScreen.status === 303 || toScreen.status === 302,
              brief(toScreen));
    assert.ok(/\/authn\/login\?/.test(toScreen.location), brief(toScreen));
  });
  const started = await follow(w.cookies, unsolicited(w.spOn));
  const signedIn = await throughTheScreen(w.cookies, started);
  const first = messageOf(signedIn.r.body);
  await check("A3. signed in there with the person's PASSWORD, the link " +
              "is answered with an UNSOLICITED Response — Success, no " +
              "InResponseTo, at the registered ACS, the target as " +
              "RelayState", async function () {
    assert.ok(!signedIn.refused, "the sign-in screen refused: " +
              JSON.stringify((signedIn.refused || {}).json || "")
                .slice(0, 300));
    assert.strictEqual(signedIn.r.status, 200, brief(signedIn.r));
    assert.ok(/<samlp:Response\b/.test(first), first.slice(0, 300));
    assert.ok(/StatusCode Value="[^"]*:Success"/.test(first),
              first.slice(0, 400));
    assert.ok(!/InResponseTo=/.test(first), "an InResponseTo was sent");
    assert.ok(first.indexOf('Destination="' + acsOf(w.spOn) + '"') >= 0,
              first.slice(0, 400));
    assert.strictEqual(fieldOf(signedIn.r.body, "RelayState"),
                       "rs-" + STAMP);
  });

  const again = await hop(w.cookies, unsolicited(w.spOn));
  const second = messageOf(again.body);
  await check("A4. with the session, the link is answered at once — no " +
              "screen", async function () {
    assert.strictEqual(again.status, 200, brief(again));
    assert.ok(/StatusCode Value="[^"]*:Success"/.test(second),
              second.slice(0, 400));
    assert.ok(!/InResponseTo=/.test(second), "an InResponseTo was sent");
  });
  const stillRefused = await hop(w.cookies, unsolicited(w.spOff));
  await check("A5. and the service provider that did not opt in is still " +
              "refused with a session — 403", async function () {
    assert.strictEqual(stillRefused.status, 403, brief(stillRefused));
    assert.ok(!/SAMLResponse/.test(stillRefused.body), brief(stillRefused));
  });

  const held = await eventually(function () {
    return inventory(w.cookies);
  }, function (answer) {
    return rowsOf(answer, "saml2-sp").some(function (row) {
      return row.label === w.spOn;
    });
  });
  await check("A6. the person's logout inventory names that service " +
              "provider in its saml2-sp family, and not the refused one",
              async function () {
    assert.strictEqual(held.status, 200, held.text.slice(0, 300));
    const labels = rowsOf(held, "saml2-sp").map(function (row) {
      return row.label;
    });
    assert.ok(labels.indexOf(w.spOn) >= 0, JSON.stringify(labels));
    assert.ok(labels.indexOf(w.spOff) < 0, JSON.stringify(labels));
  });

  // THE REALM SETTING, on for the realm and put back with `reset` in a
  // finally (tests/CLAUDE.md, *Restore a setting with reset*), the second
  // half asserting it was.
  const set = await api(REALM, "POST", "/config/set",
                        { key: "saml2.idpInitiatedSso", value: true });
  try {
    must(set.status === 200 && set.body && set.body.ok !== false,
         "setting saml2.idpInitiatedSso answered " + set.status + " " +
         set.text.slice(0, 300));
    const realmOn = await eventually(function () {
      return hop(w.cookies, unsolicited(w.spOff));
    }, function (answer) {
      return answer.status === 200;
    });
    await check("A7. the realm setting saml2.idpInitiatedSso on answers a " +
                "service provider whose entry says nothing",
                async function () {
      assert.strictEqual(realmOn.status, 200, brief(realmOn));
      assert.ok(/StatusCode Value="[^"]*:Success"/.test(
        messageOf(realmOn.body)), brief(realmOn));
    });
  } finally {
    const reset = await api(REALM, "POST", "/config/reset",
                            { key: "saml2.idpInitiatedSso" });
    if (reset.status !== 200) {
      log.error("saml2.idpInitiatedSso was not reset in " + REALM + ": " +
                reset.status + " " + reset.text.slice(0, 200));
    }
  }
  const realmOff = await eventually(function () {
    return hop(w.cookies, unsolicited(w.spOff));
  }, function (answer) {
    return answer.status === 403;
  });
  await check("A8. reset, that service provider is refused again",
              async function () {
    assert.strictEqual(realmOff.status, 403, brief(realmOff));
  });
  log.debug("Leaving sectionA().");
}

// ---------------------------------------------------------------------------
// B. SAML 2.0, SERVICE-PROVIDER-INITIATED.
// ---------------------------------------------------------------------------
async function sectionB(w) {
  log.debug("Entering sectionB().");
  log.info("=== B. SAML 2.0, an AuthnRequest ===");
  const closed = authnRequestUrl(w.spClosed);
  const denied = await follow(jar(), closed.url);
  const deniedXml = messageOf(denied.r.body);
  await check("B1. an AuthnRequest from a service provider whose entry " +
              "sets saml2SpInitiatedSso FALSE is answered RequestDenied, " +
              "naming the request — with no sign-in screen",
              async function () {
    assert.strictEqual(denied.r.status, 200, brief(denied.r));
    assert.ok(!/signin\.js/.test(denied.r.body), brief(denied.r));
    assert.ok(/status:RequestDenied"/.test(deniedXml),
              deniedXml.slice(0, 400));
    assert.ok(deniedXml.indexOf('InResponseTo="' + closed.id + '"') >= 0,
              deniedXml.slice(0, 400));
  });
  const open = authnRequestUrl(w.spOn);
  const answered = await follow(w.cookies, open.url);
  const answeredXml = messageOf(answered.r.body);
  await check("B2. another service provider's request is answered — " +
              "service-provider-initiated is on by default",
              async function () {
    assert.strictEqual(answered.r.status, 200, brief(answered.r));
    assert.ok(/StatusCode Value="[^"]*:Success"/.test(answeredXml),
              answeredXml.slice(0, 400));
    assert.ok(answeredXml.indexOf('InResponseTo="' + open.id + '"') >= 0,
              answeredXml.slice(0, 400));
  });
  log.debug("Leaving sectionB().");
}

// ---------------------------------------------------------------------------
// C. SAML 1.1.
// ---------------------------------------------------------------------------
async function sectionC(w) {
  log.debug("Entering sectionC().");
  log.info("=== C. SAML 1.1, /saml11/sso/{rp} ===");
  const refused = await hop(null, sso11(w.rpOff));
  await check("C1. a link with only a TARGET, for a relying party that did " +
              "not opt in, is REFUSED by default — 403, no sign-in screen",
              async function () {
    assert.strictEqual(refused.status, 403, brief(refused));
    assert.ok(!refused.location, brief(refused));
    assert.ok(!/SAMLResponse/.test(refused.body), brief(refused));
  });
  const opted = await follow(w.cookies, sso11(w.rpOn));
  await check("C2. answered for one whose entry sets saml11IdpInitiatedSso " +
              "TRUE", async function () {
    assert.strictEqual(opted.r.status, 200, brief(opted.r));
    assert.ok(/name="SAMLResponse"/.test(opted.r.body), brief(opted.r));
    assert.ok(/name="TARGET"/.test(opted.r.body), brief(opted.r));
  });
  const held = await eventually(function () {
    return inventory(w.cookies);
  }, function (answer) {
    return rowsOf(answer, "issued").some(function (row) {
      return /SAML 1\.1/.test(String(row.kind || "")) &&
             String(row.detail || "").indexOf("for " + w.rpOn) >= 0;
    });
  });
  await check("C3. and the person's logout inventory lists the SAML 1.1 " +
              "assertion issued for that relying party", async function () {
    assert.strictEqual(held.status, 200, held.text.slice(0, 300));
    const rows = rowsOf(held, "issued").filter(function (row) {
      return /SAML 1\.1/.test(String(row.kind || ""));
    }).map(function (row) {
      return row.detail;
    });
    assert.ok(rows.some(function (detail) {
      return String(detail).indexOf("for " + w.rpOn) >= 0;
    }), JSON.stringify(rows).slice(0, 400));
  });
  const shire = await follow(w.cookies,
                             sso11(w.rpOff, { shire: acsOf(w.rpOff) }));
  await check("C4. a request carrying shire — the relying party's own " +
              "start — is answered by default, whatever the other switch " +
              "says", async function () {
    assert.strictEqual(shire.r.status, 200, brief(shire.r));
    assert.ok(/name="SAMLResponse"/.test(shire.r.body), brief(shire.r));
  });
  const closed = await hop(w.cookies,
                           sso11(w.rpClosed, { shire: acsOf(w.rpClosed) }));
  await check("C5. and REFUSED for one whose entry sets " +
              "saml11SpInitiatedSso FALSE — 403", async function () {
    assert.strictEqual(closed.status, 403, brief(closed));
    assert.ok(!/name="SAMLResponse"/.test(closed.body), brief(closed));
  });
  log.debug("Leaving sectionC().");
}

// ---------------------------------------------------------------------------
// E. THE MECHANISM RE-PROMPT, ONCE.
// ---------------------------------------------------------------------------
async function sectionE(w) {
  log.debug("Entering sectionE().");
  log.info("=== E. the mechanism re-prompt on /saml2/unsolicited ===");
  const reprompt = await hop(w.cookies, unsolicited(w.spMech));
  await check("E1. a session signed in on a password, for a service " +
              "provider that allows only webauthn, is sent to sign in " +
              "again", async function () {
    assert.ok(reprompt.status === 303 || reprompt.status === 302,
              brief(reprompt));
    assert.ok(/\/authn\//.test(reprompt.location), brief(reprompt));
  });
  const back = await hop(w.cookies,
                         unsolicited(w.spMech, { reprompted: "1" }));
  const backXml = messageOf(back.body);
  await check("E2. back from that one trip still on a password: " +
              "RequestDenied, not another trip", async function () {
    assert.strictEqual(back.status, 200, brief(back));
    assert.ok(/status:RequestDenied"/.test(backXml), backXml.slice(0, 400));
    assert.ok(!/InResponseTo=/.test(backXml), "an InResponseTo was sent");
  });
  log.debug("Leaving sectionE().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the identity-provider-initiated SAML checks against " +
           base + " in the realm " + REALM);
  const w = await setUp();
  await sectionA(w);
  await sectionB(w);
  await sectionC(w);
  await sectionE(w);
  log.info("The realm " + REALM + " is left standing (tests/CLAUDE.md, " +
           "*No job removes a realm*).");
  if (failures.length) {
    log.error(checks + " check(s) passed, " + failures.length + " FAILED:");
    failures.forEach(function (f) {
      log.error("  ✗ " + f);
    });
    log.debug("Leaving test(). Failed.");
    return 1;
  }
  // A FLOOR ON THE COUNT: a section that stops being called takes its
  // assertions with it and the run would still say "passed".
  assert.ok(checks >= 17, "only " + checks + " checks ran; a section " +
                          "stopped being called");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_idp_initiated_saml")
  .description("Who may start a SAML sign-in (#711, #715), over HTTP in " +
      "a realm of its own, in the service's own mode: SAML 2.0's " +
      "unsolicited Response and SAML 1.1's TARGET-only link off until an " +
      "application or the realm opts in, the relying party in the logout " +
      "inventory, the service provider's own start refused per " +
      "application, and the mechanism re-prompt's one trip.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().then(function (code) {
  process.exit(code);
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
