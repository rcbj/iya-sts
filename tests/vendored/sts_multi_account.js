// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_multi_account.js
//
// ---------------------------------------------------------------------------
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER, OVER HTTP (#561).
//
// `authn/CLAUDE.md`, *Several signed-in accounts in one browser*, is the
// design; `tests/multi_account_sessions.js`, `multi_account_protocols.js` and
// `multi_account_logout.js` hold it in process. This job asks a RUNNING
// service the same questions, in whatever mode the stack runs — product
// among them — with ONE cookie jar (one browser) and two people:
//
//   1. TWO SIGN-INS KEPT LIVE, AND THE PICKER: alice signs in, then bob with
//      prompt=login, and both stay signed in (`GET /authn-api/accounts`
//      lists both, never a sid, and says where Sign in with another account
//      starts); a request naming neither goes to `/authn/accounts`, whose
//      view lists both by key, and choosing alice resumes the request as
//      her.
//   2. `login_hint` CHOOSES SILENTLY, and one naming nobody here goes to the
//      sign-in screen, never to another account.
//   3. `prompt=select_account` shows the picker whatever the hint; choosing
//      bob answers bob; "use another account" goes on to the sign-in.
//   4. `prompt=none` with nothing to choose by is
//      `account_selection_required` (OIDC Core section 3.1.2.6); with a hint
//      it is answered.
//   5. SAML 2.0: `IsPassive` with a choice to make is `NoPassive`; a
//      `<Subject>` NameID chooses its account silently, passive or not; a
//      request naming nobody goes to the picker, and the account chosen
//      there is the assertion's subject.
//   6. WS-FEDERATION: `wsignin1.0` goes to the picker; the account chosen is
//      the token's.
//   7. THE SIGN-OUT'S ACCOUNT STEP: `/logout` asks which account (its view
//      lists both by key, `login_hint` preselects one, the JSON door answers
//      409 `account_choice_required`).
//   8. RP-INITIATED LOGOUT BY `id_token_hint`'s `sid`: presented by another
//      browser it ends nothing; in this one it ends bob's session — and
//      alice stays signed in.
//   9. ONE ACCOUNT SIGNED OUT, THE OTHER LIVE: bob signs in again, and the
//      account step's alice, then her own sign-out, end hers alone.
//  10. FORGET: the picker remembers alice as signed out; forgetting bob, who
//      is live, is refused (409); forgetting alice takes her off the list.
//
// THE REALM IS THROWAWAY and inherits the process's mode, so this is the
// stack's mode; it is left behind as every realm a job creates is. Nothing
// here depends on development: the people have passwords and type them, the
// application registers every address it is answered at, the SAML requests
// are signed, risk scoring is off for `sts_admin_client_policies.js`'s
// reason, and consent is granted to the client up front.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const zlib = require("zlib");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_multi_account",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const ORIGIN = new URL(base).origin;
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const REALM = "ma-" + TAG;
const ALICE = names.usernameFor("ma-alice");
const BOB = names.usernameFor("ma-bob");
const NOBODY = names.usernameFor("ma-nobody");
const PASSWORD = "Ma-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const APP = "ma-app-" + TAG;
const SECRET = "ma-secret-" + TAG + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://" + APP + ".example.test/cb";
const ACS = "https://" + APP + ".example.test/acs";
const REPLY = "https://" + APP + ".example.test/wsfed";
// The fewest checks a full run makes: a section that stops being called
// fails the job rather than passing quietly.
const FLOOR = 30;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmBase() {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + REALM;
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const claims = JSON.parse(Buffer.from(String(jwt).split(".")[1],
                                        "base64url").toString("utf8"));
  log.debug("Leaving claimsOf().");
  return claims;
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, json: json, text: text,
           location: r.headers.get("location") || "" };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(realmBase() + "/admin-api/config/set",
            { key: key, value: value }, "set " + key + " in " + REALM);
}

// ---------------------------------------------------------------------------
// ONE BROWSER: a cookie jar, and requests with redirects left to the caller.
// The jar is a plain object, name to value, which is the shape
// `authn_signin.js`'s `signInWithJar()` and `consentWithJar()` write back
// into.
// ---------------------------------------------------------------------------
function keepCookies(jar, lines) {
  log.debug("Entering keepCookies().");
  (lines || []).forEach(function (one) {
    const pair = String(one).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const value = pair.slice(at + 1);
    if (value === "" || /Max-Age=0/i.test(String(one)) ||
        /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
      delete jar[pair.slice(0, at)];
    } else {
      jar[pair.slice(0, at)] = value;
    }
  });
  log.debug("Leaving keepCookies().");
}

function cookieOf(jar) {
  log.debug("Entering cookieOf().");
  log.debug("Leaving cookieOf().");
  return Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
}

function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    async go(method, url, extra) {
      log.debug("Entering go(). " + method);
      const opts = extra || {};
      const headers = Object.assign({}, opts.headers || {});
      const cookie = cookieOf(jar);
      if (cookie) {
        headers.cookie = cookie;
      }
      const absolute = new URL(String(url), base + "/").toString();
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers,
                                        body: opts.body });
      keepCookies(jar, r.headers.getSetCookie ? r.headers.getSetCookie()
                                              : []);
      const text = await r.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch (e) {
        log.debug("Caught in go(): " + ((e && e.message) || e));
        // Not JSON: a page, read as text.
        json = null;
      }
      const location = r.headers.get("location")
        ? new URL(r.headers.get("location"), absolute).toString() : "";
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: location, text: text,
               json: json, url: absolute };
    },
    // An act of `/authn-api`, bound as the page binds it: JSON, this
    // service's Origin, the view's CSRF token.
    async act(path, body, csrf) {
      log.debug("Entering act().");
      const answer = await authnSignin.act(realmBase(), path, body,
                                           { cookie: cookieOf(jar),
                                             csrf: csrf });
      keepCookies(jar, answer.setCookies);
      log.debug("Leaving act(). " + answer.status + " " + answer.next);
      return answer;
    }
  };
  log.debug("Leaving browser().");
  return self;
}

// ---------------------------------------------------------------------------
// FOLLOWING A FLOW: redirects on this service are followed, the consent
// screen is answered Allow, and the walk stops at the sign-in screen, at the
// account picker, at a redirect off the service (the client's redirect URI),
// or at a page.
// ---------------------------------------------------------------------------
async function follow(b, url) {
  log.debug("Entering follow().");
  let r = await b.go("GET", url);
  for (let hops = 0; hops < 12; hops += 1) {
    if (r.status < 300 || r.status >= 400 || !r.location) {
      break;
    }
    if (/\/authn\/login\?/.test(r.location) ||
        /\/authn\/accounts\?/.test(r.location)) {
      break;
    }
    if (authnSignin.isConsent(r.location)) {
      r = await authnSignin.consentWithJar(r.location, "allow", b.jar);
      if (r.status === 303 && r.location) {
        r = { status: 303, location: new URL(r.location, base + "/")
          .toString(), text: "" };
        if (new URL(r.location).origin !== ORIGIN) {
          break;
        }
        r = await b.go("GET", r.location);
        continue;
      }
      break;
    }
    if (new URL(r.location).origin !== ORIGIN) {
      break;
    }
    r = await b.go("GET", r.location);
  }
  const at = r.location || "";
  log.debug("Leaving follow(). " + r.status);
  return {
    status: r.status, location: at, text: r.text || "", json: r.json,
    screen: /\/authn\/login\?/.test(at) ? at : "",
    picker: /\/authn\/accounts\?/.test(at) ? at : ""
  };
}

// Signs in at the screen a walk stopped at, then follows on.
async function signInThere(b, where, username) {
  log.debug("Entering signInThere(). " + username);
  const r = await authnSignin.signInWithJar(realmBase(), where,
    { action: "login", username: username, password: PASSWORD }, b.jar,
    { ignoreOffer: true });
  assert.ok(r.status === 303 && r.location,
            "signing in as " + username + " should answer where to go: " +
            r.status + " " + String(r.text).slice(0, 300));
  const on = await follow(b, r.location);
  log.debug("Leaving signInThere().");
  return on;
}

// ---------------------------------------------------------------------------
// THE ACCOUNT PICKER, as its page reads and sends it: the shell (for the
// cookie), `GET /authn-api/pending/{id}/accounts` (the view and the CSRF
// token), and its three acts.
// ---------------------------------------------------------------------------
async function openPicker(b, where) {
  log.debug("Entering openPicker().");
  const id = authnSignin.pendingIdOf(where);
  const shell = await b.go("GET", where);
  const r = await b.go("GET", realmBase() + "/authn-api/pending/" +
                       encodeURIComponent(id) + "/accounts",
                       { headers: { accept: "application/json" } });
  assert.ok(shell.status === 200 && r.status === 200 && r.json &&
            r.json.view,
            "the picker should draw: " + shell.status + " " + r.status + " " +
            String(r.text).slice(0, 300));
  log.debug("Leaving openPicker().");
  return { id: id, view: r.json.view, csrf: r.json.csrf || "",
           text: r.text };
}

function keyOf(view, username) {
  log.debug("Entering keyOf(). " + username);
  const found = (view.accounts || []).filter(function (one) {
    return one.username === username;
  })[0];
  log.debug("Leaving keyOf().");
  return found ? String(found.key) : "";
}

async function pickerAct(b, opened, op, body) {
  log.debug("Entering pickerAct(). " + op);
  const answer = await b.act("/authn-api/pending/" +
                             encodeURIComponent(opened.id) + "/accounts/" +
                             op, body || {}, opened.csrf);
  log.debug("Leaving pickerAct().");
  return answer;
}

// ---------------------------------------------------------------------------
// OPENID CONNECT: the authorization request, and what came back at the
// client's redirect URI — a code exchanged for an ID Token, or an error.
// ---------------------------------------------------------------------------
function authorizeUrl(extra) {
  log.debug("Entering authorizeUrl().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const url = realmBase() + "/oauth2/authorize?" + form(Object.assign({
    response_type: "code", client_id: APP, redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + nodeCrypto.randomBytes(6)
      .toString("hex"),
    nonce: "n-" + nodeCrypto.randomBytes(9).toString("base64url"),
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"),
    code_challenge_method: "S256" }, extra || {}));
  log.debug("Leaving authorizeUrl().");
  return { url: url, verifier: verifier };
}

async function atClient(r, verifier) {
  log.debug("Entering atClient().");
  const out = { error: "", code: "", claims: null, idToken: "",
                screen: r.screen, picker: r.picker };
  if (!r.location || r.location.indexOf(REDIRECT) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return out;
  }
  const params = new URL(r.location).searchParams;
  out.error = params.get("error") || "";
  out.code = params.get("code") || "";
  if (out.code) {
    const t = await call("POST", realmBase() + "/oauth2/token",
      form({ grant_type: "authorization_code", code: out.code,
             redirect_uri: REDIRECT, code_verifier: verifier }),
      { "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + Buffer.from(APP + ":" + SECRET)
          .toString("base64") });
    assert.ok(t.status === 200 && t.json && t.json.id_token,
              "the token endpoint: " + t.status + " " + t.text.slice(0, 300));
    out.idToken = t.json.id_token;
    out.claims = claimsOf(t.json.id_token);
  }
  log.debug("Leaving atClient(). " + (out.error || "a code"));
  return out;
}

// One authorization request in this browser: signed in at the screen as
// `person` where it stops there (and `person` is given), otherwise answered
// where it stopped.
async function oidc(b, extra, person) {
  log.debug("Entering oidc().");
  const asked = authorizeUrl(extra);
  let r = await follow(b, asked.url);
  if (r.screen && person) {
    r = await signInThere(b, r.screen, person);
  }
  const out = await atClient(r, asked.verifier);
  out.verifier = asked.verifier;
  log.debug("Leaving oidc().");
  return out;
}

// The picker chose `username`: its select, and the request it resumes.
async function choose(b, opened, username, verifier) {
  log.debug("Entering choose(). " + username);
  const answer = await pickerAct(b, opened, "select",
                                 { account: keyOf(opened.view, username) });
  assert.ok(answer.status === 200 && answer.next === "redirect" &&
            answer.location,
            "selecting " + username + " should resume the request: " +
            answer.status + " " + String(answer.text).slice(0, 300));
  const r = await follow(b, answer.location);
  const out = verifier === undefined ? r : await atClient(r, verifier);
  out.ticketed = /[?&]sts_account=/.test(answer.location);
  log.debug("Leaving choose().");
  return out;
}

// ---------------------------------------------------------------------------
// SAML 2.0: a signed AuthnRequest on the Redirect binding (SAML bindings
// section 3.4.4.1; product refuses an unsigned one), and the Response the
// identity provider's POST form carries.
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
    const subject = [{ name: "commonName", value: "multi-account SP" }];
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

function samlSso(o) {
  log.debug("Entering samlSso().");
  const subject = o.subject
    ? "<saml:Subject><saml:NameID>" + o.subject +
      "</saml:NameID></saml:Subject>" : "";
  const xml = "<samlp:AuthnRequest " +
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'ID="_ma' + nodeCrypto.randomBytes(8).toString("hex") + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '" ' +
    // A SIGNED request carries its Destination, the URL it is sent to:
    // saml-bindings-2.0-os 3.4.5.2 requires it, and the service refuses
    // one without (STS-SAML-0085, #190).
    'Destination="' + realmBase() + '/saml2/sso" ' +
    'AssertionConsumerServiceURL="' + ACS + '" ' +
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"' +
    (o.passive ? ' IsPassive="true"' : "") + ">" +
    "<saml:Issuer>" + APP + "</saml:Issuer>" + subject +
    "</samlp:AuthnRequest>";
  const request = zlib.deflateRawSync(Buffer.from(xml, "utf8"))
    .toString("base64");
  const sigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const signed = "SAMLRequest=" + encodeURIComponent(request) +
    "&RelayState=" + encodeURIComponent("ma") +
    "&SigAlg=" + encodeURIComponent(sigAlg);
  const signature = nodeCrypto.sign("sha256", Buffer.from(signed),
    samlSpCredential().privateKeyPem).toString("base64");
  log.debug("Leaving samlSso().");
  return realmBase() + "/saml2/sso?" + signed + "&Signature=" +
    encodeURIComponent(signature);
}

function unescapeHtml(text) {
  log.debug("Entering unescapeHtml().");
  log.debug("Leaving unescapeHtml().");
  return String(text || "").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

// The Response a POST form carries: its status codes and its XML.
function samlOf(page) {
  log.debug("Entering samlOf().");
  const m = /name="SAMLResponse"\s+value="([^"]*)"/.exec(String(page || ""));
  if (!m) {
    log.debug("Leaving samlOf(). No Response.");
    return null;
  }
  const xml = Buffer.from(unescapeHtml(m[1]), "base64").toString("utf8");
  const codes = [];
  const re = /StatusCode[^>]*Value="[^"]*:status:([A-Za-z]+)"/g;
  let one = re.exec(xml);
  while (one) {
    codes.push(one[1]);
    one = re.exec(xml);
  }
  log.debug("Leaving samlOf(). " + codes.join(","));
  return { codes: codes, xml: xml };
}

// Whose assertion a SAML Response or a WS-Federation token is: the one of
// the two people its text names, '' where it names neither or both.
function whose(text) {
  log.debug("Entering whose().");
  const t = String(text || "");
  const a = t.indexOf(ALICE) >= 0;
  const b = t.indexOf(BOB) >= 0;
  log.debug("Leaving whose().");
  return a === b ? "" : (a ? ALICE : BOB);
}

// ---------------------------------------------------------------------------
// THE REALM.
// ---------------------------------------------------------------------------
async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: REALM + ".example.net",
             name: "#561 several accounts " + TAG },
           "created the realm " + REALM);
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason: one
  // address signing several people in, in seconds, is what it counts.
  await setting("risk.assessSignIns", false);
  await setting("authn.multipleAccounts", true);
  // `/logout` asks about this browser's accounts, not a named somebody.
  await setting("logout.anyUser", false);
  // An ID Token carries `sid` while back-channel logout is on (its default).
  await setting("oauth2.backchannelLogout", true);
  await registry.ensurePerson(realmBase(), ALICE, PASSWORD);
  await registry.ensurePerson(realmBase(), BOB, PASSWORD);
  await ok(realmBase() + "/admin-api/applications/create", {
    identifier: APP, name: "#561 several accounts " + TAG,
    protocols: ["oauth2", "oidc", "saml2", "wsfed"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthPostLogoutRedirectUri: [REDIRECT],
              oauthAllowedScope: ["openid"],
              samlEntityId: [APP], samlAssertionConsumerService: [ACS],
              samlSigningCertificate: [samlSpCredential().certificatePem],
              wsfedRealm: [APP], wsfedReplyUrl: [REPLY] } },
    REALM + ": created the application, for OpenID Connect, SAML 2.0 and " +
    "WS-Federation");
  await ok(realmBase() + "/admin-api/consent/grant-global-consent",
           { client: APP, scope: "openid" }, REALM + ": consented openid");
  log.debug("Leaving setUp().");
}

async function accountsList(b) {
  log.debug("Entering accountsList().");
  const r = await b.go("GET", realmBase() + "/authn-api/accounts",
                       { headers: { accept: "application/json" } });
  log.debug("Leaving accountsList(). " + r.status);
  return r;
}

function stateOf(list, username) {
  log.debug("Entering stateOf(). " + username);
  const found = ((list && list.accounts) || []).filter(function (one) {
    return one.username === username;
  })[0];
  log.debug("Leaving stateOf().");
  return found ? String(found.state) : "absent";
}

// Whether `username` is still signed in to this browser, asked as a relying
// party asks: prompt=none naming them answers a code, or login_required.
async function silently(b, username) {
  log.debug("Entering silently(). " + username);
  const r = await oidc(b, { prompt: "none", login_hint: username }, null);
  log.debug("Leaving silently(). " + (r.error || "a code"));
  return r;
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Several signed-in accounts in one browser at " + base +
           ", realm " + REALM);
  await setUp();
  const b = browser();
  const ids = {};

  log.info("=== 1. two sign-ins kept live, and the picker ===");
  const a1 = await oidc(b, {}, ALICE);
  const b1 = await oidc(b, { prompt: "login" }, BOB);
  check("alice and then bob (prompt=login) both signed in, with two " +
        "subjects", function () {
    assert.ok(a1.claims && b1.claims, JSON.stringify({ a: a1.error,
                                                       b: b1.error }));
    assert.notStrictEqual(a1.claims.sub, b1.claims.sub);
    ids.alice = a1.claims.sub;
    ids.bob = b1.claims.sub;
  });
  check("the browser holds the account set's cookie", function () {
    assert.ok(Object.keys(b.jar).some(function (one) {
      return /^sts_accounts/.test(one);
    }), Object.keys(b.jar).join(","));
  });
  let list = await accountsList(b);
  check("GET /authn-api/accounts lists both signed in, names no sid, and " +
        "says where Sign in with another account starts", function () {
    assert.strictEqual(list.status, 200, list.text.slice(0, 300));
    assert.strictEqual(list.json.enabled, true);
    assert.strictEqual(stateOf(list.json, ALICE), "signed-in");
    assert.strictEqual(stateOf(list.json, BOB), "signed-in");
    assert.ok(/\/portal\?accounts=another$/.test(
      String(list.json.anotherAccount)), list.json.anotherAccount);
    [a1.claims.sid, b1.claims.sid].filter(Boolean).forEach(function (sid) {
      assert.ok(list.text.indexOf(sid) < 0, "a sid is in the list");
    });
  });
  const ambiguous = await oidc(b, {}, null);
  check("a request naming neither goes to the account picker", function () {
    assert.ok(ambiguous.picker, JSON.stringify(ambiguous));
  });
  let opened = await openPicker(b, ambiguous.picker);
  check("the picker's view lists both, signed in, by key and without a sid",
        function () {
    assert.ok(keyOf(opened.view, ALICE) && keyOf(opened.view, BOB),
              opened.text.slice(0, 400));
    [a1.claims.sid, b1.claims.sid].filter(Boolean).forEach(function (sid) {
      assert.ok(opened.text.indexOf(sid) < 0, "a sid is in the view");
    });
  });
  let got = await choose(b, opened, ALICE, ambiguous.verifier);
  check("choosing alice resumes the request with a ticket, answered as " +
        "her", function () {
    assert.ok(got.ticketed);
    assert.ok(got.claims, JSON.stringify(got));
    assert.strictEqual(got.claims.sub, ids.alice);
  });

  log.info("=== 2. login_hint chooses silently ===");
  const hintedBob = await oidc(b, { login_hint: BOB }, null);
  check("login_hint=bob answers bob, with no screen and no picker",
        function () {
    assert.ok(hintedBob.claims, JSON.stringify(hintedBob));
    assert.strictEqual(hintedBob.claims.sub, ids.bob);
    assert.ok(hintedBob.claims.sid, "the ID Token carries no sid");
  });
  got = await oidc(b, { login_hint: NOBODY }, null);
  check("a login_hint naming nobody here goes to the sign-in screen, never " +
        "to another account", function () {
    assert.ok(got.screen && !got.picker && !got.code, JSON.stringify(got));
  });

  log.info("=== 3. prompt=select_account ===");
  const selecting = await oidc(b, { prompt: "select_account",
                                    login_hint: ALICE }, null);
  check("prompt=select_account shows the picker, a hint notwithstanding",
        function () {
    assert.ok(selecting.picker, JSON.stringify(selecting));
  });
  opened = await openPicker(b, selecting.picker);
  got = await choose(b, opened, BOB, selecting.verifier);
  check("choosing bob there answers bob", function () {
    assert.ok(got.claims, JSON.stringify(got));
    assert.strictEqual(got.claims.sub, ids.bob);
  });
  const another = await oidc(b, { prompt: "select_account" }, null);
  opened = await openPicker(b, another.picker);
  const onward = await pickerAct(b, opened, "another", {});
  check("use another account goes on to the sign-in screen", function () {
    assert.ok(onward.status === 200 && onward.next === "redirect" &&
              /\/authn\/login\?authn=/.test(onward.location),
              onward.status + " " + String(onward.text).slice(0, 300));
  });

  log.info("=== 4. prompt=none ===");
  got = await oidc(b, { prompt: "none" }, null);
  check("prompt=none naming neither is account_selection_required",
        function () {
    assert.strictEqual(got.error, "account_selection_required",
                       JSON.stringify(got));
  });
  got = await silently(b, ALICE);
  check("prompt=none with login_hint=alice is answered as her", function () {
    assert.ok(got.claims, JSON.stringify(got));
    assert.strictEqual(got.claims.sub, ids.alice);
  });

  log.info("=== 5. SAML 2.0 ===");
  let r = await follow(b, samlSso({ passive: true }));
  let saml = samlOf(r.text);
  check("IsPassive with a choice to make is NoPassive", function () {
    assert.ok(saml && saml.codes.indexOf("NoPassive") >= 0,
              r.status + " " + (saml ? saml.codes.join(",") :
                                r.text.slice(0, 300)));
  });
  r = await follow(b, samlSso({ passive: true, subject: ALICE }));
  saml = samlOf(r.text);
  check("IsPassive with a <Subject> naming alice is answered, as her",
        function () {
    assert.ok(saml && saml.codes[0] === "Success",
              saml ? saml.codes.join(",") : r.text.slice(0, 300));
    assert.strictEqual(whose(saml.xml), ALICE);
  });
  r = await follow(b, samlSso({ subject: BOB }));
  saml = samlOf(r.text);
  check("a <Subject> naming bob chooses him silently", function () {
    assert.ok(!r.picker && !r.screen && saml && saml.codes[0] === "Success",
              r.status + " " + r.location);
    assert.strictEqual(whose(saml.xml), BOB);
  });
  r = await follow(b, samlSso({}));
  check("a request naming nobody goes to the picker", function () {
    assert.ok(r.picker, r.status + " " + r.location);
  });
  opened = await openPicker(b, r.picker);
  r = await choose(b, opened, ALICE);
  saml = samlOf(r.text);
  check("the account chosen there, alice, is the assertion's", function () {
    assert.ok(saml && saml.codes[0] === "Success",
              r.status + " " + r.text.slice(0, 300));
    assert.strictEqual(whose(saml.xml), ALICE);
  });

  log.info("=== 6. WS-Federation ===");
  r = await follow(b, realmBase() + "/wsfed?wa=wsignin1.0&wtrealm=" +
                   encodeURIComponent(APP));
  check("wsignin1.0 goes to the picker", function () {
    assert.ok(r.picker, r.status + " " + r.location);
  });
  opened = await openPicker(b, r.picker);
  r = await choose(b, opened, BOB);
  check("the account chosen there, bob, is the token's", function () {
    assert.ok(/name="wresult"/.test(r.text), r.status + " " +
              r.text.slice(0, 300));
    const wresult = /name="wresult"\s+value="([^"]*)"/.exec(r.text);
    assert.strictEqual(whose(unescapeHtml(wresult ? wresult[1] : "")), BOB);
  });

  log.info("=== 7. the sign-out's account step ===");
  await b.go("GET", realmBase() + "/logout");
  let step = await b.go("GET", realmBase() + "/authn-api/logout?login_hint=" +
                        encodeURIComponent(ALICE),
                        { headers: { accept: "application/json" } });
  check("/logout asks which account: both by key, alice preselected by " +
        "login_hint, no sid", function () {
    assert.strictEqual(step.status, 200, step.text.slice(0, 300));
    const view = step.json.view;
    assert.strictEqual(view.state, "accounts");
    assert.ok(keyOf(view, ALICE) && keyOf(view, BOB));
    assert.strictEqual(view.preselected, keyOf(view, ALICE));
    [a1.claims.sid, b1.claims.sid].filter(Boolean).forEach(function (sid) {
      assert.ok(step.text.indexOf(sid) < 0, "a sid is in the view");
    });
  });
  const keys = { alice: keyOf(step.json.view, ALICE),
                 bob: keyOf(step.json.view, BOB) };
  r = await b.go("GET", realmBase() + "/logout",
                 { headers: { accept: "application/json" } });
  check("the JSON door answers 409 account_choice_required", function () {
    assert.strictEqual(r.status, 409, r.text.slice(0, 300));
    assert.strictEqual(r.json.error, "account_choice_required");
  });

  log.info("=== 8. RP-Initiated Logout by id_token_hint's sid ===");
  const elsewhere = browser();
  await elsewhere.go("GET", realmBase() + "/oauth2/logout?" +
                     form({ id_token_hint: hintedBob.idToken,
                            client_id: APP }));
  got = await silently(b, BOB);
  check("bob's id_token_hint presented by ANOTHER browser ends nothing",
        function () {
    assert.ok(got.claims && got.claims.sub === ids.bob, JSON.stringify(got));
  });
  r = await b.go("GET", realmBase() + "/oauth2/logout?" +
                 form({ id_token_hint: hintedBob.idToken, client_id: APP,
                        post_logout_redirect_uri: REDIRECT }));
  got = await silently(b, BOB);
  const still = await silently(b, ALICE);
  check("in this browser the hint's sid ends bob's session, and alice " +
        "stays signed in", function () {
    assert.strictEqual(got.error, "login_required",
                       r.status + " " + JSON.stringify(got));
    assert.ok(still.claims && still.claims.sub === ids.alice,
              JSON.stringify(still));
  });

  log.info("=== 9. one account signed out, the other still live ===");
  got = await oidc(b, { prompt: "login", login_hint: BOB }, BOB);
  check("bob signs in again beside alice", function () {
    assert.ok(got.claims && got.claims.sub === ids.bob, JSON.stringify(got));
  });
  step = await b.go("GET", realmBase() + "/authn-api/logout",
                    { headers: { accept: "application/json" } });
  let answer = await b.act("/authn-api/logout/accounts",
                           { account: keys.alice }, step.json.csrf);
  check("the account step's alice leads to her sign-out page", function () {
    assert.ok(answer.status === 200 && answer.json &&
              answer.json.next === "inventory",
              answer.status + " " + String(answer.text).slice(0, 300));
  });
  await b.go("GET", realmBase() + "/logout?account=" +
             encodeURIComponent(keys.alice));
  step = await b.go("GET", realmBase() + "/authn-api/logout?account=" +
                    encodeURIComponent(keys.alice),
                    { headers: { accept: "application/json" } });
  check("her page is her inventory", function () {
    assert.strictEqual(step.json.view.state, "inventory");
    assert.strictEqual(step.json.view.username, ALICE);
  });
  answer = await b.act("/authn-api/logout",
                       { scope: "global", username: ALICE,
                         account: keys.alice }, step.json.csrf);
  check("her sign-out is answered", function () {
    assert.strictEqual(answer.status, 200, String(answer.text)
      .slice(0, 300));
  });
  got = await silently(b, ALICE);
  const bobStill = await silently(b, BOB);
  check("alice is signed out and bob still signed in", function () {
    assert.strictEqual(got.error, "login_required", JSON.stringify(got));
    assert.ok(bobStill.claims && bobStill.claims.sub === ids.bob,
              JSON.stringify(bobStill));
  });
  list = await accountsList(b);
  check("the list says alice signed out and bob signed in", function () {
    assert.strictEqual(stateOf(list.json, ALICE), "signed-out");
    assert.strictEqual(stateOf(list.json, BOB), "signed-in");
  });

  log.info("=== 10. forget ===");
  const remembering = await oidc(b, { prompt: "select_account" }, null);
  opened = await openPicker(b, remembering.picker);
  check("the picker remembers alice, signed out", function () {
    const one = (opened.view.accounts || []).filter(function (a) {
      return a.username === ALICE;
    })[0];
    assert.ok(one && one.state === "signed-out", opened.text.slice(0, 400));
  });
  answer = await pickerAct(b, opened, "forget",
                           { account: keyOf(opened.view, BOB) });
  check("forgetting bob, who is signed in, is refused (409)", function () {
    assert.strictEqual(answer.status, 409, String(answer.text)
      .slice(0, 300));
  });
  answer = await pickerAct(b, opened, "forget",
                           { account: keyOf(opened.view, ALICE) });
  check("forgetting alice is answered, and the page stays", function () {
    assert.ok(answer.status === 200 && answer.next === "stay",
              answer.status + " " + String(answer.text).slice(0, 300));
  });
  opened = await openPicker(b, remembering.picker);
  list = await accountsList(b);
  check("alice is gone from the picker and the list; bob is still there",
        function () {
    assert.strictEqual(keyOf(opened.view, ALICE), "");
    assert.ok(keyOf(opened.view, BOB));
    assert.strictEqual(stateOf(list.json, ALICE), "absent");
    assert.strictEqual(stateOf(list.json, BOB), "signed-in");
  });

  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_multi_account")
  .description("#561: several signed-in accounts in one browser over HTTP " +
    "— the picker, login_hint, prompt=select_account and prompt=none, " +
    "SAML 2.0 IsPassive and <Subject>, WS-Federation, the sign-out's " +
    "account step, RP-Initiated Logout by sid, one account signed out " +
    "while the other stays, and forget.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
