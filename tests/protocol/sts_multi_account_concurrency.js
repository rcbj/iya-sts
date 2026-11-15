// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_multi_account_concurrency.js
//
// ---------------------------------------------------------------------------
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER, WHEN TWO TABS ACT AT ONCE OR A
// SESSION ENDS UNDER A FLOW (#561 TR-2, #731), OVER THE WIRE.
//
// D12 (#444): carries over `tests/multi_account_concurrency.js`, whose
// "two tabs" were two requests built from ONE cookie jar before either
// answer was taken. Over the wire that is exactly reproducible without a
// race: both requests are sent with the jar's cookies as they were, and the
// answers' Set-Cookie lines are then taken in the order a section names.
// Whose session a request acted as is a `prompt=none` authorization request
// in that browser (a code whose ID Token names the subject, or an error);
// whether a session is live is `GET /admin-api/sessions`; codes are read
// off the realm's audit log. In a throwaway realm:
//
//   1. TWO SIGN-INS AT ONCE: both sessions are live and neither ended the
//      one already there; the set holds the session of the answer taken
//      last and the one it had; a request naming the account the race left
//      out acts as that account or as NOBODY, never as another; the set
//      cookie both tabs left with opens nothing; signing that account in
//      again puts it in the set.
//   2. TWO SELECTIONS AT ONCE, IN TWO FLOWS, answers taken in either order:
//      the first answers its flow; the second, carrying the handle the
//      first retired, is refused (409, STS-AUTHN-0348) and writes nothing;
//      the first flow resumes as the account its tab chose; chosen again
//      from a picker drawn afresh, the second resumes as its own; a request
//      of neither flow names nobody.
//   3. TWO SIGN-OUTS AT ONCE: both ended, the third account's session as it
//      was, both remembered as signed out, and the browser acting as the
//      one left whichever answer came last.
//   4. A SESSION REVOKED WHILE A FLOW THAT CHOSE IT IS IN FLIGHT: the
//      resumed request goes to sign in as that account — never on as the
//      other one live in the browser; a ticket whose session ended, its
//      account signed in again meanwhile, acts as the new session; a picker
//      drawn before a revocation sends the select to the sign-in, with no
//      ticket.
//   6. AN ADMINISTRATOR ENDING ONE SESSION leaves the other's session, its
//      place in the set and the cookie, and the browser acts as it.
//   7. `GET /admin-api/sessions` (#731): `?q=` with the set's id lists that
//      browser's sessions and no other, each row names its set, another
//      browser's names its own, no answer carries the set cookie's handle,
//      and `accountChoices` answers the setting and seven counters, moved
//      by what this job did; with the setting off a row names no set.
//
// NOT carried (class (d)): part 5 (two nodes' copies of one set through
// the store's `mergeRow` — the store's own function), part 6's set the
// clean-up job cannot prune and a set removed from under an ending session
// (each needs a row written by hand into the store), and part 7's drawn
// page (the console's renderer; the view it draws from is asserted here).
//
// REALMS ARE LEFT STANDING (tests/CLAUDE.md, *No job removes a realm*)
// unless STS_TEST_REMOVE_REALMS=1, a private probe's switch.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const navigation = require("./navigation.js");
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
var log = bunyan.createLogger({ name: "sts_multi_account_concurrency",
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
const REALM = "mac-" + TAG;
const ALICE = names.usernameFor("ma-alice");
const BOB = names.usernameFor("ma-bob");
const NOBODY = names.usernameFor("ma-nobody");
// The other people a section signs in, each its own (D12).
function person(tag) {
  log.debug("Entering person(). " + tag);
  log.debug("Leaving person().");
  return names.usernameFor("mac-" + tag);
}
const PEOPLE = [
  "in-alice", "in-bob", "in-carol", "sel-alice", "sel-bob", "sel-alice-r",
  "sel-bob-r", "out-alice", "out-bob", "out-carol", "rev-alice", "rev-bob",
  "rev-carol", "iso-alice", "iso-bob", "cnt-alice", "cnt-bob", "con-alice",
  "con-bob", "con-carol", "off-solo"
];
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
const FLOOR = 24;

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
      // A link the person follows is a navigation, which `fetch` cannot say.
      const r = opts.navigate && method === "GET"
        ? await navigation.navigate(absolute, headers)
        : await fetch(absolute, { method: method, redirect: "manual",
                                  headers: headers, body: opts.body });
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
             name: "#561 several accounts " + TAG,
             // DEVELOPMENT, SAID RATHER THAN INHERITED (D12): the SAML
             // LogoutRequests here are unsigned, as the in-process file's
             // were.
             overrides: { "global.mode": "development" } },
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
  for (const tag of PEOPLE) {
    await registry.ensurePerson(realmBase(), person(tag), PASSWORD);
  }
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
// D12: WHAT THE STORE HELD, ASKED OVER THE WIRE. A session is live while
// `GET /admin-api/sessions` lists it; the codes are read off the realm's
// audit log.
// ---------------------------------------------------------------------------
function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function sessionsView(q) {
  log.debug("Entering sessionsView().");
  const r = await call("GET", realmBase() + "/admin-api/sessions?per=100" +
                       (q ? "&q=" + encodeURIComponent(q) : ""));
  assert.strictEqual(r.status, 200, "GET /admin-api/sessions: " + r.status +
                     " " + r.text.slice(0, 200));
  log.debug("Leaving sessionsView().");
  return r;
}

// The live sign-on sessions of one person: their ids.
async function liveFor(username) {
  log.debug("Entering liveFor(). " + username);
  const r = await sessionsView(username);
  const ids = ((r.json && r.json.sessions) || []).filter(function (row) {
    return row.username === username && row.sessionId;
  }).map(function (row) {
    return String(row.sessionId);
  });
  log.debug("Leaving liveFor(). " + ids.length);
  return ids;
}

// The browser's default session: the session cookie's id.
function defaultOf(b) {
  log.debug("Entering defaultOf().");
  const name = Object.keys(b.jar).filter(function (k) {
    return /^(?:__Host-)?sts_session$/.test(k);
  })[0];
  log.debug("Leaving defaultOf().");
  return name ? String(b.jar[name]).split(".")[0] : "";
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await call("GET", realmBase() + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.json && r.json.matched) || 0);
}

async function codesSettle(code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(code);
  for (let i = 0; i < 40 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) the realm is removed at the end, pass
// or fail. A suite run leaves it standing (tests/CLAUDE.md, *No job removes
// a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const r = await call("POST", base + "/admin-api/realms/remove",
                       { id: REALM });
  log.info("removed the realm " + REALM + " (" + r.status + ")");
  log.debug("Leaving removeRealms().");
}

function subOf(got) {
  log.debug("Entering subOf().");
  log.debug("Leaving subOf().");
  return got && got.claims ? String(got.claims.sub) : "";
}

// One account signed in afresh in browser `b`, answering its subject.
async function signInAs(b, username) {
  log.debug("Entering signInAs(). " + username);
  const got = await oidc(b, { prompt: "login", login_hint: username },
                         username);
  assert.ok(got.claims, "signing in as " + username + ": " +
            JSON.stringify(got).slice(0, 300));
  log.debug("Leaving signInAs().");
  return subOf(got);
}

// THE ACCOUNT SET'S COOKIE: its name, and its value as the browser holds it.
function setCookieName(b) {
  log.debug("Entering setCookieName().");
  log.debug("Leaving setCookieName().");
  return Object.keys(b.jar).filter(function (k) {
    return /^(?:__Host-)?sts_accounts/.test(k);
  })[0] || "";
}

// An act of `/authn-api` sent with the cookies of `snapshot` (the jar as it
// was), its answer NOT yet taken into the browser.
function actWith(snapshot, path, body, csrf) {
  log.debug("Entering actWith().");
  log.debug("Leaving actWith().");
  return authnSignin.act(realmBase(), path, body,
                         { cookie: cookieOf(snapshot), csrf: csrf });
}

function takeAnswer(b, answer) {
  log.debug("Entering takeAnswer().");
  keepCookies(b.jar, answer.setCookies || []);
  log.debug("Leaving takeAnswer().");
}

async function revoke(username, sid) {
  log.debug("Entering revoke(). " + username);
  await ok(realmBase() + "/admin-api/sessions/revoke",
           { key: username, select: "session:" + sid },
           "ended " + username + "'s session");
  log.debug("Leaving revoke().");
}

async function rowsOfSet(setId) {
  log.debug("Entering rowsOfSet().");
  const r = await sessionsView(setId);
  log.debug("Leaving rowsOfSet().");
  return { json: r.json, text: r.text,
           rows: ((r.json && r.json.sessions) || []).filter(function (row) {
             return row.sessionId;
           }) };
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function partSignIns() {
  log.debug("Entering partSignIns().");
  log.info("=== 1. two sign-ins at once, in two tabs ===");
  const b = browser();
  const alice = person("in-alice");
  const bob = person("in-bob");
  const carol = person("in-carol");
  const subs = { alice: await signInAs(b, alice) };
  const aliceSid = (await liveFor(alice))[0];
  const before = b.jar[setCookieName(b)];
  // Both tabs open their sign-in screens, then leave with the jar as it is.
  const one = await follow(b, authorizeUrl({ prompt: "login",
                                             login_hint: bob }).url);
  const two = await follow(b, authorizeUrl({ prompt: "login",
                                             login_hint: carol }).url);
  assert.ok(one.screen && two.screen, "two screens: " + one.location +
            " " + two.location);
  const snapshot = Object.assign({}, b.jar);
  const tab1 = await authnSignin.submit(realmBase(), one.screen,
    { action: "login", username: bob, password: PASSWORD },
    { cookie: cookieOf(snapshot) });
  const tab2 = await authnSignin.submit(realmBase(), two.screen,
    { action: "login", username: carol, password: PASSWORD },
    { cookie: cookieOf(snapshot) });
  const bobLive = await liveFor(bob);
  const carolLive = await liveFor(carol);
  const aliceLive = await liveFor(alice);
  check("1. both sign-ins made a session of their own, and neither ended " +
        "the session already there", function () {
    assert.strictEqual(bobLive.length, 1, tab1.status + " " + tab1.next);
    assert.strictEqual(carolLive.length, 1, tab2.status + " " + tab2.next);
    assert.deepStrictEqual(aliceLive, [aliceSid]);
  });
  // The answers arrive: tab1's, then tab2's.
  takeAnswer(b, tab1);
  takeAnswer(b, tab2);
  const asAlice = await silently(b, alice);
  const asCarol = await silently(b, carol);
  const asBob = await silently(b, bob);
  check("1. the set holds the session of the answer taken last (carol) and " +
        "the one it had (alice): each is answered as themselves",
        function () {
    assert.strictEqual(subOf(asAlice), subs.alice, JSON.stringify(asAlice));
    assert.ok(subOf(asCarol), JSON.stringify(asCarol));
    assert.notStrictEqual(subOf(asCarol), subs.alice);
  });
  subs.carol = subOf(asCarol);
  check("1. a request naming bob acts as bob where the set kept him, and " +
        "otherwise as NOBODY — never as alice or carol", function () {
    assert.ok(subOf(asBob) !== subs.alice && subOf(asBob) !== subs.carol,
              JSON.stringify(asBob));
  });
  const stale = browser();
  stale.jar[setCookieName(b)] = before;
  const fromStale = await oidc(stale, { prompt: "none" }, null);
  check("1. the set cookie from before the sign-ins opens nothing: a " +
        "request presenting it alone acts as nobody", function () {
    assert.ok(!fromStale.claims, JSON.stringify(fromStale));
    assert.strictEqual(fromStale.error, "login_required",
                       JSON.stringify(fromStale));
  });
  await signInAs(b, bob);
  const bobAgain = await silently(b, bob);
  check("1. signing in again as the account the race left out puts it in " +
        "the browser's set", function () {
    assert.ok(bobAgain.claims, JSON.stringify(bobAgain));
    assert.ok(subOf(bobAgain) !== subs.alice &&
              subOf(bobAgain) !== subs.carol);
  });
  log.debug("Leaving partSignIns().");
}

async function partSelections() {
  log.debug("Entering partSelections().");
  log.info("=== 2. two selections at once, in two flows ===");
  for (const reversed of [false, true]) {
    const tag = reversed ? "-r" : "";
    const b = browser();
    const alice = person("sel-alice" + tag);
    const bob = person("sel-bob" + tag);
    const subs = { alice: await signInAs(b, alice),
                   bob: await signInAs(b, bob) };
    const askOne = authorizeUrl({ state: "one" + tag });
    const askTwo = authorizeUrl({ state: "two" + tag });
    const one = await follow(b, askOne.url);
    const two = await follow(b, askTwo.url);
    assert.ok(one.picker && two.picker, "two pickers: " + one.location +
              " " + two.location);
    const openOne = await openPicker(b, one.picker);
    const openTwo = await openPicker(b, two.picker);
    const snapshot = Object.assign({}, b.jar);
    const refusedBefore = await codeCount("STS-AUTHN-0348");
    const a1 = await actWith(snapshot, "/authn-api/pending/" +
      encodeURIComponent(openOne.id) + "/accounts/select",
      { account: keyOf(openOne.view, alice) }, openOne.csrf);
    const a2 = await actWith(snapshot, "/authn-api/pending/" +
      encodeURIComponent(openTwo.id) + "/accounts/select",
      { account: keyOf(openTwo.view, bob) }, openTwo.csrf);
    if (reversed) {
      takeAnswer(b, a2);
      takeAnswer(b, a1);
    } else {
      takeAnswer(b, a1);
      takeAnswer(b, a2);
    }
    const refusedAfter = await codesSettle("STS-AUTHN-0348",
                                           refusedBefore + 1);
    check("2. the first select answers its flow; the second, carrying the " +
          "handle the first retired, is refused (409, STS-AUTHN-0348) and " +
          "writes nothing" + (reversed ? " (answers taken in reverse)" : ""),
          function () {
      assert.strictEqual(a1.next, "redirect", String(a1.text).slice(0, 300));
      assert.ok(/state=one/.test(a1.location), a1.location);
      assert.strictEqual(a2.status, 409, String(a2.text).slice(0, 300));
      assert.strictEqual(a2.next, "refused");
      assert.strictEqual((a2.setCookies || []).length, 0,
                         JSON.stringify(a2.setCookies));
      assert.ok(refusedAfter > refusedBefore,
                refusedBefore + " -> " + refusedAfter);
    });
    const firstResumed = await atClient(await follow(b, a1.location),
                                        askOne.verifier);
    check("2. the first flow resumes as alice, the account its tab chose" +
          (reversed ? " (reverse)" : ""), function () {
      assert.strictEqual(subOf(firstResumed), subs.alice,
                         JSON.stringify(firstResumed));
    });
    const afresh = await openPicker(b, two.picker);
    const a3 = await pickerAct(b, afresh, "select",
                               { account: keyOf(afresh.view, bob) });
    const secondResumed = a3.location
      ? await atClient(await follow(b, a3.location), askTwo.verifier)
      : null;
    check("2. chosen again from the picker drawn afresh, the second flow " +
          "answers its own address and resumes as bob" +
          (reversed ? " (reverse)" : ""), function () {
      assert.ok(/state=two/.test(String(a3.location)),
                String(a3.text).slice(0, 300));
      assert.strictEqual(subOf(secondResumed), subs.bob,
                         JSON.stringify(secondResumed));
    });
    const neither = await oidc(b, { prompt: "none" }, null);
    check("2. and a request of neither flow names nobody: a choice is a " +
          "flow's, never the browser's" + (reversed ? " (reverse)" : ""),
          function () {
      assert.strictEqual(neither.error, "account_selection_required",
                         JSON.stringify(neither));
    });
  }
  log.debug("Leaving partSelections().");
}

async function partSignOuts() {
  log.debug("Entering partSignOuts().");
  log.info("=== 3. two sign-outs at once ===");
  const b = browser();
  const alice = person("out-alice");
  const bob = person("out-bob");
  const carol = person("out-carol");
  await signInAs(b, alice);
  const bobSub = await signInAs(b, bob);
  await signInAs(b, carol);
  const bobRowBefore = ((await sessionsView(bob)).json.sessions || [])
    .filter(function (row) {
      return row.username === bob && row.sessionId;
    })[0];
  await b.go("GET", realmBase() + "/logout");
  const view = await b.go("GET", realmBase() + "/authn-api/logout",
                          { headers: { accept: "application/json" } });
  const keys = { alice: keyOf(view.json.view, alice),
                 carol: keyOf(view.json.view, carol) };
  const snapshot = Object.assign({}, b.jar);
  const tab1 = await actWith(snapshot, "/authn-api/logout",
    { scope: "global", username: alice, account: keys.alice },
    view.json.csrf);
  const tab2 = await actWith(snapshot, "/authn-api/logout",
    { scope: "global", username: carol, account: keys.carol },
    view.json.csrf);
  takeAnswer(b, tab2);
  takeAnswer(b, tab1);
  const left = { alice: await liveFor(alice), carol: await liveFor(carol) };
  check("3. both sign-outs ended their sessions", function () {
    assert.strictEqual(tab1.status, 200, String(tab1.text).slice(0, 300));
    assert.strictEqual(tab2.status, 200, String(tab2.text).slice(0, 300));
    assert.strictEqual(left.alice.length + left.carol.length, 0,
                       JSON.stringify(left));
  });
  const bobRowAfter = ((await sessionsView(bob)).json.sessions || [])
    .filter(function (row) {
      return row.username === bob && row.sessionId;
    })[0];
  check("3. bob's session is as it was: the same session, person, start " +
        "and methods", function () {
    assert.ok(bobRowAfter, "bob's session is gone");
    ["sessionId", "sub", "startedAt", "expiresAt"].forEach(function (k) {
      assert.strictEqual(bobRowAfter[k], bobRowBefore[k], k);
    });
    assert.deepStrictEqual(bobRowAfter.amr, bobRowBefore.amr);
  });
  const listed = await accountsList(b);
  check("3. the set holds bob, and remembers alice and carol as signed out",
        function () {
    assert.strictEqual(stateOf(listed.json, bob), "signed-in");
    assert.strictEqual(stateOf(listed.json, alice), "signed-out");
    assert.strictEqual(stateOf(listed.json, carol), "signed-out");
  });
  const bare = await oidc(b, { prompt: "none" }, null);
  const forCarol = await silently(b, carol);
  check("3. a request naming nobody acts as bob, the browser's one account " +
        "left, whichever answer came last; one naming carol acts as nobody",
        function () {
    assert.strictEqual(subOf(bare), bobSub, JSON.stringify(bare));
    assert.ok(!forCarol.claims, JSON.stringify(forCarol));
  });
  log.debug("Leaving partSignOuts().");
}

async function partRevoked() {
  log.debug("Entering partRevoked().");
  log.info("=== 4. a session revoked while a flow that chose it is in " +
           "flight ===");
  const b = browser();
  const alice = person("rev-alice");
  const bob = person("rev-bob");
  const carol = person("rev-carol");
  await signInAs(b, alice);
  await signInAs(b, bob);
  const asked = authorizeUrl({ state: "rev" });
  const flow = await follow(b, asked.url);
  const opened = await openPicker(b, flow.picker);
  const answer = await pickerAct(b, opened, "select",
                                 { account: keyOf(opened.view, alice) });
  check("4. alice was chosen, and the flow resumes with a ticket",
        function () {
    assert.ok(/sts_account=/.test(String(answer.location)),
              String(answer.text).slice(0, 300));
  });
  await revoke(alice, (await liveFor(alice))[0]);
  const resumed = await follow(b, answer.location);
  const bobLive = await liveFor(bob);
  const atScreen = resumed.screen
    ? await authnSignin.screen(realmBase(), resumed.screen,
                               { cookie: cookieOf(b.jar) })
    : null;
  check("4. the resumed request acts as NOBODY — not as bob, the one " +
        "account still live — and goes to sign in as alice, her name " +
        "filled in", function () {
    assert.ok(resumed.screen, resumed.status + " " + resumed.location);
    const drawn = JSON.stringify((atScreen && (atScreen.json ||
                                               atScreen.view)) || null);
    assert.ok(drawn.indexOf(alice) >= 0, drawn.slice(0, 300));
    assert.strictEqual(bobLive.length, 1, "bob's session was touched");
  });
  // THE SAME ACCOUNT SIGNED IN AGAIN MEANWHILE is what was chosen.
  const carolSub = await signInAs(b, carol);
  const askCarol = authorizeUrl({ state: "rev-carol" });
  const carolFlow = await follow(b, askCarol.url);
  const carolPicker = await openPicker(b, carolFlow.picker);
  const ticketed = await pickerAct(b, carolPicker, "select",
                                   { account: keyOf(carolPicker.view,
                                                    carol) });
  await revoke(carol, (await liveFor(carol))[0]);
  const carolAgain = await signInAs(b, carol);
  const later = await atClient(await follow(b, ticketed.location),
                               askCarol.verifier);
  check("4. a ticket whose session ended, its account signed in again " +
        "meanwhile, acts as that account's new session", function () {
    assert.ok(/sts_account=/.test(String(ticketed.location)),
              String(ticketed.text).slice(0, 300));
    assert.strictEqual(carolAgain, carolSub);
    assert.strictEqual(subOf(later), carolSub, JSON.stringify(later));
  });
  // A PICKER DRAWN BEFORE THE REVOCATION.
  const askDrawn = authorizeUrl({ state: "rev2" });
  const drawnFlow = await follow(b, askDrawn.url);
  const drawn = await openPicker(b, drawnFlow.picker);
  check("4. the picker lists bob as signed in", function () {
    assert.ok((drawn.view.accounts || []).some(function (one) {
      return one.username === bob && one.state === "signed-in";
    }), drawn.text.slice(0, 400));
  });
  await revoke(bob, (await liveFor(bob))[0]);
  const picked = await pickerAct(b, drawn, "select",
                                 { account: keyOf(drawn.view, bob) });
  check("4. choosing bob, revoked after the picker was drawn, goes to the " +
        "sign-in with no ticket", function () {
    assert.strictEqual(picked.next, "redirect", String(picked.text)
      .slice(0, 300));
    assert.ok(/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(
      String(picked.location)), picked.location);
    assert.ok(!/sts_account=/.test(String(picked.location)),
              picked.location);
  });
  log.debug("Leaving partRevoked().");
}

async function partIsolation() {
  log.debug("Entering partIsolation().");
  log.info("=== 6. a failure in one session leaves the others ===");
  const b = browser();
  const alice = person("iso-alice");
  const bob = person("iso-bob");
  const aliceSub = await signInAs(b, alice);
  await signInAs(b, bob);
  const aliceBefore = ((await sessionsView(alice)).json.sessions || [])
    .filter(function (row) {
      return row.username === alice && row.sessionId;
    })[0];
  const cookieBefore = b.jar[setCookieName(b)];
  await revoke(bob, (await liveFor(bob))[0]);
  const aliceAfter = ((await sessionsView(alice)).json.sessions || [])
    .filter(function (row) {
      return row.username === alice && row.sessionId;
    })[0];
  const listed = await accountsList(b);
  const bare = await oidc(b, { prompt: "none" }, null);
  check("6. an administrator ending bob's session leaves alice's session, " +
        "her place in the set and the set's cookie as they were, and the " +
        "browser acts as alice", function () {
    assert.ok(aliceAfter && aliceAfter.sessionId === aliceBefore.sessionId,
              JSON.stringify(aliceAfter));
    assert.strictEqual(aliceAfter.accountSet, aliceBefore.accountSet);
    assert.strictEqual(stateOf(listed.json, alice), "signed-in");
    assert.strictEqual(b.jar[setCookieName(b)], cookieBefore);
    assert.strictEqual(subOf(bare), aliceSub, JSON.stringify(bare));
  });
  log.debug("Leaving partIsolation().");
}

async function partConsole(countsBefore) {
  log.debug("Entering partConsole().");
  log.info("=== 7. the account set and the counters on /admin-api/sessions " +
           "===");
  // Something ambiguous and something refused, for the counters.
  const c = browser();
  await signInAs(c, person("cnt-alice"));
  await signInAs(c, person("cnt-bob"));
  await oidc(c, { prompt: "none" }, null);
  const p = await follow(c, authorizeUrl({ state: "cnt" }).url);
  const opened = await openPicker(c, p.picker);
  await pickerAct(c, opened, "select", { account: "urn:uuid:nobody" });

  const b = browser();
  const alice = person("con-alice");
  const bob = person("con-bob");
  const carol = person("con-carol");
  await signInAs(b, alice);
  await signInAs(b, bob);
  const other = browser();
  await signInAs(other, carol);
  const ids = [(await liveFor(alice))[0], (await liveFor(bob))[0]].sort();
  const aliceRow = ((await sessionsView(alice)).json.sessions || [])
    .filter(function (row) {
      return row.sessionId === ids[0] || row.sessionId === ids[1];
    })[0];
  const setId = String((aliceRow && aliceRow.accountSet) || "");
  const handle = String(b.jar[setCookieName(b)] || "").split(".")[1] || "";
  const ofSet = await rowsOfSet(setId);
  const listedIds = ofSet.rows.map(function (row) {
    return row.sessionId;
  }).sort();
  check("7. ?q= with the set's id lists the sessions of that browser and no " +
        "other, and each row names its set", function () {
    assert.ok(setId, JSON.stringify(aliceRow));
    assert.deepStrictEqual(listedIds, ids);
    assert.ok(ofSet.rows.every(function (row) {
      return row.accountSet === setId;
    }));
  });
  const carolRow = ((await sessionsView(carol)).json.sessions || [])
    .filter(function (row) {
      return row.username === carol && row.sessionId;
    })[0];
  check("7. a session of another browser names its own set", function () {
    assert.ok(carolRow && carolRow.accountSet &&
              carolRow.accountSet !== setId, JSON.stringify(carolRow));
  });
  check("7. no answer carries the set cookie's handle", function () {
    assert.ok(handle, "no handle in the cookie");
    assert.ok(ofSet.text.indexOf(handle) < 0);
  });
  const choices = (ofSet.json && ofSet.json.accountChoices) || {};
  const counts = choices.counts || {};
  check("7. accountChoices answers the setting and the seven counters",
        function () {
    assert.strictEqual(choices.enabled, true, JSON.stringify(choices));
    assert.strictEqual(Object.keys(counts).sort().join(","),
                       "added,ambiguous,expired,forgotten,selectFailed," +
                       "selected,switched");
  });
  check("7. and they moved with what this job did", function () {
    ["selected", "added", "ambiguous", "selectFailed"].forEach(function (k) {
      assert.ok(counts[k] > (countsBefore[k] || 0),
                k + ": " + JSON.stringify({ before: countsBefore,
                                            after: counts }));
    });
  });
  log.debug("Leaving partConsole().");
}

async function partOffRow() {
  log.debug("Entering partOffRow().");
  log.info("=== 7. with the setting off, a row names no set ===");
  await setting("authn.multipleAccounts", false);
  const b = browser();
  const solo = person("off-solo");
  await signInAs(b, solo);
  const row = ((await sessionsView(solo)).json.sessions || [])
    .filter(function (one) {
      return one.username === solo && one.sessionId;
    })[0];
  check("7. off, a session is in no set", function () {
    assert.ok(row, "no row");
    assert.strictEqual(row.accountSet, "");
  });
  await setting("authn.multipleAccounts", true);
  log.debug("Leaving partOffRow().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Several accounts at once at " + base + ", realm " + REALM);
  await setUp();
  await partOffRow();
  const before = (((await sessionsView("")).json || {}).accountChoices ||
                  {}).counts || {};
  await partSignIns();
  await partSelections();
  await partSignOuts();
  await partRevoked();
  await partIsolation();
  await partConsole(before);
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realm is removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.info("could not remove the realm: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

new Command()
  .name("sts_multi_account_concurrency")
  .description("#561 TR-2, #731 (D12, #444): two tabs signing in, " +
    "selecting and signing out at once, a session revoked under a flow " +
    "that chose it, " +
    "an administrator ending one session, and the set and the counters " +
    "on /admin-api/sessions.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

main();
