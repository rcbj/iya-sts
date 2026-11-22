// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_multi_account_logout.js
//
// ---------------------------------------------------------------------------
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER (#561): SIGNING OUT, OVER THE
// WIRE.
//
// D12 (#444): carries over what `tests/multi_account_logout.js` held in
// process and `sts_multi_account.js` (sections 7 to 10) does not already
// ask a running service. Whether a session is live is
// `GET /admin-api/sessions`, the browser's default is its session cookie's
// id, and every code is read off the realm's audit log. In a throwaway
// development realm (its SAML LogoutRequests are unsigned, as the
// in-process file's were):
//
//   OFF (`authn.multipleAccounts` false):
//   1. the sign-out's account step does not exist (400, STS-LOGOUT-0013);
//      `/logout`'s view is the inventory with no `account`; RP-Initiated
//      Logout with no hint asks to confirm the one session, then ends it
//      and clears the cookie.
//   ON, a browser holding alice and bob:
//   3. choosing alice answers her sign-out page, carrying her account; her
//      global sign-out ends her session and leaves bob's — the default
//      cookie (bob's) kept — and the browser lists her signed out;
//   4. signing the browser's DEFAULT out makes the next live account the
//      default, and with another account still here no Clear-Site-Data is
//      sent (#1440);
//   5. an account no longer here is refused (409, STS-LOGOUT-0012) and the
//      step drawn again; "every account in this browser" signs them all
//      out and clears the cookie, with Clear-Site-Data "storage" and never
//      cookies (#1440);
//   6. RP-Initiated Logout: an image naming a verified id_token_hint ends
//      nothing (#1443); with no hint and two accounts the page asks which,
//      a form per account, and the one chosen ends alone;
//   7. SAML 2.0 Single Logout over the front channel ends the session its
//      SessionIndex names in the set, not the default;
//   8. WS-Federation: wsignout1.0 asks which account (a link each) and ends
//      the one followed; wsignoutcleanup1.0 asks nobody and ends every
//      session of the set that signed in to the realm. In a trust realm
//      each account's link names the realm's prefix once.
//
// Already asked by `sts_multi_account.js`, and not repeated: the account
// step's view by key with no sid, `login_hint` preselecting, the JSON
// door's 409, and an id_token_hint from another browser ending nothing.
// Nothing of the in-process file is class (d).
//
// REALMS ARE LEFT STANDING (tests/CLAUDE.md, *No job removes a realm*)
// unless STS_TEST_REMOVE_REALMS=1, a private probe's switch.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
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
var log = bunyan.createLogger({ name: "sts_multi_account_logout",
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
const REALM = "mal-" + TAG;
const ALICE = names.usernameFor("ma-alice");
const BOB = names.usernameFor("ma-bob");
const NOBODY = names.usernameFor("ma-nobody");
// The other people a section signs in, each its own (D12).
function person(tag) {
  log.debug("Entering person(). " + tag);
  log.debug("Leaving person().");
  return names.usernameFor("mal-" + tag);
}
const PEOPLE = ["off", "alice", "bob", "carol", "rp-alice", "rp-bob",
                "sp-alice", "sp-bob", "ws-alice", "ws-bob"];
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
  if (!r.location || !urls.isAt(r.location, REDIRECT)) {
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
    (o.passive ? ' IsPassive="true"' : "") +
    (o.force ? ' ForceAuthn="true"' : "") + ">" +
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

// One account signed in afresh in browser `b` (prompt=login), answering
// the ID Token.
async function signInAs(b, username) {
  log.debug("Entering signInAs(). " + username);
  const got = await oidc(b, { prompt: "login", login_hint: username },
                         username);
  assert.ok(got.claims, "signing in as " + username + ": " +
            JSON.stringify(got).slice(0, 300));
  log.debug("Leaving signInAs().");
  return got;
}

async function logoutView(b, query) {
  log.debug("Entering logoutView().");
  await b.go("GET", realmBase() + "/logout" + (query || ""));
  const r = await b.go("GET", realmBase() + "/authn-api/logout" +
                       (query || ""),
                       { headers: { accept: "application/json" } });
  log.debug("Leaving logoutView(). " + r.status);
  return r;
}

function accountKey(view, username) {
  log.debug("Entering accountKey().");
  const found = ((view && view.accounts) || []).filter(function (one) {
    return one.username === username;
  })[0];
  log.debug("Leaving accountKey().");
  return found ? String(found.key) : "";
}

// A form POST from this service's own page.
function postForm(b, url, fields) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return b.go("POST", url, { body: form(fields), headers: {
    "content-type": "application/x-www-form-urlencoded", origin: ORIGIN } });
}

function hiddenFields(markup) {
  log.debug("Entering hiddenFields().");
  const fields = {};
  (String(markup).match(/<input type="hidden"[^>]*>/g) || []).forEach(
    function (tag) {
      const n = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (n) {
        fields[n[1]] = value ? unescapeHtml(value[1]) : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return fields;
}

function samlSlo(nameId, sessionIndex) {
  log.debug("Entering samlSlo().");
  const xml = "<samlp:LogoutRequest " +
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'ID="_mals' + nodeCrypto.randomBytes(8).toString("hex") + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '">' +
    "<saml:Issuer>" + APP + "</saml:Issuer><saml:NameID>" + nameId +
    "</saml:NameID><samlp:SessionIndex>" + sessionIndex +
    "</samlp:SessionIndex></samlp:LogoutRequest>";
  log.debug("Leaving samlSlo().");
  return realmBase() + "/saml2/slo?SAMLRequest=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml, "utf8")).toString("base64"));
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function partOff() {
  log.debug("Entering partOff().");
  log.info("=== 1. off: today's behaviour ===");
  await setting("authn.multipleAccounts", false);
  const b = browser();
  await signInAs(b, person("off"));
  const before = await codeCount("STS-LOGOUT-0013");
  const noStep = await b.go("GET", realmBase() +
                            "/authn-api/logout/accounts",
                            { headers: { accept: "application/json" } });
  const after = await codesSettle("STS-LOGOUT-0013", before + 1);
  check("1a. off: the account step does not exist (400, STS-LOGOUT-0013)",
        function () {
    assert.strictEqual(noStep.status, 400, noStep.text.slice(0, 200));
    assert.ok(after > before, before + " -> " + after);
  });
  const view = await logoutView(b, "");
  check("1b. off: /logout's view is the inventory, with no account in it",
        function () {
    assert.strictEqual(view.status, 200, view.text.slice(0, 200));
    assert.strictEqual(view.json.view.state, "inventory");
    assert.strictEqual(view.json.view.account, undefined);
  });
  const page = await b.go("GET", realmBase() + "/oauth2/logout",
                          { navigate: true });
  check("1c. off: RP-Initiated Logout with no hint asks to confirm and " +
        "offers no account choice", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 200));
    assert.ok(/name="confirm_for"/.test(page.text), page.text.slice(0, 300));
    assert.ok(!/sts_signout_account/.test(page.text));
  });
  const confirmFor = (/name="confirm_for" value="([^"]*)"/.exec(page.text) ||
                      [])[1] || "";
  await postForm(b, realmBase() + "/oauth2/logout",
                 { confirm: "yes", confirm_for: unescapeHtml(confirmFor) });
  const left = await liveFor(person("off"));
  check("1d. off: confirmed, the session ends and the cookie is cleared",
        function () {
    assert.strictEqual(left.length, 0, JSON.stringify(left));
    assert.strictEqual(defaultOf(b), "", JSON.stringify(Object.keys(b.jar)));
  });
  await setting("authn.multipleAccounts", true);
  log.debug("Leaving partOff().");
}

async function partAccountStep() {
  log.debug("Entering partAccountStep().");
  log.info("=== 3-5. on: the account step and what it ends ===");
  const b = browser();
  const alice = person("alice");
  const bob = person("bob");
  const carol = person("carol");
  await signInAs(b, alice);
  await signInAs(b, bob);
  const bobSid = (await liveFor(bob))[0];
  check("2a. alice and bob signed in to one browser, bob the default",
        function () {
    assert.strictEqual(defaultOf(b), bobSid);
  });
  let step = await logoutView(b, "");
  const keys = { alice: accountKey(step.json.view, alice),
                 bob: accountKey(step.json.view, bob) };
  let answer = await b.act("/authn-api/logout/accounts",
                           { account: keys.alice }, step.json.csrf);
  check("3a. choosing alice answers her sign-out page", function () {
    assert.strictEqual(answer.status, 200, String(answer.text)
      .slice(0, 300));
    assert.strictEqual(answer.json.next, "inventory");
    assert.ok(/\/logout\?account=/.test(answer.json.location) &&
              answer.json.location.indexOf(encodeURIComponent(keys.alice)) >
              0, answer.json.location);
  });
  step = await logoutView(b, "?account=" + encodeURIComponent(keys.alice));
  check("3b. her inventory, carrying her account for the forms after it",
        function () {
    assert.strictEqual(step.json.view.state, "inventory");
    assert.strictEqual(step.json.view.username, alice);
    assert.strictEqual(step.json.view.account, keys.alice);
  });
  answer = await b.act("/authn-api/logout", { scope: "global",
    username: alice, account: keys.alice }, step.json.csrf);
  const aliceLeft = await liveFor(alice);
  const bobLeft = await liveFor(bob);
  const listed = await accountsList(b);
  check("3c. alice's global sign-out ended her session and left bob's; the " +
        "default cookie (bob's) was kept, and alice is listed signed out",
        function () {
    assert.strictEqual(answer.status, 200, String(answer.text)
      .slice(0, 300));
    assert.strictEqual(aliceLeft.length, 0);
    assert.strictEqual(bobLeft.length, 1);
    assert.strictEqual(defaultOf(b), bobSid);
    assert.strictEqual(stateOf(listed.json, alice), "signed-out");
  });
  await signInAs(b, alice);
  const aliceSid = (await liveFor(alice))[0];
  check("4a. alice signed in again: she is the default", function () {
    assert.strictEqual(defaultOf(b), aliceSid);
  });
  step = await logoutView(b, "?account=" + encodeURIComponent(keys.alice));
  answer = await b.act("/authn-api/logout", { scope: "global",
    username: alice, account: keys.alice }, step.json.csrf);
  const aliceGone = await liveFor(alice);
  check("4b. signing the DEFAULT out made the next live account (bob) the " +
        "default", function () {
    assert.strictEqual(aliceGone.length, 0);
    assert.strictEqual(defaultOf(b), bobSid);
  });
  check("4c. another account is still here, so storage is left alone " +
        "(#1440)", function () {
    assert.strictEqual(answer.headers.get("clear-site-data"), null);
  });
  await signInAs(b, carol);
  step = await logoutView(b, "");
  const gone = await codeCount("STS-LOGOUT-0012");
  answer = await b.act("/authn-api/logout/accounts", { account: keys.alice },
                       step.json.csrf);
  const goneAfter = await codesSettle("STS-LOGOUT-0012", gone + 1);
  check("5a. alice, no longer signed in here, is refused (409, " +
        "STS-LOGOUT-0012) and the step drawn again", function () {
    assert.strictEqual(answer.status, 409, String(answer.text)
      .slice(0, 300));
    assert.strictEqual(answer.json.view.state, "accounts");
    assert.ok(goneAfter > gone, gone + " -> " + goneAfter);
  });
  answer = await b.act("/authn-api/logout/accounts", { account: "all" },
                       step.json.csrf);
  const bobAll = await liveFor(bob);
  const carolAll = await liveFor(carol);
  check("5b. every account in this browser: bob and carol both signed out, " +
        "and the cookie cleared", function () {
    assert.strictEqual(answer.status, 200, String(answer.text)
      .slice(0, 300));
    assert.strictEqual(answer.json.next, "signed-out");
    assert.strictEqual(bobAll.length + carolAll.length, 0);
    assert.strictEqual(defaultOf(b), "");
  });
  check("5c. the last account here is gone, so the browser is told to drop " +
        "storage, and never cookies (#1440)", function () {
    assert.strictEqual(answer.headers.get("clear-site-data"), '"storage"');
  });
  log.debug("Leaving partAccountStep().");
}

async function partRpInitiated() {
  log.debug("Entering partRpInitiated().");
  log.info("=== 6. RP-Initiated Logout ===");
  const b = browser();
  const alice = person("rp-alice");
  const bob = person("rp-bob");
  const aliceIn = await signInAs(b, alice);
  await signInAs(b, bob);
  await b.go("GET", realmBase() + "/oauth2/logout?" +
             form({ id_token_hint: aliceIn.idToken }),
             { headers: { "sec-fetch-dest": "image",
                          "sec-fetch-mode": "no-cors" } });
  const afterImage = await liveFor(alice);
  check("6a-ii. an image naming a verified hint ends nothing (#1443)",
        function () {
    assert.strictEqual(afterImage.length, 1);
  });
  const page = await b.go("GET", realmBase() + "/oauth2/logout",
                          { navigate: true });
  const forms = page.text.split("<form").filter(function (one) {
    return /sts_signout_account/.test(one);
  });
  check("6c. with no hint and two accounts, the page asks which (a form " +
        "per account)", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 200));
    assert.strictEqual(forms.length, 2, page.text.slice(0, 500));
  });
  const bobForm = forms.filter(function (one) {
    return one.indexOf(bob) >= 0;
  })[0] || "";
  const fields = hiddenFields(bobForm);
  fields.confirm = "yes";
  await postForm(b, realmBase() + "/oauth2/logout", fields);
  const bobLeft = await liveFor(bob);
  const aliceLeft = await liveFor(alice);
  check("6d. choosing bob there ends bob's session and only his",
        function () {
    assert.strictEqual(bobLeft.length, 0);
    assert.strictEqual(aliceLeft.length, 1);
  });
  log.debug("Leaving partRpInitiated().");
}

async function partSaml() {
  log.debug("Entering partSaml().");
  log.info("=== 7. SAML 2.0 Single Logout ===");
  const b = browser();
  const alice = person("sp-alice");
  const bob = person("sp-bob");
  let r = await follow(b, samlSso({}));
  if (r.screen) {
    r = await signInThere(b, r.screen, bob);
  }
  r = await follow(b, samlSso({ force: true }));
  if (r.screen) {
    r = await signInThere(b, r.screen, alice);
  }
  if (r.picker) {
    const opened = await openPicker(b, r.picker);
    const another = await pickerAct(b, opened, "another", {});
    r = await signInThere(b, another.location, alice);
  }
  const spAlice = (await liveFor(alice))[0];
  const spBob = (await liveFor(bob))[0];
  check("7a. bob then alice signed in to one service provider; alice the " +
        "default", function () {
    assert.ok(spAlice && spBob, JSON.stringify({ a: spAlice, b: spBob }));
    assert.strictEqual(defaultOf(b), spAlice);
  });
  await b.go("GET", samlSlo(bob, spBob));
  const bobLeft = await liveFor(bob);
  const aliceLeft = await liveFor(alice);
  check("7b. a front-channel LogoutRequest whose SessionIndex is bob's ends " +
        "bob's session in the set, not the default (alice's)", function () {
    assert.strictEqual(bobLeft.length, 0);
    assert.strictEqual(aliceLeft.length, 1);
    assert.strictEqual(defaultOf(b), spAlice);
  });
  log.debug("Leaving partSaml().");
}

async function wsfedIn(b, username, fresh) {
  log.debug("Entering wsfedIn(). " + username);
  let r = await follow(b, realmBase() + "/wsfed?wa=wsignin1.0&wtrealm=" +
                       encodeURIComponent(APP) + "&wreply=" +
                       encodeURIComponent(REPLY) +
                       (fresh ? "&wfresh=0" : ""));
  if (r.screen) {
    r = await signInThere(b, r.screen, username);
  }
  log.debug("Leaving wsfedIn().");
  return r;
}

async function partWsfed() {
  log.debug("Entering partWsfed().");
  log.info("=== 8. WS-Federation ===");
  const b = browser();
  const alice = person("ws-alice");
  const bob = person("ws-bob");
  await wsfedIn(b, alice, false);
  await wsfedIn(b, bob, true);
  const both = [await liveFor(alice), await liveFor(bob)];
  check("8a. alice and bob both signed in to the relying party",
        function () {
    assert.strictEqual(both[0].length, 1, JSON.stringify(both));
    assert.strictEqual(both[1].length, 1, JSON.stringify(both));
  });
  const page = await b.go("GET", realmBase() + "/wsfed?wa=wsignout1.0&" +
                          "wtrealm=" + encodeURIComponent(APP),
                          { navigate: true });
  const links = page.text.match(/href="[^"]*sts_signout_account=[^"]*"/g) ||
    [];
  const stillBoth = [await liveFor(alice), await liveFor(bob)];
  check("8b. wsignout1.0 asks which account (a link each) and ends nothing " +
        "yet", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 200));
    assert.strictEqual(links.length, 2, page.text.slice(0, 500));
    assert.strictEqual(stillBoth[0].length + stillBoth[1].length, 2);
  });
  const step = await logoutView(b, "");
  const bobKey = accountKey(step.json && step.json.view, bob);
  const bobLink = links.filter(function (one) {
    return one.indexOf(encodeURIComponent(bobKey)) >= 0;
  })[0] || "";
  const drawn = unescapeHtml(bobLink.replace(/^href="/, "")
    .replace(/"$/, ""));
  const prefix = "/realm/" + REALM;
  // In a trust realm each account's link carries the realm's prefix ONCE,
  // `/realm/<id>/wsfed?…` (it carried it twice until fix/node-defects-1114,
  // D12), and is followed as drawn.
  check("8b-ii. each account's link names the realm's prefix once",
        function () {
    assert.ok(drawn.indexOf(prefix + "/wsfed?") === 0, drawn);
    assert.ok(drawn.indexOf(prefix + prefix) < 0, drawn);
  });
  await b.go("GET", new URL(drawn, ORIGIN + "/").toString(),
             { navigate: true });
  const afterLink = [await liveFor(alice), await liveFor(bob)];
  check("8c. following bob's link ends his session only", function () {
    assert.ok(bobKey, step.text.slice(0, 300));
    assert.strictEqual(afterLink[1].length, 0, JSON.stringify(afterLink));
    assert.strictEqual(afterLink[0].length, 1, JSON.stringify(afterLink));
  });
  await wsfedIn(b, bob, true);
  const cleanup = await b.go("GET", realmBase() + "/wsfed?wa=" +
                             "wsignoutcleanup1.0&wtrealm=" +
                             encodeURIComponent(APP), { navigate: true });
  const afterCleanup = [await liveFor(alice), await liveFor(bob)];
  check("8d. wsignoutcleanup1.0 asks nobody and ends every session of the " +
        "set that signed in to the realm", function () {
    assert.strictEqual(cleanup.status, 200, cleanup.text.slice(0, 200));
    assert.ok(!/sts_signout_account/.test(cleanup.text));
    assert.strictEqual(afterCleanup[0].length + afterCleanup[1].length, 0,
                       JSON.stringify(afterCleanup));
  });
  log.debug("Leaving partWsfed().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Several accounts signing out at " + base + ", realm " + REALM);
  await setUp();
  await partOff();
  await partAccountStep();
  await partRpInitiated();
  await partSaml();
  await partWsfed();
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
  .name("sts_multi_account_logout")
  .description("#561 (D12, #444): several accounts in one browser " +
    "signing out — " +
    "the account step off and on, one account's global sign-out, the " +
    "default moved, a gone account, every account, RP-Initiated Logout's " +
    "choice, SAML front-channel SLO by SessionIndex, and WS-Federation's " +
    "wsignout1.0 and wsignoutcleanup1.0.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

main();
