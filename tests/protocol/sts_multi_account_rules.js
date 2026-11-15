// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_multi_account_rules.js
//
// ---------------------------------------------------------------------------
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER: THE RULES `sts_multi_account.js`
// DOES NOT ASK, OVER THE WIRE (#561).
//
// D12 (#444): carries over what a client can see of
// `tests/multi_account_protocols.js` and `tests/multi_account_sessions.js`.
// `sts_multi_account.js` already holds the picker, login_hint,
// prompt=select_account and prompt=none, a SAML <Subject> and IsPassive,
// WS-Federation's picker, the sign-out's account step and forget; this job
// asks the rest, in three throwaway realms of its own, with one cookie jar
// per browser and people who type real passwords:
//
//   A. OFF (`authn.multipleAccounts` false, the old behaviour unchanged): a
//      SAML 2.0 sign-in writes no account-set cookie and the account list
//      says the feature is off; a second person signing in (ForceAuthn)
//      ENDS the first one's session, whose cookie then signs nobody in; a
//      <Subject> naming the first person changes nothing; IsPassive with no
//      session is NoPassive with today's sentence; the OP iframe's script
//      is byte for byte the one before #561 (its SHA-256); no static
//      surface's shell carries `data-sts-accounts`.
//   B. ON, THE PROTOCOLS: every shell says `data-sts-accounts="on"`;
//      ForceAuthn is a FRESH sign-in, never the picker, and adds the
//      account; a NameID naming nobody signed in here goes to the sign-in
//      screen with that name filled in; a transient NameID is no hint (the
//      picker); IsPassive with a choice to make is NoPassive with a generic
//      sentence (no count, no word of accounts) and an `account.ambiguous`
//      row; SAML 1.1 reaches the picker; WS-Federation's `wfresh` the
//      screen; Session Management's browser-state cookie lists both
//      accounts' states and the script served — run here in a VM against
//      that cookie — answers `unchanged` for either account and `changed`
//      once one's state is gone.
//   C. ON, THE ACCOUNT SET: the same person signing in again
//      re-authenticates their own session (the same `sid`); a selection
//      ticket is spent once, chooses nothing in another browser and nothing
//      at another address; an account whose session ended between the
//      picker and the click goes to the sign-in screen with its name and no
//      ticket, and is remembered as signed out; an account the browser does
//      not hold is refused 409 (STS-AUTHN-0345); forgetting a signed-in one
//      is refused 409 (STS-AUTHN-0347); the full-set rule
//      (`authn.maxBrowserAccounts` 2: a third live account is refused,
//      STS-AUTHN-0340, and with one signed out it is admitted and the set
//      stays at two); a browser signed in with the setting off gets a set
//      around its session when it is turned on (D12's adoption); the
//      portal's wallet enrolment with two accounts live is refused without
//      a `login_hint` (STS-VC-0093), admitted with one naming one of them,
//      refused with one naming nobody here.
//
// Codes are read off the realm's `/admin-api/audit`, never off a response.
//
// NOT CARRIED, and why: the clean-up job's sweep and the age-out of a
// remembered account (a clock: the job runs on the scheduler, and an
// account's age cannot be moved from outside); a set that cannot be read
// (STS-AUTHN-0344, the store failing — nothing a client can cause); the
// ticket taken off the request before a route sees it and which session row
// a request resolved to (store facts: the wire shows only that the flow
// continued as the right person, which C asserts); `accountChoiceNeeded()`'s
// reasons and the audit actor's session (module answers). GNAP's `user`
// hint and its page's API calls (`multi_account_protocols.js` part 8) need
// a grant made with an interaction and approved through the picker; it is
// OWED to the GNAP family's phase (8), where `gnap_flow.js` drives the
// interaction.
//
// THE REALMS are throwaway and inherit the process's mode; each is removed
// only when STS_TEST_REMOVE_REALMS=1 (a private probe's switch;
// tests/CLAUDE.md, *No job removes a realm*).
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const navigation = require("./navigation.js");
const assert = require("assert");
const nodeCrypto = require("crypto");
const vm = require("vm");
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
var log = bunyan.createLogger({ name: "sts_multi_account_rules",
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
const REALM_OFF = "mar-off-" + TAG;
const REALM_ON = "mar-on-" + TAG;
const REALM_ADOPT = "mar-adopt-" + TAG;
const ALICE = names.usernameFor("mar-alice");
const BOB = names.usernameFor("mar-bob");
const CAROL = names.usernameFor("mar-carol");
const DAVE = names.usernameFor("mar-dave");
const NOBODY = names.usernameFor("mar-nobody");
const PASSWORD = "Mar-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const APP = "mar-app-" + TAG;
const SECRET = "mar-secret-" + TAG + "-" +
  nodeCrypto.randomBytes(16).toString("hex");
const RP = "https://" + APP + ".example.test";
const REDIRECT = RP + "/cb";
const ACS = RP + "/acs";
const REPLY = RP + "/wsfed";
// The OP iframe's script as it was before #561, by its SHA-256
// (`tests/multi_account_protocols.js`'s SCRIPT_BEFORE_561): what a realm
// with `authn.multipleAccounts` off must still be served, byte for byte.
const SCRIPT_BEFORE_561 =
  "a1d2dd635433c09291ca125a9e9392e7f82213c306cd6d46e0656d62931e2817";
const OFF_PASSIVE = "There is no browser session here, and IsPassive " +
  "forbids asking for one.";
const ON_PASSIVE = "This request cannot be answered without asking the " +
  "person at the browser, and IsPassive forbids asking.";
// The fewest checks a full run makes: a section that stops being called
// fails the job rather than passing quietly.
const FLOOR = 31;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// The realm every helper below speaks to; a section sets it.
let current = REALM_ON;

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + (realm || current);
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

function sha256Hex(text) {
  log.debug("Entering sha256Hex().");
  log.debug("Leaving sha256Hex().");
  return nodeCrypto.createHash("sha256").update(String(text), "utf8")
    .digest("hex");
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

async function setting(realm, key, value) {
  log.debug("Entering setting(). " + realm + " " + key);
  log.debug("Leaving setting().");
  return ok(realmBase(realm) + "/admin-api/config/set",
            { key: key, value: value }, "set " + key + " in " + realm);
}

// How many rows of the realm's audit log carry `code`, waited for a little
// because a row may land just after the answer.
async function codeCount(realm, code, atLeast) {
  log.debug("Entering codeCount(). " + code);
  let n = 0;
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", realmBase(realm) + "/admin-api/audit?per=500" +
                         "&code=" + encodeURIComponent(code));
    n = Number((r.json && r.json.matched) || 0);
    if (atLeast === undefined || n >= atLeast) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
  }
  log.debug("Leaving codeCount(). " + n);
  return n;
}

async function actionCount(realm, action, atLeast) {
  log.debug("Entering actionCount(). " + action);
  let n = 0;
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", realmBase(realm) + "/admin-api/audit?per=500" +
                         "&action=" + encodeURIComponent(action));
    n = Number((r.json && r.json.matched) || 0);
    if (atLeast === undefined || n >= atLeast) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
  }
  log.debug("Leaving actionCount(). " + n);
  return n;
}

// ---------------------------------------------------------------------------
// ONE BROWSER: a cookie jar, and requests with redirects left to the caller
// (`sts_multi_account.js`'s arrangement).
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

function accountSetCookie(jar) {
  log.debug("Entering accountSetCookie().");
  const name = Object.keys(jar).filter(function (one) {
    return /^(?:__Host-)?sts_accounts/.test(one);
  })[0];
  log.debug("Leaving accountSetCookie().");
  return name || "";
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

// A second browser holding a copy of this one's cookies as they are now.
function copyOf(b) {
  log.debug("Entering copyOf().");
  const other = browser();
  Object.keys(b.jar).forEach(function (k) {
    other.jar[k] = b.jar[k];
  });
  log.debug("Leaving copyOf().");
  return other;
}

// ---------------------------------------------------------------------------
// FOLLOWING A FLOW: redirects on this service are followed, the consent
// screen is answered Allow, and the walk stops at the sign-in screen, the
// account picker, a redirect off the service, or a page.
// ---------------------------------------------------------------------------
async function follow(b, url) {
  log.debug("Entering follow().");
  let r = await b.go("GET", url);
  for (let hops = 0; hops < 12; hops += 1) {
    if (r.status < 300 || r.status >= 400 || !r.location) {
      break;
    }
    if (/\/authn\/login(?:\?[^#]*)?[?&#]authn=/.test(r.location) ||
        /\/authn\/accounts(?:\?[^#]*)?[?&#]authn=/.test(r.location)) {
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
    screen: /\/authn\/login(?:\?[^#]*)?[?&#]authn=/.test(at) ? at : "",
    picker: /\/authn\/accounts(?:\?[^#]*)?[?&#]authn=/.test(at) ? at : ""
  };
}

async function signInThere(b, where, username) {
  log.debug("Entering signInThere(). " + username);
  const r = await authnSignin.signInWithJar(realmBase(), where,
    { action: "login", username: username, password: PASSWORD }, b.jar,
    { ignoreOffer: true });
  log.debug("Leaving signInThere(). " + r.status);
  return r;
}

async function signInAndFollow(b, where, username) {
  log.debug("Entering signInAndFollow(). " + username);
  const r = await signInThere(b, where, username);
  assert.ok(r.status === 303 && r.location,
            "signing in as " + username + " should answer where to go: " +
            r.status + " " + String(r.text || JSON.stringify(r.json))
              .slice(0, 300));
  const on = await follow(b, r.location);
  log.debug("Leaving signInAndFollow().");
  return on;
}

// The sign-in screen's view: what the page draws, the hint among it.
async function screenView(b, where) {
  log.debug("Entering screenView().");
  const opened = await authnSignin.screen(realmBase(), where,
                                          { cookie: cookieOf(b.jar) });
  log.debug("Leaving screenView().");
  return opened.view || {};
}

async function openPicker(b, where) {
  log.debug("Entering openPicker().");
  const id = authnSignin.pendingIdOf(where);
  await b.go("GET", where);
  const r = await b.go("GET", realmBase() + "/authn-api/pending/" +
                       encodeURIComponent(id) + "/accounts",
                       { headers: { accept: "application/json" } });
  assert.ok(r.status === 200 && r.json && r.json.view,
            "the picker should draw: " + r.status + " " +
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

// ---------------------------------------------------------------------------
// OPENID CONNECT.
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
                screen: r.screen, picker: r.picker, sessionState: "" };
  if (!r.location || r.location.indexOf(REDIRECT) !== 0) {
    log.debug("Leaving atClient(). Not at the client.");
    return out;
  }
  const params = new URL(r.location).searchParams;
  out.error = params.get("error") || "";
  out.code = params.get("code") || "";
  out.sessionState = params.get("session_state") || "";
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

async function oidc(b, extra, person) {
  log.debug("Entering oidc().");
  const asked = authorizeUrl(extra);
  let r = await follow(b, asked.url);
  if (r.screen && person) {
    r = await signInAndFollow(b, r.screen, person);
  }
  const out = await atClient(r, asked.verifier);
  out.verifier = asked.verifier;
  log.debug("Leaving oidc().");
  return out;
}

async function silently(b, username) {
  log.debug("Entering silently(). " + username);
  const r = await oidc(b, { prompt: "none", login_hint: username }, null);
  log.debug("Leaving silently(). " + (r.error || "a code"));
  return r;
}

// ---------------------------------------------------------------------------
// SAML 2.0: a signed AuthnRequest on the Redirect binding, and the Response
// the identity provider's POST form carries.
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
    const subject = [{ name: "commonName", value: "multi-account rules SP" }];
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
    ? "<saml:Subject><saml:NameID" + (o.format
      ? ' Format="' + o.format + '"' : "") + ">" + o.subject +
      "</saml:NameID></saml:Subject>" : "";
  const xml = "<samlp:AuthnRequest " +
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'ID="_mar' + nodeCrypto.randomBytes(8).toString("hex") + '" ' +
    'Version="2.0" IssueInstant="' + new Date().toISOString() + '" ' +
    'Destination="' + realmBase() + '/saml2/sso" ' +
    'AssertionConsumerServiceURL="' + ACS + '" ' +
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"' +
    (o.force ? ' ForceAuthn="true"' : "") +
    (o.passive ? ' IsPassive="true"' : "") + ">" +
    "<saml:Issuer>" + APP + "</saml:Issuer>" + subject +
    "</samlp:AuthnRequest>";
  const request = zlib.deflateRawSync(Buffer.from(xml, "utf8"))
    .toString("base64");
  const sigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  const signed = "SAMLRequest=" + encodeURIComponent(request) +
    "&RelayState=" + encodeURIComponent("mar") +
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
  const message = /StatusMessage>([^<]*)</.exec(xml);
  log.debug("Leaving samlOf(). " + codes.join(","));
  return { codes: codes, xml: xml,
           message: message ? unescapeHtml(message[1]) : "" };
}

function whose(text) {
  log.debug("Entering whose().");
  const t = String(text || "");
  const found = [ALICE, BOB, CAROL].filter(function (one) {
    return t.indexOf(one) >= 0;
  });
  log.debug("Leaving whose().");
  return found.length === 1 ? found[0] : "";
}

// A SAML 2.0 request, signed in at the screen as `person` where it stops
// there: the walk's end and the Response.
async function saml(b, o, person) {
  log.debug("Entering saml().");
  let r = await follow(b, samlSso(o));
  const screened = !!r.screen;
  const picker = r.picker;
  const screenAt = r.screen;
  if (r.screen && person) {
    r = await signInAndFollow(b, r.screen, person);
  }
  const out = samlOf(r.text);
  log.debug("Leaving saml().");
  return { r: r, saml: out, screened: screened, picker: picker,
           screenAt: screenAt, who: out ? whose(out.xml) : "" };
}

// ---------------------------------------------------------------------------
// THE REALMS.
// ---------------------------------------------------------------------------
async function makeRealm(realm, multiple) {
  log.debug("Entering makeRealm(). " + realm);
  await ok(base + "/admin-api/realms/create",
           { id: realm, domain: realm + ".example.net",
             name: "#561 rules " + realm },
           "created the realm " + realm);
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason: one
  // address signing several people in, in seconds, is what it counts.
  await setting(realm, "risk.assessSignIns", false);
  await setting(realm, "authn.multipleAccounts", multiple);
  await setting(realm, "oauth2.backchannelLogout", true);
  for (const one of [ALICE, BOB, CAROL, DAVE]) {
    await registry.ensurePerson(realmBase(realm), one, PASSWORD);
  }
  await ok(realmBase(realm) + "/admin-api/applications/create", {
    identifier: APP, name: "#561 rules " + TAG,
    protocols: ["oauth2", "oidc", "saml2", "saml11", "wsfed"],
    fields: { oauthClientId: [APP], oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic",
              oauthAllowedScope: ["openid"],
              samlEntityId: [APP], samlAssertionConsumerService: [ACS],
              samlSigningCertificate: [samlSpCredential().certificatePem],
              wsfedRealm: [APP], wsfedReplyUrl: [REPLY] } },
    realm + ": created the application");
  await ok(realmBase(realm) + "/admin-api/consent/grant-global-consent",
           { client: APP, scope: "openid" }, realm + ": consented openid");
  log.debug("Leaving makeRealm().");
}

// The four shells the in-process file asks: the front door, the portal, the
// console and a description page.
async function shells() {
  log.debug("Entering shells().");
  const out = [];
  for (const one of ["/", "/portal", "/admin", "/saml2"]) {
    const got = await call("GET", realmBase() + one, undefined,
                           { accept: "text/html" });
    out.push({ path: one, status: got.status,
               on: /<html[^>]* data-sts-accounts="on"/.test(got.text),
               any: /data-sts-accounts/.test(got.text) });
  }
  log.debug("Leaving shells().");
  return out;
}

// The OP iframe's one inline script, as the page carries it (#1297).
async function iframeScript() {
  log.debug("Entering iframeScript().");
  const page = await call("GET", realmBase() + "/oauth2/check_session",
                          undefined, { accept: "text/html" });
  const m = /<script>([\s\S]*?)<\/script>/.exec(String(page.text || ""));
  log.debug("Leaving iframeScript(). " + page.status);
  return { status: page.status, text: m ? m[1] : "" };
}

function holds(sessionState, browserState) {
  log.debug("Entering holds().");
  const salt = String(sessionState).split(".").pop();
  const digest = nodeCrypto.createHash("sha256")
    .update(APP + " " + RP + " " + String(browserState || "") + " " + salt,
            "utf8").digest("base64url");
  log.debug("Leaving holds().");
  return digest + "." + salt === sessionState;
}

// Runs the served script in a VM with `cookie` as document.cookie and asks
// it what an RP's `postMessage` would: `<client_id> <session_state>`.
async function askScript(script, cookie, state) {
  log.debug("Entering askScript().");
  const answers = [];
  let handler = null;
  const context = vm.createContext({
    window: { addEventListener: function (type, fn) {
      if (type === "message") {
        handler = fn;
      }
    }, crypto: nodeCrypto.webcrypto },
    document: { cookie: cookie }, btoa: btoa, TextEncoder: TextEncoder,
    Uint8Array: Uint8Array, String: String });
  vm.runInContext(script, context);
  handler({ data: APP + " " + state, origin: RP,
            source: { postMessage: function (text) {
              answers.push(text);
            } } });
  for (let i = 0; i < 300 && !answers.length; i += 1) {
    await new Promise(function (done) {
      setTimeout(done, 10);
    });
  }
  log.debug("Leaving askScript().");
  return answers[0] || "(no answer)";
}

// ---------------------------------------------------------------------------
// A. OFF.
// ---------------------------------------------------------------------------
async function partOff() {
  log.debug("Entering partOff().");
  current = REALM_OFF;
  log.info("=== A. off: the old behaviour, unchanged ===");
  const b = browser();
  let got = await saml(b, {}, ALICE);
  const list = await accountsList(b);
  check("A1. off: a SAML 2.0 sign-in as alice, no account-set cookie, and " +
        "the account list says the feature is off", function () {
    assert.ok(got.saml && got.saml.codes[0] === "Success" &&
              got.who === ALICE, JSON.stringify(got.saml && got.saml.codes));
    assert.strictEqual(accountSetCookie(b.jar), "",
                       Object.keys(b.jar).join(","));
    assert.strictEqual(list.status, 200, list.text.slice(0, 300));
    assert.strictEqual(list.json.enabled, false, list.text.slice(0, 300));
  });
  const aliceOnly = copyOf(b);
  got = await saml(b, { force: true }, BOB);
  check("A2. off: ForceAuthn goes to the screen, and bob signs in",
        function () {
    assert.ok(got.screened && got.saml && got.who === BOB,
              JSON.stringify({ screened: got.screened, who: got.who }));
  });
  const ended = await saml(aliceOnly, {}, null);
  check("A3. off: bob's sign-in ENDED alice's session — her cookie now " +
        "signs nobody in, as it always did", function () {
    assert.ok(ended.screened && !ended.saml, JSON.stringify({
      screened: ended.screened, who: ended.who }));
  });
  got = await saml(b, { subject: ALICE }, null);
  check("A4. off: a <Subject> naming alice changes nothing — single sign-on " +
        "as the session the cookie names, bob", function () {
    assert.ok(!got.screened && got.saml && got.who === BOB,
              JSON.stringify({ screened: got.screened, who: got.who }));
  });
  got = await saml(browser(), { passive: true }, null);
  check("A5. off: IsPassive with no session is NoPassive with today's " +
        "sentence", function () {
    assert.ok(got.saml && got.saml.codes.indexOf("NoPassive") >= 0,
              JSON.stringify(got.saml && got.saml.codes));
    assert.strictEqual(got.saml.message, OFF_PASSIVE);
  });
  await setting(REALM_OFF, "oauth2.sessionManagement", true);
  const script = await iframeScript();
  check("A6. off: the OP iframe's script is byte for byte the one before " +
        "#561", function () {
    assert.strictEqual(script.status, 200);
    assert.strictEqual(sha256Hex(script.text), SCRIPT_BEFORE_561);
  });
  const drawn = await shells();
  check("A7. off: no static surface's shell carries data-sts-accounts",
        function () {
    assert.ok(drawn.every(function (one) {
      return one.status === 200 && !one.any;
    }), JSON.stringify(drawn));
  });
  log.debug("Leaving partOff().");
}

// ---------------------------------------------------------------------------
// B. ON: THE PROTOCOLS.
// ---------------------------------------------------------------------------
async function partProtocols() {
  log.debug("Entering partProtocols().");
  current = REALM_ON;
  log.info("=== B. on: the protocol sign-ins ===");
  const drawn = await shells();
  check("B1. on: every static surface's shell says data-sts-accounts=\"on\"",
        function () {
    assert.ok(drawn.every(function (one) {
      return one.status === 200 && one.on;
    }), JSON.stringify(drawn));
  });
  const b = browser();
  let got = await saml(b, {}, ALICE);
  check("B2. a SAML 2.0 sign-in as alice writes the account set's cookie",
        function () {
    assert.ok(got.saml && got.who === ALICE, JSON.stringify(got.saml));
    assert.ok(accountSetCookie(b.jar), Object.keys(b.jar).join(","));
  });
  got = await saml(b, {}, null);
  check("B3. with one account, a plain request is single sign-on",
        function () {
    assert.ok(!got.screened && !got.picker && got.who === ALICE,
              JSON.stringify({ screened: got.screened, picker: got.picker }));
  });
  got = await saml(b, { force: true }, BOB);
  const list = await accountsList(b);
  check("B4. ForceAuthn goes to a FRESH sign-in, never the picker, and adds " +
        "bob beside alice", function () {
    assert.ok(got.screened && !got.picker && got.who === BOB,
              JSON.stringify({ screened: got.screened, picker: got.picker,
                               who: got.who }));
    assert.strictEqual(stateOf(list.json, ALICE), "signed-in");
    assert.strictEqual(stateOf(list.json, BOB), "signed-in");
  });
  got = await saml(b, { subject: NOBODY }, null);
  const view = got.screenAt ? await screenView(b, got.screenAt) : {};
  check("B5. a NameID naming nobody signed in here goes to the sign-in " +
        "screen with that name filled in — never another account",
        function () {
    assert.ok(got.screened && !got.picker && !got.saml,
              JSON.stringify({ screened: got.screened, picker: got.picker }));
    assert.strictEqual(view.hint, NOBODY, JSON.stringify(view).slice(0, 300));
  });
  got = await saml(b, { subject: ALICE, format:
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" }, null);
  check("B6. a transient NameID names no account: no hint, so the picker",
        function () {
    assert.ok(got.picker, JSON.stringify({ screened: got.screened,
                                           who: got.who }));
  });
  const rowsBefore = await actionCount(REALM_ON, "account.ambiguous");
  got = await saml(b, { passive: true }, null);
  const rowsAfter = await actionCount(REALM_ON, "account.ambiguous",
                                      rowsBefore + 1);
  check("B7. IsPassive with a choice to make is NoPassive, its sentence " +
        "generic — no count, no word of accounts — with an " +
        "account.ambiguous row", function () {
    assert.ok(got.saml && got.saml.codes.indexOf("NoPassive") >= 0,
              JSON.stringify(got.saml && got.saml.codes));
    assert.strictEqual(got.saml.message, ON_PASSIVE);
    assert.ok(!/\d|account/i.test(got.saml.message), got.saml.message);
    assert.ok(rowsAfter >= rowsBefore + 1, rowsBefore + " -> " + rowsAfter);
  });
  let r = await follow(b, realmBase() + "/saml11/sso?TARGET=" +
    encodeURIComponent(RP + "/target") + "&shire=" + encodeURIComponent(ACS) +
    "&providerId=" + encodeURIComponent(APP) + "&time=" +
    Math.floor(Date.now() / 1000));
  check("B8. SAML 1.1 (no hint, no IsPassive in the profile): the picker",
        function () {
    assert.ok(r.picker, r.status + " " + r.location + " " +
              r.text.slice(0, 200));
  });
  const wsfed = realmBase() + "/wsfed?wa=wsignin1.0&wtrealm=" +
    encodeURIComponent(APP) + "&wreply=" + encodeURIComponent(REPLY);
  r = await follow(b, wsfed);
  const fresh = await follow(b, wsfed + "&wfresh=0");
  check("B9. WS-Federation: the picker, and wfresh a fresh sign-in at the " +
        "screen instead", function () {
    assert.ok(r.picker, r.status + " " + r.location);
    assert.ok(fresh.screen && !fresh.picker,
              fresh.status + " " + fresh.location);
  });

  await setting(REALM_ON, "oauth2.sessionManagement", true);
  const a = await oidc(b, { login_hint: ALICE }, null);
  const bo = await oidc(b, { login_hint: BOB }, null);
  const name = Object.keys(b.jar).filter(function (one) {
    return /sts_op_browser_state$/.test(one);
  })[0] || "sts_op_browser_state";
  const listed = String(b.jar[name] || "").split(".");
  check("B10. Session Management: the browser-state cookie lists BOTH " +
        "accounts' states, and each session_state is over its own",
        function () {
    assert.ok(a.sessionState && bo.sessionState,
              JSON.stringify({ a: a.error, b: bo.error }));
    assert.strictEqual(listed.length, 2, String(b.jar[name]));
    assert.ok(listed.some(function (bs) {
      return holds(a.sessionState, bs);
    }) && listed.some(function (bs) {
      return holds(bo.sessionState, bs);
    }), "no listed state matches");
  });
  const script = await iframeScript();
  const cookieLine = "sts_op_browser_state=" + String(b.jar[name] || "");
  const aOk = await askScript(script.text, cookieLine, a.sessionState);
  const bOk = await askScript(script.text, cookieLine, bo.sessionState);
  const aliceOnly = listed.filter(function (bs) {
    return holds(a.sessionState, bs);
  })[0] || "";
  const bobGone = await askScript(script.text, "sts_op_browser_state=" +
                                  aliceOnly, bo.sessionState);
  check("B11. the script served is the list's (not the one before #561), " +
        "and it answers unchanged for either account and changed once " +
        "bob's state is gone", function () {
    assert.notStrictEqual(sha256Hex(script.text), SCRIPT_BEFORE_561);
    assert.strictEqual(aOk, "unchanged");
    assert.strictEqual(bOk, "unchanged");
    assert.strictEqual(bobGone, "changed");
  });
  log.debug("Leaving partProtocols().");
}

// ---------------------------------------------------------------------------
// C. ON: THE ACCOUNT SET.
// ---------------------------------------------------------------------------
// A person's live sign-on session rows, as `GET /admin-api/sessions` lists
// them (`id` is what `sessions/revoke` takes as `select`), narrowed to one
// sid where `sid` is given.
async function sessionRowOf(username, sid) {
  log.debug("Entering sessionRowOf(). " + username);
  const r = await call("GET", realmBase() + "/admin-api/sessions?per=100&q=" +
                       encodeURIComponent(username));
  const rows = ((r.json && r.json.sessions) || []).filter(function (one) {
    return one.username === username && one.id &&
      (!sid || one.sessionId === sid);
  });
  log.debug("Leaving sessionRowOf(). " + rows.length);
  return rows[0] || null;
}

async function endSession(row) {
  log.debug("Entering endSession().");
  const r = row ? await call("POST", realmBase() +
    "/admin-api/sessions/revoke", { key: row.key, select: row.id })
    : { status: 0, text: "no session row" };
  log.debug("Leaving endSession(). " + r.status);
  return r;
}

async function partSet() {
  log.debug("Entering partSet().");
  current = REALM_ON;
  log.info("=== C. on: the account set ===");
  const b = browser();
  const a1 = await oidc(b, {}, ALICE);
  const b1 = await oidc(b, { prompt: "login" }, BOB);
  const a2 = await oidc(b, { prompt: "login", login_hint: ALICE }, ALICE);
  let list = await accountsList(b);
  check("C1. alice signing in again (the cookie naming bob) " +
        "re-authenticates HER session — the same sid — and the set still " +
        "holds two", function () {
    assert.ok(a1.claims && b1.claims && a2.claims,
              JSON.stringify([a1.error, b1.error, a2.error]));
    assert.ok(a1.claims.sid, "no sid in the ID Token");
    assert.strictEqual(a2.claims.sid, a1.claims.sid);
    assert.strictEqual(a2.claims.sub, a1.claims.sub);
    assert.notStrictEqual(b1.claims.sid, a1.claims.sid);
    assert.strictEqual((list.json.accounts || []).length, 2,
                       list.text.slice(0, 300));
  });

  // TICKETS.
  const asked = authorizeUrl({});
  let r = await follow(b, asked.url);
  let opened = await openPicker(b, r.picker);
  const answer = await pickerAct(b, opened, "select",
                                 { account: keyOf(opened.view, BOB) });
  const resumed = answer.location;
  const viaTicket = await atClient(await follow(b, resumed), asked.verifier);
  const ticket = resumed ? new URL(resumed, base + "/").searchParams
    .get("sts_account") : "";
  check("C2. a choice at the picker resumes the request with a ticket, " +
        "answered as bob", function () {
    assert.ok(ticket, String(resumed));
    assert.ok(viaTicket.claims && viaTicket.claims.sub === b1.claims.sub,
              JSON.stringify(viaTicket));
  });
  const replay = await follow(b, resumed);
  check("C3. the ticket is spent once: the same address again chooses " +
        "nobody (the picker)", function () {
    assert.ok(replay.picker && !replay.location.startsWith(REDIRECT),
              replay.status + " " + replay.location);
  });
  const other = browser();
  const d1 = await oidc(other, {}, DAVE);
  const asked2 = authorizeUrl({});
  r = await follow(b, asked2.url);
  opened = await openPicker(b, r.picker);
  const fresh = await pickerAct(b, opened, "select",
                                { account: keyOf(opened.view, BOB) });
  const crossed = await atClient(await follow(other, fresh.location),
                                 asked2.verifier);
  // OBSERVED (2026-11-15, Node): the foreign ticket is not merely ignored —
  // the other browser, signed in as dave alone, is sent to the sign-in
  // screen rather than answered as dave. The in-process claim is only that
  // bob is never chosen; the wire's answer is pinned as it is.
  check("C4. a ticket for this browser's set presented by ANOTHER browser " +
        "never chooses bob: that browser (dave's) is sent to sign in",
        function () {
    assert.ok(d1.claims, JSON.stringify(d1));
    assert.ok(!crossed.claims || crossed.claims.sub !== b1.claims.sub,
              JSON.stringify(crossed));
    assert.ok(crossed.screen, JSON.stringify(crossed));
  });
  const asked3 = authorizeUrl({});
  r = await follow(b, asked3.url);
  opened = await openPicker(b, r.picker);
  const minted = await pickerAct(b, opened, "select",
                                 { account: keyOf(opened.view, ALICE) });
  const moved = new URL(minted.location, base + "/").searchParams
    .get("sts_account");
  const elsewhere = await follow(b, samlSso({}) + "&sts_account=" +
                                 encodeURIComponent(moved));
  check("C5. a ticket minted for one address chooses nothing at another " +
        "(SAML's, the picker)", function () {
    assert.ok(moved, minted.location);
    assert.ok(elsewhere.picker, elsewhere.status + " " + elsewhere.location);
  });

  // AN ACCOUNT THAT DIED BETWEEN THE PAGE AND THE CLICK.
  const before345 = await codeCount(REALM_ON, "STS-AUTHN-0345");
  const asked4 = authorizeUrl({});
  r = await follow(b, asked4.url);
  opened = await openPicker(b, r.picker);
  const bobKey = keyOf(opened.view, BOB);
  const revoked = await endSession(await sessionRowOf(BOB, b1.claims.sid));
  const dead = await pickerAct(b, opened, "select", { account: bobKey });
  const deadView = dead.location ? await screenView(b, dead.location) : {};
  list = await accountsList(b);
  check("C6. bob's session ended between the picker and the click: " +
        "choosing him goes to the sign-in screen, his name filled in, no " +
        "ticket", function () {
    assert.strictEqual(revoked.status, 200, revoked.text.slice(0, 300));
    assert.ok(dead.status === 200 && dead.next === "redirect" &&
              /\/authn\/login(?:\?[^#]*)?[?&#]authn=/.test(dead.location) &&
              !/sts_account=/.test(dead.location),
              dead.status + " " + JSON.stringify(dead.json));
    assert.strictEqual(deadView.hint, BOB, JSON.stringify(deadView)
      .slice(0, 300));
  });
  check("C7. and bob is remembered as signed out, alice still signed in",
        function () {
    assert.strictEqual(stateOf(list.json, BOB), "signed-out",
                       list.text.slice(0, 300));
    assert.strictEqual(stateOf(list.json, ALICE), "signed-in");
  });
  await oidc(b, { prompt: "login", login_hint: CAROL }, CAROL);
  const asked5 = authorizeUrl({});
  r = await follow(b, asked5.url);
  opened = await openPicker(b, r.picker);
  const stranger = await pickerAct(b, opened, "select",
                                   { account: "urn:uuid:" +
                                     nodeCrypto.randomUUID() });
  const after345 = await codeCount(REALM_ON, "STS-AUTHN-0345",
                                   before345 + 1);
  check("C8. choosing an account this browser does not hold is refused 409, " +
        "STS-AUTHN-0345 recorded, and no code sent", function () {
    assert.strictEqual(stranger.status, 409, String(stranger.text)
      .slice(0, 300));
    assert.ok(after345 >= before345 + 1, before345 + " -> " + after345);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(String(stranger.text)));
  });
  const before347 = await codeCount(REALM_ON, "STS-AUTHN-0347");
  const forgetLive = await pickerAct(b, opened, "forget",
                                     { account: keyOf(opened.view, ALICE) });
  const after347 = await codeCount(REALM_ON, "STS-AUTHN-0347",
                                   before347 + 1);
  const forgetBob = await pickerAct(b, opened, "forget", { account: bobKey });
  check("C9. forgetting a signed-in account is refused 409 (STS-AUTHN-0347); " +
        "a signed-out one is forgotten", function () {
    assert.strictEqual(forgetLive.status, 409, String(forgetLive.text)
      .slice(0, 300));
    assert.ok(after347 >= before347 + 1, before347 + " -> " + after347);
    assert.ok(forgetBob.status === 200 && forgetBob.next === "stay",
              forgetBob.status + " " + String(forgetBob.text).slice(0, 300));
  });

  // THE WALLET ENROLMENT NAMES ITS ACCOUNT.
  await setting(REALM_ON, "oid4vp.signIn", true);
  await setting(REALM_ON, "oid4vp.signInSelfIssued", true);
  const enrol = async function (hint) {
    log.debug("Entering enrol().");
    const got = await b.go("GET", realmBase() + "/authn-api/wallet?siop=1" +
                           "&enrol=1" + (hint ? "&login_hint=" +
                           encodeURIComponent(hint) : ""),
                           { headers: { accept: "application/json" } });
    log.debug("Leaving enrol(). " + got.status);
    return got;
  };
  const before93 = await codeCount(REALM_ON, "STS-VC-0093");
  const bare = await enrol("");
  const hinted = await enrol(ALICE);
  const nobody = await enrol(NOBODY);
  const after93 = await codeCount(REALM_ON, "STS-VC-0093", before93 + 2);
  check("C10. with two accounts live, a wallet enrolment naming neither is " +
        "refused 403, one naming alice is admitted, one naming nobody here " +
        "is refused — STS-VC-0093 twice", function () {
    assert.strictEqual(bare.status, 403, bare.text.slice(0, 300));
    assert.strictEqual(hinted.status, 200, hinted.text.slice(0, 300));
    assert.strictEqual(nobody.status, 403, nobody.text.slice(0, 300));
    assert.ok(after93 >= before93 + 2, before93 + " -> " + after93);
  });

  // THE FULL-SET RULE.
  await setting(REALM_ON, "authn.maxBrowserAccounts", 2);
  const full = browser();
  const fa = await oidc(full, {}, ALICE);
  await oidc(full, { prompt: "login" }, BOB);
  const before340 = await codeCount(REALM_ON, "STS-AUTHN-0340");
  const third = await follow(full, authorizeUrl({ prompt: "login" }).url);
  const refused = third.screen ? await signInThere(full, third.screen, CAROL)
    : { status: 0 };
  const after340 = await codeCount(REALM_ON, "STS-AUTHN-0340",
                                   before340 + 1);
  list = await accountsList(full);
  check("C11. a third live account in a set of two is refused, " +
        "STS-AUTHN-0340, and the set still holds the two", function () {
    assert.ok(third.screen, third.status + " " + third.location);
    assert.ok(!(refused.status === 303 && refused.next === "redirect"),
              refused.status + " " + JSON.stringify(refused.json || {})
                .slice(0, 300));
    assert.ok(after340 >= before340 + 1, before340 + " -> " + after340);
    assert.strictEqual(stateOf(list.json, CAROL), "absent");
    assert.strictEqual(stateOf(list.json, ALICE), "signed-in");
  });
  // Two of alice's sessions are live in this realm (two browsers); the one
  // ended is the one the full browser holds, which its ID Token names.
  const endAlice = await endSession(await sessionRowOf(ALICE, fa.claims.sid));
  const roomy = await oidc(full, { prompt: "login" }, CAROL);
  list = await accountsList(full);
  check("C12. with one signed out, the remembered account makes room: carol " +
        "signs in, and the set holds no more than two", function () {
    assert.strictEqual(endAlice.status, 200, endAlice.text.slice(0, 300));
    assert.ok(roomy.claims, JSON.stringify(roomy));
    assert.strictEqual(stateOf(list.json, CAROL), "signed-in");
    assert.ok((list.json.accounts || []).length <= 2,
              list.text.slice(0, 300));
  });
  log.debug("Leaving partSet().");
}

// ---------------------------------------------------------------------------
// C (adoption). A SESSION FROM BEFORE THE SETTING GETS A SET.
// ---------------------------------------------------------------------------
async function partAdopt() {
  log.debug("Entering partAdopt().");
  current = REALM_ADOPT;
  log.info("=== C13. a session from before the setting gets a set ===");
  const b = browser();
  const a = await oidc(b, {}, ALICE);
  const noSet = accountSetCookie(b.jar);
  await setting(REALM_ADOPT, "authn.multipleAccounts", true);
  const bo = await oidc(b, { prompt: "login" }, BOB);
  const still = await silently(b, ALICE);
  const list = await accountsList(b);
  check("C13. signed in with the setting off, then on: bob signs in beside " +
        "alice, whose session became the set's first", function () {
    assert.ok(a.claims && bo.claims, JSON.stringify([a.error, bo.error]));
    assert.strictEqual(noSet, "");
    assert.ok(still.claims && still.claims.sid === a.claims.sid,
              JSON.stringify(still));
    assert.strictEqual(stateOf(list.json, ALICE), "signed-in");
    assert.strictEqual(stateOf(list.json, BOB), "signed-in");
  });
  log.debug("Leaving partAdopt().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Several accounts' rules at " + base + ", realms " + REALM_OFF +
           ", " + REALM_ON + ", " + REALM_ADOPT);
  await makeRealm(REALM_OFF, false);
  await makeRealm(REALM_ON, true);
  await makeRealm(REALM_ADOPT, false);
  await partOff();
  await partProtocols();
  await partSet();
  await partAdopt();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section " +
            "has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) the three realms are removed at the
// end, pass or fail. A suite run leaves them standing (tests/CLAUDE.md, *No
// job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [REALM_OFF, REALM_ON, REALM_ADOPT]) {
    const r = await call("POST", base + "/admin-api/realms/remove",
                         { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.info("removing the realms failed: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

const program = new Command();
program
  .name("sts_multi_account_rules")
  .description("#561 over the wire: the setting off unchanged, ForceAuthn, " +
    "a NameID naming nobody, a transient NameID, IsPassive's sentence, SAML " +
    "1.1, wfresh, Session Management's list, re-authentication, tickets, a " +
    "dead account, the full-set rule, adoption and the wallet enrolment.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

main();
