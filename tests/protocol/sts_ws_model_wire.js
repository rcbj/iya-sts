// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ws_model_wire.js
//
// ===========================================================================
// WHAT WS-TRUST AND WS-FEDERATION ANSWER, HELD TO THE RECORDED WIRE, OVER THE
// WIRE (#1579 item 6; #444 D12, phase 7).
//
// `tests/ws_model_wire.js` holds every answer of a scripted conversation,
// byte for byte, to `tests/ws_model_wire.snapshot.json`, from a child
// process on a plain-HTTP loopback port. This job has the same conversation
// with a RUNNING service, in a throwaway development realm of this run's
// own, and holds every answer of the snapshot's DEVELOPMENT pass to it
// after putting back what only the place of the conversation changes:
//
//   * the realm: this run's id (and the cookies and the domain it names)
//     is the recorded `wswire`;
//   * the origin: `https://localhost:<port>` is the recorded
//     `http://127.0.0.1:<port>`, in every spelling;
//   * HSTS and a cookie's `Secure`, which only a TLS listener sends;
//   * the error code the in-process file read off the response object is
//     read here off `/admin-api/audit` — the newest `protocol.call` row the
//     step added, or none;
//   * the session the signed-in steps carry is made by signing in at the
//     screen (the in-process file started one directly; both are a password
//     session of `wswalice`).
//
// and then the in-process file's own normalisation (its placeholders for
// minted ids, instants, ports, key material and random runs). Each step is
// a check.
//
// THE PRODUCT PASS (47 steps) runs in a second realm, recorded `wswirep`:
// its sessions carry two factors — an authenticator app enrolled through
// `/account-api` with `authn.allowOptionalSecondFactor` on for the one
// sign-in that enrols it, then off, and every later sign-in answers the
// screen's code step — and /sts takes an app password scoped to it, made
// on the same page; the agreement product asks before single sign-on is
// given at the consent screen by a session of its own.
//
// OWNED HERE (local: true). Its realm is removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const tls = require("tls");
const fs = require("fs");
const path = require("path");
const K = require("./oauth_wire_kit.js").kit("sts_ws_model_wire");
const authnSignin = require("./authn_signin");

const log = K.log;
const SNAPSHOT = process.env.WS_WIRE_SNAPSHOT ||
  path.join(__dirname, "..", "ws_model_wire.snapshot.json");
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
           "(KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const SKIPPED_HEADERS = ["date", "connection", "keep-alive",
                         "content-length", "etag", "transfer-encoding",
                         "strict-transport-security"];
const SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12 = "http://www.w3.org/2003/05/soap-envelope";
const WST13 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const WST2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust";
const WST2004 = "http://schemas.xmlsoap.org/ws/2004/04/trust";
const WST14 = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
const WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
             "wssecurity-secext-1.0.xsd";
const WSP = "http://schemas.xmlsoap.org/ws/2004/09/policy";
const WSA = "http://www.w3.org/2005/08/addressing";
const SAML2_TT = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-" +
                 "profile-1.1#SAMLV2.0";
const SAML11_TT = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-" +
                  "profile-1.1#SAMLV1.1";
const JWT_TT = "urn:ietf:params:oauth:token-type:jwt";
const KERBEROS_TT = "http://docs.oasis-open.org/wss/oasis-wss-kerberos-" +
                    "token-profile-1.1#GSS_Kerberosv5_AP_REQ";
const BACK = "https://back.wswire.test/service";
const RP = "https://rp.wswire.test/app";
const RP_REPLY = "https://rp.wswire.test/reply";
const PERSON = "wswalice";
const PASSWORD = "Wire-Password-7a!Kq2";
const nodeCrypto = require("crypto");
const portalSignin = require("./portal_signin.js");

// THE REALM THE CONVERSATION IS IN NOW, and every realm it has been in,
// by the id the snapshot records for it.
let REALM = "";
let MODE = "development";
const REALMS = {};
let LEAF = "";
let LAST_BROWSER = null;

function unescapeHtml(text) {
  log.debug("Entering unescapeHtml().");
  log.debug("Leaving unescapeHtml().");
  return String(text).replace(/&#x2B;|&#43;/g, "+")
    .replace(/&#x2F;|&#47;/g, "/").replace(/&#x3D;|&#61;/g, "=")
    .replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

// What an answer carries, decoded, as the in-process file decodes it.
function decoded(res) {
  log.debug("Entering decoded().");
  const out = {};
  const location = String(res.headers.location || "");
  if (location) {
    try {
      const url = new URL(location, "http://127.0.0.1");
      url.searchParams.forEach(function (value, name) {
        out["location.param." + name] = value;
      });
      out["location.path"] = url.origin + url.pathname;
    } catch (e) {
      log.debug("Caught in decoded(): " + ((e && e.message) || e));
      // Recorded as the in-process file records it.
      out["location.unparsed"] = location;
    }
  }
  const body = String(res.body || "");
  const form = /<form[^>]*action="([^"]*)"/.exec(body);
  if (form) {
    out["form.action"] = unescapeHtml(form[1]);
    const inputs = /<input[^>]*>/g;
    let m = inputs.exec(body);
    while (m !== null) {
      const name = /name="([^"]*)"/.exec(m[0]);
      const value = /value="([^"]*)"/.exec(m[0]);
      if (name) {
        out["form." + name[1]] = value ? unescapeHtml(value[1]) : "";
      }
      m = inputs.exec(body);
    }
  }
  log.debug("Leaving decoded().");
  return out;
}

// One request as the in-process file made it: a browser's User-Agent and
// nothing else of the caller's own.
function request(method, target, cookie, body, contentType) {
  log.debug("Entering request(). " + method + " " + target);
  const url = new URL(target, K.base);
  return new Promise(function (resolve) {
    const headers = { "user-agent": UA };
    if (cookie) {
      headers.cookie = cookie;
    }
    const text = body === undefined ? "" : String(body);
    if (method === "POST") {
      headers["content-type"] = contentType ||
        "application/x-www-form-urlencoded";
      headers["content-length"] = Buffer.byteLength(text);
    }
    const req = https.request({ host: url.hostname, port: url.port,
      path: url.pathname + url.search, method: method, headers: headers,
      agent: false },
    function (res) {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        raw += chunk;
      });
      res.on("end", function () {
        const kept = {};
        Object.keys(res.headers).sort().forEach(function (name) {
          if (SKIPPED_HEADERS.indexOf(name) < 0) {
            kept[name] = res.headers[name];
          }
        });
        log.debug("Leaving request(). " + res.statusCode);
        resolve({ status: res.statusCode, headers: kept, body: raw });
      });
    });
    req.on("error", function (e) {
      log.debug("Caught in request(): " + ((e && e.message) || e));
      resolve({ status: 0, headers: {}, body: String(e && e.message) });
    });
    req.end(text);
  });
}

function rst(o) {
  log.debug("Entering rst().");
  const ns = o.trustNs || WST13;
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="' + (o.soap11 ? SOAP11 : SOAP12) +
    '" xmlns:wsse="' + WSSE + '" xmlns:wsa="' + WSA + '"><s:Header>' +
    "<wsa:Action>" + ns + "/RST/" + (o.op || "Issue") + "</wsa:Action>" +
    (o.header || "") +
    (o.security ? "<wsse:Security>" + o.security + "</wsse:Security>"
                : "") +
    '</s:Header><s:Body><wst:RequestSecurityToken xmlns:wst="' + ns +
    '"><wst:RequestType>' + ns + "/" + (o.op || "Issue") +
    "</wst:RequestType>" + (o.tokenType ? "<wst:TokenType>" +
      o.tokenType + "</wst:TokenType>" : "") + (o.appliesTo
      ? '<wsp:AppliesTo xmlns:wsp="' + WSP + '"><wsa:EndpointReference>' +
        "<wsa:Address>" + o.appliesTo + "</wsa:Address>" +
        "</wsa:EndpointReference></wsp:AppliesTo>" : "") +
    (o.body || "") +
    "</wst:RequestSecurityToken></s:Body></s:Envelope>";
}

function usernameToken(user, pass) {
  log.debug("Entering usernameToken().");
  log.debug("Leaving usernameToken().");
  return "<wsse:UsernameToken><wsse:Username>" + user +
    "</wsse:Username>" + (pass === null ? "" : "<wsse:Password>" + pass +
    "</wsse:Password>") + "</wsse:UsernameToken>";
}

// ------------------------------------------------------ the error code
async function newestAt() {
  log.debug("Entering newestAt().");
  const r = await K.send(K.rb(REALM) + "/admin-api/audit?per=1&action=" +
                         "protocol.call");
  log.debug("Leaving newestAt().");
  // BY TIME (#465): `seq` is not one order across processes, so a row a
  // request worker numbered from a lower block would be missed.
  return Number((((r.json || {}).events || [])[0] || {}).at || 0);
}

// The code of the protocol.call row a step added, '' when it added none.
async function codeSince(before, target) {
  log.debug("Entering codeSince().");
  const pathOnly = String(target).split("?")[0];
  let code = "";
  for (let i = 0; i < 6; i += 1) {
    const r = await K.send(K.rb(REALM) + "/admin-api/audit?per=5&action=" +
                           "protocol.call");
    const rows = ((r.json || {}).events || []).filter(function (one) {
      return Number(one.at || 0) > before &&
             String(one.target || one.summary || "").indexOf(pathOnly) >= 0;
    });
    if (rows.length) {
      code = String(rows[0].errorCode || "");
      break;
    }
    await K.sleep(80);
  }
  log.debug("Leaving codeSince(). " + code);
  return code;
}

// ------------------------------------------------------- normalisation
const MINTED =
  /\b(ID|AssertionID|ResponseID|Id|InResponseTo|SessionIndex)=\\?"([^"\\]+)\\?"/g;
const OPAQUE = ["SignatureValue", "DigestValue", "X509Certificate",
                "CipherValue", "KeyIdentifier", "BinarySecret",
                "BinarySecurityToken", "AssertionIDReference"];

function numberMinted(text) {
  log.debug("Entering numberMinted().");
  const seen = new Map();
  MINTED.lastIndex = 0;
  let match = MINTED.exec(text);
  while (match !== null) {
    const value = match[2];
    if (value.length >= 8 && !seen.has(value)) {
      seen.set(value, "<id" + (seen.size + 1) + ">");
    }
    match = MINTED.exec(text);
  }
  let out = text;
  seen.forEach(function (placeholder, value) {
    out = out.split(value).join(placeholder);
  });
  log.debug("Leaving numberMinted().");
  return out;
}

// `tests/ws_model_wire.js`'s normalise(), step for step.
function normalise(wire) {
  log.debug("Entering normalise().");
  const opaque = new RegExp("(<(?:[A-Za-z0-9]+:)?(?:" + OPAQUE.join("|") +
                            ")(?:\\s[^>]*)?>)[^<]*(</)", "g");
  const PATTERNS = [
    ["footer", /<footer class=\\"sts-footer\\".*?<\/footer>/g],
    ["footercss", /body:has\(>\.sts-footer\).*?\.sts-footer-social\{gap:18px\}\}/g],
    ["pem", /-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----(\\n)?/g],
    ["jwt", /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g],
    ["value", /value=\\"[^"\\]{40,}\\"/g],
    ["uuid", /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ["time", /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ["port", /127\.0\.0\.1(:|%3A|%253A)\d+/g],
    ["epoch", /\b1[789]\d{11}\b/g],
    ["cookie", /\b(sts_[a-z_]+)=[^;"\s]+/g],
    ["incident", /(Incident ID<\/dt><dd><code>)\d+/g],
    ["handle", /\b(authn|rid|fid|sts_signout_account)=[A-Za-z0-9_%-]{12,}/g],
    ["handleParam",
     /("location\.param\.(?:authn|rid|fid|sts_signout_account)": ?")[^"]+/g],
    ["chain", /(<ds:X509Certificate><opaque><\/ds:X509Certificate>)+/g],
    ["hex", /\b[0-9a-f]{24,}\b/g],
    ["random", /(?<![A-Za-z0-9_+/=.:-])(?=[A-Za-z0-9_+=-]*[A-Z])(?=[A-Za-z0-9_+=-]*[0-9])[A-Za-z0-9_+=-]{24,}/g]
  ];
  const out = wire.map(function (one) {
    let text = numberMinted(JSON.stringify(one));
    text = text.replace(opaque, "$1<opaque>$2");
    PATTERNS.forEach(function (pair) {
      if (pair[0] === "value") {
        text = text.replace(pair[1], 'value=\\"<value>\\"');
      } else if (pair[0] === "incident") {
        text = text.replace(pair[1], "$1<incident>");
      } else if (pair[0] === "handle") {
        text = text.replace(pair[1], "$1=<handle>");
      } else if (pair[0] === "handleParam") {
        text = text.replace(pair[1], "$1<handle>");
      } else if (pair[0] === "chain") {
        text = text.replace(pair[1], "<chain>");
      } else if (pair[0] === "cookie") {
        text = text.replace(pair[1], "$1=<cookie>");
      } else {
        text = text.replace(pair[1], "<" + pair[0] + ">");
      }
    });
    return JSON.parse(text);
  });
  log.debug("Leaving normalise().");
  return out;
}

// What only the place of the conversation changes, put back before the
// placeholders: the realm's id and domain, the origin, a cookie's Secure.
function placed(one) {
  log.debug("Entering placed().");
  let text = JSON.stringify(one);
  const origin = new URL(K.base);
  const swaps = [[K.base, "http://127.0.0.1:1"],
    [encodeURIComponent(K.base), encodeURIComponent("http://127.0.0.1:1")],
    [origin.host, "127.0.0.1:1"],
    [encodeURIComponent(origin.host), "127.0.0.1%3A1"],
    [REALMS.wswirep + ".example.net", "wswirep.example.com"],
    [REALMS.wswire + ".example.net", "wswire.example.com"],
    [REALMS.wswirep, "wswirep"],
    [REALMS.wswire, "wswire"]].filter(function (pair) {
    return !/^undefined/.test(String(pair[0]));
  });
  swaps.forEach(function (pair) {
    text = text.split(JSON.stringify(pair[0]).slice(1, -1))
      .join(JSON.stringify(pair[1]).slice(1, -1));
  });
  text = text.replace(/; Secure(?=;|")/g, "").replace(/__Host-sts_/g, "sts_");
  // THE MAIN PORT'S TLS LEAF, which a metadata document served over TLS
  // names as its last signing KeyDescriptor (`sts_saml_sso_rules` M3) and
  // the in-process file's plain listener had none of.
  if (LEAF) {
    text = text.replace(/<md:KeyDescriptor use=\\"signing\\">(?:(?!<\/md:KeyDescriptor>).)*<\/md:KeyDescriptor>/g,
      function (one) {
        return one.indexOf(LEAF) >= 0 ? "" : one;
      });
  }
  log.debug("Leaving placed().");
  return JSON.parse(text);
}

function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + "." + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  if (typeof a === "string" && typeof b === "string") {
    let at = 0;
    while (at < a.length && a[at] === b[at]) {
      at += 1;
    }
    log.debug("Leaving firstDifference(). At " + at + ".");
    return where + " at " + at + ": " +
      JSON.stringify(b.slice(Math.max(0, at - 60), at + 140)) +
      " where " + JSON.stringify(a.slice(Math.max(0, at - 60), at + 140)) +
      " was recorded";
  }
  log.debug("Leaving firstDifference().");
  return where + ": " + String(JSON.stringify(b)).slice(0, 400) +
    " where " + String(JSON.stringify(a)).slice(0, 400) + " was recorded";
}

// ------------------------------------------------------------- the realm
async function setUp(mode, recorded) {
  log.debug("Entering setUp(). " + mode);
  REALM = await K.realm(recorded, mode);
  REALMS[recorded] = REALM;
  MODE = mode;
  await K.ok(K.rb(REALM) + "/admin-api/users/create", { username: PERSON,
    invent: false, credential: "password", password: PASSWORD,
    attributes: { givenName: "Wire", sn: "Alice",
                  mail: PERSON + "@wire.test" } }, "created " + PERSON);
  await K.ok(K.rb(REALM) + "/admin-api/applications/create", {
    identifier: "wsback", name: "wsback", protocols: ["wstrust"],
    fields: { oauthClientId: "wsback", wstrustAppliesTo: [BACK] } },
  "created wsback");
  await K.ok(K.rb(REALM) + "/admin-api/applications/create", {
    identifier: RP, name: RP, protocols: ["wsfed"],
    fields: { wsfedReplyUrl: [RP_REPLY] } }, "created the relying party");
  let secret = PASSWORD;
  if (mode === "product") {
    secret = await secondFactor();
    await agree();
  }
  log.debug("Leaving setUp().");
  return secret;
}

// ------------------------------------------------- the product pass's
// PRODUCT REQUIRES A SECOND FACTOR OF EVERY PERSON (ASVS 5.0.0 6.3.3): the
// in-process file started a ['pwd', 'otp'] session and made an app password
// scoped to /sts directly. Here the person signs in to the portal once with
// `authn.allowOptionalSecondFactor` on, enrols an authenticator app and
// makes the app password there (`/account-api`), and the switch goes back
// off before the conversation.
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
let TOTP = { secret: "", used: -1 };

function base32ToBytes(text) {
  log.debug("Entering base32ToBytes().");
  const cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < cleaned.length; i++) {
    value = (value << 5) | B32.indexOf(cleaned[i]);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  log.debug("Leaving base32ToBytes().");
  return Buffer.from(out);
}

// RFC 4226 section 5.3 over RFC 6238 section 4.2, this job's own.
function codeFor(secret, atMs) {
  log.debug("Entering codeFor().");
  const counter = Math.floor(Number(atMs || Date.now()) / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac("sha1", base32ToBytes(secret))
    .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  log.debug("Leaving codeFor().");
  return String(binary % 1000000).padStart(6, "0");
}

// A code from a time step no earlier sign-in used: a code is taken once.
async function freshCode() {
  log.debug("Entering freshCode().");
  while (Math.floor(Date.now() / 30000) <= TOTP.used) {
    await K.sleep(1000);
  }
  TOTP.used = Math.floor(Date.now() / 30000);
  log.debug("Leaving freshCode().");
  return codeFor(TOTP.secret);
}

async function secondFactor() {
  log.debug("Entering secondFactor().");
  await K.set(REALM, "authn.allowOptionalSecondFactor", true);
  const portal = await portalSignin.signInToThePortal(K.rb(REALM), PERSON,
                                                      null,
                                                      { password: PASSWORD });
  let r = await portal.act("/portal/mfa", { action: "start" });
  assert.ok(r.status === 200 && r.json && r.json.ok, K.shown(r));
  const page = await portal.page("/portal/mfa");
  const secret = String(((page.json && page.json.setup) || {}).grouped || "")
    .replace(/\s+/g, "");
  assert.ok(secret.length >= 32, "no secret: " + page.text.slice(0, 300));
  TOTP = { secret: secret, used: -1 };
  r = await portal.act("/portal/mfa", { action: "confirm",
                                        code: await freshCode() });
  assert.ok(r.status === 200 && r.json && r.json.ok, K.shown(r));
  const made = await portal.act("/portal/app-passwords", { action: "create",
    name: "ws_model_wire", door_wstrust: "on" });
  const password = (made.json && (made.json.password ||
    ((made.json.view || {}).fresh || {}).password ||
    (made.json.made || {}).password)) || "";
  assert.ok(made.status === 200 && password, "no app password: " +
            JSON.stringify(made.json || made).slice(0, 400));
  await K.unset(REALM, "authn.allowOptionalSecondFactor");
  log.debug("Leaving secondFactor().");
  return password;
}

async function signIn() {
  log.debug("Entering signIn().");
  const b = K.browser();
  const first = await b.go(K.rb(REALM) + "/wsfed?" + new URLSearchParams({
    wa: "wsignin1.0", wtrealm: RP }).toString());
  assert.ok(K.toSignIn(first), "not sent to sign in: " + K.shown(first));
  const signed = await authnSignin.signInWithJar(K.rb(REALM), /^https?:/.test(
    first.location) ? first.location : K.base + first.location,
  { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  if (MODE === "product") {
    const jar = function () {
      log.debug("Entering jar().");
      log.debug("Leaving jar().");
      return Object.keys(b.jar).map(function (k) {
        return k + "=" + b.jar[k];
      }).join("; ");
    };
    assert.ok(signed.location && /\/authn\/totp/.test(signed.location),
              "the screen asked no second factor: " +
              JSON.stringify((signed.answer || {}).json || {}).slice(0, 300));
    const opened = await authnSignin.step(new URL(signed.location, K.base)
      .toString(), { cookie: jar() });
    const coded = await authnSignin.stepAct(opened, "totp",
      { code: await freshCode() }, { cookie: jar() });
    (coded.setCookies || []).forEach(function (line) {
      const pair = String(line).split(";")[0];
      const at = pair.indexOf("=");
      b.jar[pair.slice(0, at)] = pair.slice(at + 1);
    });
  }
  const name = Object.keys(b.jar).filter(function (k) {
    return /sts_session$/.test(k);
  })[0];
  assert.ok(name, "no session: " + JSON.stringify(Object.keys(b.jar)));
  LAST_BROWSER = b;
  log.debug("Leaving signIn().");
  return name + "=" + b.jar[name];
}

// THE AGREEMENT product mode asks before single sign-on (ASVS 5.0.0 7.6.2),
// which the in-process file recorded for the relying party: given at the
// consent screen, by a session of its own, so the conversation's sessions
// carry no extra sign-in.
async function agree() {
  log.debug("Entering agree().");
  await signIn();
  const b = LAST_BROWSER;
  const r = await b.go(K.rb(REALM) + "/wsfed?" + new URLSearchParams({
    wa: "wsignin1.0", wtrealm: RP }).toString());
  assert.ok((r.status === 302 || r.status === 303) &&
            /\/oauth2\/consent/.test(r.location), "no consent asked: " +
            K.shown(r));
  await K.consent(b, new URL(r.location, K.base).toString());
  log.debug("Leaving agree().");
}

async function conversation(secret) {
  log.debug("Entering conversation().");
  const wire = [];
  const P = "/realm/" + REALM;
  const step = async function (name, method, target, cookie, body,
                               contentType) {
    log.debug("Entering step(). " + name);
    const before = await newestAt();
    const r = await request(method, target, cookie, body, contentType);
    const code = await codeSince(before, target);
    wire.push({ mode: MODE, step: name, method: method,
                path: target, status: r.status, code: code,
                headers: r.headers, decoded: decoded(r), body: r.body });
    log.debug("Leaving step().");
    return r;
  };
  const sts = function (name, xml, soap11) {
    log.debug("Entering sts().");
    log.debug("Leaving sts().");
    return step(name, "POST", P + "/sts", "", xml,
                soap11 ? "text/xml; charset=utf-8"
                       : "application/soap+xml; charset=utf-8");
  };
  const ut = usernameToken(PERSON, secret);
  await step("GET /sts", "GET", P + "/sts");
  await step("GET /sts/cert", "GET", P + "/sts/cert");
  const issued = await sts("Issue SAML 2.0, 1.3, SOAP 1.2",
    rst({ security: ut, tokenType: SAML2_TT, appliesTo: BACK }));
  await sts("Issue SAML 2.0, 1.3, SOAP 1.1", rst({ soap11: true,
    security: ut, tokenType: SAML2_TT, appliesTo: BACK }), true);
  await sts("Issue SAML 1.1, 1.3", rst({ security: ut,
    tokenType: SAML11_TT, appliesTo: BACK }));
  await sts("Issue SAML 1.1 by its assertion namespace", rst({
    security: ut, tokenType: "urn:oasis:names:tc:SAML:1.0:assertion",
    appliesTo: BACK }));
  await sts("Issue JWT, 1.3", rst({ security: ut, tokenType: JWT_TT,
                                    appliesTo: BACK }));
  await sts("Issue, no TokenType", rst({ security: ut, appliesTo: BACK }));
  await sts("Issue, 2005/02", rst({ trustNs: WST2005, security: ut,
    tokenType: SAML2_TT, appliesTo: BACK }));
  await sts("Issue, 2004/04, SOAP 1.1", rst({ soap11: true,
    trustNs: WST2004, security: ut, tokenType: SAML2_TT,
    appliesTo: BACK }), true);
  const wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-" +
              "wssecurity-utility-1.0.xsd";
  await sts("Issue, a KeyType and a Lifetime asked for, clamped",
    rst({ security: ut, tokenType: SAML2_TT, appliesTo: BACK,
          body: "<wst:KeyType>" + WST13 + "/SymmetricKey</wst:KeyType>" +
            '<wst:Lifetime><wsu:Created xmlns:wsu="' + wsu + '">' +
            "2026-01-01T00:00:00Z</wsu:Created><wsu:Expires " +
            'xmlns:wsu="' + wsu + '">2027-01-01T00:00:00Z' +
            "</wsu:Expires></wst:Lifetime>" }));
  const assertion = ((/<saml:Assertion[\s\S]*?<\/saml:Assertion>/
    .exec(String(issued.body))) || [""])[0];
  await sts("Renew the issued assertion", rst({ op: "Renew",
    security: ut, tokenType: SAML2_TT, appliesTo: BACK,
    body: "<wst:RenewTarget>" + assertion + "</wst:RenewTarget>" }));
  await sts("Validate the issued assertion", rst({ op: "Validate",
    security: ut, tokenType: WST13 + "/RSTR/Status",
    body: "<wst:ValidateTarget>" + assertion + "</wst:ValidateTarget>" }));
  await sts("Validate nothing", rst({ op: "Validate", security: ut,
    body: "<wst:ValidateTarget/>" }));
  await sts("Cancel, 1.3", rst({ op: "Cancel", security: ut,
    body: "<wst:CancelTarget>" + assertion + "</wst:CancelTarget>" }));
  await sts("Cancel, 2004/04: refused", rst({ op: "Cancel",
    trustNs: WST2004, security: ut }));
  await sts("not XML", "this is not <xml", false);
  await sts("no credential", rst({ tokenType: SAML2_TT, appliesTo: BACK }));
  await sts("both OnBehalfOf and ActAs", rst({ security: ut,
    tokenType: SAML2_TT, appliesTo: BACK,
    body: "<wst:OnBehalfOf>" + assertion + "</wst:OnBehalfOf>" +
      '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + assertion +
      "</wst14:ActAs>" }));
  await sts("an AppliesTo nobody registered", rst({ security: ut,
    tokenType: SAML2_TT, appliesTo: "https://nobody.wswire.test/" }));
  await sts("no AppliesTo", rst({ security: ut, tokenType: SAML2_TT }));
  await sts("a Kerberos token asked for, issuing off", rst({
    security: ut, tokenType: KERBEROS_TT, appliesTo: BACK }));
  await sts("a wrong password, SOAP 1.2", rst({
    security: usernameToken(PERSON, "invalid"),
    tokenType: SAML2_TT, appliesTo: BACK }));
  await sts("a wrong password, SOAP 1.1", rst({ soap11: true,
    security: usernameToken(PERSON, "invalid"),
    tokenType: SAML2_TT, appliesTo: BACK }), true);

  const wsfed = function (params) {
    log.debug("Entering wsfed().");
    log.debug("Leaving wsfed().");
    return P + "/wsfed?" + new URLSearchParams(params).toString();
  };
  await step("GET /wsfed", "GET", P + "/wsfed");
  await step("the federation metadata", "GET",
             P + "/FederationMetadata/2007-06/FederationMetadata.xml");
  await step("one relying party's metadata", "GET",
             P + "/wsfed/metadata/" + encodeURIComponent(RP));
  await step("the metadata of a relying party nobody registered", "GET",
             P + "/wsfed/metadata/nobody.wswire.test");
  await step("wsignin1.0, no session", "GET", wsfed({ wa: "wsignin1.0",
    wtrealm: RP, wctx: "ctx-1" }));
  const alice = await signIn();
  await step("wsignin1.0, signed in: SAML 1.1", "GET", wsfed({
    wa: "wsignin1.0", wtrealm: RP, wctx: "ctx-2" }), alice);
  await step("wsignin1.0 posted: SAML 2.0 by tokenType", "POST",
             P + "/wsfed", alice, new URLSearchParams({ wa: "wsignin1.0",
               wtrealm: RP, wreply: RP_REPLY, tokenType: "saml2" })
               .toString());
  await step("wsignin1.0: trust 1.3", "GET", wsfed({ wa: "wsignin1.0",
    wtrealm: RP, trust: "1.3", tokenType: "saml2" }), alice);
  await step("wsignin1.0: wreq names the token type", "GET", wsfed({
    wa: "wsignin1.0", wtrealm: RP,
    wreq: '<wst:RequestSecurityToken xmlns:wst="' + WST2005 + '">' +
      "<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion" +
      "</wst:TokenType></wst:RequestSecurityToken>" }), alice);
  await step("wsignin1.0: wfresh=0, whr and wct", "GET", wsfed({
    wa: "wsignin1.0", wtrealm: RP, wfresh: "0", whr: "urn:home",
    wct: "2026-01-01T00:00:00Z" }), alice);
  await step("wsignin1.0: a password wauth the session meets", "GET",
    wsfed({ wa: "wsignin1.0", wtrealm: RP,
            wauth: "urn:oasis:names:tc:SAML:1.0:am:password" }), alice);
  await step("wsignin1.0: a multi-factor wauth, a step-up", "GET",
    wsfed({ wa: "wsignin1.0", wtrealm: RP,
            wauth: "http://schemas.microsoft.com/claims/multipleauthn" }),
    alice);
  await step("wsignin1.0: an unknown wauth", "GET", wsfed({
    wa: "wsignin1.0", wtrealm: RP, wauth: "urn:example:retina" }), alice);
  await step("wsignin1.0: wreqptr", "GET", wsfed({ wa: "wsignin1.0",
    wtrealm: RP, wreqptr: "https://evil.wswire.test/rst" }), alice);
  await step("wsignin1.0: no wtrealm", "GET", wsfed({ wa: "wsignin1.0" }),
             alice);
  await step("wsignin1.0: a token type not offered", "GET", wsfed({
    wa: "wsignin1.0", wtrealm: RP, tokenType: "urn:example:token" }),
    alice);
  await step("wsignin1.0: a wreply nobody registered", "GET", wsfed({
    wa: "wsignin1.0", wtrealm: RP,
    wreply: "https://elsewhere.wswire.test/" }), alice);
  await step("wsignin1.0: a wtrealm nobody registered", "GET", wsfed({
    wa: "wsignin1.0", wtrealm: "https://nobody.wswire.test/",
    wreply: "https://nobody.wswire.test/reply" }), alice);
  await step("wattr1.0", "GET", wsfed({ wa: "wattr1.0" }), alice);
  await step("an unknown wa", "GET", wsfed({ wa: "wsomething1.0" }), alice);
  await step("the initiation link, off by default", "GET",
             P + "/wsfed/initiate/" + encodeURIComponent(RP), alice);
  await step("wsignoutcleanup1.0", "GET", wsfed({
    wa: "wsignoutcleanup1.0", wtrealm: RP }), alice);
  const bob = await signIn();
  await step("wsignout1.0", "GET", wsfed({ wa: "wsignout1.0",
    wtrealm: RP, wreply: RP_REPLY }), bob);
  log.debug("Leaving conversation().");
  return wire;
}

// The certificate the main port presents, base64 DER.
function listenerLeaf() {
  log.debug("Entering listenerLeaf().");
  const u = new URL(K.base);
  return new Promise(function (resolve) {
    const socket = tls.connect({ host: u.hostname, port: Number(u.port),
                                 servername: u.hostname }, function () {
      const raw = socket.getPeerCertificate().raw;
      socket.end();
      log.debug("Leaving listenerLeaf().");
      resolve(raw ? raw.toString("base64") : "");
    });
    socket.on("error", function (e) {
      log.debug("Caught in listenerLeaf(): " + ((e && e.message) || e));
      resolve("");
    });
  });
}

async function test() {
  log.debug("Entering test().");
  const recorded = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
  // PUT BACK, AS RECORDED: the in-process record's error page links the
  // portal at the realm prefix TWICE (`/realm/wswire/realm/wswire/portal`);
  // a running service sends it once. Reported (#444 D12 phase 7), not
  // pinned: the running service's link is the right one.
  let text = JSON.stringify(recorded.wire);
  ["wswire", "wswirep"].forEach(function (id) {
    text = text.split("/realm/" + id + "/realm/" + id + "/portal")
      .join("/realm/" + id + "/portal");
  });
  // AND THE LINE ENDING AFTER A PEM: the recorded product pass's /sts/cert
  // ends its certificate with CRLF, where a service whose keys persist (the
  // probe's, every product stack's) ends it with nothing after the END line
  // — where the certificate came from, not what WS-Trust answers.
  const pemEnd = function (t) {
    log.debug("Entering pemEnd().");
    log.debug("Leaving pemEnd().");
    return t.split("<pem>\\r\\n").join("<pem>");
  };
  const expected = JSON.parse(pemEnd(text));
  LEAF = await listenerLeaf();
  let wire = [];
  for (const [mode, recordedId] of [["development", "wswire"],
                                    ["product", "wswirep"]]) {
    const secret = await setUp(mode, recordedId);
    wire = wire.concat(await conversation(secret));
  }
  const now = JSON.parse(pemEnd(JSON.stringify(normalise(wire.map(placed)))));
  K.check("the conversation has as many steps as recorded, both passes (" +
          expected.length + ")", function () {
    assert.strictEqual(now.length, expected.length);
  });
  const differing = [];
  expected.forEach(function (one, i) {
    const why = firstDifference(one, now[i], "wire");
    if (why) {
      differing.push(one.mode + ", " + one.step + ": " + why);
    } else {
      K.check(one.mode + ", " + one.step + ": " + one.method +
              " answers as recorded (" + one.status + ")", function () {
        assert.ok(true);
      });
    }
  });
  differing.forEach(function (one) {
    log.error("DIFFERS: " + one.slice(0, 1200));
  });
  K.check("every step answers as recorded", function () {
    assert.strictEqual(differing.length, 0, differing.length +
                       " step(s) differ; the first: " +
                       String(differing[0]).slice(0, 600));
  });
  log.debug("Leaving test().");
}

K.main(test, 96);
