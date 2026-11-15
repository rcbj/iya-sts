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
// OWED: the snapshot's PRODUCT pass (47 steps), which needs a session with
// two factors (an authenticator enrolled through `/account-api`, as
// `sts_portal_totp.js` does) and an app password scoped to /sts.
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
let REALM = "";
let LEAF = "";

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
async function newestSeq() {
  log.debug("Entering newestSeq().");
  const r = await K.send(K.rb(REALM) + "/admin-api/audit?per=1&action=" +
                         "protocol.call");
  log.debug("Leaving newestSeq().");
  return Number((r.json || {}).newestSeq || 0);
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
      return Number(one.seq || 0) > before &&
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
    [REALM + ".example.net", "wswire.example.com"],
    [REALM, "wswire"]];
  swaps.forEach(function (pair) {
    text = text.split(JSON.stringify(pair[0]).slice(1, -1))
      .join(JSON.stringify(pair[1]).slice(1, -1));
  });
  text = text.replace(/; Secure(?=;|")/g, "");
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
async function setUp() {
  log.debug("Entering setUp().");
  REALM = await K.realm("wswire", "development");
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
  log.debug("Leaving setUp().");
}

// A password session of wswalice, signed in at the screen; its cookie.
async function signIn() {
  log.debug("Entering signIn().");
  const b = K.browser();
  const first = await b.go(K.rb(REALM) + "/wsfed?" + new URLSearchParams({
    wa: "wsignin1.0", wtrealm: RP }).toString());
  assert.ok(K.toSignIn(first), "not sent to sign in: " + K.shown(first));
  await authnSignin.signInWithJar(K.rb(REALM), /^https?:/.test(
    first.location) ? first.location : K.base + first.location,
  { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  assert.ok(b.jar.sts_session, "no session: " + JSON.stringify(b.jar));
  log.debug("Leaving signIn().");
  return "sts_session=" + b.jar.sts_session;
}

async function conversation() {
  log.debug("Entering conversation().");
  const wire = [];
  const P = "/realm/" + REALM;
  const step = async function (name, method, target, cookie, body,
                               contentType) {
    log.debug("Entering step(). " + name);
    const before = await newestSeq();
    const r = await request(method, target, cookie, body, contentType);
    const code = await codeSince(before, target);
    wire.push({ mode: "development", step: name, method: method,
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
  const ut = usernameToken(PERSON, PASSWORD);
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
  const expected = JSON.parse(JSON.stringify(recorded.wire.filter(
    function (one) {
      return one.mode === "development";
    })).split("/realm/wswire/realm/wswire/portal")
    .join("/realm/wswire/portal"));
  LEAF = await listenerLeaf();
  await setUp();
  const now = normalise((await conversation()).map(placed));
  K.check("the conversation has as many steps as the recorded " +
          "development pass", function () {
    assert.strictEqual(now.length, expected.length);
  });
  const differing = [];
  expected.forEach(function (one, i) {
    const why = firstDifference(one, now[i], "wire");
    if (why) {
      differing.push(one.step + ": " + why);
    } else {
      K.check("development, " + one.step + ": " + one.method +
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

K.main(test, 49);
