// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_saml_model_wire.js
//
// ===========================================================================
// WHAT BOTH SAML IDENTITY PROVIDERS ANSWER, HELD TO THE RECORDED WIRE, OVER
// THE WIRE (#1579 item 6; #444 D12, phase 7).
//
// `tests/saml_model_wire.js` holds every answer of a scripted conversation —
// the metadata, sign-ins on every binding and their resolution, the
// identity provider's own start, each AuthnRequest refusal, the attribute
// authority, Single Logout both ways, SAML 1.1's profiles and responder — to
// `tests/saml_model_wire.snapshot.json`, from a child process on a
// plain-HTTP loopback port, in a development and a product realm. This job
// has the same conversation, step for step and in the same order (the ids
// it mints for its messages, `_wire-<realm>-<what>-<n>`, are recorded and
// numbered alike), with a RUNNING service, in two throwaway realms of this
// run's own, and holds every answer to the snapshot after putting back what
// only the place of the conversation changes — `sts_ws_model_wire.js`'s
// list:
//
//   * the realms: this run's ids (and the domains they name) are the
//     recorded `samlwire` and `samlwirep`;
//   * the origin: `https://localhost:<port>` is the recorded
//     `http://127.0.0.1:<port>`, in every spelling; HSTS and a cookie's
//     `Secure`, which only a TLS listener sends; the main port's TLS leaf,
//     which a metadata document served over TLS names as its last signing
//     KeyDescriptor;
//   * the error code the in-process file read off the response object is
//     read off `/admin-api/audit` — the newest `protocol.call` row the step
//     added, or none.
//
// WHERE THE IN-PROCESS FILE REACHED INSIDE, THIS JOB ASKS A DOOR:
//
//   * a session is the password sign-in at the screen (the in-process file
//     started one directly, `['pwd']`);
//   * the agreement product mode asks before single sign-on is given at the
//     consent screen, for both parties, by a session of its own (the
//     in-process file recorded it), so the conversation's sessions carry no
//     extra service provider;
//   * the SAML 1.1 relying party's Browser/Artifact consumer is written by
//     UPLOADING its metadata (`/admin-api/saml2/upload-metadata`) — what
//     consuming it writes, which the in-process file called directly;
//   * the NameID the attribute query and the service provider's
//     LogoutRequest name is the one the service provider was last GIVEN,
//     read off the step that gave it (the unsolicited Response), where the
//     in-process file read the session;
//   * the LogoutRequests an identity-provider-initiated logout sends
//     (`logoutTargetsFor()` in process) are the links of that logout's own
//     page, `GET /saml2/slo` with no message — which ENDS the session it
//     reads. So they are read from a TWIN session that signed in to the
//     same service providers as the conversation's (the registered one and,
//     in development, the stranger), at the step's place in the order, and
//     the conversation's own session goes on to the steps after it.
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const tls = require("tls");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const K = require("./oauth_wire_kit.js").kit("sts_saml_model_wire");
const authnSignin = require("./authn_signin");

const log = K.log;
const SNAPSHOT = process.env.SAML_WIRE_SNAPSHOT ||
  path.join(__dirname, "..", "saml_model_wire.snapshot.json");
const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
           "(KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const SKIPPED_HEADERS = ["date", "connection", "keep-alive",
                         "content-length", "etag", "transfer-encoding",
                         "strict-transport-security"];
const NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_SAMLP11 = "urn:oasis:names:tc:SAML:1.0:protocol";
const NS_SAML11 = "urn:oasis:names:tc:SAML:1.0:assertion";
const NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
const SP = "https://sp.wire.test/sp";
const SP_ACS = "https://sp.wire.test/acs";
const SP_SLO = "https://sp.wire.test/slo";
const RP = "https://rp.wire.test/rp";
const RP_SHIRE = "https://rp.wire.test/shire";
const RP_ARTIFACT = "https://rp.wire.test/artifact";
const PERSON = "wirealice";
const PASSWORD = "Wire-Password-7a!Kq2";
const REALMS = {};
let LEAF = "";

function soap(inner) {
  log.debug("Entering soap().");
  log.debug("Leaving soap().");
  return "<soap:Envelope xmlns:soap=\"" + NS_SOAP + "\"><soap:Body>" +
    inner + "</soap:Body></soap:Envelope>";
}

function decodeMessage(value, deflated) {
  log.debug("Entering decodeMessage().");
  try {
    const bytes = Buffer.from(String(value), "base64");
    log.debug("Leaving decodeMessage().");
    return deflated ? zlib.inflateRawSync(bytes).toString("utf8")
                    : bytes.toString("utf8");
  } catch (e) {
    log.debug("Caught in decodeMessage(): " + ((e && e.message) || e));
    // Recorded as the in-process file records it.
    log.debug("Leaving decodeMessage(). Not decodable.");
    return "(not decodable: " + (e && e.message) + ")";
  }
}

function artifactShape(value) {
  log.debug("Entering artifactShape().");
  const bytes = Buffer.from(String(value), "base64");
  const typeCode = bytes.length >= 2 ? bytes.readUInt16BE(0) : -1;
  log.debug("Leaving artifactShape().");
  return { length: bytes.length, typeCode: typeCode,
           endpointIndex: typeCode === 4 && bytes.length >= 4
             ? bytes.readUInt16BE(2) : -1 };
}

function unescapeHtml(text) {
  log.debug("Entering unescapeHtml().");
  log.debug("Leaving unescapeHtml().");
  return String(text).replace(/&#x2B;|&#43;/g, "+")
    .replace(/&#x2F;|&#47;/g, "/").replace(/&#x3D;|&#61;/g, "=")
    .replace(/&quot;/g, "\"").replace(/&#39;|&#x27;/g, "'")
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
      ["SAMLRequest", "SAMLResponse"].forEach(function (name) {
        const value = url.searchParams.get(name);
        if (value) {
          out["location." + name] = decodeMessage(value, true);
        }
      });
      const art = url.searchParams.get("SAMLart");
      if (art) {
        out["location.SAMLart"] = artifactShape(art);
      }
      url.searchParams.forEach(function (value, name) {
        out["location.param." + name] =
          ["SAMLRequest", "SAMLResponse", "SAMLart", "Signature"]
            .indexOf(name) >= 0 ? "<value>" : value;
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
    const fields = {};
    let m = inputs.exec(body);
    while (m !== null) {
      const name = /name="([^"]*)"/.exec(m[0]);
      const value = /value="([^"]*)"/.exec(m[0]);
      if (name) {
        fields[name[1]] = value ? unescapeHtml(value[1]) : "";
      }
      m = inputs.exec(body);
    }
    Object.keys(fields).forEach(function (name) {
      if (name === "SAMLResponse" || name === "SAMLRequest") {
        out["form." + name] = decodeMessage(fields[name], false);
      } else if (name === "SAMLart") {
        out["form.SAMLart"] = artifactShape(fields[name]);
      } else {
        out["form." + name] = fields[name];
      }
    });
  }
  log.debug("Leaving decoded().");
  return out;
}

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

function form(fields) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return Object.keys(fields).map(function (k) {
    return encodeURIComponent(k) + "=" + encodeURIComponent(fields[k]);
  }).join("&");
}

// ------------------------------------------------------ the error code
async function newestSeq(realm) {
  log.debug("Entering newestSeq().");
  const r = await K.send(K.rb(realm) + "/admin-api/audit?per=1&action=" +
                         "protocol.call");
  log.debug("Leaving newestSeq().");
  return Number((r.json || {}).newestSeq || 0);
}

async function codeSince(realm, before, target) {
  log.debug("Entering codeSince().");
  const pathOnly = String(target).split("?")[0].replace(/^https?:\/\/[^/]+/,
                                                         "");
  let code = "";
  for (let i = 0; i < 6; i += 1) {
    const r = await K.send(K.rb(realm) + "/admin-api/audit?per=5&action=" +
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
// `tests/saml_model_wire.js`'s, unchanged.
const MINTED =
  /\b(ID|AssertionID|ResponseID|SessionIndex|RequestID|Id)=\\?"([^"\\]+)\\?"/g;
const MINTED_TEXT = /<(?:[A-Za-z0-9]+:)?(SessionIndex)>([^<]+)</g;
const OPAQUE = ["SignatureValue", "DigestValue", "X509Certificate",
                "CipherValue", "MessageHandle", "AssertionArtifact",
                "Artifact"];

function numberMinted(text) {
  log.debug("Entering numberMinted().");
  const seen = new Map();
  [MINTED, MINTED_TEXT].forEach(function (pattern) {
    pattern.lastIndex = 0;
    let match = pattern.exec(text);
    while (match !== null) {
      const value = match[2];
      if (!/^_wire-/.test(value) && value.length >= 8 && !seen.has(value)) {
        seen.set(value, "<id" + (seen.size + 1) + ">");
      }
      match = pattern.exec(text);
    }
  });
  let out = text;
  seen.forEach(function (placeholder, value) {
    out = out.split(value).join(placeholder);
  });
  log.debug("Leaving numberMinted().");
  return out;
}

function normalise(wire) {
  log.debug("Entering normalise().");
  const opaque = new RegExp("(<(?:[A-Za-z0-9]+:)?(?:" + OPAQUE.join("|") +
                            ")(?:\\s[^>]*)?>)[^<]*(</)", "g");
  const PATTERNS = [
    ["footer", /<footer class=\\"sts-footer\\".*?<\/footer>/g],
    ["footercss", /body:has\(>\.sts-footer\).*?\.sts-footer-social\{gap:18px\}\}/g],
    ["param", /\b(SAMLart|SAMLResponse|SAMLRequest|Signature)=[^&"\\\s]+/g],
    ["value", /value=\\"[^"\\]{40,}\\"/g],
    ["uuid", /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ["time", /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ["port", /127\.0\.0\.1(:|%3A|%253A)\d+/g],
    ["epoch", /\b1[789]\d{11}\b/g],
    ["cookie", /\b(sts_[a-z_]+)=[^;"\s]+/g],
    ["nameid", /(Format=\\?"urn:oasis:names:tc:SAML:2\.0:nameid-format:(?:transient|persistent)\\?"[^>]*>)[^<]+/g],
    ["incident", /(Incident ID<\/dt><dd><code>)\d+/g],
    ["handle", /\b(authn|rid|fid)=[A-Za-z0-9_-]{12,}/g],
    ["handleParam", /("location\.param\.(?:authn|rid|fid)":\s?")[^"]+/g],
    ["chain", /(<ds:X509Certificate><opaque><\/ds:X509Certificate>)+/g],
    ["hex", /\b[0-9a-f]{24,}\b/g],
    ["random", /(?<![A-Za-z0-9_+/=-])(?=[A-Za-z0-9_+/=-]*[A-Z])(?=[A-Za-z0-9_+/=-]*[0-9])[A-Za-z0-9_+/=-]{24,}/g]
  ];
  const out = wire.map(function (one) {
    let text = numberMinted(JSON.stringify(one));
    text = text.replace(opaque, "$1<opaque>$2");
    PATTERNS.forEach(function (pair) {
      const how = { param: "$1=<value>", value: "value=\\\"<value>\\\"",
                    incident: "$1<incident>", handle: "$1=<handle>",
                    handleParam: "$1<handle>", chain: "<chain>",
                    nameid: "$1<nameid>", cookie: "$1=<cookie>" }[pair[0]];
      text = text.replace(pair[1], how || "<" + pair[0] + ">");
    });
    return JSON.parse(text);
  });
  log.debug("Leaving normalise().");
  return out;
}

// What only the place of the conversation changes, put back before the
// placeholders: the realms' ids and domains, the origin, a cookie's prefix
// and Secure, and the main port's TLS leaf in a metadata document.
function placed(one) {
  log.debug("Entering placed().");
  let text = JSON.stringify(one);
  const origin = new URL(K.base);
  const swaps = [[K.base, "http://127.0.0.1:1"],
    [encodeURIComponent(K.base), encodeURIComponent("http://127.0.0.1:1")],
    [origin.host, "127.0.0.1:1"],
    [encodeURIComponent(origin.host), "127.0.0.1%3A1"]];
  Object.keys(REALMS).forEach(function (recorded) {
    swaps.push([REALMS[recorded] + ".example.net",
                recorded + ".example.com"]);
  });
  // The longer id first, so samlwirep is not read as samlwire + "p".
  Object.keys(REALMS).sort(function (a, b) {
    return REALMS[b].length - REALMS[a].length;
  }).forEach(function (recorded) {
    swaps.push([REALMS[recorded], recorded]);
  });
  swaps.forEach(function (pair) {
    text = text.split(JSON.stringify(pair[0]).slice(1, -1))
      .join(JSON.stringify(pair[1]).slice(1, -1));
  });
  text = text.replace(/; Secure(?=;|")/g, "").replace(/__Host-sts_/g, "sts_")
    // The address the browser came from: the probe's gateway, where the
    // in-process file's loopback.
    .replace(/(IPAddress=\\?")[0-9a-f.:]+(\\?")/g, "$1127.0.0.1$2");
  if (LEAF) {
    text = text.replace(/<md:KeyDescriptor use=\\"signing\\">(?:(?!<\/md:KeyDescriptor>).)*<\/md:KeyDescriptor>/g,
      function (kd) {
        return kd.indexOf(LEAF) >= 0 ? "" : kd;
      });
  }
  log.debug("Leaving placed().");
  return JSON.parse(text);
}

// WHAT BOTH SIDES SAY OF THE PLACE: the size of a posted message, which a
// longer origin and the TLS leaf in the signer's chain lengthen; and the
// recorded error page's portal link, which carries the realm's prefix
// twice where a running service sends it once (reported with
// `sts_ws_model_wire.js`'s same finding).
function placeless(one) {
  log.debug("Entering placeless().");
  let text = JSON.stringify(one);
  text = text.replace(/\d+ base64 characters/g, "<n> base64 characters");
  ["samlwire", "samlwirep"].forEach(function (id) {
    text = text.split("/realm/" + id + "/realm/" + id + "/portal")
      .join("/realm/" + id + "/portal");
  });
  log.debug("Leaving placeless().");
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

// ------------------------------------------------------------- set up
const RP_METADATA = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:" +
  "SAML:2.0:metadata\" entityID=\"" + RP + "\"><md:SPSSODescriptor " +
  "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:1.1:protocol\">" +
  "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:1.0:" +
  "profiles:artifact-01\" Location=\"" + RP_ARTIFACT + "\" index=\"1\"/>" +
  "</md:SPSSODescriptor></md:EntityDescriptor>";

async function setUp(mode, recorded) {
  log.debug("Entering setUp(). " + mode);
  const id = (recorded + "-" + K.STAMP).slice(0, 31);
  await K.ok(K.base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: recorded + " " + K.STAMP,
    overrides: { "global.mode": mode } }, "created the realm " + id);
  await K.set(id, "risk.assessSignIns", false);
  // A PASSWORD SESSION, as the in-process file started one (`['pwd']`):
  // product asks a second factor of everyone at the screen unless this is
  // on, and nothing after the screen reads it.
  if (mode === "product") {
    await K.set(id, "authn.allowOptionalSecondFactor", true);
  }
  REALMS[recorded] = id;
  await K.ok(K.rb(id) + "/admin-api/users/create", { username: PERSON,
    invent: false, credential: "password", password: PASSWORD,
    attributes: { givenName: "Wire", sn: "Alice",
                  mail: PERSON + "@wire.test" } }, "created " + PERSON);
  await K.ok(K.rb(id) + "/admin-api/applications/create", {
    identifier: SP, name: SP, protocols: ["saml2"],
    fields: { samlEntityId: [SP], samlAssertionConsumerService: [SP_ACS],
              samlSingleLogoutService: [SP_SLO],
              saml2IdpInitiatedSso: "TRUE" } }, "created the SP");
  await K.ok(K.rb(id) + "/admin-api/applications/create", {
    identifier: RP, name: RP, protocols: ["saml11"],
    fields: { samlEntityId: [RP], samlAssertionConsumerService: [RP_SHIRE],
              saml11IdpInitiatedSso: "TRUE" } }, "created the RP");
  await K.ok(K.rb(id) + "/admin-api/saml2/upload-metadata", {
    sp: RP, document: RP_METADATA, family: "saml11" },
  "uploaded the RP's metadata");
  log.debug("Leaving setUp().");
  return id;
}

// A PASSWORD SESSION at the screen, reached through an AuthnRequest that is
// not one of the conversation's (its id is not minted by nextId) and never
// answered.
async function signIn(realm, tag) {
  log.debug("Entering signIn(). " + tag);
  const b = K.browser();
  const xml = "<samlp:AuthnRequest xmlns:samlp=\"" + NS_SAMLP +
    "\" xmlns:saml=\"" + NS_SAML + "\" ID=\"_signin-" + tag + "-" +
    K.rand(4) + "\" Version=\"2.0\" IssueInstant=\"" +
    new Date().toISOString() + "\"><saml:Issuer>" + SP +
    "</saml:Issuer></samlp:AuthnRequest>";
  const first = await b.go(K.rb(realm) + "/saml2/sso?SAMLRequest=" +
    encodeURIComponent(zlib.deflateRawSync(Buffer.from(xml))
      .toString("base64")));
  assert.ok(K.toSignIn(first), "not sent to sign in: " + K.shown(first));
  await authnSignin.signInWithJar(K.rb(realm), /^https?:/.test(
    first.location) ? first.location : K.base + first.location,
  { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  const name = Object.keys(b.jar).filter(function (k) {
    return /sts_session$/.test(k);
  })[0];
  assert.ok(name, "no session: " + JSON.stringify(Object.keys(b.jar)));
  log.debug("Leaving signIn().");
  return { b: b, cookie: name + "=" + b.jar[name] };
}

// THE AGREEMENT product mode asks before single sign-on, given at the
// consent screen by a session of its own for one party.
async function agree(realm, start) {
  log.debug("Entering agree().");
  const s = await signIn(realm, "agree");
  const r = await s.b.go(start);
  if ((r.status === 302 || r.status === 303) &&
      /\/oauth2\/consent/.test(r.location)) {
    await K.consent(s.b, new URL(r.location, K.base).toString());
  }
  log.debug("Leaving agree(). " + r.status);
}

// ------------------------------------------------------- the conversation
async function conversation(modeName, recorded, realm, product) {
  log.debug("Entering conversation(). " + modeName);
  const wire = [];
  const P = "/realm/" + realm;
  const step = async function (name, method, target, cookie, body,
                               contentType) {
    log.debug("Entering step(). " + name);
    const before = await newestSeq(realm);
    const r = await request(method, target, cookie, body, contentType);
    const code = await codeSince(realm, before, target);
    wire.push({ mode: modeName, step: name, method: method,
                path: target.replace(/(SAMLRequest|SAMLResponse|Signature)=[^&]+/g,
                                     "$1=<value>"),
                status: r.status, code: code, headers: r.headers,
                decoded: decoded(r), body: r.body });
    log.debug("Leaving step().");
    return r;
  };
  let n = 0;
  const nextId = function (what) {
    log.debug("Entering nextId().");
    n += 1;
    log.debug("Leaving nextId().");
    return "_wire-" + realm + "-" + what + "-" + n;
  };
  const authnRequest = function (o) {
    log.debug("Entering authnRequest().");
    o = o || {};
    const id = o.id || nextId("ar");
    const attrs = ["xmlns:samlp=\"" + NS_SAMLP + "\"",
      "xmlns:saml=\"" + NS_SAML + "\"", "ID=\"" + id + "\"",
      "Version=\"" + (o.version || "2.0") + "\"",
      "IssueInstant=\"" + (o.issueInstant || new Date().toISOString()) +
        "\""];
    if (o.destination) {
      attrs.push("Destination=\"" + o.destination + "\"");
    }
    if (o.acsIndex !== undefined) {
      attrs.push("AssertionConsumerServiceIndex=\"" + o.acsIndex + "\"");
    } else if (o.acs !== "") {
      attrs.push("AssertionConsumerServiceURL=\"" + (o.acs || SP_ACS) +
                 "\"");
    }
    if (o.binding) {
      attrs.push("ProtocolBinding=\"" + o.binding + "\"");
    }
    if (o.forceAuthn) {
      attrs.push("ForceAuthn=\"true\"");
    }
    if (o.isPassive) {
      attrs.push("IsPassive=\"true\"");
    }
    let inner = "<saml:Issuer>" + (o.issuer || SP) + "</saml:Issuer>";
    if (o.subject) {
      inner += "<saml:Subject><saml:NameID>" + o.subject +
        "</saml:NameID></saml:Subject>";
    }
    if (o.nameIdFormat) {
      inner += "<samlp:NameIDPolicy Format=\"" + o.nameIdFormat +
        "\" AllowCreate=\"true\"/>";
    }
    if (o.classRefs) {
      inner += "<samlp:RequestedAuthnContext Comparison=\"exact\">" +
        o.classRefs.map(function (ref) {
          return "<saml:AuthnContextClassRef>" + ref +
            "</saml:AuthnContextClassRef>";
        }).join("") + "</samlp:RequestedAuthnContext>";
    }
    if (o.scoping) {
      inner += "<samlp:Scoping ProxyCount=\"1\"><samlp:RequesterID>" + SP +
        "</samlp:RequesterID></samlp:Scoping>";
    }
    log.debug("Leaving authnRequest().");
    return "<samlp:AuthnRequest " + attrs.join(" ") + ">" + inner +
      "</samlp:AuthnRequest>";
  };
  const redirect = function (xml, extra) {
    log.debug("Entering redirect().");
    log.debug("Leaving redirect().");
    return P + "/saml2/sso?SAMLRequest=" + encodeURIComponent(
      zlib.deflateRawSync(Buffer.from(xml)).toString("base64")) +
      (extra || "");
  };
  const posted = function (xml) {
    log.debug("Entering posted().");
    log.debug("Leaving posted().");
    return form({ SAMLRequest: Buffer.from(xml).toString("base64"),
                  RelayState: "rs-post" });
  };
  const set = function (key, value) {
    log.debug("Entering set(). " + key);
    log.debug("Leaving set().");
    return K.set(realm, key, value);
  };
  const clear = function (key) {
    log.debug("Entering clear(). " + key);
    log.debug("Leaving clear().");
    return K.unset(realm, key);
  };
  // The in-process file's own origin for a Destination it means to be this
  // service: placed() turns it into the recorded one.
  const here = K.base;

  await step("SAML 2.0 metadata", "GET", P + "/saml2/metadata");
  await step("SAML 2.0 metadata for one service provider", "GET",
             P + "/saml2/metadata/" + encodeURIComponent(SP));
  await step("SAML 2.0 metadata for a name nobody registered", "GET",
             P + "/saml2/metadata/nobody.wire.test");
  await step("SAML 1.1 metadata", "GET", P + "/saml11/metadata");
  await step("SAML 1.1 metadata for one relying party", "GET",
             P + "/saml11/metadata/" + encodeURIComponent(RP));
  await step("the WS-Federation view of the entity", "GET",
             P + "/FederationMetadata/2007-06/FederationMetadata.xml");
  await step("an unsigned AuthnRequest, signatures required by default",
             "GET", redirect(authnRequest({}), "&RelayState=rs-1"));
  await set("saml2.requireSignedAuthnRequests", "off");
  await step("Redirect, no session: to the sign-in screen", "GET",
             redirect(authnRequest({}), "&RelayState=rs-2"));
  const alice = await signIn(realm, "alice");
  await step("signed in, the sign-in not yet agreed to", "GET",
             redirect(authnRequest({})), alice.cookie);
  if (product) {
    await agree(realm, K.base + redirect(authnRequest({ id: "_agree-sp-" +
      K.rand(4) })));
    await agree(realm, K.base + P + "/saml11/sso?" + new URLSearchParams({
      providerId: RP, shire: RP_SHIRE, TARGET: "https://rp.wire.test/app" })
      .toString());
  }
  await step("Redirect, signed in: the POST binding answers", "GET",
             redirect(authnRequest({ destination: here + P + "/saml2/sso" }),
                      "&RelayState=rs-3"), alice.cookie);
  const heldPost = await step("POST binding: held and sent to a GET",
                              "POST", P + "/saml2/sso", alice.cookie,
                              posted(authnRequest({})));
  if (heldPost.headers.location) {
    await step("POST binding: the held request answered", "GET",
               heldPost.headers.location, alice.cookie);
  }
  for (const [label, format] of [
    ["NameIDPolicy persistent",
     "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"],
    ["NameIDPolicy transient",
     "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"],
    ["NameIDPolicy emailAddress",
     "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]]) {
    await step(label, "GET", redirect(authnRequest({ nameIdFormat: format })),
               alice.cookie);
  }
  await step("a Subject hint and Scoping are read and not refused", "GET",
             redirect(authnRequest({ subject: PERSON, scoping: true })),
             alice.cookie);
  await step("ProtocolBinding HTTP-Redirect", "GET", redirect(authnRequest({
    binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" })),
  alice.cookie);
  await step("ProtocolBinding HTTP-POST-SimpleSign", "GET",
             redirect(authnRequest({ binding:
               "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" })),
             alice.cookie);
  const art = await step("ProtocolBinding HTTP-Artifact", "GET",
    redirect(authnRequest({ binding:
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" }),
    "&RelayState=rs-art"), alice.cookie);
  let artValue = "";
  try {
    artValue = new URL(String(art.headers.location || ""))
      .searchParams.get("SAMLart") || "";
  } catch (e) {
    log.debug("Caught in conversation(): " + ((e && e.message) || e));
    // No artifact: the resolve steps record what an empty one answers.
    artValue = "";
  }
  const resolve = function (artifact, id) {
    log.debug("Entering resolve().");
    log.debug("Leaving resolve().");
    return soap("<samlp:ArtifactResolve xmlns:samlp=\"" + NS_SAMLP +
      "\" xmlns:saml=\"" + NS_SAML + "\" ID=\"" + id +
      "\" Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() +
      "\"><saml:Issuer>" + SP + "</saml:Issuer><samlp:Artifact>" +
      artifact + "</samlp:Artifact></samlp:ArtifactResolve>");
  };
  await step("ArtifactResolve", "POST", P + "/saml2/ars", "",
             resolve(artValue, nextId("resolve")), "text/xml");
  await step("ArtifactResolve, the same artifact again", "POST",
             P + "/saml2/ars", "", resolve(artValue, nextId("resolve")),
             "text/xml");
  await step("ArtifactResolve, not XML", "POST", P + "/saml2/ars", "",
             "not xml", "text/xml");
  await set("saml2.signResponse", false);
  await step("saml2.signResponse off", "GET", redirect(authnRequest({})),
             alice.cookie);
  await clear("saml2.signResponse");
  if (!product) {
    await set("saml2.signAssertion", false);
    await step("saml2.signAssertion off", "GET", redirect(authnRequest({})),
               alice.cookie);
    await clear("saml2.signAssertion");
  }
  await set("saml2.nameIdFormat",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
  await step("saml2.nameIdFormat emailAddress", "GET",
             redirect(authnRequest({})), alice.cookie);
  await clear("saml2.nameIdFormat");
  await step("a SAMLRequest that is not a message", "GET",
             P + "/saml2/sso?SAMLRequest=bm90IGEgbWVzc2FnZQ%3D%3D",
             alice.cookie);
  await step("no SAMLRequest at all", "GET", P + "/saml2/sso", alice.cookie);
  await step("a LogoutRequest at the SSO service", "GET", redirect(
    "<samlp:LogoutRequest xmlns:samlp=\"" + NS_SAMLP + "\" ID=\"" +
    nextId("lr") + "\" Version=\"2.0\" IssueInstant=\"" +
    new Date().toISOString() + "\"/>"), alice.cookie);
  await step("Version 1.0", "GET", redirect(authnRequest({ version: "1.0" })),
             alice.cookie);
  await step("a Destination elsewhere", "GET", redirect(authnRequest({
    destination: "https://elsewhere.wire.test/sso" })), alice.cookie);
  await step("an IssueInstant an hour old", "GET", redirect(authnRequest({
    issueInstant: new Date(Date.now() - 3600000).toISOString() })),
  alice.cookie);
  const replayed = authnRequest({ id: nextId("replay") });
  await step("an AuthnRequest, the first time", "GET", redirect(replayed),
             alice.cookie);
  await step("the same AuthnRequest again", "GET", redirect(replayed),
             alice.cookie);
  await step("ProtocolBinding PAOS", "GET", redirect(authnRequest({
    binding: "urn:oasis:names:tc:SAML:2.0:bindings:PAOS" })), alice.cookie);
  await step("IsPassive with no session", "GET",
             redirect(authnRequest({ isPassive: true })));
  await step("ForceAuthn: one trip to the screen", "GET",
             redirect(authnRequest({ forceAuthn: true })), alice.cookie);
  await step("RequestedAuthnContext MultiFactor, a password session", "GET",
             redirect(authnRequest({ classRefs: [
               "urn:oasis:names:tc:SAML:2.0:ac:classes:" +
               "MultiFactorAuthnContract"] })), alice.cookie);
  await step("RequestedAuthnContext PasswordProtectedTransport", "GET",
             redirect(authnRequest({ classRefs: [
               "urn:oasis:names:tc:SAML:2.0:ac:classes:" +
               "PasswordProtectedTransport"] })), alice.cookie);
  await step("an unknown AssertionConsumerServiceIndex", "GET",
             redirect(authnRequest({ acsIndex: 7 })), alice.cookie);
  await step("an AssertionConsumerServiceURL nobody registered", "GET",
             redirect(authnRequest({ acs: "https://evil.wire.test/acs" })),
             alice.cookie);
  const strangerRequest = { issuer: "https://stranger.wire.test/sp",
                            acs: "https://stranger.wire.test/acs" };
  await step("an Issuer nobody registered", "GET",
             redirect(authnRequest(strangerRequest)), alice.cookie);
  const unsolicited = await step("an unsolicited Response", "GET", P +
    "/saml2/unsolicited?providerId=" + encodeURIComponent(SP) + "&shire=" +
    encodeURIComponent(SP_ACS) + "&target=rs-u", alice.cookie);
  await step("an unsolicited Response for a stranger", "GET", P +
             "/saml2/unsolicited?providerId=" +
             encodeURIComponent("https://stranger.wire.test/sp"),
             alice.cookie);
  // The NameID the service provider was last given: the unsolicited
  // Response's.
  const given = ((/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/.exec(
    decoded(unsolicited)["form.SAMLResponse"] || "")) || [])[1] || PERSON;
  const query = function (nameId, id) {
    log.debug("Entering query().");
    log.debug("Leaving query().");
    return soap("<samlp:AttributeQuery xmlns:samlp=\"" + NS_SAMLP +
      "\" xmlns:saml=\"" + NS_SAML + "\" ID=\"" + id +
      "\" Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() +
      "\"><saml:Issuer>" + SP + "</saml:Issuer><saml:Subject>" +
      "<saml:NameID>" + nameId + "</saml:NameID></saml:Subject>" +
      "</samlp:AttributeQuery>");
  };
  await step("an AttributeQuery about the session's subject", "POST",
             P + "/saml2/aa", "", query(given, nextId("aq")), "text/xml");
  await step("an AttributeQuery about nobody", "POST", P + "/saml2/aa", "",
             query("nobody-at-all", nextId("aq")), "text/xml");
  // THE TWIN: the same service providers as the conversation's session —
  // the registered one with no NameIDPolicy, and in development the
  // stranger — so its identity-provider-initiated logout names what
  // alice's would, and alice's session goes on.
  const twin = await signIn(realm, "twin");
  const twinRequest = function (o) {
    log.debug("Entering twinRequest().");
    log.debug("Leaving twinRequest().");
    return redirect(authnRequest(Object.assign({ id: "_twin-" + K.rand(6) },
                                               o || {})));
  };
  await request("GET", twinRequest({}), twin.cookie);
  if (!product) {
    await request("GET", twinRequest(strangerRequest), twin.cookie);
  }
  await request("GET", P + "/saml2/unsolicited?providerId=" +
                encodeURIComponent(SP) + "&shire=" +
                encodeURIComponent(SP_ACS) + "&target=rs-u", twin.cookie);
  const page = await request("GET", P + "/saml2/slo", twin.cookie);
  const targets = [];
  const rows = /<tr><td><code>([^<]*)<\/code><\/td><td>(?:<a href="([^"]*)">[\s\S]*?<span class="sub">([^<]*)<\/span>|<span class="fail">)/g;
  let row = rows.exec(page.body);
  while (row !== null) {
    const url = unescapeHtml(row[2] || "");
    let xml = "";
    try {
      const parsed = new URL(url);
      xml = parsed.searchParams.get("SAMLRequest")
        ? decodeMessage(parsed.searchParams.get("SAMLRequest"), true) : "";
    } catch (e) {
      log.debug("Caught in conversation(): " + ((e && e.message) || e));
      // No link: recorded as the in-process file records one.
      xml = "";
    }
    targets.push({ party: unescapeHtml(row[1]),
                   from: unescapeHtml(row[3] || ""),
                   url: url.replace(/(SAMLRequest|Signature)=[^&]+/g,
                                    "$1=<value>"),
                   decoded: xml });
    row = rows.exec(page.body);
  }
  // The in-process record's request ids are minted by logoutTargetsFor()
  // in one call: each target its own.
  wire.push({ mode: modeName, step: "the LogoutRequests an identity-" +
              "provider-initiated logout sends", targets: targets });
  const logoutResponse = "<samlp:LogoutResponse xmlns:samlp=\"" + NS_SAMLP +
    "\" xmlns:saml=\"" + NS_SAML + "\" ID=\"" + nextId("lresp") +
    "\" Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() +
    "\" InResponseTo=\"_wire-none\"><saml:Issuer>" + SP +
    "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"" +
    "urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
    "</samlp:LogoutResponse>";
  await step("a LogoutResponse from the service provider", "GET",
             P + "/saml2/slo?SAMLResponse=" + encodeURIComponent(
               zlib.deflateRawSync(Buffer.from(logoutResponse))
                 .toString("base64")) + "&RelayState=rs-lr", alice.cookie);
  const logoutRequest = function (nameId, id) {
    log.debug("Entering logoutRequest().");
    log.debug("Leaving logoutRequest().");
    return "<samlp:LogoutRequest xmlns:samlp=\"" + NS_SAMLP +
      "\" xmlns:saml=\"" + NS_SAML + "\" ID=\"" + id +
      "\" Version=\"2.0\" IssueInstant=\"" + new Date().toISOString() +
      "\" Destination=\"" + here + P + "/saml2/slo\">" +
      "<saml:Issuer>" + SP + "</saml:Issuer><saml:NameID>" + nameId +
      "</saml:NameID></samlp:LogoutRequest>";
  };
  await step("a LogoutRequest that is not XML", "GET",
             P + "/saml2/slo?SAMLRequest=bm90IHhtbA%3D%3D", alice.cookie);
  await step("a LogoutRequest from the service provider", "GET",
             P + "/saml2/slo?SAMLRequest=" + encodeURIComponent(
               zlib.deflateRawSync(Buffer.from(logoutRequest(given,
                 nextId("slo")))).toString("base64")) + "&RelayState=rs-slo",
             alice.cookie);
  await step("a LogoutRequest with no session", "POST", P + "/saml2/slo", "",
             form({ SAMLRequest: Buffer.from(logoutRequest("nobody",
               nextId("slo"))).toString("base64") }));
  const bob = await signIn(realm, "bob");
  const sso11 = function (extra) {
    log.debug("Entering sso11().");
    log.debug("Leaving sso11().");
    return P + "/saml11/sso?" + new URLSearchParams(Object.assign({
      providerId: RP, shire: RP_SHIRE, TARGET: "https://rp.wire.test/app" },
    extra || {})).toString();
  };
  await step("Browser/POST, no session: to the sign-in screen", "GET",
             sso11());
  await step("Browser/POST", "GET", sso11(), bob.cookie);
  await set("saml11.nameIdFormat",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
  await step("Browser/POST, saml11.nameIdFormat emailAddress", "GET",
             sso11(), bob.cookie);
  await clear("saml11.nameIdFormat");
  const art11 = await step("Browser/Artifact, the shire's registered " +
                           "binding", "GET", sso11({ shire: RP_ARTIFACT }),
                           bob.cookie);
  let art11Value = "";
  try {
    art11Value = new URL(String(art11.headers.location || ""))
      .searchParams.get("SAMLart") || "";
  } catch (e) {
    log.debug("Caught in conversation(): " + ((e && e.message) || e));
    // No artifact: the responder steps record what an empty one answers.
    art11Value = "";
  }
  const request11 = function (inner, id) {
    log.debug("Entering request11().");
    log.debug("Leaving request11().");
    return soap("<samlp:Request xmlns:samlp=\"" + NS_SAMLP11 +
      "\" xmlns:saml=\"" + NS_SAML11 + "\" MajorVersion=\"1\" " +
      "MinorVersion=\"1\" RequestID=\"" + id + "\" IssueInstant=\"" +
      new Date().toISOString() + "\">" + inner + "</samlp:Request>");
  };
  const responder = P + "/saml11/responder";
  await step("the responder: an AssertionArtifact", "POST", responder, "",
             request11("<samlp:AssertionArtifact>" + art11Value +
                       "</samlp:AssertionArtifact>", nextId("r11")),
             "text/xml");
  await step("the responder: the same artifact again", "POST", responder, "",
             request11("<samlp:AssertionArtifact>" + art11Value +
                       "</samlp:AssertionArtifact>", nextId("r11")),
             "text/xml");
  const subject11 = "<saml:Subject><saml:NameIdentifier Format=\"" +
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">" + PERSON +
    "</saml:NameIdentifier></saml:Subject>";
  await step("the responder: an AttributeQuery", "POST", responder, "",
             request11("<samlp:AttributeQuery Resource=\"" + RP + "\">" +
                       subject11 + "</samlp:AttributeQuery>", nextId("r11")),
             "text/xml");
  await step("the responder: an AuthenticationQuery", "POST", responder, "",
             request11("<samlp:AuthenticationQuery>" + subject11 +
                       "</samlp:AuthenticationQuery>", nextId("r11")),
             "text/xml");
  await step("the responder: an AuthorizationDecisionQuery", "POST",
             responder, "", request11(
               "<samlp:AuthorizationDecisionQuery Resource=\"x\">" +
               subject11 + "<saml:Action>read</saml:Action>" +
               "</samlp:AuthorizationDecisionQuery>", nextId("r11")),
             "text/xml");
  await step("the responder: an AssertionIDReference nobody holds", "POST",
             responder, "", request11("<saml:AssertionIDReference>_nothing" +
               "</saml:AssertionIDReference>", nextId("r11")), "text/xml");
  await step("the responder: a Request carrying nothing", "POST", responder,
             "", request11("", nextId("r11")), "text/xml");
  await step("the responder: not XML", "POST", responder, "", "not xml",
             "text/xml");
  await step("no TARGET", "GET", P + "/saml11/sso?providerId=" +
             encodeURIComponent(RP) + "&shire=" +
             encodeURIComponent(RP_SHIRE), bob.cookie);
  await step("a shire nobody registered", "GET",
             sso11({ shire: "https://evil.wire.test/shire" }), bob.cookie);
  await step("a relying party nobody registered", "GET", sso11({
    providerId: "https://stranger.wire.test/rp",
    shire: "https://stranger.wire.test/shire" }), bob.cookie);
  await step("profile and format parameters, ignored", "GET",
             sso11({ profile: "artifact", format: "urn:made:up" }),
             bob.cookie);
  await step("the inter-site transfer service's own start", "GET",
             P + "/saml11/sso/" + encodeURIComponent(RP) + "?TARGET=" +
             encodeURIComponent("https://rp.wire.test/x"), bob.cookie);
  log.debug("Leaving conversation(). " + wire.length);
  return wire;
}

async function test() {
  log.debug("Entering test().");
  const recorded = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
  LEAF = await listenerLeaf();
  const realmD = await setUp("development", "samlwire");
  const realmP = await setUp("product", "samlwirep");
  const now = normalise((await conversation("development", "samlwire",
                                            realmD, false))
    .concat(await conversation("product", "samlwirep", realmP, true))
    .map(placed)).map(placeless);
  const expected = recorded.wire.map(placeless);
  K.check("the conversation has as many steps as recorded (" +
          expected.length + ")", function () {
    assert.strictEqual(now.length, expected.length);
  });
  const differing = [];
  expected.forEach(function (one, i) {
    const why = firstDifference(one, now[i], "wire");
    if (why) {
      differing.push(one.mode + ", " + one.step + ": " + why);
    } else {
      K.check(one.mode + ", " + one.step + " answers as recorded (" +
              (one.status === undefined ? "the logout page" : one.status) +
              ")", function () {
        assert.ok(true);
      });
    }
  });
  differing.forEach(function (one) {
    log.error("DIFFERS: " + one.slice(0, 1500));
  });
  K.check("every step answers as recorded", function () {
    assert.strictEqual(differing.length, 0, differing.length +
                       " step(s) differ; the first: " +
                       String(differing[0]).slice(0, 600));
  });
  log.debug("Leaving test().");
}

K.main(test, 135);
