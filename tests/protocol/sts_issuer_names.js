// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_issuer_names.js
//
// ---------------------------------------------------------------------------
// ONE ISSUER PER REALM, IN EVERY PROTOCOL (#523), OVER THE WIRE.
//
// D12 (#444): carries over tests/issuer_names.js. The realm's OAuth issuer
// (its discovery document's `issuer`) is every name the realm issues under.
// In a development realm and a product one, each read off a real answer:
//
//   U2. the seven retired issuer settings are refused if named, naming
//       global.publicBaseUrl;
//   U3. WS-Trust: a SAML 2.0 Issuer, a SAML 1.1 Issuer and a JWT's `iss`
//       for a registered AppliesTo are the one string; in development an
//       AppliesTo nobody registered gets the same name, before and after
//       it is seen; in product it is refused (STS-WSTRUST-0030);
//   U4. WS-Federation: the sign-in response's assertion carries the issuer
//       for a registered wtrealm (and, in development, one nobody
//       registered);
//   U5. WS-Federation metadata: the shared document and
//       /wsfed/metadata/{rp}, by identifier and by slug, name the issuer,
//       no-store, the realm's one entity with its SAML roles beside it; an
//       unregistered segment is a 404 (STS-WSFED-0019);
//   U6. SAML 2.0's entityID and SAML 1.1's providerID in their metadata
//       are the issuer;
//   U7. the issuer carries the realm's prefix and is not the default
//       realm's.
//
// NOT CARRIED: U1 (the function's own identity with oauth2.issuerOf(), and
// its answer with no request at all — library, class (d)); U2b (the four
// codes are retired in the table — tests/error_codes.js owns it); U4's
// signature check, which `wstrust_chain_kit.js` and the WS-Federation
// jobs hold against the realm's published certificate.
//
// OWNED HERE (local: true): this repository's own identity provider.
// ---------------------------------------------------------------------------

const authnSignin = require("./authn_signin");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_issuer_names",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const DEV = "iss-" + STAMP;
const PROD = "issp-" + STAMP;
const PASSWORD = "Issuer-Names-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = "alice-" + STAMP;
const APP = "in-app";
const SP_URL = "https://in-sp.issuer.example.test";
const REPLY_URL = "https://in-rp.issuer.example.test/wsfed";
const WSFED_URL_RP = "https://in-wsfed.issuer.example.test/";
const UNREG_URL = "https://in-unregistered.issuer.example.test";
const WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
const SAML11 = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-" +
  "profile-1.1#SAMLV1.1";
const JWT = "urn:ietf:params:oauth:token-type:jwt";
const RETIRED = ["saml.issuer", "saml2.entityId",
                 "saml2.perApplicationEntityId", "saml11.providerId",
                 "saml11.perApplicationProviderId", "wstrust.issuer",
                 "wsfed.entityId"];
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_issuer_names/1.0 (" + STAMP + ")";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page or a JWT; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A refusal: a 400 whose answer names no code.
async function refused(url, payload, what) {
  log.debug("Entering refused().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 400 && r.body && r.body.ok === false,
    "POST " + url + " should have refused " + what + "; it answered " +
    r.status + " " + String(r.raw).slice(0, 400));
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "no code is sent: " + r.raw);
  log.debug("Leaving refused().");
  return r.body;
}

async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(api, code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(api, code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(api, code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// One browser, with a cookie jar, signed in once and kept.
function browser(realmPath) {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    realm: realmPath,
    header() {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    keep(headers) {
      log.debug("Entering keep().");
      const set = headers.getSetCookie ? headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      log.debug("Leaving keep().");
    },
    async go(method, path) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = { "User-Agent": AGENT };
      const cookie = self.header();
      if (cookie) {
        headers.cookie = cookie;
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers });
      self.keep(r.headers);
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, headers: r.headers };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const answer = await authnSignin.submit(base + b.realm, location,
    { action: "login", username: who, password: PASSWORD },
    { cookie: b.header(), headers: { "User-Agent": AGENT } });
  assert.ok(answer.view, "the sign-in screen: " + answer.status + " " +
            JSON.stringify(answer.errors));
  b.keep(answer.headers);
  const posted = await authnSignin.asFormAnswer(answer, function (m, u) {
    return b.go(m, u);
  });
  log.debug("Leaving signIn().");
  return posted;
}


function unescapeXml(text) {
  log.debug("Entering unescapeXml().");
  log.debug("Leaving unescapeXml().");
  return String(text).replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/&amp;/g, "&");
}

// A WS-Trust Issue for `appliesTo` as ALICE, asking for `tokenType`.
async function issued(realmPath, appliesTo, tokenType) {
  log.debug("Entering issued(). " + appliesTo);
  const envelope = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + ALICE + '</wsse:Username>' +
    '<wsse:Password>' + PASSWORD + '</wsse:Password></wsse:UsernameToken>' +
    '</wsse:Security></soap:Header><soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="' + WST + '"><wst:RequestType>' + WST + '/Issue' +
    '</wst:RequestType>' + (tokenType ? '<wst:TokenType>' + tokenType +
    '</wst:TokenType>' : '') + '<wsp:AppliesTo xmlns:wsp="http://' +
    'schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    appliesTo + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const r = await send(base + realmPath + "/sts", { method: "POST",
    // A desktop browser's agent: product's risk engine reads a bare
    // client as automated and the issuance policy refuses it (#62).
    headers: { "Content-Type": "application/soap+xml", "User-Agent": AGENT },
    body: envelope });
  const text = String(r.raw);
  const s2 = /<saml:Issuer>([^<]*)<\/saml:Issuer>/.exec(text);
  const s11 = /<saml:Assertion [^>]*\bIssuer="([^"]*)"/.exec(text);
  const jwt = /<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(text);
  let iss = "";
  if (jwt) {
    iss = String(JSON.parse(Buffer.from(jwt[1].trim().split(".")[1],
                                        "base64url").toString("utf8")).iss);
  }
  log.debug("Leaving issued(). " + r.status);
  return { status: r.status, issuer: tokenType === SAML11
             ? (s11 ? s11[1] : "") : (s2 ? s2[1] : ""),
           iss: iss, raw: text.slice(0, 400) };
}

function entityIdOf(xml) {
  log.debug("Entering entityIdOf().");
  const m = /<(?:md:)?EntityDescriptor [^>]*\bentityID="([^"]*)"/
    .exec(String(xml));
  log.debug("Leaving entityIdOf().");
  return m ? m[1] : "";
}

async function setupRealm(id, mode) {
  log.debug("Entering setupRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Issuer names " + id },
    "created the realm " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
      value: mode }, "put " + id + " in " + mode + " mode");
    await ok(base + "/admin-api/realms/set", { id: id,
      key: "authn.allowOptionalSecondFactor", value: "true" },
      "let a password alone sign in to " + id);
  }
  const api = base + "/realm/" + id + "/admin-api";
  await ok(api + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: ALICE, givenName: "Alice", sn: "Issuer",
                  mail: ALICE + "@issuer.example.test" } },
    "created " + ALICE + " in " + id);
  await ok(api + "/applications/create", { identifier: APP, name: APP,
    protocols: ["wstrust", "wsfed", "saml2", "saml11"],
    fields: { wstrustAppliesTo: [SP_URL], wsfedReplyUrl: [REPLY_URL] } },
    "registered " + APP + " in " + id);
  await ok(api + "/applications/create", { identifier: WSFED_URL_RP,
    name: "wsfed url rp", protocols: ["wsfed"],
    fields: { wsfedRealm: [WSFED_URL_RP], wsfedReplyUrl: [REPLY_URL] } },
    "registered a relying party named by a URL in " + id);
  log.debug("Leaving setupRealm().");
  return api;
}

async function wsfedSignIn(realmPath, wtrealm) {
  log.debug("Entering wsfedSignIn(). " + wtrealm);
  const b = browser(realmPath);
  let r = await b.go("GET", realmPath + "/wsfed?" + form({ wa: "wsignin1.0",
    wtrealm: wtrealm, wreply: REPLY_URL }));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location)) {
    const signed = await signIn(b, r.location, ALICE);
    r = await b.go("GET", signed.location);
  }
  for (let i = 0; i < 6 && (r.status === 302 || r.status === 303) &&
       r.location.indexOf(REPLY_URL) !== 0; i += 1) {
    if (authnSignin.isConsent(r.location)) {
      // Product asks the person first; they allow.
      const answered = await authnSignin.consentWithJar(
        absolute(r.location), "allow", b.jar,
        { headers: { "User-Agent": AGENT } });
      r = answered.status === 303 ? await b.go("GET", answered.location)
        : { status: answered.status, location: "", text: answered.text };
    } else {
      r = await b.go("GET", r.location);
    }
  }
  const m = /name="wresult" value="([^"]*)"/.exec(r.text);
  const wresult = m ? unescapeXml(m[1]) : "";
  // SAML 2.0's Issuer element, or SAML 1.1's Issuer attribute (the
  // passive profile's default token here).
  const s2 = /<(?:saml2?:)?Issuer>([^<]*)<\/(?:saml2?:)?Issuer>/
    .exec(wresult) || /<saml:Assertion [^>]*\bIssuer="([^"]*)"/
    .exec(wresult);
  log.debug("Leaving wsfedSignIn(). " + r.status);
  return { status: r.status, issuer: s2 ? s2[1] : "",
           text: String(wresult || r.text).slice(0, 400) };
}

async function inRealm(id, mode) {
  log.debug("Entering inRealm(). " + id);
  const m = mode || "development";
  log.info("=== " + m + ": the realm " + id + " ===");
  const api = await setupRealm(id, mode);
  const rp = "/realm/" + id;
  const expected = (await send(base + rp +
    "/.well-known/openid-configuration")).body.issuer;
  const defaultIssuer = (await send(base +
    "/.well-known/openid-configuration")).body.issuer;
  check("U7. " + m + ": the issuer carries the realm's prefix and is not " +
        "the default realm's", function () {
    assert.ok(String(expected).indexOf(rp) >= 0, expected);
    assert.notStrictEqual(expected, defaultIssuer);
  });

  const s2 = await issued(rp, SP_URL);
  const s11 = await issued(rp, SP_URL, SAML11);
  const jwt = await issued(rp, SP_URL, JWT);
  check("U3. " + m + ": WS-Trust's SAML 2.0 Issuer, SAML 1.1 Issuer and " +
        "JWT iss are one string, the OAuth issuer", function () {
    assert.ok(s2.status === 200 && s2.issuer === expected, JSON.stringify(s2));
    assert.ok(s11.status === 200 && s11.issuer === expected,
              JSON.stringify(s11));
    assert.ok(jwt.status === 200 && jwt.iss === expected,
              JSON.stringify(jwt));
  });
  const before = await codeCount(api, "STS-WSTRUST-0030");
  const first = await issued(rp, UNREG_URL + "/" + m);
  const second = await issued(rp, UNREG_URL + "/" + m);
  if (!mode) {
    check("U3b. development: an AppliesTo nobody registered gets the same " +
          "name, before and after it is seen", function () {
      assert.ok(first.status === 200 && first.issuer === expected,
                JSON.stringify(first));
      assert.ok(second.status === 200 && second.issuer === expected,
                JSON.stringify(second));
    });
  } else {
    const after = await codesSettle(api, "STS-WSTRUST-0030", before + 2);
    check("U3b. product: an AppliesTo nobody registered is refused, even " +
          "after a sighting, STS-WSTRUST-0030", function () {
      assert.strictEqual(first.status, 500, first.raw);
      assert.strictEqual(second.status, 500, second.raw);
      assert.ok(after - before >= 2, "rows added: " + (after - before));
    });
  }

  const signedIn = await wsfedSignIn(rp, APP);
  check("U4. " + m + ": a WS-Federation sign-in response's assertion " +
        "carries the issuer", function () {
    assert.strictEqual(signedIn.issuer, expected, JSON.stringify(signedIn));
  });
  if (!mode) {
    const unreg = await wsfedSignIn(rp, "urn:in-unregistered-rp");
    check("U4. development: one for a wtrealm nobody registered carries it " +
          "too", function () {
      assert.strictEqual(unreg.issuer, expected, JSON.stringify(unreg));
    });
  }

  const meta = async function (path) {
    const r = await send(base + rp + path);
    return { status: r.status, entityId: entityIdOf(r.raw),
             cache: String(r.headers.get("cache-control") || ""),
             roles: /fed:SecurityTokenServiceType/.test(r.raw) &&
                    /<md:IDPSSODescriptor[\s>]/.test(r.raw) &&
                    /<md:AttributeAuthorityDescriptor[\s>]/.test(r.raw),
             raw: r.raw.slice(0, 200) };
  };
  const own = await meta("/wsfed/metadata/" + APP);
  const byUrl = await meta("/wsfed/metadata/" +
                           encodeURIComponent(WSFED_URL_RP));
  const bySlug = await meta("/wsfed/metadata/app-" + nodeCrypto
    .createHash("sha256").update(WSFED_URL_RP).digest("hex").slice(0, 12));
  const shared = await meta("/FederationMetadata/2007-06/" +
                            "FederationMetadata.xml");
  check("U5. " + m + ": the shared document and /wsfed/metadata/{rp}, by " +
        "identifier and by slug, name the issuer, no-store, the realm's one " +
        "entity with its SAML roles beside it", function () {
    assert.ok(own.status === 200 && own.entityId === expected &&
              /no-store/.test(own.cache) && own.roles, JSON.stringify(own));
    assert.ok(byUrl.entityId === expected, JSON.stringify(byUrl));
    assert.ok(bySlug.entityId === expected, JSON.stringify(bySlug));
    assert.ok(shared.status === 200 && shared.entityId === expected &&
              shared.roles, JSON.stringify(shared));
  });
  const wsBefore = await codeCount(api, "STS-WSFED-0019");
  const unregMeta = await meta("/wsfed/metadata/in-nobody");
  const wsAfter = await codesSettle(api, "STS-WSFED-0019", wsBefore + 1);
  check("U5b. " + m + ": an unregistered segment is a 404, no-store, " +
        "recorded STS-WSFED-0019", function () {
    assert.strictEqual(unregMeta.status, 404, JSON.stringify(unregMeta));
    assert.ok(/no-store/.test(unregMeta.cache), unregMeta.cache);
    assert.ok(wsAfter - wsBefore >= 1, "rows added: " +
              (wsAfter - wsBefore));
  });
  const saml2 = await send(base + rp + "/saml2/metadata");
  const saml11 = await send(base + rp + "/saml11/metadata");
  check("U6. " + m + ": SAML 2.0's entityID and SAML 1.1's providerID are " +
        "the issuer", function () {
    assert.strictEqual(entityIdOf(saml2.raw), expected,
                       saml2.raw.slice(0, 300));
    assert.strictEqual(entityIdOf(saml11.raw), expected,
                       saml11.raw.slice(0, 300));
  });
  log.debug("Leaving inRealm().");
}

async function retired() {
  log.debug("Entering retired().");
  log.info("=== U2. the retired issuer settings ===");
  for (const key of RETIRED) {
    const r = await postJson(base + "/realm/" + DEV + "/admin-api/config/set",
                             { key: key, value: "https://x.example" });
    check("U2. " + key + " is refused if named, naming " +
          "global.publicBaseUrl", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(/global\.publicBaseUrl/.test(r.raw), r.raw.slice(0, 300));
    });
  }
  log.debug("Leaving retired().");
}

async function test() {
  log.debug("Entering test().");
  await inRealm(DEV, "");
  await retired();
  await inRealm(PROD, "product");
  assert.ok(checks >= 22, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [DEV, PROD]) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
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
    log.debug("Caught in main() removing realms: " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving main().");
}

main();
