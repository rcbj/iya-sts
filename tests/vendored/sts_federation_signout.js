// ===========================================================================
// A FEDERATION PARTNER'S SIGN-OUT, OVER THE NETWORK (#167).
//
// Until #167 a partner's sign-out was refused at the assertion consumer
// service (STS-FED-0024) and dropped, and its SAML SessionNotOnOrAfter was
// ignored: the session here, and every token issued from it, outlived the
// partner's. `federation/federation_slo.ts` now receives every sign-out a
// partner can send and ends the session it names, and a sign-out here offers
// the partner its own. `tests/federation_signout.js` holds the functions in
// process; this job drives a running service, in whichever mode it is in:
//
//   1. SAML 2.0, REALM TO REALM: the service-provider realm's metadata
//      publishes SingleLogoutService; the identity-provider realm's own
//      identity-provider-initiated Single Logout ends the federated session
//      here and gets a signed LogoutResponse it verifies; and the
//      service-provider-initiated round trip — /logout here, the partner's
//      LogoutRequest link, the partner's LogoutResponse back — matched once.
//   2. SAML 2.0, A PARTNER WRITTEN HERE (this job's own key): every
//      LogoutRequest refusal — unsigned, another key, another issuer,
//      another Destination, stale, replayed — each ending nothing; an
//      unknown SessionIndex answered UnknownPrincipal; the match ending
//      only its session; SessionNotOnOrAfter ending the session when it
//      passes, and one already passed refused.
//   3. OPENID CONNECT, A PARTNER WRITTEN HERE: Back-Channel Logout (the
//      section 2.6 refusals, a replayed jti, the match), Front-Channel
//      Logout (iss and sid required, the partner's origin the only frame
//      ancestor), fedAcceptSignout off, and RP-Initiated Logout offered from
//      /logout and matched once on the way back.
//   4. OPENID CONNECT FRONT-CHANNEL, REALM TO REALM: the identity-provider
//      realm's own sign-out page frames this relying party's
//      frontchannel_logout_uri, and loading it ends the session here.
//   5. WS-FEDERATION, A PARTNER WRITTEN HERE: the ACS refuses a sign-out and
//      names the new path; wsignoutcleanup1.0 draws a confirmation and ends
//      nothing until it is confirmed in the browser it was drawn for.
//   6. SAML 1.1 defines no sign-out; fedRequireSignedLogout off is refused
//      in product and, in development, admits an unsigned LogoutRequest.
//
// THE PARTNER IS WRITTEN HERE where a realm of this service cannot play it:
// a back channel from this service to itself is not reachable from every
// stack (sts_federation_realms.js argues it), and a forgery built by the
// implementation under test proves only that it agrees with itself. Every
// realm, person, application and relationship is CREATED by this run and
// left standing; nothing service-wide is changed.
// ===========================================================================

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const zlib = require("zlib");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const xmldsig = require("./saml_xmldsig.js");

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
var log = bunyan.createLogger({ name: "sts_federation_signout",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp();
const IDP = "soi-" + STAMP;
const SP = "sos-" + STAMP;
const PERSON = names.usernameFor("fed-so");
const PASSWORD = "Signout-Passw0rd!-" + String(Date.now()).slice(-6);
const IDP_MAIL = IDP + ".example.net";
const REL = {
  saml: "saml",            // SAML 2.0 to the IdP realm
  oidc: "oidc",            // OIDC front-channel shape to the IdP realm
  samlT: "saml-t",         // SAML 2.0 to a partner written here
  oidcT: "oidc-t",         // OIDC to a partner written here
  wsfedT: "wsfed-t",       // WS-Federation to a partner written here
  saml11: "saml11-t"       // SAML 1.1, which defines no sign-out
};
const PARTNER_SAML = "urn:test:signout-partner:" + STAMP;
const PARTNER_SLO = "https://saml-partner.invalid/slo";
const PARTNER_OIDC = "https://oidc-partner.invalid";
const PARTNER_WSFED = "urn:test:signout-wsfed:" + STAMP;
const NAMEID = "saml-subject-" + STAMP;
const OIDC_SUB = "oidc-subject-" + STAMP;
const WSFED_NAME = "wsfed-subject-" + STAMP;
const OIDC_CLIENT = "so-oidc-" + STAMP;
const T_CLIENT = "so-oidc-t-" + STAMP;
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const BCL_EVENT = "http://schemas.openid.net/event/backchannel-logout";

let isProduct = false;
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

function realmBase(realm) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + realm;
}

function squash(text) {
  log.debug("Entering squash().");
  log.debug("Leaving squash().");
  return String(text || "").replace(/<style[\s\S]*?<\/style>/g, " ")
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
}

function htmlDecode(text) {
  log.debug("Entering htmlDecode().");
  log.debug("Leaving htmlDecode().");
  return String(text || "").replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

async function api(realm, method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = { method: method, redirect: "manual", headers: {} };
  if (payload !== undefined) {
    options.headers["content-type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const prefix = realm ? realmBase(realm) : base;
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

// A cookie jar per browser. Both realms are one origin and the session
// cookie has one name at Path=/, so a browser holding a session in each
// holds one cookie: a partner's session is kept in a jar of its own.
function jar(from) {
  log.debug("Entering jar().");
  const store = Object.assign({}, (from && from.dump()) || {});
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
          const name = pair.slice(0, i).trim();
          const value = pair.slice(i + 1).trim();
          if (value && !/Max-Age=0/i.test(line)) {
            store[name] = value;
          } else {
            delete store[name];
          }
        });
      log.debug("Leaving take().");
    },
    has: function () {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return Object.keys(store).length > 0;
    },
    dump: function () {
      log.debug("Entering dump().");
      log.debug("Leaving dump().");
      return Object.assign({}, store);
    }
  };
}

async function hop(cookies, url, options) {
  log.debug("Entering hop(). " + ((options && options.method) || "GET") +
            " " + url);
  const o = Object.assign({ redirect: "manual", headers: {} }, options || {});
  o.headers = Object.assign({}, o.headers);
  if (cookies && cookies.has()) {
    o.headers.cookie = cookies.header();
  }
  const r = await fetch(url, o);
  if (cookies) {
    cookies.take(r);
  }
  const body = r.status >= 300 && r.status < 400 ? "" : await r.text();
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, headers: r.headers, body: body, url: url,
           location: r.headers.get("location") || "" };
}

function postForm(cookies, url, fields) {
  log.debug("Entering postForm(). " + url);
  log.debug("Leaving postForm().");
  return hop(cookies, url, {
    method: "POST", body: new URLSearchParams(fields).toString(),
    headers: { "content-type": "application/x-www-form-urlencoded" } });
}

function formsIn(html) {
  log.debug("Entering formsIn().");
  const out = [];
  const re = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
  let m = re.exec(String(html || ""));
  while (m) {
    const action = htmlDecode((/action="([^"]*)"/i.exec(m[1]) || [])[1] || "");
    const method = ((/method="([^"]*)"/i.exec(m[1]) || [])[1] || "get")
      .toLowerCase();
    const fields = {};
    [...m[2].matchAll(/<input[^>]*type="hidden"[^>]*>/gi)].forEach(
      function (one) {
        const n = /name="([^"]+)"/.exec(one[0]);
        const v = /value="([^"]*)"/.exec(one[0]);
        if (n) {
          fields[htmlDecode(n[1])] = v ? htmlDecode(v[1]) : "";
        }
      });
    out.push({ action: action, method: method, fields: fields });
    m = re.exec(String(html || ""));
  }
  log.debug("Leaving formsIn(). " + out.length);
  return out;
}

function isAcs(url) {
  log.debug("Entering isAcs().");
  log.debug("Leaving isAcs().");
  return /\/federation\/acs\//.test(String(url || ""));
}

// A BROWSER UP TO THE SERVICE PROVIDER'S DOOR (sts_federation_realms.js's
// toTheDoor()): follows redirects, answers the partner realm's sign-in and
// consent screens, and STOPS at the first request addressed to an ACS,
// returning it unsent — with the jar that holds the PARTNER's session.
async function toTheDoor(cookies, startUrl) {
  log.debug("Entering toTheDoor(). " + startUrl);
  let r = await hop(cookies, startUrl);
  for (let step = 0; step < 24; step += 1) {
    if (r.status >= 300 && r.status < 400 && r.location) {
      const next = new URL(r.location, r.url).toString();
      if (isAcs(next)) {
        log.debug("Leaving toTheDoor(). A redirect to the ACS.");
        return { method: "GET", url: next, fields: null };
      }
      r = await hop(cookies, next);
      continue;
    }
    if (r.status !== 200) {
      break;
    }
    const forms = formsIn(r.body);
    const signIn = forms.find(function (f) {
      return "authn_id" in f.fields;
    });
    const consent = forms.find(function (f) {
      return /consent/.test(f.action) || "consent_id" in f.fields;
    });
    const onward = forms.find(function (f) {
      return f.method === "post" &&
             ("SAMLResponse" in f.fields || "SAMLRequest" in f.fields ||
              "id_token" in f.fields || "code" in f.fields);
    });
    if (signIn) {
      r = await postForm(cookies, new URL(signIn.action || r.url, r.url)
        .toString(), Object.assign({}, signIn.fields, {
          username: PERSON, password: PASSWORD, action: "login" }));
      continue;
    }
    if (consent) {
      r = await postForm(cookies, new URL(consent.action || r.url, r.url)
        .toString(), Object.assign({}, consent.fields, {
          action: "allow", decision: "allow" }));
      continue;
    }
    if (onward) {
      const to = new URL(onward.action, r.url).toString();
      if (isAcs(to)) {
        log.debug("Leaving toTheDoor(). A form addressed to the ACS.");
        return { method: "POST", url: to, fields: onward.fields };
      }
      r = await postForm(cookies, to, onward.fields);
      continue;
    }
    break;
  }
  log.debug("Leaving toTheDoor(). It never reached the ACS.");
  throw new Error("the browser never reached a /federation/acs/ door: HTTP " +
                  r.status + " at " + r.url + " — " + squash(r.body));
}

// A FEDERATED SIGN-IN THROUGH THE IDP REALM: `partner` is the jar holding
// the partner realm's session, `browser` the service provider's.
async function realmSignIn(relationship) {
  log.debug("Entering realmSignIn(). " + relationship);
  const partner = jar();
  const door = await toTheDoor(partner, realmBase(SP) + "/federation/login/" +
                                        relationship);
  const browser = jar();
  let r = door.method === "GET" ? await hop(browser, door.url)
                                : await postForm(browser, door.url,
                                                 door.fields);
  for (let i = 0; i < 4 && r.status >= 300 && r.status < 400; i += 1) {
    r = await hop(browser, new URL(r.location, r.url).toString());
  }
  log.debug("Leaving realmSignIn(). " + r.status);
  return { partner: partner, browser: browser, r: r };
}

// The SP realm's federated sessions for PERSON through one relationship.
async function sessionsThrough(relationship) {
  log.debug("Entering sessionsThrough(). " + relationship);
  const r = await api(SP, "GET", "/users?user=" +
                                  encodeURIComponent(PERSON));
  must(r.status === 200 && r.body, "GET /users answered " + r.status);
  const sessions = (Array.isArray(r.body.sessions) ? r.body.sessions : [])
    .filter(function (s) {
      return /^federated\b/.test(String(s.amr || "")) && !s.expired;
    });
  log.debug("Leaving sessionsThrough(). " + sessions.length);
  return sessions.length;
}

// Whether a browser's cookie still names a live session in the SP realm:
// /logout answers a program with JSON, 200 naming the person or 401 when the
// request carries no session.
async function liveIn(browser) {
  log.debug("Entering liveIn().");
  const r = await hop(browser, realmBase(SP) + "/logout",
                      { headers: { accept: "application/json" } });
  log.debug("Leaving liveIn(). " + r.status);
  return r.status === 200;
}

function b64uJson(value) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function signJwt(header, payload, privateKey) {
  log.debug("Entering signJwt().");
  const input = b64uJson(header) + "." + b64uJson(payload);
  log.debug("Leaving signJwt().");
  return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
                                       privateKey).toString("base64url");
}

function credential(cn) {
  log.debug("Entering credential().");
  const forge = require("node-forge");
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  cert.setSubject([{ name: "commonName", value: cn }]);
  cert.setIssuer([{ name: "commonName", value: cn }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const certificatePem = forge.pki.certificateToPem(cert);
  const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
  log.debug("Leaving credential().");
  return { certificatePem: certificatePem, privateKeyPem: privateKeyPem,
           der: certificatePem.replace(/-----[^-]+-----/g, "")
             .replace(/\s+/g, ""),
           privateKey: nodeCrypto.createPrivateKey(privateKeyPem),
           publicJwk: nodeCrypto.createPublicKey(privateKeyPem)
             .export({ format: "jwk" }) };
}

async function ensureRealm(id) {
  log.debug("Entering ensureRealm(). " + id);
  const made = await api(null, "POST", "/realms/create",
                         { id: id, domain: id + ".example.net", name: id });
  must(made.status === 200 ||
       /already/i.test(JSON.stringify(made.body || made.text)),
       "creating the realm " + id + " answered " + made.status);
  log.debug("Leaving ensureRealm().");
}

async function createPerson(realm, withPassword) {
  log.debug("Entering createPerson(). " + realm);
  const payload = { username: PERSON, invent: false,
                    attributes: { cn: "Signout " + PERSON, sn: PERSON,
                                  mail: PERSON + "@" + IDP_MAIL },
                    credential: withPassword ? "password" : "none" };
  if (withPassword) {
    payload.password = PASSWORD;
  }
  const r = await api(realm, "POST", "/users/create", payload);
  must(r.status === 200 && r.body && r.body.ok,
       "creating " + PERSON + " in " + realm + " answered " + r.status + " " +
       r.text.slice(0, 300));
  log.debug("Leaving createPerson().");
}

async function createApplication(realm, identifier, protocols, fields) {
  log.debug("Entering createApplication(). " + identifier);
  const r = await api(realm, "POST", "/applications/create",
    { identifier: identifier, name: "signout " + identifier,
      protocols: protocols, fields: fields });
  must(r.status === 200 && r.body && r.body.ok,
       "creating the application " + identifier + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createApplication().");
}

async function setRel(id, field, value) {
  log.debug("Entering setRel(). " + id + " " + field);
  const r = await api(SP, "POST", "/federation/set",
                      { id: id, field: field, value: value });
  log.debug("Leaving setRel(). " + r.status);
  return r;
}

async function createRelationship(id, protocol, peer, settings) {
  log.debug("Entering createRelationship(). " + id);
  const made = await api(SP, "POST", "/federation/create",
    { id: id, role: "service-provider", protocol: protocol, peer: peer });
  must(made.status === 200 && made.body && made.body.ok,
       "creating " + id + " answered " + made.status + " " +
       made.text.slice(0, 300));
  for (const field of Object.keys(settings)) {
    const set = await setRel(id, field, settings[field]);
    must(set.status === 200 && set.body && set.body.ok,
         "setting " + field + " on " + id + " answered " + set.status + " " +
         set.text.slice(0, 300));
  }
  const enabled = await api(SP, "POST", "/federation/enable", { id: id });
  must(enabled.status === 200 && enabled.body && enabled.body.ok,
       "enabling " + id + " answered " + enabled.status + " " +
       enabled.text.slice(0, 300));
  const view = await api(SP, "GET", "/federation?relationship=" +
                                    encodeURIComponent(id));
  must(view.status === 200 && view.body && view.body.found,
       "reading " + id + " back answered " + view.status);
  log.debug("Leaving createRelationship().");
  return view.body;
}

async function link(relationship, subject) {
  log.debug("Entering link(). " + relationship);
  const r = await api(SP, "POST", "/users/federation-link",
                      { user: PERSON, relationship: relationship,
                        subject: subject });
  must(r.status === 200 && r.body && r.body.ok,
       "linking " + PERSON + " through " + relationship + " answered " +
       r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving link().");
}

// A query parameter exactly as it arrived.
function rawParam(url, name) {
  log.debug("Entering rawParam(). " + name);
  const raw = new URL(url).search.slice(1);
  const m = new RegExp("(?:^|&)" + name + "=([^&]*)").exec(raw);
  log.debug("Leaving rawParam().");
  return m ? m[1] : "";
}

// What a SAML message on the Redirect binding in `url` says.
function messageIn(url, field) {
  log.debug("Entering messageIn(). " + field);
  const encoded = decodeURIComponent(rawParam(url, field));
  let xml = "";
  try {
    xml = zlib.inflateRawSync(Buffer.from(encoded, "base64")).toString("utf8");
  } catch (e) {
    log.debug("Caught in messageIn(): " + ((e && e.message) || e));
    xml = Buffer.from(encoded, "base64").toString("utf8");
  }
  log.debug("Leaving messageIn().");
  return { xml: xml,
           codes: [...xml.matchAll(/StatusCode Value="([^"]+)"/g)]
             .map(function (m) { return m[1].split(":").pop(); }),
           relay: decodeURIComponent(rawParam(url, "RelayState")),
           signed: !!rawParam(url, "Signature") ||
                   /<(?:\w+:)?Signature\b/.test(xml) };
}

// ===========================================================================
// SET UP
// ===========================================================================
async function setUp() {
  log.debug("Entering setUp().");
  isProduct = await facts.isProduct(base + "/admin-api");
  log.info("The service is in " + (isProduct ? "PRODUCT" : "DEVELOPMENT") +
           " mode. Identity provider realm " + IDP + ", service provider " +
           "realm " + SP + ".");
  await ensureRealm(IDP);
  await ensureRealm(SP);
  await createPerson(IDP, true);
  await createPerson(SP, false);
  const world = { partnerKey: credential("signout partner " + STAMP),
                  otherKey: credential("signout somebody " + STAMP) };

  // --- SAML 2.0 to the IdP realm -------------------------------------------
  const samlMade = await api(SP, "POST", "/federation/create",
    { id: REL.saml, role: "service-provider", protocol: "saml2" });
  must(samlMade.status === 200 && samlMade.body && samlMade.body.ok,
       "creating the SAML relationship answered " + samlMade.status);
  let view = (await api(SP, "GET", "/federation?relationship=" +
                                   REL.saml)).body;
  const ourMetadata = await fetch(new URL(view.endpoints.metadata, base));
  const ourXml = await ourMetadata.text();
  const ourEntityId = (/entityID="([^"]+)"/.exec(ourXml) || [])[1] || "";
  const ourCert = ((/X509Certificate>([^<]+)</.exec(ourXml) || [])[1] || "")
    .replace(/\s+/g, "");
  world.ourSamlXml = ourXml;
  world.samlSlo = view.endpoints.singleLogout;
  must(ourEntityId && ourCert && world.samlSlo,
       "the SP realm's SAML relationship publishes no entityID, certificate " +
       "or singleLogout endpoint: " + JSON.stringify(view.endpoints));
  await createApplication(IDP, ourEntityId, ["saml2"], {
    samlEntityId: [ourEntityId],
    samlAssertionConsumerService: [view.endpoints.assertionConsumerService],
    samlSigningCertificate: ["-----BEGIN CERTIFICATE-----\n" +
      (ourCert.match(/.{1,64}/g) || []).join("\n") +
      "\n-----END CERTIFICATE-----\n"],
    samlSingleLogoutService: [world.samlSlo] });
  const idpMeta = await fetch(realmBase(IDP) + "/saml2/metadata/" +
                              encodeURIComponent(ourEntityId));
  const idpXml = await idpMeta.text();
  const idpEntityId = (/entityID="([^"]+)"/.exec(idpXml) || [])[1] || "";
  const keyDescriptor = (/<md:KeyDescriptor[^>]*use="signing"[\s\S]*?<\/md:KeyDescriptor>/
    .exec(idpXml) || [])[0] || idpXml;
  const idpCert = ((/X509Certificate>([^<]+)</.exec(keyDescriptor) || [])[1] ||
                   "").replace(/\s+/g, "");
  const idpSso = (/SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"[^>]*Location="([^"]+)"/
    .exec(idpXml) || [])[1] || "";
  const idpSlo = (/SingleLogoutService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-Redirect"[^>]*Location="([^"]+)"/
    .exec(idpXml) || [])[1] || "";
  must(idpEntityId && idpCert && idpSso && idpSlo,
       "the IdP realm's metadata lacks an entityID, certificate, SSO or SLO: " +
       idpXml.slice(0, 300));
  world.idpSlo = idpSlo;
  for (const [field, value] of [["fedPeer", idpEntityId],
                                ["fedSsoUrl", idpSso],
                                ["fedSigningCertificate", idpCert],
                                ["fedBinding", "HTTP-POST"],
                                ["fedSignRequest", "TRUE"],
                                ["fedSloUrl", idpSlo],
                                ["fedSubjectPolicy", "pre-linked"]]) {
    const set = await setRel(REL.saml, field, value);
    must(set.status === 200 && set.body && set.body.ok,
         "setting " + field + " answered " + set.status + " " +
         set.text.slice(0, 200));
  }
  const on = await api(SP, "POST", "/federation/enable", { id: REL.saml });
  must(on.status === 200 && on.body.ok, "enabling saml answered " + on.status);
  await link(REL.saml, PERSON);

  // --- OIDC to the IdP realm (the front-channel shape) ---------------------
  const d = await fetch(realmBase(IDP) + "/.well-known/openid-configuration");
  const discovery = await d.json();
  const jwks = await (await fetch(discovery.jwks_uri)).json();
  world.issuer = discovery.issuer;
  view = await createRelationship(REL.oidc, "oidc", discovery.issuer, {
    fedSsoUrl: discovery.authorization_endpoint,
    fedScope: "openid profile email", fedClientId: OIDC_CLIENT,
    fedResponseType: "id_token", fedJwks: JSON.stringify(jwks),
    fedSubjectPolicy: "pre-linked" });
  world.oidcFront = view.endpoints.frontchannelLogout;
  await createApplication(IDP, OIDC_CLIENT, ["oidc"], {
    oauthClientId: [OIDC_CLIENT],
    oauthRedirectUri: [view.endpoints.assertionConsumerService],
    oauthTokenEndpointAuthMethod: "none",
    oauthGrantType: ["implicit"], oauthResponseType: ["id_token"],
    oauthFrontchannelLogoutUri: view.endpoints.frontchannelLogout,
    oauthFrontchannelLogoutSessionRequired: "TRUE" });
  const partnerView = await api(IDP, "GET", "/users?user=" +
                                            encodeURIComponent(PERSON));
  must(partnerView.body && partnerView.body.subject,
       "the IdP realm holds no subject for " + PERSON);
  await link(REL.oidc, partnerView.body.subject);

  // --- the partners written here ------------------------------------------
  view = await createRelationship(REL.samlT, "saml2", PARTNER_SAML, {
    fedSsoUrl: "https://saml-partner.invalid/sso",
    fedSigningCertificate: world.partnerKey.der,
    fedAllowUnsolicited: "TRUE", fedSloUrl: PARTNER_SLO,
    fedSubjectPolicy: "pre-linked" });
  world.samlTAcs = view.endpoints.assertionConsumerService;
  world.samlTSlo = view.endpoints.singleLogout;
  await link(REL.samlT, NAMEID);

  const partnerJwk = Object.assign({}, world.partnerKey.publicJwk,
                                   { kid: "so-partner", alg: "RS256",
                                     use: "sig" });
  view = await createRelationship(REL.oidcT, "oidc", PARTNER_OIDC, {
    fedSsoUrl: PARTNER_OIDC + "/authorize", fedClientId: T_CLIENT,
    fedResponseType: "id_token", fedScope: "openid",
    fedJwks: JSON.stringify({ keys: [partnerJwk] }),
    fedSubjectPolicy: "pre-linked" });
  world.oidcT = view.endpoints;
  await link(REL.oidcT, OIDC_SUB);

  view = await createRelationship(REL.wsfedT, "wsfed", PARTNER_WSFED, {
    fedSsoUrl: "https://wsfed-partner.invalid/",
    fedSigningCertificate: world.partnerKey.der,
    fedAllowUnsolicited: "TRUE", fedSubjectPolicy: "pre-linked" });
  world.wsfedAcs = view.endpoints.assertionConsumerService;
  world.wsfedSlo = view.endpoints.signOutCleanup;
  await link(REL.wsfedT, WSFED_NAME);

  view = await createRelationship(REL.saml11, "saml11",
    "urn:test:signout-saml11:" + STAMP, {
      fedSsoUrl: "https://saml11-partner.invalid/",
      fedSigningCertificate: world.partnerKey.der });
  world.saml11Endpoints = view.endpoints;
  log.debug("Leaving setUp().");
  return world;
}

// ===========================================================================
// 1. SAML 2.0, REALM TO REALM
// ===========================================================================
async function samlRealmToRealm(world) {
  log.debug("Entering samlRealmToRealm().");
  log.info("=== 1. SAML 2.0 Single Logout between two realms ===");
  await check("the relationship's metadata publishes SingleLogoutService on " +
              "the Redirect and POST bindings", async function () {
    assert.ok(world.ourSamlXml.indexOf("<md:SingleLogoutService Binding=\"" +
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" +
      world.samlSlo + "\"/>") >= 0, world.ourSamlXml.slice(0, 500));
    assert.ok(/SingleLogoutService Binding="[^"]*HTTP-POST"/
      .test(world.ourSamlXml));
  });

  const before = await sessionsThrough(REL.saml);
  let signedIn = await realmSignIn(REL.saml);
  await check("(a federated SAML sign-in through the IdP realm)",
              async function () {
    assert.ok(await liveIn(signedIn.browser), squash(signedIn.r.body));
  });
  // IdP-initiated: the partner's own Single Logout page names this service
  // provider with a LogoutRequest ready to send.
  const idpPage = await hop(signedIn.partner, realmBase(IDP) + "/saml2/slo");
  const sloLink = htmlDecode((new RegExp("href=\"(" + world.samlSlo
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\?[^\"]+)\"")
    .exec(idpPage.body) || [])[1] || "");
  await check("the IdP realm's own Single Logout offers a LogoutRequest to " +
              "this relationship's SingleLogoutService", async function () {
    assert.strictEqual(idpPage.status, 200);
    assert.ok(sloLink, squash(idpPage.body));
  });
  if (sloLink) {
    const answered = await hop(jar(), sloLink);
    await check("the partner's signed LogoutRequest ends the federated " +
                "session here and is answered with a signed LogoutResponse " +
                "to the partner's SingleLogoutService", async function () {
      assert.strictEqual(answered.status, 303, squash(answered.body));
      assert.ok(answered.location.indexOf(world.idpSlo) === 0,
                answered.location);
      const said = messageIn(answered.location, "SAMLResponse");
      assert.ok(said.signed && said.codes[0] === "Success",
                JSON.stringify(said.codes));
      assert.ok(!(await liveIn(signedIn.browser)),
                "the federated session is still live");
    });
    const received = await hop(signedIn.partner, answered.location);
    await check("the partner realm verifies the LogoutResponse's signature " +
                "against this service provider's registered certificate",
                async function () {
      assert.strictEqual(received.status, 200, squash(received.body));
      assert.ok(/verified/.test(received.body), squash(received.body));
    });
  }

  // The service-provider-initiated round trip.
  signedIn = await realmSignIn(REL.saml);
  const bye = await postForm(signedIn.browser, realmBase(SP) + "/logout",
                             { scope: "global" });
  const toPartner = htmlDecode((new RegExp("href=\"(" + world.idpSlo
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\?[^\"]+)\"")
    .exec(bye.body) || [])[1] || "");
  await check("/logout here ends the session and offers the partner a " +
              "signed LogoutRequest naming its SessionIndex",
              async function () {
    assert.strictEqual(bye.status, 200);
    assert.ok(toPartner, squash(bye.body));
    const sent = messageIn(toPartner, "SAMLRequest");
    assert.ok(sent.signed && /<samlp:SessionIndex>/.test(sent.xml),
              sent.xml.slice(0, 400));
    assert.ok(!(await liveIn(signedIn.browser)));
  });
  if (toPartner) {
    const atPartner = await hop(signedIn.partner, toPartner);
    await check("the partner verifies it, ends its own session and answers " +
                "with a LogoutResponse to this relationship's " +
                "SingleLogoutService", async function () {
      assert.strictEqual(atPartner.status, 303, squash(atPartner.body));
      assert.ok(atPartner.location.indexOf(world.samlSlo) === 0,
                atPartner.location);
    });
    if (atPartner.location) {
      const back = await hop(jar(), atPartner.location);
      const again = await hop(jar(), atPartner.location);
      await check("the partner's LogoutResponse is matched by InResponseTo " +
                  "and RelayState once, and refused the second time",
                  async function () {
        assert.strictEqual(back.status, 200, squash(back.body));
        assert.ok(/confirmed/.test(back.body), squash(back.body));
        assert.strictEqual(again.status, 400, squash(again.body));
      });
    }
  }
  await check("no federated session through the SAML relationship is left " +
              "live", async function () {
    assert.strictEqual(await sessionsThrough(REL.saml), before);
  });
  log.debug("Leaving samlRealmToRealm().");
}

// ===========================================================================
// 2. SAML 2.0, A PARTNER WRITTEN HERE
// ===========================================================================
async function samlSignIn(world, sessionIndex, notOnOrAfter) {
  log.debug("Entering samlSignIn().");
  const built = xmldsig.buildAssertion({
    issuer: PARTNER_SAML, subject: NAMEID, audience: world.samlTAcs,
    recipient: world.samlTAcs,
    nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    authnStatement: true, sessionIndex: sessionIndex,
    sessionNotOnOrAfter: notOnOrAfter });
  const signed = xmldsig.sign(built, world.partnerKey.privateKeyPem, "");
  const response = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:" +
    "2.0:protocol\" ID=\"_r" + nodeCrypto.randomBytes(8).toString("hex") +
    "\" Version=\"2.0\" IssueInstant=\"" + xmldsig.iso(0) +
    "\" Destination=\"" + world.samlTAcs + "\"><samlp:Status>" +
    "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:" +
    "Success\"></samlp:StatusCode></samlp:Status>" + signed +
    "</samlp:Response>";
  const browser = jar();
  let r = await postForm(browser, world.samlTAcs,
                         { SAMLResponse: Buffer.from(response)
                             .toString("base64") });
  for (let i = 0; i < 3 && r.status >= 300 && r.status < 400; i += 1) {
    r = await hop(browser, new URL(r.location, r.url).toString());
  }
  log.debug("Leaving samlSignIn(). " + r.status);
  return { browser: browser, r: r };
}

function logoutRequest(world, o) {
  log.debug("Entering logoutRequest().");
  const id = "_lr" + nodeCrypto.randomBytes(8).toString("hex");
  const xml = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:" +
    "2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
    "ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"" +
    (o.issueInstant || xmldsig.iso(0)) + "\" Destination=\"" +
    (o.destination || world.samlTSlo) + "\"><saml:Issuer>" +
    (o.issuer || PARTNER_SAML) + "</saml:Issuer><saml:NameID Format=\"urn:" +
    "oasis:names:tc:SAML:2.0:nameid-format:persistent\">" + NAMEID +
    "</saml:NameID>" + (o.sessionIndex ? "<samlp:SessionIndex>" +
    o.sessionIndex + "</samlp:SessionIndex>" : "") +
    "</samlp:LogoutRequest>";
  let qs = "SAMLRequest=" + encodeURIComponent(
    zlib.deflateRawSync(Buffer.from(xml)).toString("base64")) +
    "&RelayState=so-relay";
  if (o.key) {
    qs += "&SigAlg=" + encodeURIComponent(RSA_SHA256);
    qs += "&Signature=" + encodeURIComponent(nodeCrypto.sign("sha256",
      Buffer.from(qs), o.key.privateKeyPem).toString("base64"));
  }
  log.debug("Leaving logoutRequest().");
  return world.samlTSlo + "?" + qs;
}

async function samlPartnerWrittenHere(world) {
  log.debug("Entering samlPartnerWrittenHere().");
  log.info("=== 2. SAML 2.0 Single Logout from a partner written here ===");
  const index = "idx-" + STAMP;
  const signedIn = await samlSignIn(world, index, "");
  await check("(a SAML sign-in from the partner written here, with a " +
              "SessionIndex)", async function () {
    assert.ok(await liveIn(signedIn.browser), squash(signedIn.r.body));
  });
  const refusals = [
    ["an UNSIGNED LogoutRequest is refused 403",
     logoutRequest(world, { sessionIndex: index })],
    ["one signed by a key the relationship does not name is refused 403",
     logoutRequest(world, { sessionIndex: index, key: world.otherKey })],
    ["one issued by somebody else is refused 403",
     logoutRequest(world, { sessionIndex: index, key: world.partnerKey,
                            issuer: "urn:somebody:else" })],
    ["one addressed to another endpoint is refused 403",
     logoutRequest(world, { sessionIndex: index, key: world.partnerKey,
                            destination: "https://elsewhere.invalid/slo" })],
    ["one issued an hour ago is refused 403",
     logoutRequest(world, { sessionIndex: index, key: world.partnerKey,
                            issueInstant: xmldsig.iso(-3600000) })]
  ];
  for (const [what, url] of refusals) {
    const r = await hop(jar(), url);
    await check(what + ", and ends nothing", async function () {
      assert.strictEqual(r.status, 403, squash(r.body));
      assert.ok(await liveIn(signedIn.browser));
    });
  }
  const unknown = await hop(jar(), logoutRequest(world, {
    sessionIndex: "idx-nobody", key: world.partnerKey }));
  await check("an unknown SessionIndex is answered with a signed " +
              "LogoutResponse, Requester/UnknownPrincipal, and ends nothing",
              async function () {
    assert.strictEqual(unknown.status, 303, squash(unknown.body));
    assert.ok(unknown.location.indexOf(PARTNER_SLO) === 0, unknown.location);
    const said = messageIn(unknown.location, "SAMLResponse");
    assert.ok(said.signed && said.codes.indexOf("Requester") >= 0 &&
              said.codes.indexOf("UnknownPrincipal") >= 0 &&
              said.relay === "so-relay", JSON.stringify(said));
    assert.ok(await liveIn(signedIn.browser));
  });
  const valid = logoutRequest(world, { sessionIndex: index,
                                       key: world.partnerKey });
  const accepted = await hop(jar(), valid);
  await check("a signed LogoutRequest naming the session ends it, answered " +
              "Success", async function () {
    assert.strictEqual(accepted.status, 303, squash(accepted.body));
    assert.strictEqual(messageIn(accepted.location, "SAMLResponse")
      .codes[0], "Success");
    assert.ok(!(await liveIn(signedIn.browser)));
  });
  const replayed = await hop(jar(), valid);
  await check("the same LogoutRequest again is a replay, refused 403",
              async function () {
    assert.strictEqual(replayed.status, 403, squash(replayed.body));
  });

  // SessionNotOnOrAfter.
  const late = await samlSignIn(world, "idx-late-" + STAMP,
                                xmldsig.iso(-3600000));
  await check("an assertion whose SessionNotOnOrAfter has passed starts no " +
              "session (401)", async function () {
    assert.strictEqual(late.r.status, 401, squash(late.r.body));
    assert.ok(/already ended/.test(late.r.body), squash(late.r.body));
  });
  const skew = 30;
  const short = await samlSignIn(world, "idx-short-" + STAMP,
                                 xmldsig.iso(2000));
  await check("a SessionNotOnOrAfter a moment away still signs in",
              async function () {
    assert.ok(await liveIn(short.browser), squash(short.r.body));
  });
  // The bound is the partner's instant plus the clock skew an assertion is
  // read with (oauth2.clockSkewS, 30 s by default and not changed here).
  await sleep((skew + 4) * 1000);
  await check("and the session has ended once that instant passes, on the " +
              "next request", async function () {
    assert.ok(!(await liveIn(short.browser)),
              "the session outlived the partner's SessionNotOnOrAfter");
  });
  log.debug("Leaving samlPartnerWrittenHere().");
}

// ===========================================================================
// 3. OPENID CONNECT, A PARTNER WRITTEN HERE
// ===========================================================================
async function oidcSignIn(world, sid) {
  log.debug("Entering oidcSignIn(). " + sid);
  const browser = jar();
  const begun = await hop(browser, realmBase(SP) + "/federation/login/" +
                                   REL.oidcT);
  const asked = new URL(begun.location);
  const now = Math.floor(Date.now() / 1000);
  const idToken = signJwt({ alg: "RS256", typ: "JWT", kid: "so-partner" },
    { iss: PARTNER_OIDC, aud: T_CLIENT, sub: OIDC_SUB, sid: sid, iat: now,
      exp: now + 300, nonce: asked.searchParams.get("nonce") },
    world.partnerKey.privateKey);
  let r = await postForm(browser, world.oidcT.assertionConsumerService,
                         { id_token: idToken,
                           state: asked.searchParams.get("state") });
  for (let i = 0; i < 3 && r.status >= 300 && r.status < 400; i += 1) {
    r = await hop(browser, new URL(r.location, r.url).toString());
  }
  log.debug("Leaving oidcSignIn(). " + r.status);
  return { browser: browser, r: r };
}

function logoutToken(world, extra, key, header) {
  log.debug("Entering logoutToken().");
  const now = Math.floor(Date.now() / 1000);
  const claims = Object.assign({
    iss: PARTNER_OIDC, aud: T_CLIENT, iat: now, exp: now + 120,
    jti: "so-" + nodeCrypto.randomBytes(8).toString("hex"),
    events: { [BCL_EVENT]: {} } }, extra || {});
  log.debug("Leaving logoutToken().");
  return signJwt(header || { alg: "RS256", typ: "logout+jwt",
                             kid: "so-partner" },
                 claims, key || world.partnerKey.privateKey);
}

async function oidcPartnerWrittenHere(world) {
  log.debug("Entering oidcPartnerWrittenHere().");
  log.info("=== 3. OpenID Connect logout from a partner written here ===");
  const bc = world.oidcT.backchannelLogout;
  const fc = world.oidcT.frontchannelLogout;
  await check("the relationship view names the three logout URIs to " +
              "register at the partner", async function () {
    assert.ok(/\/federation\/backchannel-logout\//.test(bc) &&
              /\/federation\/frontchannel-logout\//.test(fc) &&
              /\/federation\/slo\//.test(world.oidcT.postLogoutRedirect),
              JSON.stringify(world.oidcT));
  });
  let signedIn = await oidcSignIn(world, "sid-a-" + STAMP);
  await check("(an OpenID Connect sign-in from the partner written here, " +
              "with a sid)", async function () {
    assert.ok(await liveIn(signedIn.browser), squash(signedIn.r.body));
  });
  const post = function (token) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return hop(null, bc, { method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: token === null ? "" : new URLSearchParams(
        { logout_token: token }).toString() });
  };
  const refusals = [
    ["no logout_token", null],
    ["a token signed by a key that is not the partner's",
     logoutToken(world, { sid: "sid-a-" + STAMP },
                 world.otherKey.privateKey)],
    ["a token with a nonce",
     logoutToken(world, { sid: "sid-a-" + STAMP, nonce: "n" })],
    ["a token with no events member",
     logoutToken(world, { sid: "sid-a-" + STAMP, events: {} })],
    ["a token naming neither sub nor sid", logoutToken(world, {})],
    ["a token for another audience",
     logoutToken(world, { sid: "sid-a-" + STAMP, aud: "somebody" })],
    ["a token typed at+jwt",
     logoutToken(world, { sid: "sid-a-" + STAMP }, null,
                 { alg: "RS256", typ: "at+jwt", kid: "so-partner" })]
  ];
  for (const [what, token] of refusals) {
    const r = await post(token);
    await check("Back-Channel Logout: " + what + " is refused 400 " +
                "invalid_request, and ends nothing", async function () {
      assert.strictEqual(r.status, 400, r.body);
      assert.strictEqual(JSON.parse(r.body).error, "invalid_request");
      assert.ok(await liveIn(signedIn.browser));
    });
  }
  const good = logoutToken(world, { sid: "sid-a-" + STAMP, sub: OIDC_SUB });
  const ended = await post(good);
  const replay = await post(good);
  await check("Back-Channel Logout: the partner's token ends the session " +
              "with that sid (200, no-store); the same jti again is refused " +
              "400", async function () {
    assert.strictEqual(ended.status, 200, ended.body);
    assert.ok(/no-store/.test(String(ended.headers.get("cache-control"))));
    assert.ok(!(await liveIn(signedIn.browser)));
    assert.strictEqual(replay.status, 400, replay.body);
  });

  await setRel(REL.oidcT, "fedAcceptSignout", "FALSE");
  signedIn = await oidcSignIn(world, "sid-b-" + STAMP);
  const refusedOff = await post(logoutToken(world, { sid: "sid-b-" + STAMP }));
  await check("with fedAcceptSignout off the partner's token is refused and " +
              "the session lives", async function () {
    assert.strictEqual(refusedOff.status, 400, refusedOff.body);
    assert.ok(await liveIn(signedIn.browser));
  });
  await setRel(REL.oidcT, "fedAcceptSignout", "TRUE");

  const noSid = await hop(null, fc);
  const wrongIss = await hop(null, fc + "?iss=" +
    encodeURIComponent("https://elsewhere.invalid") + "&sid=sid-b-" + STAMP);
  await check("Front-Channel Logout without sid, or with an iss that is not " +
              "the partner, is refused 400 and ends nothing",
              async function () {
    assert.strictEqual(noSid.status, 400, squash(noSid.body));
    assert.strictEqual(wrongIss.status, 400, squash(wrongIss.body));
    assert.ok(await liveIn(signedIn.browser));
  });
  const front = await hop(null, fc + "?iss=" +
    encodeURIComponent(PARTNER_OIDC) + "&sid=sid-b-" + STAMP);
  await check("Front-Channel Logout with the partner's iss and sid ends the " +
              "session; only the partner's origin may frame the page, and " +
              "it runs no script", async function () {
    assert.strictEqual(front.status, 200, squash(front.body));
    const csp = String(front.headers.get("content-security-policy") || "");
    assert.ok(csp.indexOf("frame-ancestors " + PARTNER_OIDC) >= 0, csp);
    assert.ok(!/script-src 'self'/.test(csp) && !/<script/i.test(front.body),
              csp);
    assert.ok(!front.headers.get("x-frame-options"));
    assert.ok(!(await liveIn(signedIn.browser)));
  });

  // RP-Initiated Logout to the partner, from /logout here.
  await setRel(REL.oidcT, "fedEndSessionUrl", PARTNER_OIDC + "/logout");
  signedIn = await oidcSignIn(world, "sid-c-" + STAMP);
  const bye = await postForm(signedIn.browser, realmBase(SP) + "/logout",
                             { scope: "global" });
  const toPartner = htmlDecode((/href="(https:\/\/oidc-partner\.invalid\/logout\?[^"]+)"/
    .exec(bye.body) || [])[1] || "");
  const asked = toPartner ? new URL(toPartner) : null;
  await check("/logout ends the session and offers RP-Initiated Logout at " +
              "the partner with id_token_hint, client_id, " +
              "post_logout_redirect_uri and state", async function () {
    assert.ok(asked, squash(bye.body));
    assert.strictEqual(asked.searchParams.get("client_id"), T_CLIENT);
    assert.strictEqual(asked.searchParams.get("post_logout_redirect_uri"),
                       world.oidcT.postLogoutRedirect);
    assert.ok(asked.searchParams.get("id_token_hint") &&
              /^fed-/.test(asked.searchParams.get("state")));
    assert.ok(!(await liveIn(signedIn.browser)));
  });
  if (asked) {
    const back = world.oidcT.postLogoutRedirect + "?state=" +
                 encodeURIComponent(asked.searchParams.get("state"));
    const first = await hop(jar(), back);
    const second = await hop(jar(), back);
    await check("the return from the partner's end_session_endpoint is " +
                "matched once, and refused the second time",
                async function () {
      assert.strictEqual(first.status, 200, squash(first.body));
      assert.strictEqual(second.status, 400, squash(second.body));
    });
  }
  log.debug("Leaving oidcPartnerWrittenHere().");
}

// ===========================================================================
// 4. OPENID CONNECT FRONT-CHANNEL, REALM TO REALM
// ===========================================================================
async function oidcFrontChannelRealmToRealm(world) {
  log.debug("Entering oidcFrontChannelRealmToRealm().");
  log.info("=== 4. Front-Channel Logout between two realms ===");
  const signedIn = await realmSignIn(REL.oidc);
  await check("(a federated OpenID Connect sign-in through the IdP realm)",
              async function () {
    assert.ok(await liveIn(signedIn.browser), squash(signedIn.r.body));
  });
  const page = await postForm(signedIn.partner, realmBase(IDP) + "/logout",
                              { scope: "global" });
  const frame = htmlDecode((new RegExp("<iframe[^>]*src=\"(" +
    world.oidcFront.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
    "\\?[^\"]+)\"").exec(page.body) || [])[1] || "");
  await check("the IdP realm's sign-out frames this relying party's " +
              "frontchannel_logout_uri with iss and sid", async function () {
    assert.ok(frame && /[?&]iss=/.test(frame) && /[?&]sid=/.test(frame),
              squash(page.body));
  });
  if (frame) {
    const loaded = await hop(null, frame);
    await check("loading it ends the federated session here",
                async function () {
      assert.strictEqual(loaded.status, 200, squash(loaded.body));
      assert.ok(!(await liveIn(signedIn.browser)));
    });
  }
  log.debug("Leaving oidcFrontChannelRealmToRealm().");
}

// ===========================================================================
// 5. WS-FEDERATION, A PARTNER WRITTEN HERE
// ===========================================================================
async function wsfedSignIn(world) {
  log.debug("Entering wsfedSignIn().");
  const built = xmldsig.buildAssertion({
    issuer: PARTNER_WSFED, subject: WSFED_NAME, audience: world.wsfedAcs,
    recipient: world.wsfedAcs,
    nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    authnStatement: true, sessionIndex: "ws-" + STAMP });
  const signed = xmldsig.sign(built, world.partnerKey.privateKeyPem, "");
  const wresult = "<t:RequestSecurityTokenResponse xmlns:t=\"http://" +
    "schemas.xmlsoap.org/ws/2005/02/trust\"><t:RequestedSecurityToken>" +
    signed + "</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>";
  const browser = jar();
  let r = await postForm(browser, world.wsfedAcs,
                         { wa: "wsignin1.0", wresult: wresult });
  for (let i = 0; i < 3 && r.status >= 300 && r.status < 400; i += 1) {
    r = await hop(browser, new URL(r.location, r.url).toString());
  }
  log.debug("Leaving wsfedSignIn(). " + r.status);
  return { browser: browser, r: r };
}

async function wsfedPartnerWrittenHere(world) {
  log.debug("Entering wsfedPartnerWrittenHere().");
  log.info("=== 5. WS-Federation sign-out, confirmed ===");
  const signedIn = await wsfedSignIn(world);
  await check("(a WS-Federation sign-in from the partner written here)",
              async function () {
    assert.ok(await liveIn(signedIn.browser), squash(signedIn.r.body));
  });
  const atAcs = await postForm(signedIn.browser, world.wsfedAcs,
                               { wa: "wsignout1.0" });
  await check("a wsignout1.0 at the ACS is refused 400 and names the path " +
              "that consumes a sign-out", async function () {
    assert.strictEqual(atAcs.status, 400, squash(atAcs.body));
    assert.ok(atAcs.body.indexOf("/federation/slo/" + REL.wsfedT) >= 0,
              squash(atAcs.body));
    assert.ok(await liveIn(signedIn.browser));
  });
  const asked = await hop(signedIn.browser, world.wsfedSlo +
                                            "?wa=wsignoutcleanup1.0");
  const form = formsIn(asked.body).find(function (f) {
    return "confirm" in f.fields;
  });
  await check("wsignoutcleanup1.0 draws a confirmation with a real button " +
              "and no script, and ends nothing by itself", async function () {
    assert.strictEqual(asked.status, 200, squash(asked.body));
    assert.ok(form && /<button type="submit">/.test(asked.body));
    assert.ok(!/<script/i.test(asked.body));
    assert.ok(await liveIn(signedIn.browser));
  });
  if (form) {
    const noConfirm = await postForm(signedIn.browser, world.wsfedSlo,
                                     { wa: "wsignoutcleanup1.0" });
    const otherBrowser = await postForm(jar(), world.wsfedSlo, form.fields);
    await check("a POST with no confirmation, or the confirmation in " +
                "another browser, is refused 403 and ends nothing",
                async function () {
      assert.strictEqual(noConfirm.status, 403, squash(noConfirm.body));
      assert.strictEqual(otherBrowser.status, 403, squash(otherBrowser.body));
      assert.ok(await liveIn(signedIn.browser));
    });
    // The other browser SPENT the handle: draw the confirmation again.
    const again = await hop(signedIn.browser, world.wsfedSlo +
                                              "?wa=wsignoutcleanup1.0");
    const fresh = formsIn(again.body).find(function (f) {
      return "confirm" in f.fields;
    });
    const confirmed = fresh
      ? await postForm(signedIn.browser, world.wsfedSlo, fresh.fields)
      : { status: 0, body: "" };
    await check("confirmed in the browser it was drawn for, the session " +
                "ends", async function () {
      assert.strictEqual(confirmed.status, 200, squash(confirmed.body));
      assert.ok(!(await liveIn(signedIn.browser)));
    });
  }
  log.debug("Leaving wsfedPartnerWrittenHere().");
}

// ===========================================================================
// 6. WHAT DEFINES NO SIGN-OUT, AND THE SIGNATURE SWITCH
// ===========================================================================
async function theEdges(world) {
  log.debug("Entering theEdges().");
  log.info("=== 6. SAML 1.1, and fedRequireSignedLogout ===");
  const saml11 = await hop(jar(), realmBase(SP) + "/federation/slo/" +
                                  REL.saml11 + "?SAMLRequest=eA");
  await check("SAML 1.1 defines no sign-out: a message for it is refused " +
              "400 naming that", async function () {
    assert.strictEqual(saml11.status, 400, squash(saml11.body));
    assert.ok(/defines no sign-out/.test(saml11.body), squash(saml11.body));
    assert.ok(!world.saml11Endpoints.singleLogout);
  });
  const off = await setRel(REL.samlT, "fedRequireSignedLogout", "FALSE");
  if (isProduct) {
    await check("product refuses fedRequireSignedLogout off",
                async function () {
      assert.ok(off.status === 400 || (off.body && off.body.ok === false),
                off.status + " " + off.text.slice(0, 200));
    });
  } else {
    const index = "idx-unsigned-" + STAMP;
    const signedIn = await samlSignIn(world, index, "");
    const r = await hop(jar(), logoutRequest(world, { sessionIndex: index }));
    await check("development with fedRequireSignedLogout off accepts an " +
                "UNSIGNED LogoutRequest", async function () {
      assert.ok(off.status === 200 && off.body.ok, off.text.slice(0, 200));
      assert.strictEqual(r.status, 303, squash(r.body));
      assert.ok(!(await liveIn(signedIn.browser)));
    });
    await setRel(REL.samlT, "fedRequireSignedLogout", "TRUE");
  }
  log.debug("Leaving theEdges().");
}

async function test() {
  log.debug("Entering test().");
  const world = await setUp();
  await samlRealmToRealm(world);
  await samlPartnerWrittenHere(world);
  await oidcPartnerWrittenHere(world);
  await oidcFrontChannelRealmToRealm(world);
  await wsfedPartnerWrittenHere(world);
  await theEdges(world);
  log.info("The realms " + IDP + " and " + SP + " are left standing " +
           "(tests/CLAUDE.md, *No job removes a realm*).");
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
  assert.ok(checks >= 40, "only " + checks + " checks ran; a section " +
                          "stopped being called");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_federation_signout")
  .description("A federation partner's sign-out (#167) over HTTP: SAML " +
      "2.0 Single Logout between two realms in both directions, a partner " +
      "written here for every LogoutRequest refusal and SessionNotOnOrAfter, " +
      "OpenID Connect Back-Channel, Front-Channel and RP-Initiated Logout, " +
      "Front-Channel between two realms, a WS-Federation cleanup confirmed " +
      "in the browser, SAML 1.1's absence of a sign-out, and the signature " +
      "switch by mode.")
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
