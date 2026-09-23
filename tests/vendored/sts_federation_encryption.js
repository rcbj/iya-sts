// ===========================================================================
// A PARTNER'S ENCRYPTED ASSERTION OR ID TOKEN, OVER THE NETWORK (#168).
//
// Until #168 `/federation/acs/{id}` refused an `<EncryptedAssertion>` as "no
// assertion", read a JWE ID Token's header as a JWS's, and published no key a
// partner could encrypt to — so the only way to federate was for the partner
// to send the person's identifier and attributes IN CLEAR through their
// browser. Each SAML 2.0, WS-Federation and OpenID Connect relationship now
// holds an encryption key of its own, publishes it, decrypts with it under
// exactly the algorithms it publishes, and — in product mode — refuses
// plaintext unless `fedAllowUnencrypted` says otherwise.
//
// ---------------------------------------------------------------------------
// THE PARTIES, ALL CREATED BEFOREHAND AND ALL LEFT STANDING
//
//   /realm/fei-<stamp>  the IDENTITY PROVIDER: this service's own SAML 2.0
//                       identity provider and OpenID Provider, which ENCRYPT
//                       to a certificate or a JWKS they hold — the positive
//                       paths go through this realm's own encryptor.
//   /realm/fes-<stamp>  the SERVICE PROVIDER: the relationships under test.
//   THIS FILE           a second partner for every refusal, with an XML
//                       Encryption and a JWE implementation of its OWN
//                       (node's crypto and string concatenation) — the
//                       reason sts_dpop.js writes its own DPoP client: if
//                       both ends came from one implementation, a shared
//                       misunderstanding would pass here and interoperate
//                       with nobody.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED
//
//   1. PUBLICATION: the SAML metadata's KeyDescriptor use="encryption" with
//      rsa-oaep (SHA-256, MGF1-SHA-256) and aes256-gcm; the WS-Federation
//      metadata's; the OpenID Connect JWKS (use enc, ECDH-ES, no private
//      member, no-store); the API view carrying no private key.
//   2. SAML 2.0, the IdP realm encrypting: a genuine EncryptedAssertion
//      (rsa-oaep) signs the person in.
//   3. SAML 2.0, this file encrypting: EncryptedAssertion, EncryptedID and
//      EncryptedAttribute (the attribute's value lands on the entry); ECDH-ES
//      to an EC relationship; every refused algorithm (aes256-cbc, rsa-1_5,
//      rsa-oaep-mgf1p); a wrong key and an altered ciphertext, which read
//      THE SAME; an encrypted and a plain assertion together; plaintext —
//      refused in product and accepted with fedAllowUnencrypted.
//   4. WS-Federation: a bare EncryptedData in the RequestedSecurityToken.
//   5. OpenID Connect: an ID Token signed and then encrypted (ECDH-ES,
//      A256GCM) by this file, and — in development, where the IdP realm will
//      register an id_token client — by the IdP realm's own OpenID Provider;
//      A128CBC-HS256 and RSA1_5 refused; a JWE to another key; a JWE with
//      nothing signed inside; a signed-only token refused in product.
//   6. ROTATION: the replaced key decrypts in its grace, not after it, and
//      the scheduler job federation.encryption-key-retire removes it.
//   7. THE FIELDS: AES-CBC refused at the API in every mode.
//
// Every refusal is asserted with its status, the page naming the check, and
// no session cookie.
// ===========================================================================

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_federation_encryption",
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
const IDP = "fei-" + STAMP;
const SP = "fes-" + STAMP;
const PERSON = names.usernameFor("fenc");
const PASSWORD = "Encryption-Passw0rd!-" + String(Date.now()).slice(-6);
const IDP_MAIL = IDP + ".example.net";
const SP_MAIL = "sp-local.encryption.test";
// THIS FILE AS A PARTNER: its issuer, and the subject it asserts.
const SELF_ISSUER = "urn:test:fe-partner:" + STAMP;
const SELF_SUBJECT = "fe-subject-" + STAMP;
const REL = {
  saml: "enc-saml",        // SAML 2.0 to the IdP realm, which encrypts
  self: "enc-self",        // SAML 2.0 to this file, RSA key
  selfEc: "enc-self-ec",   // SAML 2.0 to this file, EC key
  wsfed: "enc-wsfed",      // WS-Federation to this file
  oidc: "enc-oidc",        // OpenID Connect to the IdP realm, id_token
  oidcSelf: "enc-oidc-self" // OpenID Connect to this file, id_token
};
const SELF_CLIENT = "fe-self-client-" + STAMP;

const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const DSIG11 = "http://www.w3.org/2009/xmldsig11#";
const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const MAIL_OID = "urn:oid:0.9.2342.19200300.100.1.3";

let isProduct = false;
let checks = 0;
const failures = [];

// ---------------------------------------------------------------------------
// ONE CHECK. A failure is recorded and the run carries on, so one broken
// property does not hide the forty behind it — the refusals are independent
// of each other and each is worth knowing about. Setup that later sections
// depend on uses `must()` instead, which throws.
// ---------------------------------------------------------------------------
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
    .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 400);
}

function htmlDecode(text) {
  log.debug("Entering htmlDecode().");
  log.debug("Leaving htmlDecode().");
  return String(text || "").replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

// ---------------------------------------------------------------------------
// THE MANAGEMENT API, in the realm named. The run's token is attached by
// tests/tools/attach-admin-token.js to every /admin-api request, including
// /realm/<id>/admin-api.
// ---------------------------------------------------------------------------
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
    // Not JSON; `text` carries the answer into every message that quotes it.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

// ---------------------------------------------------------------------------
// A COOKIE JAR PER SIGN-IN. Both realms are one origin and the session cookie
// has one name at `Path=/`, so one jar is what a browser has — a session
// minted at the identity provider is PRESENTED to the service provider and
// must mean nothing there. A fresh jar per flow keeps each sign-in's evidence
// its own.
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

// One request, one body read, redirects NOT followed.
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
  const setCookies = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, headers: r.headers, body: body, url: url,
           setCookies: setCookies,
           location: r.headers.get("location") || "" };
}

function postForm(cookies, url, fields) {
  log.debug("Entering postForm(). " + url);
  log.debug("Leaving postForm().");
  return hop(cookies, url, {
    method: "POST", body: new URLSearchParams(fields).toString(),
    headers: { "content-type": "application/x-www-form-urlencoded" } });
}

// Did this response START a session? A refusal must not — and the session
// cookie is the first place that would show, before any listing catches up.
function startsSession(r) {
  log.debug("Entering startsSession().");
  const started = (r.setCookies || []).some(function (line) {
    return /^sts_session=[^;]+/.test(line) &&
           !/^sts_session=;/.test(line) && !/Max-Age=0/i.test(line);
  });
  log.debug("Leaving startsSession(). " + started);
  return started;
}

// Every form on a page, with its action and its hidden fields decoded.
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
    out.push({ action: action, method: method, fields: fields,
               inner: m[2] });
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

// ---------------------------------------------------------------------------
// A BROWSER, UP TO THE SERVICE PROVIDER'S DOOR. Follows redirects, answers
// the identity provider's sign-in screen and consent screen, posts any form
// that leads onward — and STOPS at the first request addressed to a
// `/federation/acs/` path, returning it UNSENT. Stopping there is what lets a
// section send a genuine answer somewhere it was not addressed, or send it
// twice, which is where every interesting refusal in this file comes from.
//
// `trail` records every screen drawn and where, so a section can assert WHICH
// realm asked for the password.
// ---------------------------------------------------------------------------
async function toTheDoor(cookies, startUrl, username) {
  log.debug("Entering toTheDoor(). " + startUrl);
  const trail = { screens: [], hops: [], first: null };
  let r = await hop(cookies, startUrl);
  trail.first = r;
  for (let step = 0; step < 24; step += 1) {
    trail.hops.push(r.status + " " + r.url);
    if (r.status >= 300 && r.status < 400 && r.location) {
      const next = new URL(r.location, r.url).toString();
      if (isAcs(next)) {
        log.debug("Leaving toTheDoor(). A redirect to the ACS.");
        return { method: "GET", url: next, fields: null, trail: trail };
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
      const to = new URL(signIn.action || r.url, r.url).toString();
      trail.screens.push({ kind: "sign-in", at: to });
      r = await postForm(cookies, to, Object.assign({}, signIn.fields, {
        username: username, password: PASSWORD, action: "login" }));
      continue;
    }
    if (consent) {
      const to = new URL(consent.action || r.url, r.url).toString();
      trail.screens.push({ kind: "consent", at: to });
      r = await postForm(cookies, to, Object.assign({}, consent.fields, {
        action: "allow", decision: "allow" }));
      continue;
    }
    if (onward) {
      const to = new URL(onward.action, r.url).toString();
      if (isAcs(to)) {
        log.debug("Leaving toTheDoor(). A form addressed to the ACS.");
        return { method: "POST", url: to, fields: onward.fields,
                 trail: trail, page: r };
      }
      trail.screens.push({ kind: "onward", at: to, page: r.body });
      r = await postForm(cookies, to, onward.fields);
      continue;
    }
    break;
  }
  log.debug("Leaving toTheDoor(). It never reached the ACS.");
  throw new Error("the browser never reached a /federation/acs/ door: the " +
    "last answer was HTTP " + r.status + " at " + r.url + " — " +
    squash(r.body) + " (trail: " + trail.hops.join(" → ") + ")");
}

// Deliver what toTheDoor() stopped at — to where it was addressed, or, for a
// negative, somewhere else.
function deliver(cookies, door, toUrl, fields) {
  log.debug("Entering deliver().");
  const url = toUrl || door.url;
  if (door.method === "GET" && !fields) {
    log.debug("Leaving deliver(). GET.");
    return hop(cookies, url);
  }
  log.debug("Leaving deliver(). POST.");
  return postForm(cookies, url, fields || door.fields);
}

// ---------------------------------------------------------------------------
// SETTING THE WORLD UP. Nothing here changes a service-wide setting: every
// call creates something this run owns.
// ---------------------------------------------------------------------------
async function ensureRealm(id) {
  log.debug("Entering ensureRealm(). " + id);
  const made = await api(null, "POST", "/realms/create",
                         { id: id, domain: id + ".example.net", name: id });
  must(made.status === 200 ||
       /already/i.test(JSON.stringify(made.body || made.text)),
       "creating the realm " + id + " answered " + made.status + " " +
       made.text.slice(0, 300));
  log.debug("Leaving ensureRealm().");
}

async function createPerson(realm, username, mailDomain, withPassword) {
  log.debug("Entering createPerson(). " + realm + " " + username);
  const payload = {
    username: username, invent: false,
    attributes: { cn: "Federation " + username, givenName: "Federation",
                  sn: username, displayName: "Federation " + username,
                  mail: username + "@" + mailDomain },
    credential: withPassword ? "password" : "none" };
  if (withPassword) {
    payload.password = PASSWORD;
  }
  const r = await api(realm, "POST", "/users/create", payload);
  must(r.status === 200 && r.body && r.body.ok,
       "creating " + username + " in " + realm + " answered " + r.status +
       " " + r.text.slice(0, 300));
  log.debug("Leaving createPerson().");
}

async function createApplication(realm, identifier, protocols, fields) {
  log.debug("Entering createApplication(). " + identifier);
  const r = await api(realm, "POST", "/applications/create",
    { identifier: identifier, name: "federation " + identifier,
      protocols: protocols, fields: fields });
  must(r.status === 200 && r.body && r.body.ok,
       "creating the application " + identifier + " in " + realm +
       " answered " + r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving createApplication().");
}

function pemOf(derBase64) {
  log.debug("Entering pemOf().");
  const lines = String(derBase64).match(/.{1,64}/g) || [];
  log.debug("Leaving pemOf().");
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") +
         "\n-----END CERTIFICATE-----\n";
}

async function sessionsOf(username) {
  log.debug("Entering sessionsOf(). " + username);
  const r = await api(SP, "GET", "/users?user=" +
                                  encodeURIComponent(username));
  must(r.status === 200 && r.body,
       "GET /realm/" + SP + "/admin-api/users answered " + r.status);
  const ldap = r.body.ldap || {};
  const paging = r.body.sessionsPaging || {};
  const sessions = Array.isArray(r.body.sessions) ? r.body.sessions : [];
  log.debug("Leaving sessionsOf().");
  return { count: Number(paging.total || sessions.length || 0),
           entry: ldap.found && ldap.entry ? ldap.entry.attributes || {}
                                           : null };
}

async function relationship(id) {
  log.debug("Entering relationship(). " + id);
  const r = await api(SP, "GET", "/federation?relationship=" +
                                 encodeURIComponent(id));
  must(r.status === 200 && r.body && r.body.found,
       "the relationship " + id + " should be registered in " + SP +
       "; GET answered " + r.status + " " + r.text.slice(0, 200));
  log.debug("Leaving relationship().");
  return r.body;
}

async function setRel(id, field, value) {
  log.debug("Entering setRel(). " + id + " " + field);
  const r = await api(SP, "POST", "/federation/set",
                      { id: id, field: field, value: value });
  log.debug("Leaving setRel(). " + r.status);
  return r;
}

// Create, configure and enable a service-provider-side relationship — the
// feature's own order. The encryption key is issued by the create.
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
  log.debug("Leaving createRelationship().");
  return made.body;
}

async function link(rel, subject) {
  log.debug("Entering link(). " + rel);
  const linked = await api(SP, "POST", "/users/federation-link",
                           { user: PERSON, relationship: rel,
                             subject: subject });
  must(linked.status === 200 && linked.body && linked.body.ok,
       "linking " + PERSON + " through " + rel + " answered " +
       linked.status + " " + linked.text.slice(0, 300));
  log.debug("Leaving link().");
}

// What a relationship publishes for a partner to encrypt to.
async function metadataOf(id) {
  log.debug("Entering metadataOf(). " + id);
  const r = await hop(null, realmBase(SP) + "/federation/metadata/" + id);
  const encryption = (/<md:KeyDescriptor use="encryption">[\s\S]*?<\/md:KeyDescriptor>/
    .exec(r.body) || [])[0] || "";
  const certificate = ((/X509Certificate>([^<]+)</.exec(encryption) ||
                       [])[1] || "").replace(/\s+/g, "");
  log.debug("Leaving metadataOf().");
  return { status: r.status, xml: r.body, encryption: encryption,
           certificate: certificate,
           cacheControl: r.headers.get("cache-control") || "",
           entityId: (/entityID="([^"]+)"/.exec(r.body) || [])[1] || "" };
}

// ---------------------------------------------------------------------------
// XML ENCRYPTION, WRITTEN HERE: node's crypto and string concatenation. The
// output is ALREADY in exclusive-canonical form (declarations before
// attributes, no self-closing element), because an EncryptedID and an
// EncryptedAttribute are encrypted BEFORE the assertion around them is signed
// by saml_xmldsig.js, which signs canonical-by-construction XML.
//
// `o.cipher` aes256-gcm | aes128-gcm | aes256-cbc; `o.transport` rsa-oaep
// (SHA-256, MGF1-SHA-256) | rsa-oaep-mgf1p | rsa-1_5 | ecdh-es (to an EC
// certificate: XML Encryption 1.1 section 5.6.4, ConcatKDF over SHA-256 with
// AlgorithmID the kw-aes256 URI and empty party infos, kw-aes256).
// `o.wrapper` is the SAML element around the EncryptedData, or none.
// ---------------------------------------------------------------------------
function el(name, attrs, inner) {
  log.debug("Entering el().");
  log.debug("Leaving el().");
  return "<" + name + (attrs || "") + ">" + (inner || "") + "</" + name + ">";
}

function encryptXml(xml, certPem, o) {
  log.debug("Entering encryptXml(). " + o.cipher + " " + o.transport);
  const recipient = new nodeCrypto.X509Certificate(certPem).publicKey;
  const gcm = /gcm$/.test(o.cipher);
  const keyBytes = /256/.test(o.cipher) ? 32 : 16;
  const key = nodeCrypto.randomBytes(keyBytes);
  const iv = nodeCrypto.randomBytes(gcm ? 12 : 16);
  const cipher = nodeCrypto.createCipheriv(
    "aes-" + (keyBytes * 8) + (gcm ? "-gcm" : "-cbc"), key, iv);
  const body = Buffer.concat([iv, cipher.update(Buffer.from(xml, "utf8")),
                              cipher.final(),
                              gcm ? cipher.getAuthTag() : Buffer.alloc(0)]);
  const dataUri = (gcm ? XENC11 : XENC) + o.cipher;
  let keyXml;
  if (o.transport === "ecdh-es") {
    const crv = recipient.export({ format: "jwk" }).crv;
    const ephemeral = nodeCrypto.generateKeyPairSync("ec",
      { namedCurve: crv === "P-256" ? "prime256v1" : crv });
    const z = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey,
                                         publicKey: recipient });
    const kwUri = XENC + "kw-aes256";
    const counter = Buffer.from([0, 0, 0, 1]);
    const kek = nodeCrypto.createHash("sha256")
      .update(Buffer.concat([counter, z, Buffer.from(kwUri, "utf8")]))
      .digest();
    const wrapper = nodeCrypto.createCipheriv("id-aes256-wrap", kek,
      Buffer.from("A6A6A6A6A6A6A6A6", "hex"));
    const wrapped = Buffer.concat([wrapper.update(key), wrapper.final()]);
    const point = ephemeral.publicKey.export({ format: "jwk" });
    const pub = Buffer.concat([Buffer.from([4]),
                               Buffer.from(point.x, "base64url"),
                               Buffer.from(point.y, "base64url")]);
    keyXml = el("xenc:EncryptedKey", "",
      el("xenc:EncryptionMethod", " Algorithm=\"" + kwUri + "\"") +
      el("ds:KeyInfo", "",
        el("xenc:AgreementMethod", " Algorithm=\"" + XENC11 + "ECDH-ES\"",
          el("xenc11:KeyDerivationMethod", " xmlns:xenc11=\"" + XENC11 +
             "\" Algorithm=\"" + XENC11 + "ConcatKDF\"",
            el("xenc11:ConcatKDFParams", " AlgorithmID=\"00" +
               Buffer.from(kwUri, "utf8").toString("hex").toUpperCase() +
               "\" PartyUInfo=\"00\" PartyVInfo=\"00\"",
              el("ds:DigestMethod", " Algorithm=\"" + XENC + "sha256\""))) +
          el("xenc:OriginatorKeyInfo", "",
            el("ds:KeyValue", "",
              el("dsig11:ECKeyValue", " xmlns:dsig11=\"" + DSIG11 + "\"",
                el("dsig11:NamedCurve",
                   " URI=\"urn:oid:1.2.840.10045.3.1.7\"") +
                el("dsig11:PublicKey", "", pub.toString("base64"))))))) +
      el("xenc:CipherData", "",
         el("xenc:CipherValue", "", wrapped.toString("base64"))));
  } else {
    let wrapped;
    let method;
    if (o.transport === "rsa-1_5") {
      // Refused on its NAME before any key operation; the ciphertext is
      // made anyway, so the document is the one a partner would send.
      wrapped = nodeCrypto.publicEncrypt({ key: recipient,
        padding: nodeCrypto.constants.RSA_PKCS1_PADDING }, key);
      method = el("xenc:EncryptionMethod",
                  " Algorithm=\"" + XENC + "rsa-1_5\"");
    } else {
      const sha256 = o.transport === "rsa-oaep";
      wrapped = nodeCrypto.publicEncrypt({ key: recipient,
        padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: sha256 ? "sha256" : "sha1" }, key);
      method = sha256
        ? el("xenc:EncryptionMethod", " Algorithm=\"" + XENC11 +
             "rsa-oaep\"",
             el("ds:DigestMethod", " Algorithm=\"" + XENC + "sha256\"") +
             el("xenc11:MGF", " xmlns:xenc11=\"" + XENC11 +
                "\" Algorithm=\"" + XENC11 + "mgf1sha256\""))
        : el("xenc:EncryptionMethod", " Algorithm=\"" + XENC +
             "rsa-oaep-mgf1p\"",
             el("ds:DigestMethod", " Algorithm=\"" + DS + "sha1\""));
    }
    keyXml = el("xenc:EncryptedKey", "", method +
      el("xenc:CipherData", "",
         el("xenc:CipherValue", "", wrapped.toString("base64"))));
  }
  const data = el("xenc:EncryptedData", " xmlns:xenc=\"" + XENC +
                  "\" Type=\"" + XENC + "Element\"",
    el("xenc:EncryptionMethod", " Algorithm=\"" + dataUri + "\"") +
    el("ds:KeyInfo", " xmlns:ds=\"" + DS + "\"", keyXml) +
    el("xenc:CipherData", "",
       el("xenc:CipherValue", "", body.toString("base64"))));
  if (!o.wrapper) {
    log.debug("Leaving encryptXml(). Bare.");
    return data;
  }
  log.debug("Leaving encryptXml().");
  return el(o.wrapper, o.declare ? " xmlns:saml=\"" + SAML + "\"" : "", data);
}

// A signed assertion from THIS FILE as partner, optionally with its NameID
// and its mail attribute encrypted INSIDE it before it is signed.
function selfAssertion(signer, acs, opts) {
  log.debug("Entering selfAssertion().");
  const o = opts || {};
  const built = xmldsig.buildAssertion({
    issuer: SELF_ISSUER, subject: SELF_SUBJECT, audience: acs,
    recipient: acs, authnStatement: true,
    // The attribute by its SAML name, which the default map turns into
    // `mail` (federation/federation_map.ts).
    attributes: { [MAIL_OID]: o.mail ||
                              (PERSON + "@partner.encryption.test") } });
  if (o.encryptId) {
    built.xml = built.xml.replace(/<saml:NameID[^>]*>[^<]*<\/saml:NameID>/,
      encryptXml(el("saml:NameID", " xmlns:saml=\"" + SAML + "\" Format=\"" +
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified\"",
                    SELF_SUBJECT),
                 o.certPem, { cipher: "aes256-gcm", transport: "rsa-oaep",
                              wrapper: "saml:EncryptedID" }));
  }
  if (o.encryptAttribute) {
    built.xml = built.xml.replace(
      /<saml:Attribute Name="urn:oid:[0-9.]+">[\s\S]*?<\/saml:Attribute>/,
      encryptXml(el("saml:Attribute", " xmlns:saml=\"" + SAML +
                    "\" Name=\"" + MAIL_OID + "\"",
                    el("saml:AttributeValue", "", o.mail)),
                 o.certPem, { cipher: "aes256-gcm", transport: "rsa-oaep",
                              wrapper: "saml:EncryptedAttribute" }));
  }
  log.debug("Leaving selfAssertion().");
  return xmldsig.sign(built, signer.privateKeyPem, "");
}

function samlResponse(inner) {
  log.debug("Entering samlResponse().");
  log.debug("Leaving samlResponse().");
  return Buffer.from("<samlp:Response xmlns:samlp=\"" + SAMLP + "\" ID=\"" +
    xmldsig.id() + "\" IssueInstant=\"" + xmldsig.iso(0) +
    "\" Version=\"2.0\"><saml:Issuer xmlns:saml=\"" + SAML + "\">" +
    SELF_ISSUER + "</saml:Issuer><samlp:Status><samlp:StatusCode " +
    "Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\">" +
    "</samlp:StatusCode></samlp:Status>" + inner + "</samlp:Response>",
    "utf8").toString("base64");
}

// ---------------------------------------------------------------------------
// JWE, WRITTEN HERE: ECDH-ES direct with A256GCM (RFC 7518 section 4.6: the
// Concat KDF's OtherInfo is the length-prefixed enc, two empty party infos
// and the key length in bits). What goes in the header beyond that is the
// caller's, so a refused alg or enc can be announced on a real JWE.
// ---------------------------------------------------------------------------
function jweTo(jwk, plaintext, headerExtra) {
  log.debug("Entering jweTo().");
  const recipient = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  const ephemeral = nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "prime256v1" });
  const epk = ephemeral.publicKey.export({ format: "jwk" });
  const header = Object.assign({ alg: "ECDH-ES", enc: "A256GCM", cty: "JWT",
    kid: jwk.kid, epk: { kty: "EC", crv: "P-256", x: epk.x, y: epk.y } },
    headerExtra || {});
  const z = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey,
                                       publicKey: recipient });
  const u32 = function (n) {
    log.debug("Entering u32().");
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    log.debug("Leaving u32().");
    return b;
  };
  const algId = Buffer.from("A256GCM", "utf8");
  const cek = nodeCrypto.createHash("sha256").update(Buffer.concat([
    u32(1), z, u32(algId.length), algId, u32(0), u32(0), u32(256)]))
    .digest();
  const protectedHeader = Buffer.from(JSON.stringify(header))
    .toString("base64url");
  const iv = nodeCrypto.randomBytes(12);
  const c = nodeCrypto.createCipheriv("aes-256-gcm", cek, iv);
  c.setAAD(Buffer.from(protectedHeader, "ascii"));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext, "utf8")),
                            c.final()]);
  log.debug("Leaving jweTo().");
  return [protectedHeader, "", iv.toString("base64url"),
          ct.toString("base64url"), c.getAuthTag().toString("base64url")]
    .join(".");
}

function selfSigner() {
  log.debug("Entering selfSigner().");
  const forge = require("node-forge");
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  const subject = [{ name: "commonName", value: "fe partner " + STAMP }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(cert);
  log.debug("Leaving selfSigner().");
  return { certificatePem: pem,
           der: pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
           privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

// ---------------------------------------------------------------------------
// SETTING THE WORLD UP. Everything is created; nothing service-wide changes.
// The one setting this job moves — the grace period in the SP realm — is a
// per-realm override of a realm it owns.
// ---------------------------------------------------------------------------
async function setUp() {
  log.debug("Entering setUp().");
  isProduct = await facts.isProduct(base + "/admin-api");
  log.info("The service is in " + (isProduct ? "PRODUCT" : "DEVELOPMENT") +
           " mode. Identity provider realm " + IDP + ", service provider " +
           "realm " + SP + ".");
  await ensureRealm(IDP);
  await ensureRealm(SP);
  await createPerson(IDP, PERSON, IDP_MAIL, true);
  await createPerson(SP, PERSON, SP_MAIL, false);
  const signer = selfSigner();

  // --- the SAML relationship the IdP realm encrypts to ---------------------
  const samlMade = await api(SP, "POST", "/federation/create",
    { id: REL.saml, role: "service-provider", protocol: "saml2" });
  must(samlMade.status === 200 && samlMade.body && samlMade.body.ok,
       "creating " + REL.saml + " answered " + samlMade.status + " " +
       samlMade.text.slice(0, 300));
  const samlView = await relationship(REL.saml);
  const samlAcs = samlView.endpoints.assertionConsumerService;
  const ours = await metadataOf(REL.saml);
  const signing = ((/<md:KeyDescriptor use="signing">[\s\S]*?X509Certificate>([^<]+)</
    .exec(ours.xml) || [])[1] || "").replace(/\s+/g, "");
  must(ours.entityId && signing && ours.certificate,
       "the SP metadata lacks an entityID, a signing certificate or an " +
       "encryption certificate: " + ours.xml.slice(0, 400));
  await createApplication(IDP, ours.entityId, ["saml2"], {
    samlEntityId: [ours.entityId],
    samlAssertionConsumerService: [samlAcs],
    samlSigningCertificate: [pemOf(signing)],
    // THE IdP REALM ENCRYPTS, to the certificate our metadata publishes,
    // with the key transport it publishes.
    samlEncryptionCertificate: pemOf(ours.certificate),
    saml2EncryptAssertion: "TRUE",
    saml2KeyTransportAlgorithm: "rsa-oaep",
    saml2EncryptionAlgorithm: "aes256-gcm" });
  const idpMeta = await hop(null, realmBase(IDP) + "/saml2/metadata/" +
                                  encodeURIComponent(ours.entityId));
  const idpEntity = (/entityID="([^"]+)"/.exec(idpMeta.body) || [])[1] || "";
  const idpCert = ((/<md:KeyDescriptor[^>]*use="signing"[\s\S]*?X509Certificate>([^<]+)</
    .exec(idpMeta.body) || [])[1] || "").replace(/\s+/g, "");
  const idpSso = (/SingleSignOnService[^>]*Binding="urn:oasis:names:tc:SAML:2\.0:bindings:HTTP-POST"[^>]*Location="([^"]+)"/
    .exec(idpMeta.body) || [])[1] || "";
  must(idpEntity && idpCert && idpSso, "the IdP realm's metadata lacks " +
       "something: " + idpMeta.body.slice(0, 300));
  for (const [field, value] of [["fedPeer", idpEntity],
                                ["fedSsoUrl", idpSso],
                                ["fedSigningCertificate", idpCert],
                                ["fedBinding", "HTTP-POST"],
                                ["fedSignRequest", "TRUE"]]) {
    const set = await setRel(REL.saml, field, value);
    must(set.status === 200 && set.body.ok, "setting " + field + " on " +
         REL.saml + " answered " + set.status + " " + set.text.slice(0, 200));
  }
  const on = await api(SP, "POST", "/federation/enable", { id: REL.saml });
  must(on.status === 200 && on.body.ok, "enabling " + REL.saml + " answered " +
       on.status + " " + on.text.slice(0, 200));
  await link(REL.saml, PERSON);

  // --- the relationships to THIS FILE as partner ---------------------------
  const selfSettings = { fedSsoUrl: "https://fe-partner.invalid/sso",
                         fedSigningCertificate: signer.der,
                         fedAllowUnsolicited: "TRUE" };
  await createRelationship(REL.self, "saml2", SELF_ISSUER, selfSettings);
  await createRelationship(REL.selfEc, "saml2", SELF_ISSUER, selfSettings);
  const typed = await setRel(REL.selfEc, "fedEncryptionKeyType", "ec-p256");
  must(typed.status === 200 && typed.body.ok, "setting the EC key type " +
       "answered " + typed.status + " " + typed.text.slice(0, 200));
  await createRelationship(REL.wsfed, "wsfed", SELF_ISSUER, {
    fedSsoUrl: "https://fe-partner.invalid/wsfed",
    fedSigningCertificate: signer.der, fedAllowUnsolicited: "TRUE" });
  for (const rel of [REL.self, REL.selfEc, REL.wsfed]) {
    await link(rel, SELF_SUBJECT);
  }

  // --- the OpenID Connect relationship, and the IdP realm's client --------
  const discovery = await (await fetch(realmBase(IDP) +
                                       "/.well-known/openid-configuration"))
    .json();
  const partnerJwks = await (await fetch(discovery.jwks_uri)).json();
  const client = "fe-oidc-" + STAMP;
  await createRelationship(REL.oidc, "oidc", discovery.issuer, {
    fedSsoUrl: discovery.authorization_endpoint, fedClientId: client,
    fedResponseType: "id_token", fedScope: "openid profile email",
    fedUsernameSource: "preferred_username",
    fedJwks: JSON.stringify(partnerJwks) });
  const oidcView = await relationship(REL.oidc);
  const ourJwks = await (await fetch(oidcView.endpoints.jwks)).json();
  // THIS FILE AS AN OPENID PROVIDER TOO: the relationship's partner key is
  // the one this file signs with, so every ID Token below is this file's
  // own, signed and then encrypted here.
  const selfJwk = Object.assign(nodeCrypto.createPublicKey(
    signer.privateKeyPem).export({ format: "jwk" }),
    { kid: "fe-self-" + STAMP, alg: "RS256", use: "sig" });
  await createRelationship(REL.oidcSelf, "oidc", SELF_ISSUER, {
    fedSsoUrl: "https://fe-partner.invalid/authorize",
    fedClientId: SELF_CLIENT, fedResponseType: "id_token",
    fedScope: "openid", fedJwks: JSON.stringify({ keys: [selfJwk] }) });
  await link(REL.oidcSelf, SELF_SUBJECT);
  const selfView = await relationship(REL.oidcSelf);
  const selfJwks = await (await fetch(selfView.endpoints.jwks)).json();
  // THE IdP REALM'S OWN OPENID PROVIDER ENCRYPTING, in DEVELOPMENT only.
  // Encryption is registration metadata (OpenID Connect Registration section
  // 2), and a product realm will not REGISTER a client for an ID Token by
  // form_post: it is in RFC 9700 mode, which refuses the implicit grant, and
  // RFC 7591 refuses response_types [id_token] beside authorization_code.
  // The encrypted ID Token itself is covered in both modes by this file's
  // own OpenID Provider above.
  if (!isProduct) {
    const reg = await fetch(realmBase(IDP) + "/oauth2/register", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: client, redirect_uris: [oidcView.endpoints
          .assertionConsumerService],
        response_types: ["id_token"], grant_types: ["implicit"],
        token_endpoint_auth_method: "none",
        id_token_encrypted_response_alg: "ECDH-ES",
        id_token_encrypted_response_enc: "A256GCM",
        jwks: ourJwks }) });
    const regBody = await reg.json().catch(function () {
      return {};
    });
    must(reg.status === 201 && regBody.client_id, "registering the " +
         "partner's client answered " + reg.status + " " +
         JSON.stringify(regBody).slice(0, 300));
    const setClient = await setRel(REL.oidc, "fedClientId",
                                   regBody.client_id);
    must(setClient.status === 200, "setting fedClientId answered " +
                                   setClient.status);
    const partnerView = await api(IDP, "GET", "/users?user=" +
                                                encodeURIComponent(PERSON));
    await link(REL.oidc, (partnerView.body && partnerView.body.subject) ||
                         "");
  }
  log.debug("Leaving setUp().");
  return { signer: signer, samlAcs: samlAcs, ours: ours,
           discovery: discovery, ourJwks: ourJwks, oidcView: oidcView,
           selfView: selfView, selfJwks: selfJwks };
}

async function acsOf(id) {
  log.debug("Entering acsOf(). " + id);
  const view = await relationship(id);
  log.debug("Leaving acsOf().");
  return view.endpoints.assertionConsumerService;
}

async function signedIn(what, r) {
  log.debug("Entering signedIn(). " + what);
  await check(what, async function () {
    assert.ok(startsSession(r), "no session was started: HTTP " + r.status +
              " — " + squash(r.body));
  });
  log.debug("Leaving signedIn().");
}

async function refused(what, r, status, pattern) {
  log.debug("Entering refused(). " + what);
  await check(what + " — refused " + status + ", no session",
              async function () {
    assert.strictEqual(r.status, status, "HTTP " + r.status + " — " +
                       squash(r.body));
    assert.ok(pattern.test(squash(r.body)), "the page should say " + pattern +
              "; it says " + squash(r.body));
    assert.ok(!startsSession(r), "a session was started");
  });
  log.debug("Leaving refused().");
}

// ---------------------------------------------------------------------------
// 1. PUBLICATION
// ---------------------------------------------------------------------------
async function publication(world) {
  log.debug("Entering publication().");
  log.info("=== 1. what a partner encrypts to ===");
  await check("the SAML metadata publishes KeyDescriptor use=\"encryption\" " +
              "with rsa-oaep (SHA-256, MGF1-SHA-256) and aes256-gcm, " +
              "no-store", async function () {
    const m = world.ours;
    assert.ok(m.encryption && /xmlenc11#rsa-oaep/.test(m.encryption) &&
              /mgf1sha256/.test(m.encryption) &&
              /xmlenc#sha256/.test(m.encryption) &&
              /xmlenc11#aes256-gcm/.test(m.encryption) &&
              !/cbc|rsa-1_5/.test(m.encryption), m.encryption);
    assert.ok(/no-store/.test(m.cacheControl), m.cacheControl);
  });
  await check("the WS-Federation relationship has metadata too: a " +
              "fed:ApplicationServiceType RoleDescriptor with its endpoint " +
              "and its encryption key", async function () {
    const m = await metadataOf(REL.wsfed);
    assert.strictEqual(m.status, 200, m.xml.slice(0, 200));
    assert.ok(/fed:ApplicationServiceType/.test(m.xml) &&
              /PassiveRequestorEndpoint/.test(m.xml) &&
              m.certificate, m.xml.slice(0, 600));
  });
  await check("the OpenID Connect JWKS is one public key, use enc, alg " +
              "ECDH-ES, P-256, no-store", async function () {
    const r = await hop(null, world.selfView.endpoints.jwks);
    const keys = JSON.parse(r.body).keys;
    assert.strictEqual(keys.length, 1);
    const k = keys[0];
    assert.ok(k.use === "enc" && k.alg === "ECDH-ES" && k.kty === "EC" &&
              k.crv === "P-256" && !k.d && k.kid, JSON.stringify(k));
    assert.ok(/no-store/.test(r.headers.get("cache-control") || ""));
  });
  await check("a SAML relationship has no JWKS (404) and an OpenID Connect " +
              "one no SAML metadata", async function () {
    const a = await hop(null, realmBase(SP) + "/federation/jwks/" + REL.self);
    const b = await hop(null, realmBase(SP) + "/federation/metadata/" +
                              REL.oidc);
    assert.ok(a.status === 404 && b.status === 404, a.status + " " +
              b.status);
  });
  await check("the API view names the key and never a private one",
              async function () {
    const view = await relationship(REL.self);
    const text = JSON.stringify(view);
    assert.ok(view.encryption && view.encryption.current &&
              /BEGIN CERTIFICATE/.test(view.encryption.certificatePem),
              JSON.stringify(view.encryption));
    assert.ok(!/PRIVATE KEY|\$aesgcm\$|privateKey/.test(text),
              "the view carries private key material");
    assert.strictEqual(view.fields.fedEncryptionKey,
                       "(set — not returned)");
    assert.strictEqual(view.encryption.required, isProduct);
  });
  log.debug("Leaving publication().");
}

// ---------------------------------------------------------------------------
// 2. SAML 2.0, THE IdP REALM ENCRYPTING
// ---------------------------------------------------------------------------
async function samlFromPartner(world) {
  log.debug("Entering samlFromPartner().");
  log.info("=== 2. SAML 2.0: the IdP realm's encrypted assertion ===");
  const cookies = jar();
  const door = await toTheDoor(cookies, realmBase(SP) +
                               "/federation/login/" + REL.saml, PERSON);
  const xml = Buffer.from(String(door.fields.SAMLResponse || ""), "base64")
    .toString("utf8");
  await check("the IdP realm sent an EncryptedAssertion under rsa-oaep and " +
              "no assertion in clear", async function () {
    assert.ok(/EncryptedAssertion/.test(xml) &&
              xml.indexOf(XENC11 + "rsa-oaep") >= 0 &&
              !/<saml2?:Assertion[ >]/.test(xml), xml.slice(0, 600));
  });
  await signedIn("and it signs the person in", await deliver(cookies, door));
  log.debug("Leaving samlFromPartner().");
}

// ---------------------------------------------------------------------------
// 3. SAML 2.0, THIS FILE ENCRYPTING
// ---------------------------------------------------------------------------
async function samlFromSelf(world) {
  log.debug("Entering samlFromSelf().");
  log.info("=== 3. SAML 2.0: this file's encryptor ===");
  const acs = await acsOf(REL.self);
  const cert = pemOf((await metadataOf(REL.self)).certificate);
  const post = function (inner, url) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return postForm(jar(), url || acs, { SAMLResponse: samlResponse(inner) });
  };
  const signed = function (opts) {
    log.debug("Entering signed().");
    log.debug("Leaving signed().");
    return selfAssertion(world.signer, acs, Object.assign({ certPem: cert },
                                                          opts || {}));
  };
  await signedIn("an EncryptedAssertion (rsa-oaep, aes256-gcm) signs in",
    await post(encryptXml(signed(), cert, { cipher: "aes256-gcm",
      transport: "rsa-oaep", wrapper: "saml:EncryptedAssertion",
      declare: true })));
  const mail = "enc-attr-" + STAMP + "@partner.encryption.test";
  await signedIn("an EncryptedID and an EncryptedAttribute inside it are " +
                 "decrypted after the signature over them verifies",
    await post(encryptXml(signed({ encryptId: true, encryptAttribute: true,
                                    mail: mail }),
      cert, { cipher: "aes256-gcm", transport: "rsa-oaep",
              wrapper: "saml:EncryptedAssertion", declare: true })));
  await check("the encrypted attribute's value is on the person's entry",
              async function () {
    const view = await sessionsOf(PERSON);
    assert.deepStrictEqual((view.entry || {}).mail, [mail],
                           JSON.stringify(view.entry));
  });

  const ecAcs = await acsOf(REL.selfEc);
  const ecMeta = await metadataOf(REL.selfEc);
  const ecCert = pemOf(ecMeta.certificate);
  await check("an EC relationship publishes an EC key with ECDH-ES and " +
              "kw-aes256", async function () {
    assert.strictEqual(new nodeCrypto.X509Certificate(ecCert).publicKey
      .asymmetricKeyType, "ec");
    assert.ok(/xmlenc11#ECDH-ES/.test(ecMeta.encryption) &&
              /kw-aes256/.test(ecMeta.encryption), ecMeta.encryption);
  });
  await signedIn("an assertion encrypted by ECDH-ES key agreement to it " +
                 "signs in",
    await postForm(jar(), ecAcs, { SAMLResponse: samlResponse(encryptXml(
      selfAssertion(world.signer, ecAcs), ecCert, { cipher: "aes256-gcm",
        transport: "ecdh-es", wrapper: "saml:EncryptedAssertion",
        declare: true })) }));

  for (const [cipherName, transport] of [["aes256-cbc", "rsa-oaep"],
                                         ["aes256-gcm", "rsa-1_5"],
                                         ["aes256-gcm", "rsa-oaep-mgf1p"],
                                         ["aes128-gcm", "rsa-oaep"]]) {
    await refused(cipherName + " under " + transport,
      await post(encryptXml(signed(), cert, { cipher: cipherName,
        transport: transport, wrapper: "saml:EncryptedAssertion",
        declare: true })), 401, /algorithm this relationship refuses/);
  }
  const other = await (async function () {
    const r = await hop(null, realmBase(SP) + "/federation/metadata/" +
                              REL.saml);
    return pemOf(((/<md:KeyDescriptor use="encryption">[\s\S]*?X509Certificate>([^<]+)</
      .exec(r.body) || [])[1] || "").replace(/\s+/g, ""));
  }());
  const wrong = await post(encryptXml(signed(), other, { cipher: "aes256-gcm",
    transport: "rsa-oaep", wrapper: "saml:EncryptedAssertion",
    declare: true }));
  await refused("an assertion encrypted to ANOTHER relationship's key",
                wrong, 401, /could not be decrypted/);
  const sealed = encryptXml(signed(), cert, { cipher: "aes256-gcm",
    transport: "rsa-oaep", wrapper: "saml:EncryptedAssertion",
    declare: true });
  const altered = sealed.replace(
    /(<\/xenc:KeyInfo><xenc:CipherData><xenc:CipherValue>|<\/ds:KeyInfo><xenc:CipherData><xenc:CipherValue>)([A-Za-z0-9+/])/,
    function (all, a, b) {
      return a + (b === "A" ? "B" : "A");
    });
  const tampered = await post(altered);
  await refused("an altered ciphertext", tampered, 401,
                /could not be decrypted/);
  await check("a wrong key and an altered ciphertext read THE SAME (no " +
              "oracle)", async function () {
    const why = function (r) {
      log.debug("Entering why().");
      log.debug("Leaving why().");
      return (/<p class="bad">[^<]*<\/p><p>([^<]*)<\/p>/.exec(r.body) ||
              [])[1] || "";
    };
    assert.ok(why(wrong) && why(wrong) === why(tampered),
              why(wrong) + " | " + why(tampered));
  });
  await refused("an encrypted and a plaintext assertion together",
    await post(sealed + signed()), 400, /more than one assertion/);

  const plain = await post(signed());
  if (isProduct) {
    await refused("PRODUCT: a plaintext assertion", plain, 401,
                  /not encrypted/);
    const allow = await setRel(REL.self, "fedAllowUnencrypted", "TRUE");
    must(allow.status === 200 && allow.body.ok, "fedAllowUnencrypted " +
         "answered " + allow.status);
    await signedIn("PRODUCT: with fedAllowUnencrypted the same plaintext " +
                   "assertion signs in", await post(signed()));
    await setRel(REL.self, "fedAllowUnencrypted", "FALSE");
  } else {
    await signedIn("DEVELOPMENT: a plaintext assertion is accepted", plain);
  }
  log.debug("Leaving samlFromSelf().");
}

// ---------------------------------------------------------------------------
// 4. WS-FEDERATION
// ---------------------------------------------------------------------------
async function wsfed(world) {
  log.debug("Entering wsfed().");
  log.info("=== 4. WS-Federation: an encrypted token in the RSTR ===");
  const acs = await acsOf(REL.wsfed);
  const cert = pemOf((await metadataOf(REL.wsfed)).certificate);
  const rstr = function (token) {
    log.debug("Entering rstr().");
    log.debug("Leaving rstr().");
    return "<t:RequestSecurityTokenResponse xmlns:t=\"http://schemas." +
      "xmlsoap.org/ws/2005/02/trust\"><t:RequestedSecurityToken>" + token +
      "</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>";
  };
  const post = function (token) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return postForm(jar(), acs, { wa: "wsignin1.0", wresult: rstr(token) });
  };
  await signedIn("a bare xenc:EncryptedData (rsa-oaep, aes256-gcm) holding " +
                 "a signed SAML 2.0 assertion signs in",
    await post(encryptXml(selfAssertion(world.signer, acs), cert,
      { cipher: "aes256-gcm", transport: "rsa-oaep" })));
  await refused("aes256-cbc in the RSTR",
    await post(encryptXml(selfAssertion(world.signer, acs), cert,
      { cipher: "aes256-cbc", transport: "rsa-oaep" })), 401,
    /algorithm this relationship refuses/);
  const plain = await post(selfAssertion(world.signer, acs));
  if (isProduct) {
    await refused("PRODUCT: a plaintext token", plain, 401, /not encrypted/);
  } else {
    await signedIn("DEVELOPMENT: a plaintext token is accepted", plain);
  }
  log.debug("Leaving wsfed().");
}

// ---------------------------------------------------------------------------
// 5. OPENID CONNECT
// ---------------------------------------------------------------------------
async function oidc(world) {
  log.debug("Entering oidc().");
  log.info("=== 5. OpenID Connect: an encrypted ID Token ===");
  if (!isProduct) {
    const cookies = jar();
    const door = await toTheDoor(cookies, realmBase(SP) +
                                 "/federation/login/" + REL.oidc, PERSON);
    const token = String((door.fields || {}).id_token || "");
    await check("DEVELOPMENT: the IdP realm sent a five-part JWE, ECDH-ES / " +
                "A256GCM, to our key", async function () {
      const parts = token.split(".");
      assert.strictEqual(parts.length, 5, token.slice(0, 80));
      const header = JSON.parse(Buffer.from(parts[0], "base64url")
        .toString());
      assert.ok(header.alg === "ECDH-ES" && header.enc === "A256GCM" &&
                header.kid === world.ourJwks.keys[0].kid,
                JSON.stringify(header));
    });
    await signedIn("DEVELOPMENT: and it signs the person in",
                   await deliver(cookies, door));
  }

  const acs = world.selfView.endpoints.assertionConsumerService;
  const jwk = world.selfJwks.keys[0];
  // A sign-in begun here and finished by this file: the state and the nonce
  // this service minted, and an ID Token for them signed with this file's
  // key.
  const begin = async function () {
    log.debug("Entering begin().");
    const begun = await hop(jar(), realmBase(SP) + "/federation/login/" +
                                   REL.oidcSelf);
    const asked = new URL(begun.location);
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: SELF_ISSUER, aud: SELF_CLIENT, sub: SELF_SUBJECT,
                     iat: now, exp: now + 300,
                     nonce: asked.searchParams.get("nonce") };
    const input = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT",
      kid: "fe-self-" + STAMP })).toString("base64url") + "." +
      Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signed = input + "." + nodeCrypto.sign("sha256",
      Buffer.from(input), world.signer.privateKeyPem).toString("base64url");
    log.debug("Leaving begin().");
    return { state: asked.searchParams.get("state"), signed: signed };
  };
  const answer = function (begun, idToken) {
    log.debug("Entering answer().");
    log.debug("Leaving answer().");
    return postForm(jar(), acs, { id_token: idToken, state: begun.state });
  };
  let begun = await begin();
  await signedIn("an ID Token signed and then encrypted (ECDH-ES, A256GCM) " +
                 "by this file signs in",
                 await answer(begun, jweTo(jwk, begun.signed)));
  begun = await begin();
  await refused("enc A128CBC-HS256", await answer(begun,
    jweTo(jwk, begun.signed, { enc: "A128CBC-HS256" })), 401,
    /algorithm this relationship refuses/);
  begun = await begin();
  await refused("alg RSA1_5", await answer(begun,
    jweTo(jwk, begun.signed, { alg: "RSA1_5" })), 401,
    /algorithm this relationship refuses/);
  const stranger = nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "prime256v1" }).publicKey.export({ format: "jwk" });
  begun = await begin();
  await refused("a JWE to another key under our kid", await answer(begun,
    jweTo(Object.assign(stranger, { kid: jwk.kid }), begun.signed)), 401,
    /could not be decrypted/);
  begun = await begin();
  await refused("a JWE with nothing signed inside", await answer(begun,
    jweTo(jwk, "{\"sub\":\"" + SELF_SUBJECT + "\"}")), 401,
    /not signed/);
  begun = await begin();
  const signedOnly = await answer(begun, begun.signed);
  if (isProduct) {
    await refused("PRODUCT: a signed-only ID Token by form_post", signedOnly,
                  401, /not encrypted/);
  } else {
    await signedIn("DEVELOPMENT: a signed-only ID Token is accepted",
                   signedOnly);
  }
  log.debug("Leaving oidc().");
}

// ---------------------------------------------------------------------------
// 6. ROTATION AND ITS GRACE PERIOD
// ---------------------------------------------------------------------------
async function rotation(world) {
  log.debug("Entering rotation().");
  log.info("=== 6. rotation ===");
  const acs = await acsOf(REL.self);
  const first = pemOf((await metadataOf(REL.self)).certificate);
  const toKey = function (certPem) {
    log.debug("Entering toKey().");
    log.debug("Leaving toKey().");
    return postForm(jar(), acs, { SAMLResponse: samlResponse(encryptXml(
      selfAssertion(world.signer, acs), certPem, { cipher: "aes256-gcm",
        transport: "rsa-oaep", wrapper: "saml:EncryptedAssertion",
        declare: true })) });
  };
  const rotated = await api(SP, "POST", "/federation/rotate-key",
                            { id: REL.self });
  must(rotated.status === 200 && rotated.body.ok, "rotate-key answered " +
       rotated.status + " " + rotated.text.slice(0, 300));
  const second = pemOf((await metadataOf(REL.self)).certificate);
  await check("the metadata publishes the NEW key", async function () {
    assert.notStrictEqual(second, first);
  });
  await signedIn("the new key decrypts", await toKey(second));
  await signedIn("the key it replaced still decrypts in its grace",
                 await toKey(first));
  // A SHORT GRACE, in this realm only, then a second rotation.
  const grace = await api(SP, "POST", "/config/set",
    { key: "federation.encryptionKeyGraceS", value: 2 });
  must(grace.status === 200, "setting the grace answered " + grace.status +
       " " + grace.text.slice(0, 200));
  await api(SP, "POST", "/federation/rotate-key", { id: REL.self });
  await refused("a key two rotations old decrypts nothing",
                await toKey(first), 401, /could not be decrypted/);
  await sleep(3000);
  await refused("past its grace the replaced key decrypts nothing, before " +
                "any job has run", await toKey(second), 401,
                /could not be decrypted/);
  const queued = await api(SP, "POST", "/scheduler/run",
    { job: "federation.encryption-key-retire", realm: SP });
  await check("the retirement job removes it from the entry",
              async function () {
    assert.ok((queued.status === 200 || queued.status === 202) &&
              queued.body.ok, queued.text);
    let keys = [];
    const until = Date.now() + 45000;
    while (Date.now() < until) {
      keys = (await relationship(REL.self)).encryption.keys;
      if (keys.length === 1) {
        break;
      }
      await sleep(1000);
    }
    assert.strictEqual(keys.length, 1, JSON.stringify(keys));
  });
  await api(SP, "POST", "/config/set",
            { key: "federation.encryptionKeyGraceS", value: 86400 });
  log.debug("Leaving rotation().");
}

// ---------------------------------------------------------------------------
// 7. THE FIELDS
// ---------------------------------------------------------------------------
async function fields() {
  log.debug("Entering fields().");
  log.info("=== 7. the algorithm fields ===");
  for (const [rel, field, value] of [
    [REL.self, "fedContentEncryptionAlgorithm", "aes256-cbc"],
    [REL.self, "fedKeyManagementAlgorithm", "rsa-1_5"],
    [REL.oidcSelf, "fedContentEncryptionAlgorithm", "A128CBC-HS256"],
    [REL.oidcSelf, "fedKeyManagementAlgorithm", "RSA1_5"]]) {
    await check(field + "=" + value + " is refused at the API in every mode",
                async function () {
      const r = await setRel(rel, field, value);
      assert.strictEqual(r.status, 400, r.text.slice(0, 200));
      assert.ok(/refused in every mode/.test(r.text), r.text.slice(0, 300));
    });
  }
  log.debug("Leaving fields().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the federation encryption checks against " + base);
  const world = await setUp();
  await publication(world);
  await samlFromPartner(world);
  await samlFromSelf(world);
  await wsfed(world);
  await oidc(world);
  await rotation(world);
  await fields();
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
  assert.ok(checks >= 35, "only " + checks + " checks ran, so a SECTION " +
            "STOPPED BEING CALLED.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
  return 0;
}

const program = new Command();
program
  .name("sts_federation_encryption")
  .description("A federation partner's encrypted assertion or ID Token " +
      "(#168), between two trust realms of one service and this file as a " +
      "partner of its own: the published keys, SAML 2.0 EncryptedAssertion, " +
      "EncryptedID and EncryptedAttribute, ECDH-ES, WS-Federation, a JWE " +
      "ID Token, every refused algorithm, plaintext in product, and " +
      "rotation with its grace period.")
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
