// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_webauthn_attestation.js
//
// ===========================================================================
// A SECURITY KEY'S ATTESTATION, VERIFIED OVER HTTP (#105).
//
// A person enrols keys at `/portal/keys` in a throwaway trust realm this job
// creates (and leaves behind, tests/CLAUDE.md), each with an attestation
// statement this job's own authenticator makes: a `packed` statement whose
// certificate chains to a root minted here at run time and handed to the
// realm as `webauthn.attestationTrustAnchors`. No key material is in the
// repository; every key and certificate below is made when the job runs.
//
//   1. require-trusted: the anchored statement is accepted, a self
//      attestation is refused, and so is the anchored statement when the
//      realm's AAGUID allow-list names another model;
//   2. verify-if-present: a statement whose signature does not verify is
//      refused, and `none` is accepted as untrusted;
//   3. THE REPORTING: what each statement proved is on the key's row on
//      `/portal/keys`, on `GET /admin-api/users`, and on the console's
//      `/admin/users` row; `/admin/webauthn` and `GET /admin-api/webauthn`
//      report the policy in force — `by-mode` is verify-if-present in
//      product and off in development, which is the one assertion here that
//      differs by mode;
//   4. the verifier's rules format by format, in a realm of its own (D12,
//      #444: carried from `tests/webauthn_attestation.js`) — see section
//      4's own header below.
//
// `local: true`: the portal, the API and the console are this repository's.
// It carries its own AUTHENTICATOR (the CBOR, the authenticator data, the
// signatures) for `sts_dpop.js`'s reason; the certificates are minted with the
// vendored X.509 engine, which verifies nothing here.
//
// SINCE #568 THE PORTAL IS A STATIC APPLICATION: the person signs in as it
// does (`portal_signin.js`: PKCE, a DPoP-bound token for the realm's
// `/account-api`), and `/portal/keys` is that operation's answer drawn by the
// portal's own renderers, its forms the operations that mirror them
// (`portalPages()`). An enrolment answers 200 where it answered 303.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const consoleSignIn = require("./console_signin.js");
const x509 = require("../../common/crypto_impl/x509");
const keyMaterial = require("../../common/crypto_impl/key_material");

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
var log = bunyan.createLogger({ name: "sts_webauthn_attestation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");

const STAMP = names.runStamp();
const REALM = ("wa105-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const ORIGIN = new URL(base).origin;
const RP_ID = new URL(base).hostname;
const PASSWORD = "Wa-105-Passw0rd!-" + String(Date.now()).slice(-6);
const PERSON = names.usernameFor("wa105");
const CONSOLE_USER = names.usernameFor("wa105-console");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
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
    // A page rather than JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  await ok(realmApi + "/config/set", { key: key, value: value },
           "set " + key);
  log.debug("Leaving setting().");
}

async function reset(key) {
  log.debug("Entering reset(). " + key);
  await ok(realmApi + "/config/reset", { key: key }, "reset " + key);
  log.debug("Leaving reset().");
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR: CBOR, authenticator data, and the attestation.
// ---------------------------------------------------------------------------
function cborHead(major, n) {
  log.debug("Entering cborHead().");
  let out;
  if (n < 24) {
    out = Buffer.from([(major << 5) | n]);
  } else if (n < 256) {
    out = Buffer.from([(major << 5) | 24, n]);
  } else {
    out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(n, 1);
  }
  log.debug("Leaving cborHead().");
  return out;
}

function cbor(v) {
  log.debug("Entering cbor().");
  let out;
  if (Buffer.isBuffer(v)) {
    out = Buffer.concat([cborHead(2, v.length), v]);
  } else if (typeof v === "string") {
    const b = Buffer.from(v, "utf8");
    out = Buffer.concat([cborHead(3, b.length), b]);
  } else if (typeof v === "number") {
    out = v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  } else if (Array.isArray(v)) {
    out = Buffer.concat([cborHead(4, v.length)].concat(v.map(cbor)));
  } else {
    const entries = v instanceof Map ? Array.from(v.entries())
      : Object.keys(v).map(function (k) { return [k, v[k]]; });
    out = Buffer.concat([cborHead(5, entries.length)].concat(
      entries.map(function (kv) {
        return Buffer.concat([cbor(kv[0]), cbor(kv[1])]);
      })));
  }
  log.debug("Leaving cbor().");
  return out;
}

function sha256(b) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash("sha256").update(b).digest();
}

function derOf(pem) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")
    .replace(/\s+/g, ""), "base64");
}

// A root, and a packed attestation certificate under it for `aaguid`, with
// the fields WebAuthn Level 3 section 8.2.1 requires.
async function vendor(name) {
  log.debug("Entering vendor(). " + name);
  const rootPair = await keyMaterial.generateKeyPair("ec-p256");
  const root = await x509.issueCertificate({
    subject: [{ name: "CN", value: name + " Root" }],
    subjectPublicKey: rootPair.publicPem, signatureAlg: "sha256-ecdsa",
    profile: "root-ca",
    issuer: { privateKeyPem: rootPair.privatePem, keyAlg: "ec-p256" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] } } });
  log.debug("Leaving vendor().");
  return {
    rootPem: root.pem,
    attestationCertificate: async function (aaguid, usages) {
      log.debug("Entering attestationCertificate().");
      const pair = await keyMaterial.generateKeyPair("ec-p256");
      const cert = await x509.issueCertificate({
        subject: [{ name: "C", value: "US" },
                  { name: "O", value: name },
                  { name: "OU", value: "Authenticator Attestation" },
                  { name: "CN", value: name + " Attestation" }],
        subjectPublicKey: pair.publicPem, signatureAlg: "sha256-ecdsa",
        profile: "digital-signature",
        issuer: { certificatePem: root.pem, privateKeyPem: rootPair.privatePem,
                  keyAlg: "ec-p256" },
        extensions: {
          basicConstraints: { present: true, critical: true, ca: false },
          keyUsage: { present: true, critical: true,
                      usages: usages || ["digitalSignature"] },
          custom: [{ oid: "1.3.6.1.4.1.45724.1.1.4", critical: false,
                     value: Buffer.concat([Buffer.from([0x04, 0x10]),
                                           aaguid]).toString("base64") }] } });
      log.debug("Leaving attestationCertificate().");
      return { der: derOf(cert.pem), privatePem: pair.privatePem };
    }
  };
}

// One authenticator of one model: `register(challenge, how)` answers the
// credential `/portal/keys` takes, attested `how`: "packed" (the x5c
// statement), "self", "forged" (packed, signature over something else) or
// "none".
async function authenticator(model, aaguid, usages) {
  log.debug("Entering authenticator().");
  const pair = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const cose = new Map([[1, 2], [3, -7], [-1, 1],
                        [-2, Buffer.from(jwk.x, "base64url")],
                        [-3, Buffer.from(jwk.y, "base64url")]]);
  const attCert = await model.attestationCertificate(aaguid, usages);
  log.debug("Leaving authenticator().");
  return {
    register: function (challenge, how) {
      log.debug("Entering register(). " + how);
      const id = nodeCrypto.randomBytes(32);
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(id.length, 0);
      const authData = Buffer.concat([sha256(Buffer.from(RP_ID, "utf8")),
        Buffer.from([0x45]), Buffer.alloc(4), aaguid, idLength, id,
        cbor(cose)]);
      const clientDataJSON = Buffer.from(JSON.stringify({
        type: "webauthn.create", challenge: challenge, origin: ORIGIN,
        crossOrigin: false }));
      const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
      let fmt = "packed";
      let attStmt;
      if (how === "none") {
        fmt = "none";
        attStmt = {};
      } else if (how === "self") {
        attStmt = { alg: -7,
                    sig: nodeCrypto.sign("sha256", signed, pair.privateKey) };
      } else {
        attStmt = { alg: -7, x5c: [attCert.der],
          sig: nodeCrypto.sign("sha256", how === "forged"
            ? Buffer.from("something else entirely") : signed,
            attCert.privatePem) };
      }
      log.debug("Leaving register().");
      return {
        id: id.toString("base64url"), rawId: id.toString("base64url"),
        type: "public-key", authenticatorAttachment: "cross-platform",
        clientExtensionResults: {},
        response: {
          attestationObject: cbor(new Map([["fmt", fmt],
            ["attStmt", attStmt], ["authData", authData]]))
            .toString("base64url"),
          clientDataJSON: clientDataJSON.toString("base64url") } };
    }
  };
}

// ---------------------------------------------------------------------------
// THE BROWSER, THE SIGN-IN AND THE ENROLMENT.
// ---------------------------------------------------------------------------
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const url = /^https?:\/\//i.test(path) ? path : base + path;
      const r = await fetch(url, { method: method, redirect: "manual",
                                   headers: headers, body: body });
      (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
        .forEach(function (one) {
          const pair = String(one).split(";")[0];
          const at = pair.indexOf("=");
          if (at <= 0) {
            return;
          }
          const value = pair.slice(at + 1);
          if (value === "") {
            delete jar[pair.slice(0, at)];
          } else {
            jar[pair.slice(0, at)] = value;
          }
        });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

function attr(html, name) {
  log.debug("Entering attr().");
  const m = String(html).match(new RegExp(name + '="([^"]*)"'));
  log.debug("Leaving attr().");
  return m ? m[1] : "";
}

// The passkeys a drawn /portal/keys lists, by the id each row's forms carry,
// each id ONCE: a row has two forms carrying it (Rename and Remove), so a
// plain count saw every new key twice (run of 2026-10-28, after 63ea34b5).
function credentialIdsOn(text) {
  log.debug("Entering credentialIdsOn().");
  const ids = [];
  const re = /name="credentialId" value="([^"]+)"/g;
  let m;
  while ((m = re.exec(String(text))) !== null) {
    if (ids.indexOf(m[1]) < 0) {
      ids.push(m[1]);
    }
  }
  log.debug("Leaving credentialIdsOn().");
  return ids;
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

// ---------------------------------------------------------------------------
// THE PORTAL'S PAGES SINCE #568, BEHIND THE VERB THIS JOB ALWAYS USED.
//
// The portal is a static application since #568: `/portal/*` answers one
// shell document, every page is drawn in the browser from an `/account-api`
// operation and every form is sent there as JSON, with a DPoP-bound token
// and no CSRF field. `portalPages()` keeps this job's `go(method, path,
// body)` and does what the portal's runtime does instead of what the server
// used to: a GET asks the operation that MIRRORS the page and draws its
// answer with the portal's own renderers (`portal/portal.bundle.js`); a POST
// sends the form's fields to the operation that mirrors the form. What comes
// back is the page as the browser would show it — `text` the drawn markup
// with any refusal or message above it, `location` an answer's `go`, `csp`
// the shell's policy — so an assertion about what the page SAYS still reads
// the page. A signed-in page takes `client`, the portal's client
// (`portal_signin.js`); a page drawn for nobody (an activation link) takes
// none.
// ---------------------------------------------------------------------------
const portalSignin = require("./portal_signin.js");

// The forms that post to a path with no page of its own, and the page whose
// view their answer carries.
const DRAWN_ON = { "/portal/remove-key": "/portal/keys",
                   "/portal/rename-key": "/portal/keys" };

function portalPages(root, client) {
  log.debug("Entering portalPages().");
  const rootPath = new URL(root + "/").pathname.replace(/\/+$/, "");
  let translator = null;
  const translate = async function () {
    log.debug("Entering translate().");
    if (!translator) {
      const table = portalSignin.portalBundle();
      let locale = null;
      if (client) {
        const me = await client.api("GET", "/account-api/me");
        locale = me.json && me.json.locale;
      } else {
        const said = await portalSignin.nobody(root, "GET",
                                               "/account-api/locale");
        locale = said.json && said.json.locale;
      }
      translator = table.messages.WebTranslator.fromData(locale);
    }
    log.debug("Leaving translate().");
    return translator;
  };
  const operation = async function (method, page) {
    log.debug("Entering operation().");
    const ops = await portalSignin.operationsOf(root);
    log.debug("Leaving operation().");
    return ops.filter(function (op) {
      return op.mirrors === method + " " + page;
    })[0] || null;
  };
  const call = async function (op, method, target, body) {
    log.debug("Entering call().");
    log.debug("Leaving call().");
    return op.access === "person" ? client.api(method, target, body)
                                  : portalSignin.nobody(root, method, target,
                                                        body);
  };
  const draw = async function (page, view, query) {
    log.debug("Entering draw().");
    const row = portalSignin.portalBundle().PAGES.filter(function (one) {
      return one.path === page;
    })[0];
    if (!row || !view) {
      log.debug("Leaving draw(). Nothing to draw.");
      return "";
    }
    const t = await translate();
    log.debug("Leaving draw().");
    return row.render(view, { t: t, query: query || {}, prefix: "",
                              origin: new URL(root).origin, me: null,
                              locale: null, version: null, here: page });
  };
  const said = function (json) {
    log.debug("Entering said().");
    log.debug("Leaving said().");
    return (json && Array.isArray(json.errors) ? json.errors.join(" ") + " "
                                               : "") +
           (json && json.message ? String(json.message) + " " : "");
  };
  log.debug("Leaving portalPages().");
  return {
    client: client,
    go: async function (method, path, body) {
      log.debug("Entering go().");
      // A root-relative path is under `root`, the realm's prefix added
      // where the caller left it off, as this job's browser read one.
      const raw = String(path);
      const url = /^https?:\/\//i.test(raw) ? new URL(raw)
        : new URL(new URL(root).origin +
                  (rootPath && raw.indexOf(rootPath + "/") === 0 ? raw
                                                                 : rootPath +
                                                                   raw));
      const page = url.pathname.slice(rootPath.length) || "/portal";
      const query = {};
      url.searchParams.forEach(function (value, name) {
        if (name !== "realm") {
          query[name] = value;
        }
      });
      const op = await operation(method, page);
      assert.ok(op, "no /account-api operation mirrors " + method + " " +
                page);
      if (method === "GET") {
        const qs = new URLSearchParams(query).toString();
        const r = await call(op, "GET", op.path + (qs ? "?" + qs : ""));
        const view = r.json && r.json.view ? r.json.view : r.json;
        const shell = await fetch(root + page + url.search);
        log.debug("Leaving go(). GET " + page);
        return { status: r.status, json: r.json,
                 text: said(r.json) + await draw(page, view, query),
                 location: "",
                 csp: shell.headers.get("content-security-policy") || "" };
      }
      const fields = {};
      new URLSearchParams(String(body || "")).forEach(function (value, name) {
        if (name === "csrf_token") {
          return;
        }
        fields[name] = Object.prototype.hasOwnProperty.call(fields, name)
          ? [].concat(fields[name], value) : value;
      });
      const r = await call(op, "POST", op.path, fields);
      log.debug("Leaving go(). POST " + page);
      return { status: r.status, json: r.json,
               text: said(r.json) + await draw(DRAWN_ON[page] || page,
                                               r.json && r.json.view, {}),
               location: (r.json && r.json.go) || "", csp: "" };
    }
  };
}

// Signs `who` in to the realm's portal as the static portal does, and
// answers its pages (`path` is the page the job goes on to read).
async function portalSignIn(who, path) {
  log.debug("Entering portalSignIn(). " + who + " " + path);
  const client = await portalSignin.signInToThePortal(realmBase, who, null,
                                                       { password: PASSWORD });
  log.debug("Leaving portalSignIn().");
  return portalPages(realmBase, client);
}

// `/portal/keys`'s two steps, with one attestation. Answers the finish.
async function enrol(b, key, how, label) {
  log.debug("Entering enrol(). " + how);
  let page = await b.go("GET", R + "/portal/keys");
  // The plain page's rows, read before the ceremony is armed: the armed
  // page draws the ceremony in their place.
  const listedBefore = credentialIdsOn(page.text);
  const begun = await b.go("POST", R + "/portal/keys",
    form({ action: "begin", role: "mfa", kind: "security-key",
           csrf_token: csrfOf(page.text) }));
  assert.strictEqual(begun.status, 200, "beginning the enrolment answered " +
    begun.status + " " + begun.text.slice(0, 300));
  page = await b.go("GET", R + "/portal/keys");
  const challenge = attr(page.text, "data-challenge");
  assert.ok(challenge, "the armed page carries no challenge");
  const done = await b.go("POST", R + "/portal/keys",
    form({ action: "finish", enrolment_id: hiddenFields(page.text)
             .enrolment_id || "",
           credential: JSON.stringify(key.register(challenge, how)),
           csrf_token: csrfOf(page.text) }));
  if (done.status === 200 && label) {
    // THE NAME: there is none before the ceremony, and since 2026-10-28 the
    // answer names nothing either (#470's `?named=` prompt is gone) — the new
    // key sits on the plain page under its default name, and is renamed
    // through its own row's form. Which row is new is the one whose id was
    // not on the page before the finish.
    const after = await b.go("GET", R + "/portal/keys");
    const fresh = credentialIdsOn(after.text).filter(function (id) {
      return listedBefore.indexOf(id) < 0;
    });
    assert.strictEqual(fresh.length, 1, "after the finish the page should " +
      "list exactly one passkey it did not list before; it lists " +
      fresh.length + ": " + String(after.text).slice(0, 300));
    const renamed = await b.go("POST", R + "/portal/rename-key",
      form({ credentialId: fresh[0], label: label,
             csrf_token: csrfOf(after.text) }));
    assert.strictEqual(renamed.status, 200, "naming the passkey answered " +
      renamed.status + " " + String(renamed.text).slice(0, 300));
  }
  if (done.status !== 200) {
    // A refused enrolment keeps the ceremony armed; cancel it so the next
    // one starts clean.
    const again = await b.go("GET", R + "/portal/keys");
    await b.go("POST", R + "/portal/keys",
               form({ action: "cancel", csrf_token: csrfOf(again.text) }));
  }
  log.debug("Leaving enrol(). " + done.status);
  return done;
}

async function keysOf(who) {
  log.debug("Entering keysOf().");
  const r = await send(realmApi + "/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200, "GET /admin-api/users answered " +
                     r.status);
  log.debug("Leaving keysOf().");
  return (r.body.factors && r.body.factors.keys) || [];
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(base + "/admin-api");
  log.info("Driving " + base + " (" + (product ? "product" : "development") +
           " mode) in the trust realm \"" + REALM + "\".");

  log.info("=== setup: the realm, the person, the vendor's root ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "WebAuthn attestation " + STAMP }, "created the realm");
  await ok(realmApi + "/users/create", { username: PERSON, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "WA " + PERSON, givenName: "WA", sn: PERSON,
                  mail: PERSON + "@wa105.test" } }, "created " + PERSON);
  const model = await vendor("Synthetic Vendor " + STAMP);
  const AAGUID = nodeCrypto.randomBytes(16);
  const OTHER = nodeCrypto.randomBytes(16).toString("hex");
  await setting("webauthn.attestationTrustAnchors", model.rootPem);
  await setting("webauthn.maxKeysPerPerson", 20);

  const b = await portalSignIn(PERSON, R + "/portal/keys");

  // -------------------------------------------------------------------------
  log.info("=== 1. require-trusted ===");
  await setting("webauthn.attestationPolicy", "require-trusted");
  const trusted = await authenticator(model, AAGUID);
  const accepted = await enrol(b, trusted, "packed", "anchored key");
  check("an x5c statement chaining to the realm's anchor is accepted",
    function () {
      assert.strictEqual(accepted.status, 200, accepted.text.slice(0, 500));
    });
  const self = await enrol(b, await authenticator(model, AAGUID), "self",
                           "self key");
  check("a SELF attestation is refused: it proves nothing about what made " +
        "the key", function () {
    assert.strictEqual(self.status, 400, self.text.slice(0, 300));
    assert.ok(/self attestation/i.test(self.text), self.text.slice(0, 600));
  });
  await setting("webauthn.attestationAllowedAaguids", OTHER);
  const notAllowed = await enrol(b, await authenticator(model, AAGUID),
                                 "packed", "other model");
  check("an anchored key from a model the allow-list does not name is " +
        "refused", function () {
    assert.strictEqual(notAllowed.status, 400, notAllowed.text.slice(0, 300));
    assert.ok(/not one this realm allows/i.test(notAllowed.text),
              notAllowed.text.slice(0, 600));
  });
  await reset("webauthn.attestationAllowedAaguids");

  // -------------------------------------------------------------------------
  log.info("=== 1b. paranoid PKI mode: the statement's certificate ===");
  await setting("pki.paranoid", "on");
  const mayNotSign = await enrol(b,
    await authenticator(model, AAGUID, ["keyEncipherment"]), "packed",
    "cannot sign");
  check("in force, an attestation certificate whose keyUsage forbids signing " +
        "is not trusted", function () {
    assert.strictEqual(mayNotSign.status, 400, mayNotSign.text.slice(0, 300));
    assert.ok(/keyUsage/i.test(mayNotSign.text),
              mayNotSign.text.slice(0, 600));
  });
  await setting("pki.paranoidWebauthnAttestation", false);
  const rowOff = await enrol(b,
    await authenticator(model, AAGUID, ["keyEncipherment"]), "packed",
    "row off");
  check("with the row off the same statement is accepted", function () {
    assert.strictEqual(rowOff.status, 200, rowOff.text.slice(0, 500));
  });
  await reset("pki.paranoidWebauthnAttestation");
  await reset("pki.paranoid");

  // -------------------------------------------------------------------------
  log.info("=== 2. verify-if-present ===");
  await setting("webauthn.attestationPolicy", "verify-if-present");
  const forged = await enrol(b, await authenticator(model, AAGUID), "forged",
                             "forged key");
  check("a statement whose signature does not verify is refused", function () {
    assert.strictEqual(forged.status, 400, forged.text.slice(0, 300));
    assert.ok(/does not verify/i.test(forged.text), forged.text.slice(0, 600));
  });
  const none = await enrol(b, await authenticator(model, AAGUID), "none",
                           "passkey");
  check("`none` is accepted — what a synced passkey sends", function () {
    assert.strictEqual(none.status, 200, none.text.slice(0, 500));
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. what each key's statement proved is reported ===");
  const keys = await keysOf(PERSON);
  const byLabel = {};
  keys.forEach(function (k) { byLabel[k.label] = k; });
  check("GET /admin-api/users: the anchored key is verified, trusted, " +
        "packed, through the configured anchor", function () {
    const a = (byLabel["anchored key"] || {}).attestation || {};
    assert.ok(a.verified === true && a.trusted === true &&
              a.format === "packed" && a.type === "basic" &&
              a.anchor === "configured", JSON.stringify(keys));
  });
  check("and the passkey is recorded as `none`, untrusted", function () {
    const a = (byLabel.passkey || {}).attestation || {};
    assert.ok(a.verified === true && a.trusted === false &&
              a.type === "none", JSON.stringify(keys));
  });
  check("and none of the refused keys was stored: the anchored key, the one " +
        "section 1b took with its row off, and the passkey", function () {
    assert.strictEqual(keys.length, 3, JSON.stringify(keys));
  });
  const portal = await b.go("GET", R + "/portal/keys");
  check("/portal/keys shows the person what each key's statement proved",
    function () {
      assert.ok(/verified and trusted/.test(portal.text),
                portal.text.slice(0, 800));
      assert.ok(/no attestation sent/.test(portal.text),
                portal.text.slice(0, 800));
    });
  // THE CONSOLE, AS IT IS SINCE THE #446 CUTOVER: signed in at the realm
  // as the static console (PKCE, a DPoP-bound token for the realm's
  // `/admin-api`), each page its operation's answer drawn by the console's
  // own renderers (`console_signin.js`).
  //
  // The realm's console is OPENED first, as a browser opening it does: the
  // shell's answer is what registers the realm's console callback
  // (`oidc_rp.ensureConsoleCallback()`), and an authorization request naming
  // it before then is refused as an unregistered redirect_uri.
  await fetch(realmBase + "/admin", { redirect: "manual" });
  const consoleClient = await consoleSignIn.signInToTheConsole(realmBase,
    CONSOLE_USER, log, { grant: "read" });
  const row = await consoleClient.get("/admin/users?user=" +
                                      encodeURIComponent(PERSON));
  check("the console's /admin/users row draws an Attestation column: " +
        "verified and trusted for one key, untrusted for the other",
    function () {
      assert.strictEqual(row.status, 200, row.text.slice(0, 300));
      assert.ok(/<th>Attestation<\/th>/.test(row.text),
                "no Attestation column");
      assert.ok(/verified, trusted/.test(row.text), "no trusted key");
      assert.ok(/verified, untrusted/.test(row.text), "no untrusted key");
    });
  await reset("webauthn.attestationPolicy");
  const page = await consoleClient.get("/admin/webauthn");
  const api = await send(realmApi + "/webauthn");
  const status = (api.body && api.body.status) || {};
  check("/admin/webauthn and GET /admin-api/webauthn report the policy in " +
        "force: by-mode is " + (product ? "verify-if-present in product"
                                        : "off in development"),
    function () {
      assert.strictEqual(page.status, 200, page.text.slice(0, 300));
      assert.ok(/The attestation statement/.test(page.text),
                "the page has no attestation section");
      assert.strictEqual(status.attestationPolicy,
                         product ? "verify-if-present" : "off",
                         JSON.stringify(status).slice(0, 600));
      assert.strictEqual((status.attestationFormats || []).length, 8,
                         JSON.stringify(status.attestationFormats));
    });

  const matrix = await attestationMatrix();
  try {
    await matrix.removeRealms();
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // A realm left behind is not a failed assertion.
    log.warn("removing this run's realms failed: " + e.message);
  }
  assert.ok(checks >= 30,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// ---------------------------------------------------------------------------
// 4. THE VERIFIER'S RULES, FORMAT BY FORMAT (D12, #444: the wire half of
// `tests/webauthn_attestation.js`, deleted at the cutover).
//
// In a realm of its own, every registration is a real one at the portal's
// `/account-api/keys` — begun, the armed ceremony read back, finished with
// a credential this section builds over THAT ceremony's challenge and RP
// ID — and every refusal is read back as the code on `/admin-api/audit`,
// never off the answer. The statements are
// `tests/webauthn_attestation_kit.js`'s eight formats, written from the
// specification (every key and certificate made at run time); **the kit
// must move beside this job when the in-process files are deleted** (it
// is required from `../`).
//
//   4A. section 7.1: a credential algorithm the realm did not offer
//       (STS-AUTHN-0228), a 1024-byte credential id (0229), BS without BE
//       (0230), and the controls beside each;
//   4B. every algorithm the verifier knows registers AND signs its person
//       in at the typed passkey step; RS1 only behind
//       `webauthn.insecureAlgorithms`, and its assertion refused once the
//       flag is off (STS-AUTHN-0294);
//   4C. each format valid and wrong in one way — packed, tpm, android-key,
//       android-safetynet, fido-u2f, none, apple, compound, and a format
//       section 8 does not define (0231, 0232, 0233, 0234), what each valid
//       one proved read off `GET /admin-api/users`;
//   4D. the policy by mode: development's `off` takes a statement that does
//       not verify and records it unverified; product's by-mode refuses it
//       (0233); `off` is refused at the write in product (STS-CORE-0103);
//       a realm requiring a trusted statement ASKS for `direct`.
//
// NOT CARRIED (class (d)): the FIDO Metadata Service (E: a BLOB imported
// through the risk datasets, a stubbed download, `risk.mds-refresh` — I),
// Google's attestation status list (C16b/c: a dataset import), the
// revocation of an attestation chain (needs a CRL the chain names and a
// reachable distribution point), `credentials.addKey()`'s record (H1) and
// the formats table (H2, H3: the report's eight formats are section 3's).
// ---------------------------------------------------------------------------
const attKit = require("../webauthn_attestation_kit.js");
const wire = require("./passkey_wire_kit.js");

// A credential over the armed ceremony `c` (`challenge`, `rpId`), its
// attestation made by `fmt(ctx)` over the authenticator data and client
// data — the kit's builders read `authData`, `clientDataHash`, `aaguid`
// and `credential`.
async function builtCredential(c, o) {
  log.debug("Entering builtCredential().");
  const opts = o || {};
  const cred = opts.credential || await attKit.credential(opts.alg || -7);
  const id = opts.credentialId || cred.id;
  const aaguid = opts.aaguid || nodeCrypto.randomBytes(16);
  const count = Buffer.alloc(4);
  const idLen = Buffer.alloc(2);
  idLen.writeUInt16BE(id.length, 0);
  const authData = Buffer.concat([
    sha256(Buffer.from(c.rpId || RP_ID, "utf8")),
    Buffer.from([opts.flags === undefined ? 0x45 : opts.flags]), count,
    aaguid, idLen, id, attKit.cbor(cred.cose)]);
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.create", challenge: c.challenge, origin: ORIGIN,
    crossOrigin: false }));
  const ctx = { credential: cred, rpId: c.rpId || RP_ID, origin: ORIGIN,
                challenge: c.challenge, aaguid: aaguid, authData: authData,
                clientDataJSON: clientDataJSON,
                clientDataHash: sha256(clientDataJSON) };
  const made = opts.fmt ? await opts.fmt(ctx) : attKit.none();
  const idText = id.toString("base64url");
  log.debug("Leaving builtCredential().");
  return { cred: cred, id: idText, credential: {
    id: idText, rawId: idText, type: "public-key",
    authenticatorAttachment: "cross-platform",
    clientExtensionResults: { credProps: { rk: true } },
    response: {
      attestationObject: attKit.cbor(new Map([["fmt", made.fmt],
        ["attStmt", made.attStmt], ["authData", authData]]))
        .toString("base64url"),
      clientDataJSON: clientDataJSON.toString("base64url"),
      transports: ["usb"] } } };
}

// An assertion by `cred` (a kit credential) over `challenge`.
function assertionBy(cred, id, challenge, rpId) {
  log.debug("Entering assertionBy().");
  const count = Buffer.alloc(4);
  count.writeUInt32BE(1, 0);
  const authData = Buffer.concat([sha256(Buffer.from(rpId || RP_ID,
                                                     "utf8")),
                                  Buffer.from([0x05]), count]);
  const cdj = Buffer.from(JSON.stringify({ type: "webauthn.get",
    challenge: challenge, origin: ORIGIN, crossOrigin: false }));
  const signature = cred.sign(Buffer.concat([authData, sha256(cdj)]));
  log.debug("Leaving assertionBy().");
  return { id: id, rawId: id, type: "public-key",
           authenticatorAttachment: "cross-platform",
           response: { authenticatorData: authData.toString("base64url"),
                       clientDataJSON: cdj.toString("base64url"),
                       signature: Buffer.from(signature)
                         .toString("base64url"),
                       userHandle: null } };
}

async function attestationMatrix() {
  log.debug("Entering attestationMatrix().");
  const k = wire.kit("sts_webauthn_attestation", { log: log });
  const realm = await k.realm("wa105m", "development");
  const who = ("wa105m-" + k.STAMP).slice(0, 30);
  await k.person(realm, who, PASSWORD);
  await k.client(realm);
  await k.mustSet(realm, "webauthn.maxKeysPerPerson", 50);
  const portal = await portalSignin.signInToThePortal(realm.base, who, null,
    { password: PASSWORD });

  // The newest audit row's `seq` in the realm, and the codes of the rows
  // after it: two reads per registration rather than two per code.
  const newestSeq = async function () {
    log.debug("Entering newestSeq().");
    const r = await k.call(realm, "GET", "/audit?per=1");
    log.debug("Leaving newestSeq().");
    return Number((((r.body && r.body.events) || [])[0] || {}).seq || 0);
  };
  const codesAfter = async function (seq, watched) {
    log.debug("Entering codesAfter().");
    let found = "";
    for (let i = 0; i < 20 && !found; i += 1) {
      const r = await k.call(realm, "GET", "/audit?per=100");
      ((r.body && r.body.events) || []).forEach(function (row) {
        if (!found && Number(row.seq) > seq &&
            watched.indexOf(row.errorCode) >= 0) {
          found = row.errorCode;
        }
      });
      if (!found) {
        await k.sleep(150);
      }
      if (i >= 9 && !found) {
        // Ten reads, a second and a half: the row is written as the
        // answer leaves.
        break;
      }
    }
    log.debug("Leaving codesAfter(). " + found);
    return found;
  };

  // One registration: begun, armed, finished with `o`'s credential. The
  // finish's answer and the code it recorded (`code` the one of `codes`
  // on a row written after the finish began).
  const enrolOne = async function (o, codes) {
    log.debug("Entering enrolOne().");
    const watched = codes || [];
    await portal.api("POST", "/account-api/keys", { action: "cancel" });
    const begun = await portal.api("POST", "/account-api/keys",
      { action: "begin", kind: "security-key" });
    assert.ok(begun.status === 200, "begin answered " + begun.status + " " +
              JSON.stringify(begun.json).slice(0, 300));
    const page = await portal.api("GET", "/account-api/keys");
    const pending = (page.json && page.json.enrol &&
                     page.json.enrol.pending) || {};
    const built = await builtCredential(pending, o);
    const seq = await newestSeq();
    const done = await portal.api("POST", "/account-api/keys",
      { action: "finish", enrolment_id: pending.id,
        credential: JSON.stringify(built.credential) });
    const refusedHere = !(done.status === 200 && done.json &&
                          done.json.ok !== false);
    const code = refusedHere && watched.length
      ? await codesAfter(seq, watched) : "";
    log.debug("Leaving enrolOne(). " + done.status + " " + code);
    return { done: done, code: code, built: built, pending: pending };
  };
  const ALL = ["STS-AUTHN-0228", "STS-AUTHN-0229", "STS-AUTHN-0230",
               "STS-AUTHN-0231", "STS-AUTHN-0232", "STS-AUTHN-0233",
               "STS-AUTHN-0234"];
  const accepted = function (r) {
    return r.done.status === 200 && r.done.json && r.done.json.ok !== false;
  };
  const keyRow = async function (id) {
    log.debug("Entering keyRow().");
    const keys = await k.keysOf(realm, who);
    log.debug("Leaving keyRow().");
    return keys.filter(function (one) {
      return one.credentialId === id;
    })[0] || null;
  };

  log.info("=== 4A. section 7.1: alg offered, 1024 bytes, BE and BS ===");
  await k.mustSet(realm, "webauthn.algorithms", "RS256");
  const notOffered = await enrolOne({ alg: -7 }, ALL);
  check("4A1. an ES256 credential when only RS256 was offered is refused " +
        "(STS-AUTHN-0228)", function () {
    assert.ok(!accepted(notOffered), JSON.stringify(notOffered.done.json));
    assert.strictEqual(notOffered.code, "STS-AUTHN-0228");
  });
  await k.mustSet(realm, "webauthn.algorithms", "ES256,RS256");
  const offered = await enrolOne({ alg: -7 }, ALL);
  check("4A2. and taken once ES256 is offered", function () {
    assert.ok(accepted(offered), JSON.stringify(offered.done.json));
  });
  const long = await enrolOne({ alg: -7,
    credentialId: nodeCrypto.randomBytes(1024) }, ALL);
  check("4A3. a credential id of 1024 bytes is refused (STS-AUTHN-0229)",
    function () {
      assert.ok(!accepted(long), JSON.stringify(long.done.json));
      assert.strictEqual(long.code, "STS-AUTHN-0229");
    });
  const bsOnly = await enrolOne({ alg: -7, flags: 0x45 | 0x10 }, ALL);
  check("4A4. BS set without BE is refused (STS-AUTHN-0230)", function () {
    assert.ok(!accepted(bsOnly), JSON.stringify(bsOnly.done.json));
    assert.strictEqual(bsOnly.code, "STS-AUTHN-0230");
  });
  const both = await enrolOne({ alg: -7, flags: 0x45 | 0x18 }, ALL);
  check("4A5. and BS with BE is taken", function () {
    assert.ok(accepted(both), JSON.stringify(both.done.json));
  });
  await k.reset(realm, "webauthn.algorithms");

  log.info("=== 4B. every algorithm registers and signs in ===");
  const ALGS = { "-7": "ES256", "-35": "ES384", "-36": "ES512",
                 "-8": "EdDSA", "-257": "RS256", "-37": "PS256",
                 "-48": "ML-DSA-44", "-49": "ML-DSA-65",
                 "-50": "ML-DSA-87" };
  await k.mustSet(realm, "webauthn.algorithms",
                  Object.keys(ALGS).map(function (a) {
                    return ALGS[a];
                  }).join(","));
  const made = [];
  for (const alg of Object.keys(ALGS)) {
    const r = await enrolOne({ alg: Number(alg) }, ALL);
    made.push({ alg: alg, r: r });
  }
  check("4B1. a credential of each of " + Object.keys(ALGS).length +
        " algorithms is registered", function () {
    made.forEach(function (one) {
      assert.ok(accepted(one.r), ALGS[one.alg] + ": " +
                JSON.stringify(one.r.done.json).slice(0, 300) + " " +
                one.r.code);
    });
  });
  const signedIn = [];
  for (const one of made) {
    const t = await k.typed(realm, who, { password: PASSWORD });
    let answer = t.answer;
    if (t.step) {
      answer = await k.ceremony(t.step, function (c) {
        return assertionBy(one.r.built.cred, one.r.built.id, c.challenge,
                           c.rpId);
      }, (t.step.view && t.step.view.webauthn &&
          (t.step.view.webauthn.choices || []).length)
        ? one.r.built.id : undefined);
    }
    signedIn.push({ alg: ALGS[one.alg], next: answer.next,
                    said: k.said(answer).slice(0, 200) });
  }
  check("4B2. and each one's assertion answers the passkey step of its " +
        "person's sign-in", function () {
    signedIn.forEach(function (one) {
      assert.strictEqual(one.next, "redirect", JSON.stringify(one));
    });
  });
  await k.mustSet(realm, "webauthn.algorithms", "ES256,RS1");
  const rs1Off = await enrolOne({ alg: -65535 }, ALL);
  await k.mustSet(realm, "webauthn.insecureAlgorithms", true);
  const rs1On = await enrolOne({ alg: -65535 }, ALL);
  check("4B3. RS1 is not offered, so not taken, while " +
        "webauthn.insecureAlgorithms is off — and is taken behind it in " +
        "development", function () {
    assert.ok(!accepted(rs1Off), JSON.stringify(rs1Off.done.json));
    assert.strictEqual(rs1Off.code, "STS-AUTHN-0228");
    assert.ok(accepted(rs1On), JSON.stringify(rs1On.done.json) + " " +
              rs1On.code);
  });
  await k.reset(realm, "webauthn.insecureAlgorithms");
  const before0294 = await k.codeCount(realm, "STS-AUTHN-0294");
  const t1 = await k.typed(realm, who, { password: PASSWORD });
  let rs1Answer = t1.answer;
  if (t1.step) {
    rs1Answer = await k.ceremony(t1.step, function (c) {
      return assertionBy(rs1On.built.cred, rs1On.built.id, c.challenge,
                         c.rpId);
    }, (t1.step.view && t1.step.view.webauthn &&
        (t1.step.view.webauthn.choices || []).length)
      ? rs1On.built.id : undefined);
  }
  const n0294 = await k.newCodes(realm, "STS-AUTHN-0294", before0294);
  check("4B4. with the flag off again, the RS1 key's assertion is refused " +
        "(STS-AUTHN-0294)", function () {
    assert.notStrictEqual(rs1Answer.next, "redirect",
                          k.said(rs1Answer).slice(0, 300));
    assert.ok(n0294 >= 1, "STS-AUTHN-0294 rows: " + n0294);
  });
  await k.reset(realm, "webauthn.algorithms");

  log.info("=== 4C. each format, valid and wrong in one way ===");
  const vendorRoot = await attKit.root("Synthetic Vendor " + k.STAMP);
  const tpmCa = await attKit.root("Synthetic TPM " + k.STAMP, "rsa");
  const google = await attKit.root("Synthetic Google " + k.STAMP);
  const apple = await attKit.root("Synthetic Apple " + k.STAMP);
  await k.mustSet(realm, "webauthn.attestationPolicy", "verify-if-present");
  await k.mustSet(realm, "webauthn.attestationTrustAnchors",
    [vendorRoot, tpmCa, google, apple].map(function (r) {
      return r.pem;
    }).join(""));
  const CASES = [
    ["packed, Basic, trusted", function (c) {
      return attKit.packed(c, vendorRoot);
    }, "", { type: "basic", trusted: true }],
    ["packed, the signature over something else", function (c) {
      return attKit.packed(c, vendorRoot, "signature");
    }, "STS-AUTHN-0233"],
    ["packed, the subject OU is not Authenticator Attestation", function (c) {
      return attKit.packed(c, vendorRoot, "ou");
    }, "STS-AUTHN-0234"],
    ["packed, the AAGUID extension names another model", function (c) {
      return attKit.packed(c, vendorRoot, "aaguid-extension");
    }, "STS-AUTHN-0234"],
    ["packed, the attestation certificate is a CA", function (c) {
      return attKit.packed(c, vendorRoot, "ca");
    }, "STS-AUTHN-0234"],
    ["packed self attestation, untrusted", function (c) {
      return attKit.packedSelf(c);
    }, "", { type: "self", trusted: false }],
    ["packed self, alg not the credential's", function (c) {
      return attKit.packedSelf(c, "alg");
    }, "STS-AUTHN-0234"],
    ["packed self, the signature over something else", function (c) {
      return attKit.packedSelf(c, "signature");
    }, "STS-AUTHN-0233"],
    ["packed with a member the format does not define", async function (c) {
      const m = await attKit.packed(c, vendorRoot);
      m.attStmt.extra = Buffer.from([1]);
      return m;
    }, "STS-AUTHN-0232"],
    ["tpm, AttCA, trusted", function (c) {
      return attKit.tpm(c, tpmCa);
    }, "", { type: "attca", trusted: true }],
    ["tpm with the bare signature Windows sends", function (c) {
      return attKit.tpm(c, tpmCa, "bare-signature");
    }, "", { type: "attca", trusted: true }]
  ];
  ["extra-data", "name", "magic", "eku", "subject", "key"].forEach(
    function (spoil) {
      CASES.push(["tpm, " + spoil + " wrong", function (c) {
        return attKit.tpm(c, tpmCa, spoil);
      }, "STS-AUTHN-0234"]);
    });
  CASES.push(["tpm, the signature over something else", function (c) {
    return attKit.tpm(c, tpmCa, "signature");
  }, "STS-AUTHN-0233"]);
  CASES.push(["android-key, Basic, trusted", function (c) {
    return attKit.androidKey(c, google);
  }, "", { type: "basic", trusted: true }]);
  CASES.push(["android-key, a certificate for another key", function (c) {
    return attKit.androidKey(c, google, "key");
  }, "STS-AUTHN-0233"]);
  ["challenge", "all-applications", "purpose", "software-origin"].forEach(
    function (spoil) {
      CASES.push(["android-key, " + spoil, function (c) {
        return attKit.androidKey(c, google, spoil);
      }, "STS-AUTHN-0234"]);
    });
  CASES.push(["android-safetynet, verified and untrusted while " +
              "attestationAllowSafetynet is off", function (c) {
    return attKit.safetynet(c, google);
  }, "", { type: "basic", trusted: false }]);
  ["nonce", "cts", "stale", "host"].forEach(function (spoil) {
    CASES.push(["android-safetynet, " + spoil, function (c) {
      return attKit.safetynet(c, google, spoil);
    }, "STS-AUTHN-0234"]);
  });
  CASES.push(["android-safetynet, a changed signature", function (c) {
    return attKit.safetynet(c, google, "signature");
  }, "STS-AUTHN-0233"]);
  CASES.push(["fido-u2f, Basic, trusted", function (c) {
    return attKit.fidoU2f(c, vendorRoot);
  }, "", { type: "basic", trusted: true }, { aaguid: Buffer.alloc(16) }]);
  CASES.push(["fido-u2f, the signature over another message", function (c) {
    return attKit.fidoU2f(c, vendorRoot, "signature");
  }, "STS-AUTHN-0233", null, { aaguid: Buffer.alloc(16) }]);
  CASES.push(["fido-u2f with two certificates", function (c) {
    return attKit.fidoU2f(c, vendorRoot, "two-certificates");
  }, "STS-AUTHN-0232", null, { aaguid: Buffer.alloc(16) }]);
  CASES.push(["none, untrusted", function () {
    return attKit.none();
  }, "", { type: "none", trusted: false }]);
  CASES.push(["none carrying anything", function () {
    return { fmt: "none", attStmt: { sig: Buffer.from([1]) } };
  }, "STS-AUTHN-0232"]);
  CASES.push(["apple, AnonCA, trusted", function (c) {
    return attKit.apple(c, apple);
  }, "", { type: "anonca", trusted: true }]);
  CASES.push(["apple, the nonce of another ceremony", function (c) {
    return attKit.apple(c, apple, "nonce");
  }, "STS-AUTHN-0234"]);
  CASES.push(["apple, a certificate for another key", function (c) {
    return attKit.apple(c, apple, "key");
  }, "STS-AUTHN-0234"]);
  CASES.push(["compound of packed and tpm, trusted", async function (c) {
    const a = await attKit.packed(c, vendorRoot);
    const b = await attKit.tpm(c, tpmCa);
    return { fmt: "compound", attStmt: [
      { fmt: a.fmt, attStmt: a.attStmt }, { fmt: b.fmt, attStmt: b.attStmt }
    ] };
  }, "", { type: "compound", trusted: true }]);
  CASES.push(["compound with one member that does not verify",
    async function (c) {
      const a = await attKit.packed(c, vendorRoot);
      const b = await attKit.tpm(c, tpmCa, "signature");
      return { fmt: "compound", attStmt: [
        { fmt: a.fmt, attStmt: a.attStmt },
        { fmt: b.fmt, attStmt: b.attStmt }] };
    }, "STS-AUTHN-0233"]);
  CASES.push(["compound of one statement", async function (c) {
    const a = await attKit.packed(c, vendorRoot);
    return { fmt: "compound", attStmt: [{ fmt: a.fmt, attStmt: a.attStmt }] };
  }, "STS-AUTHN-0232"]);
  CASES.push(["compound inside compound", async function (c) {
    const a = await attKit.packed(c, vendorRoot);
    return { fmt: "compound", attStmt: [{ fmt: a.fmt, attStmt: a.attStmt },
      { fmt: "compound", attStmt: [] }] };
  }, "STS-AUTHN-0232"]);
  CASES.push(["a format section 8 does not define", function () {
    return { fmt: "packed2", attStmt: {} };
  }, "STS-AUTHN-0231"]);
  const results = [];
  for (const one of CASES) {
    const r = await enrolOne(Object.assign({ fmt: one[1] }, one[4] || {}),
                             ALL);
    const row = accepted(r) ? await keyRow(r.built.id) : null;
    results.push({ label: one[0], want: one[2], expect: one[3], r: r,
                   row: row });
  }
  check("4C1. every statement that is wrong in one way is refused, each " +
        "under its own code (0231, 0232, 0233, 0234 off the audit log)",
    function () {
      results.filter(function (one) {
        return one.want;
      }).forEach(function (one) {
        assert.ok(!accepted(one.r), one.label + " was taken");
        assert.strictEqual(one.r.code, one.want, one.label + ": " +
          JSON.stringify(one.r.done.json).slice(0, 300));
      });
    });
  check("4C2. every valid one is taken, and its key's row says what it " +
        "proved: verified, the type, trusted or not", function () {
    results.filter(function (one) {
      return !one.want;
    }).forEach(function (one) {
      assert.ok(accepted(one.r), one.label + ": " +
        JSON.stringify(one.r.done.json).slice(0, 300) + " " + one.r.code);
      const a = (one.row && one.row.attestation) || {};
      assert.ok(a.verified === true && a.type === one.expect.type &&
                a.trusted === one.expect.trusted,
                one.label + ": " + JSON.stringify(one.row).slice(0, 400));
    });
  });
  check("4C3. no answer names a code", function () {
    results.forEach(function (one) {
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(JSON.stringify(one.r.done.json)),
                one.label);
    });
  });
  await k.mustSet(realm, "webauthn.attestationAllowSafetynet", true);
  const safetyOn = await enrolOne({ fmt: function (c) {
    return attKit.safetynet(c, google);
  } }, ALL);
  const safetyRow = accepted(safetyOn) ? await keyRow(safetyOn.built.id)
                                       : null;
  check("4C4. android-safetynet is trusted where " +
        "webauthn.attestationAllowSafetynet is on", function () {
    assert.ok(safetyRow && safetyRow.attestation &&
              safetyRow.attestation.trusted === true,
              JSON.stringify(safetyRow || safetyOn.done.json).slice(0, 400));
  });
  await k.reset(realm, "webauthn.attestationAllowSafetynet");
  await k.mustSet(realm, "webauthn.attestationAndroidSoftwareKeys", true);
  const software = await enrolOne({ fmt: function (c) {
    return attKit.androidKey(c, google, "software-origin");
  } }, ALL);
  check("4C5. an android-key origin only the software list states is taken " +
        "where webauthn.attestationAndroidSoftwareKeys says", function () {
    assert.ok(accepted(software), JSON.stringify(software.done.json) + " " +
              software.code);
  });
  await k.reset(realm, "webauthn.attestationAndroidSoftwareKeys");

  log.info("=== 4D. the policy, by mode ===");
  await k.reset(realm, "webauthn.attestationPolicy");
  const devBad = await enrolOne({ fmt: function (c) {
    return attKit.packed(c, vendorRoot, "signature");
  } }, ALL);
  const devRow = accepted(devBad) ? await keyRow(devBad.built.id) : null;
  check("4D1. development's by-mode policy is off: a statement that does " +
        "not verify is taken, and recorded as unverified", function () {
    assert.ok(accepted(devBad), JSON.stringify(devBad.done.json));
    assert.ok(devRow && devRow.attestation &&
              devRow.attestation.verified !== true,
              JSON.stringify(devRow).slice(0, 400));
  });
  await k.mustSet(realm, "webauthn.attestationPolicy", "require-trusted");
  await portal.api("POST", "/account-api/keys", { action: "cancel" });
  await portal.api("POST", "/account-api/keys",
                   { action: "begin", kind: "security-key" });
  const asking = await portal.api("GET", "/account-api/keys");
  const pend = (asking.json && asking.json.enrol &&
                asking.json.enrol.pending) || {};
  await portal.api("POST", "/account-api/keys", { action: "cancel" });
  check("4D2. a realm that requires a trusted statement ASKS for one: the " +
        "ceremony's conveyance is direct", function () {
    const opts = pend.options || pend.publicKey || {};
    assert.strictEqual(opts.attestation, "direct",
                       JSON.stringify(pend).slice(0, 600));
  });
  await k.reset(realm, "webauthn.attestationPolicy");
  const set = await k.send("POST", k.root + "/admin-api/realms/set",
    { id: realm.id, key: "global.mode", value: "product" });
  assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
  const prodBad = await enrolOne({ fmt: function (c) {
    return attKit.packed(c, vendorRoot, "signature");
  } }, ALL);
  check("4D3. product's by-mode policy verifies: the same statement is " +
        "refused (STS-AUTHN-0233)", function () {
    assert.ok(!accepted(prodBad), JSON.stringify(prodBad.done.json));
    assert.strictEqual(prodBad.code, "STS-AUTHN-0233");
  });
  const before0103 = await k.codeCount(realm, "STS-CORE-0103");
  const offWrite = await k.setting(realm, "webauthn.attestationPolicy",
                                   "off");
  const n0103 = await k.newCodes(realm, "STS-CORE-0103", before0103);
  check("4D4. writing off in product is refused (STS-CORE-0103)",
    function () {
      assert.ok(offWrite.status === 400 ||
                (offWrite.body && offWrite.body.ok === false),
                offWrite.status + " " + offWrite.raw.slice(0, 300));
      assert.ok(n0103 >= 1, "STS-CORE-0103 rows: " + n0103);
    });
  log.debug("Leaving attestationMatrix().");
  return k;
}

const program = new Command();
program
  .name("sts_webauthn_attestation")
  .description("Enrol security keys at /portal/keys with attestation " +
      "statements this job makes — an x5c packed statement under a root " +
      "minted at run time, a self attestation, a forged one, none — under " +
      "require-trusted, an AAGUID allow-list and verify-if-present, and read " +
      "what each proved back from /portal/keys, /admin-api/users, the " +
      "console's /admin/users and /admin/webauthn.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
