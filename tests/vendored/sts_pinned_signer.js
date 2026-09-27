"use strict";
//
// File: sts_pinned_signer.js
//
// ---------------------------------------------------------------------------
// A PINNED KEY PAIR SIGNS THE REALM'S ID TOKENS, OVER HTTP (#263,
// 2026-09-27), in a throwaway realm with `pki.pinnedSigners` on and a
// publication lead of 0.
//
//   1. A pin whose key does not match the slot is refused (400).
//   2. An RSA key generated here is pinned into the `jose` RS256 slot through
//      `POST /admin-api/pki/pin-key`; `GET /admin-api/pki` lists it.
//   3. An ID token from the authorization code flow carries the pinned key's
//      kid, and VERIFIES AGAINST THE JWKS ENTRY OF THAT KEY, whose x5c holds
//      the key; the generated key stays published beside it.
//   3b. An RSA key pinned into the xml slot is the metadata's use="encryption"
//      KeyDescriptor too (one key for both uses); it is then unpinned.
//   3a. While it is pinned, turning `pki.pinnedSigners` off is refused (400,
//      "Unpin first") through `config/set`, `realms/set` and `realms/unset`,
//      and the pinned key goes on signing.
//   4. `POST /admin-api/pki/unpin-key` restores the generated key: the next
//      ID token carries its kid, and the pinned key stays in the JWKS through
//      its grace; the setting can then be turned off.
//
// The key material is generated at test time and never written anywhere.
//
// OWNED HERE (local: true): this repository's PKI, authorization server and
// API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_pinned_signer",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const REALM = "pin-" + TAG;
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const PERSON = names.usernameFor("pin-person");
const PASSWORD = "Pn-" + crypto.randomBytes(9).toString("base64url") + "-Aa1!";
const RP_REDIRECT = "https://rp.pinned.example/cb";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

// A cookie jar that keeps each cookie's Path, as a browser does: the two
// realms are on one host, and their session cookies share names, so a jar
// keyed by name alone lets the provider realm's sign-in overwrite the OP
// realm's session.
function jar() {
  log.debug("Entering jar().");
  const cookies = {};
  log.debug("Leaving jar().");
  return {
    header: function header(url) {
      log.debug("Entering header().");
      const at = new URL(url).pathname;
      const out = Object.keys(cookies).map(function (k) {
        return cookies[k];
      }).filter(function (c) {
        return at === c.path || at.indexOf(c.path.replace(/\/?$/, "/")) ===
          0 || c.path === "/";
      }).sort(function (a, b) {
        return b.path.length - a.path.length;
      }).map(function (c) {
        return c.name + "=" + c.value;
      }).join("; ");
      log.debug("Leaving header().");
      return out;
    },
    take: function take(response, url) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        const p = (/;\s*path=([^;]*)/i.exec(line) || [])[1];
        const cpath = p ? p.trim() :
          new URL(url).pathname.replace(/\/[^/]*$/, "") || "/";
        const key = name + " " + cpath;
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[key];
        } else {
          cookies[key] = { name: name, value: value, path: cpath };
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header(url)) {
    headers.cookie = who.header(url);
  }
  const r = await fetch(url, { method: method, headers: headers,
                               body: body, redirect: "manual" });
  if (who) {
    who.take(r, url);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  if (process.env.CA_TRACE) {
    log.info("HOP " + method + " " + url + " -> " + r.status + " " +
             (location || ""));
  }
  return { status: r.status, text: text, json: json,
           location: location ? new URL(location, url).toString() : "" };
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

function csrfOf(html) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (/name="csrf_token" value="([^"]+)"/.exec(html) || [])[1] || "";
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

// Follows redirects inside this service, signing the person in on the
// realm's screen and allowing a consent screen, until the answer leaves the
// service or is a page.
async function follow(who, first) {
  log.debug("Entering follow().");
  let r = first;
  for (let i = 0; i < 20; i++) {
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = PERSON;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await hop(who, "POST", base + "/authn/login", { form: fields });
      continue;
    }
    if (r.status === 200 && /id="consent-allow"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.action = "allow";
      r = await hop(who, "POST", base + "/oauth2/consent", { form: fields });
      continue;
    }
    if (!(r.status === 302 || r.status === 303) ||
        r.location.indexOf(root + "/") !== 0) {
      break;
    }
    r = await hop(who, "GET", r.location);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function authorizeUrl(client, extra) {
  log.debug("Entering authorizeUrl().");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const q = new URLSearchParams(Object.assign({
    response_type: "code", client_id: client.client_id,
    redirect_uri: RP_REDIRECT, scope: "openid", state: "s-" + TAG + "-" +
      crypto.randomBytes(6).toString("hex"),
    // A fresh state and nonce per request: in RFC 9700 mode (which
    // product mode implies) a value reused after its code was redeemed is
    // refused, STS-OAUTH-0125.
    nonce: "n-" + TAG + "-" + crypto.randomBytes(6).toString("hex"),
    code_challenge: crypto.createHash("sha256")
      .update(verifier).digest("base64url"),
    code_challenge_method: "S256" }, extra || {}));
  log.debug("Leaving authorizeUrl().");
  return { url: base + "/oauth2/authorize?" + q.toString(),
           verifier: verifier };
}

async function idTokenFor(browser, client) {
  log.debug("Entering idTokenFor().");
  const asked = authorizeUrl(client);
  const landed = await follow(browser, await hop(browser, "GET", asked.url));
  assert.ok(/^https:\/\/rp\.pinned\.example\/cb\?/.test(landed.location),
            "the authorization response: " + landed.status + " " +
            (landed.location || landed.text.slice(0, 300)));
  const code = new URL(landed.location).searchParams.get("code");
  const tokens = await hop(null, "POST", base + "/oauth2/token", { form: {
    grant_type: "authorization_code", code: code, redirect_uri: RP_REDIRECT,
    code_verifier: asked.verifier, client_id: client.client_id,
    client_secret: client.client_secret } });
  assert.strictEqual(tokens.status, 200, tokens.text.slice(0, 300));
  log.debug("Leaving idTokenFor().");
  return tokens.json.id_token;
}

function headerOf(jwt) {
  log.debug("Entering headerOf().");
  log.debug("Leaving headerOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[0], "base64url")
    .toString("utf8"));
}

// Does the JWKS entry verify the token's RS256 signature?
function verifiesWith(jwt, entry) {
  log.debug("Entering verifiesWith().");
  const parts = String(jwt).split(".");
  const key = crypto.createPublicKey({ key: { kty: entry.kty, n: entry.n,
                                              e: entry.e }, format: "jwk" });
  const good = crypto.verify("sha256", Buffer.from(parts[0] + "." + parts[1]),
                             key, Buffer.from(parts[2], "base64url"));
  log.debug("Leaving verifiesWith(). " + good);
  return good;
}

async function jwks() {
  log.debug("Entering jwks().");
  const r = await hop(null, "GET", base + "/oauth2/jwks");
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving jwks().");
  return r.json.keys || [];
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " that signs with pins ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Pinned signer " + TAG,
    overrides: { "pki.pinnedSigners": true,
                 "pki.pinnedSignerLeadMinutes": 0 } },
    "created the realm with pki.pinnedSigners on");
  await ok(api + "/pki/build", { organisation: "Pinned " + TAG },
           "built the realm's certificate authority branch");
  await ok(api + "/config/set", { key: "oauth2.openRegistration",
                                  value: true }, "opened registration");
  await registry.ensurePerson(base, PERSON, PASSWORD);
  const reg = await hop(null, "POST", base + "/oauth2/register", { json: {
    redirect_uris: [RP_REDIRECT], token_endpoint_auth_method:
      "client_secret_post", grant_types: ["authorization_code"],
    response_types: ["code"], client_name: "RP " + TAG } });
  assert.strictEqual(reg.status, 201, reg.text.slice(0, 300));
  const client = reg.json;
  const browser = jar();
  const before = await idTokenFor(browser, client);
  const generatedKid = headerOf(before).kid;

  log.info("=== 1. a key of the wrong type is refused ===");
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const wrong = await hop(null, "POST", api + "/pki/pin-key", { json: {
    useCase: "jose", slot: "RS256",
    privateKeyPem: ec.privateKey.export({ type: "pkcs8", format: "pem" }) } });
  check("an EC key in the RS256 slot is refused", function () {
    assert.strictEqual(wrong.status, 400, wrong.text.slice(0, 300));
    assert.ok(wrong.json && wrong.json.ok === false, wrong.text.slice(0, 300));
  });

  log.info("=== 2. an RSA key pinned into jose RS256 ===");
  const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pinned = await ok(api + "/pki/pin-key", { useCase: "jose",
    slot: "RS256",
    privateKeyPem: rsa.privateKey.export({ type: "pkcs8", format: "pem" }) },
    "pinned the key");
  const pinnedKid = pinned.kid;
  const view = await hop(null, "GET", api + "/pki");
  check("the pin answers the key's kid, and GET /admin-api/pki lists it as " +
        "signing", function () {
    assert.ok(/^sts-pinned-/.test(String(pinnedKid)), JSON.stringify(pinned));
    const listed = ((view.json && view.json.pinnedSigners &&
                     view.json.pinnedSigners.keys) || [])
      .filter(function (one) {
        return one.kid === pinnedKid;
      })[0];
    assert.ok(listed && listed.role === "active" &&
              view.json.pinnedSigners.on === true,
              JSON.stringify(view.json && view.json.pinnedSigners));
    assert.ok(view.text.indexOf("PRIVATE KEY") < 0,
              "no private key in the API's view");
  });

  log.info("=== 3. the ID token is signed by it ===");
  const idToken = await idTokenFor(browser, client);
  const published = await jwks();
  const entry = published.filter(function (k) {
    return k.kid === pinnedKid;
  })[0];
  check("the ID token carries the pinned kid and verifies against that " +
        "JWKS entry, whose x5c holds the key", function () {
    assert.strictEqual(headerOf(idToken).kid, pinnedKid);
    assert.ok(entry, "no JWKS entry for " + pinnedKid);
    assert.ok(verifiesWith(idToken, entry), "the signature does not verify");
    const leaf = new crypto.X509Certificate(Buffer.from(entry.x5c[0],
                                                        "base64"));
    assert.ok(leaf.publicKey.export({ type: "spki", format: "der" })
      .equals(rsa.publicKey.export({ type: "spki", format: "der" })),
              "the x5c leaf is over another key");
  });
  check("the generated key stays published beside it", function () {
    assert.ok(published.some(function (k) {
      return k.kid === generatedKid;
    }), generatedKid);
  });

  log.info("=== 3b. an xml pin is the encryption key too ===");
  const xmlRsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  await ok(api + "/pki/pin-key", { useCase: "xml", slot: "RS256",
    privateKeyPem: xmlRsa.privateKey.export({ type: "pkcs8",
                                               format: "pem" }) },
    "pinned an xml key");
  const md = await hop(null, "GET", base + "/saml2/metadata");
  const encCert = (/<md:KeyDescriptor use="encryption">[\s\S]*?<ds:X509Certificate>([^<]+)</
    .exec(md.text) || [])[1];
  check("the SAML metadata's use=\"encryption\" KeyDescriptor carries the " +
        "pinned xml key's certificate", function () {
    assert.ok(encCert, md.text.slice(0, 400));
    const cert = new crypto.X509Certificate(Buffer.from(encCert, "base64"));
    assert.ok(cert.publicKey.export({ type: "spki", format: "der" })
      .equals(xmlRsa.publicKey.export({ type: "spki", format: "der" })),
              "the encryption certificate is over another key");
  });
  await ok(api + "/pki/unpin-key", { useCase: "xml", slot: "RS256" },
           "unpinned the xml key");

  log.info("=== 3a. the setting cannot be turned off under the pin ===");
  const offInRealm = await hop(null, "POST", api + "/config/set",
    { json: { key: "pki.pinnedSigners", value: false } });
  const offOnRealm = await hop(null, "POST", root + "/admin-api/realms/set",
    { json: { id: REALM, key: "pki.pinnedSigners", value: false } });
  const offCleared = await hop(null, "POST", root + "/admin-api/realms/unset",
    { json: { id: REALM, key: "pki.pinnedSigners" } });
  check("turning pki.pinnedSigners off is refused while the pin is live, " +
        "through config/set, realms/set and realms/unset, saying to unpin " +
        "first", function () {
    [offInRealm, offOnRealm, offCleared].forEach(function (r) {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.ok(/[Uu]npin first/.test(r.text), r.text.slice(0, 300));
    });
  });
  const stillPinned = await idTokenFor(browser, client);
  check("and the pinned key still signs", function () {
    assert.strictEqual(headerOf(stillPinned).kid, pinnedKid);
  });

  log.info("=== 4. unpinned: the generated key signs again ===");
  await ok(api + "/pki/unpin-key", { useCase: "jose", slot: "RS256" },
           "unpinned the key");
  const after = await idTokenFor(browser, client);
  const stillPublished = await jwks();
  check("the next ID token is the generated key's again, and the pinned " +
        "key stays in the JWKS through its grace", function () {
    assert.strictEqual(headerOf(after).kid, generatedKid);
    const again = stillPublished.filter(function (k) {
      return k.kid === generatedKid;
    })[0];
    assert.ok(again && verifiesWith(after, again), "does not verify");
    assert.ok(stillPublished.some(function (k) {
      return k.kid === pinnedKid;
    }), "the pinned key left the JWKS at once");
  });
  const nothing = await hop(null, "POST", api + "/pki/unpin-key",
    { json: { useCase: "jose", slot: "RS256" } });
  check("an unpin with nothing pinned is refused", function () {
    assert.strictEqual(nothing.status, 400, nothing.text.slice(0, 300));
  });
  const offAfter = await hop(null, "POST", api + "/config/set",
    { json: { key: "pki.pinnedSigners", value: false } });
  check("with nothing pinned, the setting can be turned off", function () {
    assert.strictEqual(offAfter.status, 200, offAfter.text.slice(0, 300));
  });

  assert.ok(checks >= 10, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("A pinned key pair signs a realm's ID tokens (#263), over " +
    "HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
