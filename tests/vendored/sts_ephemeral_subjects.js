"use strict";
//
// File: sts_ephemeral_subjects.js
//
// ---------------------------------------------------------------------------
// THE EPHEMERAL SUBJECT IDENTIFIER (#149, 2026-09-26), over HTTP, in a
// throwaway realm.
//
//   1. DISCOVERY and REGISTRATION: `ephemeral` in subject_types_supported;
//      a client registers for it, and an unknown subject_type is refused.
//   2. ONE AUTHENTICATION: the ID Token, UserInfo and a refreshed ID Token
//      name the same random `sub`, not the person's public one.
//   3. ANOTHER AUTHENTICATION (a new browser) gets another `sub`; a public
//      client is still told the public one.
//   4. id_token_hint: the ephemeral `sub` maps back to the person — a
//      prompt=none request carrying it answers with a code.
//
// OWNED HERE (local: true): this repository's authorization server and API.
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
var log = bunyan.createLogger({ name: "sts_ephemeral_subjects",
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
const REALM = "es-" + TAG;
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const PERSON = names.usernameFor("es-person");
const PASSWORD = "Es-" + crypto.randomBytes(9).toString("base64url") + "-Aa1!";
const RP_REDIRECT = "https://rp.ephemeral.example/cb";

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
    redirect_uri: RP_REDIRECT, scope: "openid", state: "s-" + TAG,
    nonce: "n-" + TAG, code_challenge: crypto.createHash("sha256")
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
  assert.ok(/^https:\/\/rp\.ephemeral\.example\/cb\?/.test(landed.location),
            "the authorization response: " + landed.status + " " +
            (landed.location || landed.text.slice(0, 300)));
  const code = new URL(landed.location).searchParams.get("code");
  const tokens = await hop(null, "POST", base + "/oauth2/token", { form: {
    grant_type: "authorization_code", code: code, redirect_uri: RP_REDIRECT,
    code_verifier: asked.verifier, client_id: client.client_id,
    client_secret: client.client_secret } });
  assert.strictEqual(tokens.status, 200, tokens.text.slice(0, 300));
  log.debug("Leaving idTokenFor().");
  return tokens.json;
}

async function register(extra) {
  log.debug("Entering register().");
  const r = await hop(null, "POST", base + "/oauth2/register", { json:
    Object.assign({ redirect_uris: [RP_REDIRECT],
      token_endpoint_auth_method: "client_secret_post",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"], scope: "openid offline_access",
      client_name: "RP " + TAG }, extra || {}) });
  log.debug("Leaving register().");
  return r;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Ephemeral subjects " + TAG },
    "created the realm");
  await ok(api + "/config/set", { key: "oauth2.openRegistration",
                                  value: true }, "opened registration");
  await registry.ensurePerson(base, PERSON, PASSWORD);

  log.info("=== 1. discovery and registration ===");
  const discovery = (await hop(null, "GET", base +
                               "/.well-known/openid-configuration")).json;
  const bogus = await register({ subject_type: "bogus" });
  const eph = await register({ subject_type: "ephemeral" });
  const pub = await register({});
  check("ephemeral is published and registrable; an unknown subject_type " +
        "is refused", function () {
    assert.ok(discovery.subject_types_supported.indexOf("ephemeral") >= 0);
    assert.strictEqual(bogus.status, 400, bogus.text.slice(0, 200));
    assert.strictEqual(bogus.json.error, "invalid_client_metadata");
    assert.strictEqual(eph.status, 201, eph.text.slice(0, 200));
  });

  log.info("=== 2. one authentication ===");
  const browser = jar();
  const set = await idTokenFor(browser, eph.json);
  const first = payloadOf(set.id_token);
  const userinfo = await hop(null, "GET", base + "/oauth2/userinfo",
    { headers: { Authorization: "Bearer " + set.access_token } });
  const refreshed = await hop(null, "POST", base + "/oauth2/token", { form: {
    grant_type: "refresh_token", refresh_token: set.refresh_token,
    client_id: eph.json.client_id, client_secret: eph.json.client_secret } });
  const again = payloadOf((await idTokenFor(browser, eph.json)).id_token);
  check("the ID Token, UserInfo, a refresh and a second code in the same " +
        "session name one random sub, not the public one", function () {
    assert.ok(!/^urn:uuid:/.test(first.sub) && first.sub.length >= 27,
              first.sub);
    assert.strictEqual(userinfo.json.sub, first.sub);
    assert.strictEqual(refreshed.status, 200, refreshed.text.slice(0, 200));
    assert.strictEqual(payloadOf(refreshed.json.id_token).sub, first.sub);
    assert.strictEqual(again.sub, first.sub);
  });

  log.info("=== 3. another authentication, and a public client ===");
  const other = payloadOf((await idTokenFor(jar(), eph.json)).id_token);
  const publicSub = payloadOf((await idTokenFor(browser, pub.json))
    .id_token).sub;
  check("a new authentication gets a new sub; a public client the public " +
        "one", function () {
    assert.notStrictEqual(other.sub, first.sub);
    assert.ok(/^urn:uuid:/.test(publicSub), publicSub);
  });

  log.info("=== 4. id_token_hint ===");
  const hinted = authorizeUrl(eph.json, { prompt: "none",
                                          id_token_hint: set.id_token });
  const answer = await hop(browser, "GET", hinted.url);
  check("an ephemeral sub in an id_token_hint maps back to the person",
        function () {
    assert.ok(/[?&]code=/.test(answer.location), answer.status + " " +
              answer.location);
  });

  assert.ok(checks >= 4, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The Ephemeral Subject Identifier (#149): minted per " +
    "authentication, held for it, never reused, over HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
