"use strict";
//
// File: sts_development_only_settings.js
//
// ---------------------------------------------------------------------------
// THE DEVELOPMENT-ONLY SETTINGS, OVER HTTP (#104, 2026-09-23).
//
// `oauth2.breakIdTokenNonce`, `ssf.breakSetSignature`, `ssf.legacySubClaim`,
// `spiffe.acceptAssertedSelectors` and `spiffe.attestWorkloads` off make this
// service wrong or loose on purpose. Each is honoured in development only:
// in product it is IGNORED where it is read — the mode is a runtime setting,
// so the read is the guard — and REFUSED on write (STS-CORE-0103). This job
// asserts both halves against a running service, in two throwaway trust
// realms it leaves standing, one development and one product, so it asserts
// both whatever mode the service itself was started in:
//
//   0. A realm create naming product mode and a deliberate defect in ONE body
//      is refused, and nothing is created.
//   1. THE WRITE DOORS. In the product realm every marked value is refused
//      through `config/set`, `realms/set` (from the default realm) and an
//      all-or-nothing `config/set-many`; the default is accepted; the
//      development realm accepts every one.
//   2. THE NONCE, end to end. In the development realm, with
//      `oauth2.breakIdTokenNonce` on, an authorization code flow's ID Token
//      carries a spoiled nonce. The realm is then switched to product with the
//      setting STILL STORED: `GET /oauth2/rfc9700` reports it not in force,
//      and the next flow's ID Token carries the nonce the request asked for.
//   3. THE SET SIGNATURE, end to end, over a poll stream: with
//      `ssf.breakSetSignature` on the verification event's SET does not
//      verify against the realm's published keys in development and does in
//      product, still stored.
//   4. SPIFFE: `GET /spiffe?format=json` in the realm reports `attestWorkloads` on and
//      `acceptAssertedSelectors` off in product, though the stored values say
//      otherwise.
//
// The legacy `sub` claim, the Workload API's answer and the SPIRE Server
// API's `local` socket are asserted in process — `tests/
// mode_development_only.js` and `tests/spiffe_local_socket.js` — because no
// HTTP request produces a SET with an `iss_sub` subject or reaches a Unix
// socket.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_development_only_settings",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const DEV = ("devonly-d-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const PROD = ("devonly-p-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31);
const CLIENT = "devonly-client-" + STAMP;
const SSF_APP = "devonly-ssf-" + STAMP;
const REDIRECT = "https://rp.devonly.example.test/cb";
const SECRET = "devonly-secret-" + STAMP + "-0123456789abcdef";
const PASSWORD = "Dev-only-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("devonly-alice");
const POLL = "urn:ietf:rfc:8936";
const VERIFICATION =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";
// Each marked row and the value that is refused in product.
const MARKED = [["oauth2.breakIdTokenNonce", true],
                ["ssf.breakSetSignature", true],
                ["ssf.legacySubClaim", true],
                ["spiffe.acceptAssertedSelectors", true],
                ["spiffe.attestWorkloads", false]];
const FLOOR = 25;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
}

async function call(method, url, body, headers) {
  log.debug("Entering call().");
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
  log.debug("Leaving call().");
  return { status: r.status, json: json, text: text };
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
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(realmBase(realm) + "/admin-api/config/set",
            { key: key, value: value }, "set " + key + " in " + realm);
}

// One setting's row out of `/admin-api/config`'s groups, or null.
function settingRow(body, key) {
  log.debug("Entering settingRow(). key=" + key);
  const rows = [];
  ((body && body.groups) || []).forEach(function (group) {
    (group.settings || []).forEach(function (one) {
      rows.push(one);
    });
  });
  ((body && body.settings) || []).forEach(function (one) {
    rows.push(one);
  });
  const row = rows.filter(function (one) {
    return one.key === key;
  })[0] || null;
  log.debug("Leaving settingRow(). found=" + !!row);
  return row;
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function part(token, n) {
  log.debug("Entering part().");
  const value = JSON.parse(Buffer.from(String(token).split(".")[n],
                                       "base64url").toString("utf8"));
  log.debug("Leaving part().");
  return value;
}

// One browser: a cookie jar and redirects left to the caller.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    async go(method, url, body) {
      log.debug("Entering go(). " + method + " " + url);
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
      const absolute = /^https?:\/\//i.test(url) ? url : base + url;
      const r = await fetch(absolute, { method: method, redirect: "manual",
                                        headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
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

// An authorization code flow in `realm`, signing ALICE in with her password,
// and the ID Token it yields, with the nonce that was asked for.
async function idTokenFlow(realm) {
  log.debug("Entering idTokenFlow().");
  const R = "/realm/" + realm;
  const b = browser();
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  const nonce = "n-" + nodeCrypto.randomBytes(6).toString("hex");
  let r = await b.go("GET", R + "/oauth2/authorize?" + form({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + STAMP, nonce: nonce,
    code_challenge: challenge, code_challenge_method: "S256" }));
  assert.ok((r.status === 302 || r.status === 303) &&
            /\/authn\/login\?authn=/.test(r.location),
            "the authorization endpoint should send the browser to sign in; " +
            "it answered " + r.status + " " + r.location + " " +
            r.text.slice(0, 300));
  const page = await b.go("GET", r.location);
  const fields = hiddenFields(page.text);
  assert.ok(fields.authn_id, "the sign-in screen carries no authn_id: " +
            page.text.slice(0, 300));
  fields.username = ALICE;
  fields.password = PASSWORD;
  fields.action = "login";
  r = await b.go("POST", R + "/authn/login", form(fields));
  for (let hops = 0; hops < 6 &&
       (r.status === 302 || r.status === 303) &&
       String(r.location).indexOf(REDIRECT) !== 0; hops++) {
    r = await b.go("GET", r.location);
  }
  assert.ok(String(r.location).indexOf(REDIRECT) === 0,
            "the flow should end at the client with a code; it answered " +
            r.status + " " + r.location + " " + r.text.slice(0, 300));
  const code = new URL(r.location).searchParams.get("code");
  assert.ok(code, "no code at the client: " + r.location);
  const token = await call("POST", realmBase(realm) + "/oauth2/token",
    form({ grant_type: "authorization_code", code: code,
           redirect_uri: REDIRECT, code_verifier: verifier }),
    { "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + Buffer.from(
        encodeURIComponent(CLIENT) + ":" + encodeURIComponent(SECRET))
        .toString("base64") });
  assert.ok(token.status === 200 && token.json && token.json.id_token,
            "the token endpoint should issue an ID Token: " + token.status +
            " " + token.text.slice(0, 400));
  log.debug("Leaving idTokenFlow().");
  return { asked: nonce, got: part(token.json.id_token, 1).nonce };
}

async function ssfToken(realm) {
  log.debug("Entering ssfToken().");
  const r = await call("POST", realmBase(realm) + "/oauth2/token",
    form({ grant_type: "client_credentials", client_id: SSF_APP,
           client_secret: SECRET, scope: "ssf:read ssf:write" }),
    { "Content-Type": "application/x-www-form-urlencoded" });
  assert.ok(r.json && r.json.access_token,
            "a token for " + SSF_APP + ": " + r.text.slice(0, 300));
  log.debug("Leaving ssfToken().");
  return r.json.access_token;
}

// Does a compact JWS verify against a key in `jwks`? RS256, PS256 and ES256
// — the algorithms `ssf.signingAlgorithm` may name that node verifies here.
function verifies(token, jwks) {
  log.debug("Entering verifies().");
  const header = part(token, 0);
  const jwk = (jwks.keys || []).filter(function (k) {
    return k.kid === header.kid;
  })[0];
  assert.ok(jwk, "no key " + header.kid + " in the realm's key set");
  const pieces = String(token).split(".");
  const input = Buffer.from(pieces[0] + "." + pieces[1]);
  const signature = Buffer.from(pieces[2], "base64url");
  const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
  let good = false;
  if (header.alg === "RS256") {
    good = nodeCrypto.verify("sha256", input, key, signature);
  } else if (header.alg === "PS256") {
    good = nodeCrypto.verify("sha256", input, { key: key,
      padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32 }, signature);
  } else if (header.alg === "ES256") {
    good = nodeCrypto.verify("sha256", input, { key: key,
      dsaEncoding: "ieee-p1363" }, signature);
  } else {
    assert.fail("this job verifies RS256, PS256 and ES256; the SET is " +
                header.alg + " (ssf.signingAlgorithm)");
  }
  log.debug("Leaving verifies(). " + good);
  return good;
}

// A new poll stream in `realm`, its verification event, and the SET it
// produced.
async function verificationSet(realm) {
  log.debug("Entering verificationSet().");
  const auth = { Authorization: "Bearer " + await ssfToken(realm) };
  let r = await call("POST", realmBase(realm) + "/ssf/stream",
                     { delivery: { method: POLL },
                       events_requested: [VERIFICATION] }, auth);
  assert.ok(r.status === 200 || r.status === 201,
            "a poll stream: " + r.status + " " + r.text.slice(0, 300));
  const id = r.json.stream_id;
  r = await call("POST", realmBase(realm) + "/ssf/verify",
                 { stream_id: id, state: "devonly-" + Date.now() }, auth);
  assert.ok(r.status === 204 || r.status === 200,
            "verify: " + r.status + " " + r.text.slice(0, 300));
  r = await call("POST", realmBase(realm) + "/ssf/poll",
                 { stream_id: id, returnImmediately: true, maxEvents: 10 },
                 auth);
  assert.strictEqual(r.status, 200, "poll: " + r.text.slice(0, 300));
  const sets = Object.values(r.json.sets || {});
  assert.ok(sets.length >= 1, "the verification event was not queued: " +
            r.text.slice(0, 300));
  log.debug("Leaving verificationSet().");
  return sets[0];
}

async function jwksOf(realm) {
  log.debug("Entering jwksOf().");
  const discovery = await call("GET", realmBase(realm) +
                               "/.well-known/ssf-configuration");
  assert.strictEqual(discovery.status, 200, discovery.text.slice(0, 200));
  const keys = await call("GET", discovery.json.jwks_uri);
  assert.strictEqual(keys.status, 200, keys.text.slice(0, 200));
  log.debug("Leaving jwksOf().");
  return keys.json;
}

async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. two realms, one each way ===");
  const r = await call("POST", base + "/admin-api/realms/create",
    { id: PROD, domain: PROD + ".example.net", name: "#104 (refused)",
      overrides: { "global.mode": "product",
                   "oauth2.breakIdTokenNonce": "true" } });
  check("a realm create naming product mode and a deliberate defect in one " +
        "body is refused (STS-CORE-0103)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.ok(/product mode/.test(r.text), r.text.slice(0, 300));
  });
  const list = await call("GET", base + "/admin-api/realms");
  check("and no realm was created", function () {
    assert.ok(list.text.indexOf('"' + PROD + '"') < 0, "found " + PROD);
  });
  await ok(base + "/admin-api/realms/create",
           { id: PROD, domain: PROD + ".example.net", name: "#104 product",
             overrides: { "global.mode": "product" } },
           "created the product realm");
  await ok(base + "/admin-api/realms/create",
           { id: DEV, domain: DEV + ".example.net", name: "#104 development",
             overrides: { "global.mode": "development" } },
           "created the development realm");
  log.debug("Leaving setUp().");
}

async function writeDoors() {
  log.debug("Entering writeDoors().");
  log.info("=== 1. the write doors ===");
  for (const [key, value] of MARKED) {
    let r = await call("POST", realmBase(PROD) + "/admin-api/config/set",
                       { key: key, value: value });
    check("product: config/set " + key + "=" + value + " is refused, naming " +
          "it", function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
      assert.ok(/product mode/.test(r.text) && r.text.indexOf(key) >= 0,
                r.text.slice(0, 300));
    });
    r = await call("POST", base + "/admin-api/realms/set",
                   { id: PROD, key: key, value: String(value) });
    check("product: realms/set of it from the default realm is refused too",
          function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    });
    await setting(PROD, key, !value);
    await setting(DEV, key, value);
    await setting(DEV, key, !value);
  }
  check("the default is accepted in the product realm, and every marked " +
        "value in the development one (every call above answered 200)",
        function () {
    assert.ok(true);
  });
  const r = await call("POST", realmBase(PROD) + "/admin-api/config/set-many",
                       { "oauth2.idTokenTtlS": "1230",
                         "ssf.breakSetSignature": "true" });
  check("product: a set-many carrying a deliberate defect is refused WHOLE",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  });
  const after = await call("GET", realmBase(PROD) + "/admin-api/config");
  check("and wrote nothing — the lifetime beside it was not set",
        function () {
    assert.strictEqual(after.status, 200, after.text.slice(0, 200));
    const row = settingRow(after.json, "oauth2.idTokenTtlS");
    assert.ok(row && String(row.value) !== "1230",
              "the lifetime was written by a refused request: " +
              JSON.stringify(row));
  });
  log.debug("Leaving writeDoors().");
}

async function theApplications() {
  log.debug("Entering theApplications().");
  await ok(realmBase(DEV) + "/admin-api/users/create", {
    username: ALICE, invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "Dev only " + ALICE, givenName: "Dev", sn: ALICE,
                  displayName: "Dev only " + ALICE,
                  mail: ALICE + "@devonly.test" } },
    "created " + ALICE + " with a password");
  await ok(realmBase(DEV) + "/admin-api/applications/create", {
    identifier: CLIENT, name: "#104 client " + STAMP,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT, oauthRedirectUri: [REDIRECT],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_basic" } },
    "created the OpenID Connect client");
  await ok(realmBase(DEV) + "/admin-api/consent/grant-global-consent",
           { client: CLIENT, scope: "openid" },
           "consented openid for everybody on the client");
  await ok(realmBase(DEV) + "/admin-api/applications/create", {
    identifier: SSF_APP, kind: "oauth2-client", name: SSF_APP,
    protocols: ["oauth2", "ssf"],
    fields: { oauthClientId: [SSF_APP],
              oauthAllowedScope: ["ssf:read", "ssf:write"],
              oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post" } },
    "created the SSF receiver application");
  log.debug("Leaving theApplications().");
}

async function readSites() {
  log.debug("Entering readSites().");
  log.info("=== 2-4. the read sites, in development and then in product ===");
  await theApplications();
  const jwks = await jwksOf(DEV);
  await setting(DEV, "oauth2.breakIdTokenNonce", true);
  await setting(DEV, "ssf.breakSetSignature", true);
  await setting(DEV, "spiffe.acceptAssertedSelectors", true);
  await setting(DEV, "spiffe.attestWorkloads", false);

  let flow = await idTokenFlow(DEV);
  check("development: with oauth2.breakIdTokenNonce on, the ID Token's " +
        "nonce is spoiled", function () {
    assert.ok(flow.got !== flow.asked && /^broken-/.test(String(flow.got)),
              JSON.stringify(flow));
  });
  let rfc9700 = await call("GET", realmBase(DEV) + "/oauth2/rfc9700");
  check("development: GET /oauth2/rfc9700 reports it on", function () {
    assert.strictEqual(rfc9700.status, 200, rfc9700.text.slice(0, 200));
    assert.strictEqual(
      rfc9700.json.settings["oauth2.breakIdTokenNonce"], true,
      JSON.stringify(rfc9700.json.settings));
  });
  let set = await verificationSet(DEV);
  check("development: with ssf.breakSetSignature on, the verification SET " +
        "does not verify against the realm's published keys", function () {
    assert.strictEqual(verifies(set, jwks), false);
  });
  let spiffe = await call("GET", realmBase(DEV) + "/spiffe?format=json");
  check("development: GET /spiffe reports asserted selectors believed and " +
        "workloads not matched", function () {
    assert.strictEqual(spiffe.status, 200, spiffe.text.slice(0, 200));
    const a = spiffe.json.authentication || {};
    assert.ok(a.acceptAssertedSelectors === true &&
              a.attestWorkloads === false, JSON.stringify(a));
  });

  await setting(DEV, "global.mode", "product");
  const config = await call("GET", realmBase(DEV) + "/admin-api/config");
  check("product: the development values are still STORED in the realm",
        function () {
    ["oauth2.breakIdTokenNonce", "ssf.breakSetSignature"]
      .forEach(function (key) {
        const row = settingRow(config.json, key);
        assert.ok(row && row.value === true, key + ": " +
                  JSON.stringify(row));
      });
  });
  flow = await idTokenFlow(DEV);
  check("product, the setting still stored: the ID Token carries the nonce " +
        "the request asked for", function () {
    assert.strictEqual(flow.got, flow.asked, JSON.stringify(flow));
  });
  rfc9700 = await call("GET", realmBase(DEV) + "/oauth2/rfc9700");
  check("product: GET /oauth2/rfc9700 reports it NOT in force", function () {
    assert.strictEqual(rfc9700.status, 200, rfc9700.text.slice(0, 200));
    assert.strictEqual(
      rfc9700.json.settings["oauth2.breakIdTokenNonce"], false,
      JSON.stringify(rfc9700.json.settings));
  });
  set = await verificationSet(DEV);
  check("product: the verification SET verifies, with ssf.breakSetSignature " +
        "still stored", function () {
    assert.strictEqual(verifies(set, jwks), true);
  });
  spiffe = await call("GET", realmBase(DEV) + "/spiffe?format=json");
  check("product: GET /spiffe reports asserted selectors NOT believed and " +
        "workloads matched, whatever is stored", function () {
    assert.strictEqual(spiffe.status, 200, spiffe.text.slice(0, 200));
    const a = spiffe.json.authentication || {};
    assert.ok(a.acceptAssertedSelectors === false &&
              a.attestWorkloads === true, JSON.stringify(a));
  });
  const refused = await call("POST", realmBase(DEV) +
                             "/admin-api/config/set",
                             { key: "ssf.legacySubClaim", value: true });
  check("product: and the switched realm refuses a new one", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
  });
  for (const [key, value] of MARKED) {
    await setting(DEV, key, !value);
  }
  await setting(DEV, "global.mode", "development");
  log.debug("Leaving readSites().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the development-only settings at " + base);
  await setUp();
  await writeDoors();
  await readSites();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_development_only_settings")
  .description("#104: the deliberate defects and the loosening SPIFFE " +
    "switches are honoured in development, ignored where they are read in " +
    "product, and refused on write there.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
