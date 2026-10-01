// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: sts_attribute_sources.js
// ---------------------------------------------------------------------------
// ATTRIBUTE SOURCES AGAINST A REAL DATABASE (#94, 2026-09-28).
//
// `tests/attribute_sources.js` holds everything this service decides with
// the database stubbed. This job is the other half: a real PostgreSQL over
// TLS that the service VERIFIES against a chain the source carries, a
// password the service reads from a file, the statement Knex builds, and
// the value arriving in a token.
//
//   0. A database of this job's own on the stack's `postgres` (never the
//      service's schema): a table of people, and a role that may only read
//      it. The server certificate is taken off the handshake and handed to
//      the source as its CA chain; the role's password is written into the
//      directory the runner and the service share, and the source names it.
//   1. add-source, then test-source reads the person's row and writes
//      nothing.
//   2. A browser sign-in (sign-in mode) writes the row onto the entry, and
//      the access token issued after it carries the attribute claim.
//   3. The row changes; refresh-person reads it; the claims preview says so.
//   4. A chain that did not sign the server: the connection is refused.
//   5. With onFailure refuse and that chain, a sign-in is refused and the
//      client is told access_denied.
//   6. The source is removed; the database, the role and the password file
//      go with it. The realm is left standing, as every realm job's is.
//
// SKIPPED, SAYING WHY, where there is no database the runner can create
// one in (`STS_TEST_ATTRIBUTE_DB_URL`, set by the compose stack only) or no
// directory shared with the service (an AWS target, `./run-coverage.sh`).
// `local: true` — written here, not in the parent project.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const outboundCa = require("./outbound_test_ca.js");

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
var log = bunyan.createLogger({ name: "sts_attribute_sources",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const DB_URL = String(process.env.STS_TEST_ATTRIBUTE_DB_URL || "");
const STAMP = names.runStamp();
const SAFE = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20);
const REALM = ("attrsrc-" + SAFE).slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const DATABASE = "attrsrc_" + SAFE;
const READER = "attrsrc_" + SAFE + "_r";
const READER_PASSWORD = nodeCrypto.randomBytes(18).toString("base64url");
const SECRET = "attrsrc-" + nodeCrypto.randomBytes(8).toString("hex");
const CLIENT = "attrsrc-rp-" + SAFE;
const REDIRECT = "https://rp.attrsrc.example.test/cb";
const PASSWORD = "Attr-Src-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = names.usernameFor("as-alice");
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_attribute_sources/1.0 (" + STAMP + ")";

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
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
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

// One browser, with a cookie jar.
function browser(name) {
  log.debug("Entering browser(). " + name);
  const jar = {};
  const self = {
    async go(method, where, body) {
      log.debug("Entering go(). " + method + " " + where);
      const headers = { "User-Agent": AGENT };
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(where), { method: method,
        redirect: "manual", headers: headers, body: body });
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

// An authorization request; follows a sign-in when there is no session.
async function authorize(b, state) {
  log.debug("Entering authorize(). state=" + state);
  const params = { response_type: "code", client_id: CLIENT,
    redirect_uri: REDIRECT, scope: "openid profile", state: state,
    nonce: "n-" + state,
    code_challenge: nodeCrypto.createHash("sha256").update("v".repeat(43))
      .digest("base64url"), code_challenge_method: "S256" };
  let r = await b.go("GET", R + "/oauth2/authorize?" + form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login\?authn=/.test(r.location)) {
    const page = await b.go("GET", r.location);
    assert.strictEqual(page.status, 200, "the sign-in screen: " +
                       page.status + " " + page.text.slice(0, 300));
    const fields = hiddenFields(page.text);
    fields.username = ALICE;
    fields.password = PASSWORD;
    fields.action = "login";
    const posted = await b.go("POST", R + "/authn/login", form(fields));
    r = await b.go("GET", posted.location);
  }
  log.debug("Leaving authorize(). " + r.status);
  return r;
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// A code from `r`'s redirect, redeemed: the access token's claims.
async function redeem(r) {
  log.debug("Entering redeem().");
  const code = r.location ? new URL(absolute(r.location)).searchParams
    .get("code") : "";
  assert.ok(code, "the sign-in should reach the client with a code; it " +
            "answered " + r.status + " " + r.location);
  const token = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: REDIRECT, client_id: CLIENT,
                 client_secret: SECRET, code_verifier: "v".repeat(43) }) });
  assert.strictEqual(token.status, 200, token.raw.slice(0, 300));
  log.debug("Leaving redeem().");
  return decode(token.body.access_token);
}

// ---------------------------------------------------------------------------
// THE DATABASE, as the stack's PostgreSQL superuser (a test's database,
// never the service's). `pg` is the service's own driver, installed at the
// repository root the job resolves from.
// ---------------------------------------------------------------------------
function pgClient(database) {
  log.debug("Entering pgClient(). " + (database || "(the URL's)"));
  const { Client } = require("pg");
  const url = new URL(DB_URL);
  if (database) {
    url.pathname = "/" + database;
  }
  // Encrypted, and deliberately NOT verified: this is the job setting up,
  // and the certificate it reads off this handshake is the one the SERVICE
  // is then made to verify against.
  log.debug("Leaving pgClient().");
  return new Client({ connectionString: url.toString(),
                      ssl: { rejectUnauthorized: false } });
}

// The server's certificate, as PEM, off a connected client's TLS socket.
function serverCertificateOf(client) {
  log.debug("Entering serverCertificateOf().");
  const socket = client.connection && client.connection.stream;
  const cert = socket && typeof socket.getPeerCertificate === "function"
    ? socket.getPeerCertificate() : null;
  assert.ok(cert && cert.raw, "the database's TLS certificate could not be " +
            "read off the connection");
  log.debug("Leaving serverCertificateOf().");
  return "-----BEGIN CERTIFICATE-----\n" +
    cert.raw.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

async function setUpDatabase() {
  log.debug("Entering setUpDatabase().");
  const admin = pgClient("");
  await admin.connect();
  const pem = serverCertificateOf(admin);
  await admin.query("CREATE DATABASE " + DATABASE);
  await admin.query("CREATE ROLE " + READER + " LOGIN PASSWORD '" +
                    READER_PASSWORD + "'");
  await admin.query("GRANT CONNECT ON DATABASE " + DATABASE + " TO " +
                    READER);
  await admin.end();
  const owner = pgClient(DATABASE);
  await owner.connect();
  await owner.query("CREATE TABLE people (login text PRIMARY KEY, " +
                    "cost_center text, grade text)");
  await owner.query("GRANT USAGE ON SCHEMA public TO " + READER);
  await owner.query("GRANT SELECT ON people TO " + READER);
  await owner.query("INSERT INTO people VALUES ($1, $2, $3)",
                    [ALICE, "CC-42", "G7"]);
  await owner.end();
  log.debug("Leaving setUpDatabase().");
  return pem;
}

async function setRow(costCenter) {
  log.debug("Entering setRow(). " + costCenter);
  const owner = pgClient(DATABASE);
  await owner.connect();
  await owner.query("UPDATE people SET cost_center = $1 WHERE login = $2",
                    [costCenter, ALICE]);
  await owner.end();
  log.debug("Leaving setRow().");
}

async function tearDownDatabase(passwordFile) {
  log.debug("Entering tearDownDatabase().");
  try {
    const admin = pgClient("");
    await admin.connect();
    // WITH (FORCE): the service's pool for the source may still hold a
    // connection until it idles out.
    await admin.query("DROP DATABASE IF EXISTS " + DATABASE +
                      " WITH (FORCE)");
    await admin.query("DROP ROLE IF EXISTS " + READER);
    await admin.end();
  } catch (e) {
    log.debug("Caught in tearDownDatabase(): " + ((e && e.message) || e));
    // A database left behind is named for this run and harms nothing; the
    // stack's postgres keeps no volume.
    log.warn("the test database " + DATABASE + " could not be dropped: " +
             ((e && e.message) || e));
  }
  try {
    fs.unlinkSync(passwordFile);
  } catch (e) {
    log.debug("Caught in tearDownDatabase(): " + ((e && e.message) || e));
    // Already gone, or never written.
  }
  log.debug("Leaving tearDownDatabase().");
}

async function test() {
  log.debug("Entering test().");
  const shared = outboundCa.caLocation();
  if (!DB_URL || !shared) {
    log.info("SKIPPED: " + (!DB_URL
      ? "STS_TEST_ATTRIBUTE_DB_URL is not set, so there is no database " +
        "this job may create one in (the compose stack sets it; an AWS " +
        "target and ./run-coverage.sh do not)."
      : outboundCa.skipReason()));
    log.debug("Leaving test(). Skipped.");
    return;
  }
  // The same path in both containers: the runner writes it, the service
  // reads it through the `file` provider.
  const passwordFile = path.join(shared.dir, "attrsrc-" + SAFE + ".pw");

  log.info("=== 0. a database, a reader, a realm, a person, a client ===");
  const pem = await setUpDatabase();
  fs.writeFileSync(passwordFile, READER_PASSWORD, { mode: 0o644 });
  try {
    await ok(base + "/admin-api/realms/create", { id: REALM,
      domain: REALM + ".example.net", name: "attribute sources " + STAMP },
      "created the realm");
    await ok(realmApi + "/applications/create", { identifier: CLIENT,
      kind: "oauth2-client", name: CLIENT, protocols: ["oauth2"],
      fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: "client_secret_post",
                oauthAllowedScope: ["openid", "profile"],
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ["authorization_code"],
                oauthResponseType: ["code"] } },
      "created the client");
    for (const one of ["openid", "profile"]) {
      await ok(realmApi + "/consent/grant-global-consent",
               { client: CLIENT, scope: one }, "consented " + one);
    }
    await ok(realmApi + "/users/create", { username: ALICE, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "Attr " + ALICE, givenName: "Attr", sn: "Source" } },
      "created " + ALICE);
    await ok(realmApi + "/claims/add-attribute-claim", { set: "access_token",
      name: "cost_center", attribute: "costCenter" },
      "added the cost_center attribute claim");

    const source = { id: "hr", dialect: "postgres",
      host: new URL(DB_URL).hostname, port: Number(new URL(DB_URL).port) ||
        5432,
      database: DATABASE, user: READER, passwordProvider: "file",
      passwordRef: passwordFile, caCertificates: pem,
      table: "people", keyColumn: "login", keyAttribute: "uid",
      columns: { cost_center: "costCenter", grade: "employeeType" },
      refresh: ["sign-in", "on-demand"] };

    log.info("=== 1. the source, and a test that writes nothing ===");
    await ok(realmApi + "/attribute-sources/add-source", source,
             "added the source");
    const tested = await postJson(realmApi +
      "/attribute-sources/test-source", { id: "hr", username: ALICE });
    check("1. test-source connects over verified TLS with the password " +
          "from the file, and reads the row", function () {
      assert.strictEqual(tested.status, 200, tested.raw.slice(0, 400));
      assert.ok(tested.body.found &&
                tested.body.row.cost_center[0] === "CC-42",
                JSON.stringify(tested.body));
    });

    log.info("=== 2. a sign-in reads it, and the token carries it ===");
    const b = browser("alice");
    const claims = await redeem(await authorize(b, "s1"));
    check("2. the access token issued after the sign-in carries the " +
          "attribute claim", function () {
      assert.strictEqual(claims.cost_center, "CC-42", JSON.stringify(claims));
    });
    const editor = await send(realmApi + "/users?user=" +
                              encodeURIComponent(ALICE), {});
    const grade = ((editor.body && editor.body.attributeEditor &&
                    editor.body.attributeEditor.attributes) || [])
      .filter(function (one) {
        return one.name === "employeeType";
      })[0];
    check("2. and the other column is on the person's entry", function () {
      assert.ok(grade && grade.values.indexOf("G7") >= 0,
                JSON.stringify(grade));
    });

    log.info("=== 3. the row changes; refresh-person reads it ===");
    await setRow("CC-43");
    const refreshed = await postJson(realmApi +
      "/attribute-sources/refresh-person", { username: ALICE });
    const preview = await send(realmApi + "/claims?user=" +
                               encodeURIComponent(ALICE), {});
    const set = ((preview.body && preview.body.sets) || [])
      .filter(function (one) {
        return one.id === "access_token";
      })[0];
    const row = ((set && set.attributeClaimPreview) || [])
      .filter(function (one) {
        return one.name === "cost_center";
      })[0];
    check("3. refresh-person writes the new value, and the claims preview " +
          "carries it", function () {
      assert.ok(refreshed.status === 200 && refreshed.body.ok,
                refreshed.raw.slice(0, 400));
      assert.ok(row && row.value === "CC-43", JSON.stringify(row));
    });

    log.info("=== 4. a chain that did not sign the database ===");
    const stranger = await outboundCa.makeCa();
    await ok(realmApi + "/attribute-sources/update-source",
             { id: "hr", caCertificates: stranger.certPem },
             "named a chain that did not sign the database");
    const refused = await postJson(realmApi +
      "/attribute-sources/test-source", { id: "hr", username: ALICE });
    check("4. the connection is refused: the certificate is verified " +
          "against the source's chain alone", function () {
      assert.strictEqual(refused.status, 400, refused.raw.slice(0, 400));
      assert.ok(/certificate|self.signed|verify/i.test(
                  (refused.body.errors || []).join(" ")),
                JSON.stringify(refused.body));
    });

    log.info("=== 5. onFailure refuse: the sign-in is refused ===");
    await ok(realmApi + "/attribute-sources/update-source",
             { id: "hr", onFailure: "refuse" }, "set onFailure refuse");
    const denied = await authorize(browser("alice-again"), "s2");
    check("5. a sign-in whose refusing source cannot be read reaches the " +
          "client as access_denied", function () {
      assert.ok(/[?&]error=access_denied/.test(denied.location),
                denied.status + " " + denied.location);
    });

    log.info("=== 6. removed ===");
    await ok(realmApi + "/attribute-sources/remove-source", { id: "hr" },
             "removed the source");
  } finally {
    await tearDownDatabase(passwordFile);
  }
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_attribute_sources FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
