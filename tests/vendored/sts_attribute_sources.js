// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: sts_attribute_sources.js
// ---------------------------------------------------------------------------
// ATTRIBUTE SOURCES AGAINST REAL DATABASES (#94, 2026-09-28; MariaDB #356).
//
// `tests/attribute_sources.js` holds everything this service decides with
// the database stubbed. This job is the other half: a real PostgreSQL and
// a real MariaDB, each over TLS that the service VERIFIES against a chain
// the source carries, a password the service reads from a file, the
// statement Knex builds, and the value arriving in a token.
//
// The six checks run once per dialect that has a URL. The realm, the
// person, the client and the claim are created once. MariaDB runs after
// PostgreSQL's source is removed: an attribute has one source
// (STS-ATTR-0009), and the second sign-in overwrites what the first wrote.
//
//   0. A database of this job's own (never the service's schema): a table
//      of people, and an account that may only read it. The server
//      certificate is taken off the handshake and handed to the source as
//      its CA chain; the account's password is written into the directory
//      the runner and the service share, and the source names it.
//   1. add-source, then test-source reads the person's row and writes
//      nothing.
//   2. A browser sign-in (sign-in mode) writes the row onto the entry, and
//      the access token issued after it carries the attribute claim.
//   3. The row changes; refresh-person reads it; the claims preview says so.
//   4. A chain that did not sign the server: the connection is refused.
//   5. With onFailure refuse and that chain, a sign-in is refused and the
//      client is told access_denied.
//   6. The source is removed; the database, the account and the password
//      file go with it. The realm is left standing, as every realm job's is.
//
// SKIPPED, SAYING WHY, where neither URL is set or there is no directory
// shared with the service. One URL set runs that dialect and says the
// other is skipped. The compose stack sets both in every mode;
// `./run-coverage.sh` empties both, and an AWS target sets neither.
// `local: true` — written here, not in the parent project.
// ---------------------------------------------------------------------------

"use strict";

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
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
const MYSQL_URL = String(process.env.STS_TEST_ATTRIBUTE_MYSQL_URL || "");
const STAMP = names.runStamp();
const SAFE = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20);
const REALM = ("attrsrc-" + SAFE).slice(0, 31);
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const PG_DATABASE = "attrsrc_" + SAFE;
const PG_READER = "attrsrc_" + SAFE + "_r";
const MY_DATABASE = "attrsrc_" + SAFE + "_m";
const MY_READER = "attrsrc_" + SAFE + "_mr";
const PG_PASSWORD = nodeCrypto.randomBytes(18).toString("base64url");
const MY_PASSWORD = nodeCrypto.randomBytes(18).toString("base64url");
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
    // The jar, for the sign-in over /authn-api (#571).
    jar: jar,
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
    // THE SCREEN OVER `/authn-api` (#571), with this browser's jar and
    // User-Agent; the answer is read as the form's 303 was.
    const posted = await authnSignin.signInWithJar(base + R, r.location,
      { action: "login", username: ALICE, password: PASSWORD }, b.jar,
      { headers: { "User-Agent": AGENT } });
    assert.ok(posted.answer.view, "the sign-in screen: " +
              posted.answer.status + " " + JSON.stringify(posted.answer.json));
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
// THE DATABASES. PostgreSQL as the stack's superuser (`pg` is the service's
// own driver). MariaDB as root (`mysql2` is the optional peer, installed
// for this job in tests/package.json; the service image gets it from
// STS_CLOUD_SDKS). Each is a database of this job's own, never the
// service's schema.
//
// Names and passwords are interpolated into SQL only after a charset check.
// The password is base64url and the names are a stamp, so a placeholder
// would be enough for the values — MariaDB's CREATE USER does not take a
// placeholder for the account, which is why the check exists.
// ---------------------------------------------------------------------------
function sqlName(name) {
  log.debug("Entering sqlName().");
  if (!/^[A-Za-z0-9_]+$/.test(String(name))) {
    log.debug("Leaving sqlName(). Refused.");
    throw new Error("refusing to interpolate an identifier");
  }
  log.debug("Leaving sqlName().");
  return String(name);
}

function sqlText(value) {
  log.debug("Entering sqlText().");
  if (!/^[A-Za-z0-9_-]+$/.test(String(value))) {
    log.debug("Leaving sqlText(). Refused.");
    throw new Error("refusing to interpolate a literal");
  }
  log.debug("Leaving sqlText().");
  return "'" + String(value) + "'";
}

function pgClient(urlText, database) {
  log.debug("Entering pgClient(). " + (database || "(the URL's)"));
  const { Client } = require("pg");
  const url = new URL(urlText);
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

async function mysqlAdmin(spec, database) {
  log.debug("Entering mysqlAdmin(). " + (database || "(the URL's)"));
  const mysql = require("mysql2/promise");
  const url = new URL(spec.url);
  const named = database || url.pathname.replace(/^\//, "");
  const conn = await mysql.createConnection({
    host: url.hostname,
    port: Number(url.port) || spec.port,
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: named || undefined,
    ssl: { rejectUnauthorized: false }
  });
  log.debug("Leaving mysqlAdmin().");
  return conn;
}

// The server's certificate, as PEM, off a connected client's TLS socket.
// `pg`'s client and mysql2's promise connection both keep the socket at
// `connection.stream` once the handshake has finished.
function tlsSocketOf(holder) {
  log.debug("Entering tlsSocketOf().");
  const socket = holder && holder.connection && holder.connection.stream;
  log.debug("Leaving tlsSocketOf().");
  return socket || null;
}

function pemFromSocket(socket) {
  log.debug("Entering pemFromSocket().");
  const cert = socket && typeof socket.getPeerCertificate === "function"
    ? socket.getPeerCertificate() : null;
  assert.ok(cert && cert.raw, "the database's TLS certificate could not be " +
            "read off the connection");
  log.debug("Leaving pemFromSocket().");
  return "-----BEGIN CERTIFICATE-----\n" +
    cert.raw.toString("base64").match(/.{1,64}/g).join("\n") +
    "\n-----END CERTIFICATE-----\n";
}

async function setUpPostgres(spec) {
  log.debug("Entering setUpPostgres().");
  const admin = pgClient(spec.url, "");
  await admin.connect();
  let pem;
  try {
    pem = pemFromSocket(tlsSocketOf(admin));
    await admin.query("CREATE DATABASE " + sqlName(spec.database));
    await admin.query("CREATE ROLE " + sqlName(spec.reader) +
                      " LOGIN PASSWORD " + sqlText(spec.readerPassword));
    await admin.query("GRANT CONNECT ON DATABASE " +
                      sqlName(spec.database) + " TO " +
                      sqlName(spec.reader));
  } finally {
    await admin.end();
  }
  const owner = pgClient(spec.url, spec.database);
  await owner.connect();
  try {
    await owner.query("CREATE TABLE people (login text PRIMARY KEY, " +
                      "cost_center text, grade text)");
    await owner.query("GRANT USAGE ON SCHEMA public TO " +
                      sqlName(spec.reader));
    await owner.query("GRANT SELECT ON people TO " + sqlName(spec.reader));
    await owner.query("INSERT INTO people VALUES ($1, $2, $3)",
                      [ALICE, "CC-42", "G7"]);
  } finally {
    await owner.end();
  }
  log.debug("Leaving setUpPostgres().");
  return pem;
}

async function setUpMysql(spec) {
  log.debug("Entering setUpMysql().");
  const admin = await mysqlAdmin(spec, "");
  let pem;
  try {
    pem = pemFromSocket(tlsSocketOf(admin));
    const db = sqlName(spec.database);
    const reader = sqlText(spec.reader);
    const password = sqlText(spec.readerPassword);
    await admin.query("CREATE DATABASE " + db);
    await admin.query("CREATE TABLE " + db + ".people (" +
      "login varchar(255) PRIMARY KEY, cost_center varchar(64), " +
      "grade varchar(64))");
    await admin.query("INSERT INTO " + db +
      ".people (login, cost_center, grade) VALUES (?, ?, ?)",
      [ALICE, "CC-42", "G7"]);
    // mysql2 does not speak MariaDB's ed25519 plugin, so the reader is
    // pinned to the native password plugin rather than left to the
    // server's default.
    await admin.query("CREATE USER " + reader + "@'%' IDENTIFIED VIA " +
      "mysql_native_password USING PASSWORD(" + password + ")");
    await admin.query("GRANT SELECT ON " + db + ".people TO " + reader +
      "@'%'");
  } finally {
    await admin.end();
  }
  log.debug("Leaving setUpMysql().");
  return pem;
}

async function setUpDatabase(spec) {
  log.debug("Entering setUpDatabase(). " + spec.dialect);
  const pem = spec.dialect === "mysql" ? await setUpMysql(spec)
                                        : await setUpPostgres(spec);
  log.debug("Leaving setUpDatabase().");
  return pem;
}

async function setRow(spec, costCenter) {
  log.debug("Entering setRow(). " + spec.dialect + " " + costCenter);
  if (spec.dialect === "mysql") {
    const admin = await mysqlAdmin(spec, spec.database);
    try {
      await admin.query("UPDATE people SET cost_center = ? WHERE login = ?",
                        [costCenter, ALICE]);
    } finally {
      await admin.end();
    }
  } else {
    const owner = pgClient(spec.url, spec.database);
    await owner.connect();
    try {
      await owner.query("UPDATE people SET cost_center = $1 WHERE login = $2",
                        [costCenter, ALICE]);
    } finally {
      await owner.end();
    }
  }
  log.debug("Leaving setRow().");
}

function removePasswordFile(file) {
  log.debug("Entering removePasswordFile().");
  try {
    fs.unlinkSync(file);
  } catch (e) {
    log.debug("Caught in removePasswordFile(): " + ((e && e.message) || e));
    // Already gone, or never written.
  }
  log.debug("Leaving removePasswordFile().");
}

async function tearDownPostgres(spec) {
  log.debug("Entering tearDownPostgres().");
  const admin = pgClient(spec.url, "");
  await admin.connect();
  try {
    // WITH (FORCE): the service's pool for the source may still hold a
    // connection until it idles out.
    await admin.query("DROP DATABASE IF EXISTS " + sqlName(spec.database) +
                      " WITH (FORCE)");
    await admin.query("DROP ROLE IF EXISTS " + sqlName(spec.reader));
  } finally {
    await admin.end();
  }
  log.debug("Leaving tearDownPostgres().");
}

async function tearDownMysql(spec) {
  log.debug("Entering tearDownMysql().");
  const admin = await mysqlAdmin(spec, "");
  try {
    // MariaDB has no DROP DATABASE ... WITH (FORCE). The service's pool
    // may still hold a connection, and a drop then waits on it.
    const listed = await admin.query(
      "SELECT ID AS conn_id FROM information_schema.processlist " +
      "WHERE DB = ?", [spec.database]);
    const rows = listed[0] || [];
    for (let i = 0; i < rows.length; i++) {
      const id = Number(rows[i].conn_id);
      if (!id) {
        continue;
      }
      try {
        await admin.query("KILL " + id);
      } catch (e) {
        log.debug("Caught in tearDownMysql(): " + ((e && e.message) || e));
        // The session left between the listing and the kill.
      }
    }
    await admin.query("DROP DATABASE IF EXISTS " + sqlName(spec.database));
    await admin.query("DROP USER IF EXISTS " + sqlText(spec.reader) +
                      "@'%'");
  } finally {
    await admin.end();
  }
  log.debug("Leaving tearDownMysql().");
}

async function tearDownDatabase(spec) {
  log.debug("Entering tearDownDatabase(). " + spec.dialect);
  try {
    if (spec.dialect === "mysql") {
      await tearDownMysql(spec);
    } else {
      await tearDownPostgres(spec);
    }
  } catch (e) {
    log.debug("Caught in tearDownDatabase(): " + ((e && e.message) || e));
    // A database left behind is named for this run and harms nothing; the
    // stack keeps no volume for either server.
    log.warn("the test database " + spec.database + " could not be " +
             "dropped: " + ((e && e.message) || e));
  }
  removePasswordFile(spec.passwordFile);
  log.debug("Leaving tearDownDatabase().");
}

// The six checks, against one dialect's database. The source is removed
// before this returns, so the next dialect may own the same attributes.
async function exerciseSource(spec, pem) {
  log.debug("Entering exerciseSource(). " + spec.dialect);
  const tag = spec.label;
  const source = { id: spec.sourceId, dialect: spec.dialect,
    host: new URL(spec.url).hostname,
    port: Number(new URL(spec.url).port) || spec.port,
    database: spec.database, user: spec.reader, passwordProvider: "file",
    passwordRef: spec.passwordFile, caCertificates: pem,
    table: "people", keyColumn: "login", keyAttribute: "uid",
    columns: { cost_center: "costCenter", grade: "employeeType" },
    refresh: ["sign-in", "on-demand"] };

  log.info("=== " + tag + " 1. the source, and a test that writes nothing ===");
  await ok(realmApi + "/attribute-sources/add-source", source,
           "added the " + tag + " source");
  const tested = await postJson(realmApi + "/attribute-sources/test-source",
                                { id: spec.sourceId, username: ALICE });
  check("1. " + tag + ": test-source connects over verified TLS with the " +
        "password from the file, and reads the row", function () {
    assert.strictEqual(tested.status, 200, tested.raw.slice(0, 400));
    assert.ok(tested.body.found &&
              tested.body.row.cost_center[0] === "CC-42",
              JSON.stringify(tested.body));
  });

  log.info("=== " + tag +
           " 2. a sign-in reads it, and the token carries it ===");
  const claims = await redeem(await authorize(browser(spec.state + "-alice"),
                                              spec.state + "-s1"));
  check("2. " + tag + ": the access token issued after the sign-in carries " +
        "the attribute claim", function () {
    assert.strictEqual(claims.cost_center, "CC-42", JSON.stringify(claims));
  });
  const editor = await send(realmApi + "/users?user=" +
                            encodeURIComponent(ALICE), {});
  const grade = ((editor.body && editor.body.attributeEditor &&
                  editor.body.attributeEditor.attributes) || [])
    .filter(function (one) {
      return one.name === "employeeType";
    })[0];
  check("2. " + tag + ": and the other column is on the person's entry",
        function () {
    assert.ok(grade && grade.values.indexOf("G7") >= 0,
              JSON.stringify(grade));
  });

  log.info("=== " + tag + " 3. the row changes; refresh-person reads it ===");
  await setRow(spec, "CC-43");
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
  check("3. " + tag + ": refresh-person writes the new value, and the " +
        "claims preview carries it", function () {
    assert.ok(refreshed.status === 200 && refreshed.body.ok,
              refreshed.raw.slice(0, 400));
    assert.ok(row && row.value === "CC-43", JSON.stringify(row));
  });

  log.info("=== " + tag + " 4. a chain that did not sign the database ===");
  const stranger = await outboundCa.makeCa();
  await ok(realmApi + "/attribute-sources/update-source",
           { id: spec.sourceId, caCertificates: stranger.certPem },
           "named a chain that did not sign the " + tag + " database");
  const refused = await postJson(realmApi + "/attribute-sources/test-source",
                                 { id: spec.sourceId, username: ALICE });
  check("4. " + tag + ": the connection is refused: the certificate is " +
        "verified against the source's chain alone", function () {
    assert.strictEqual(refused.status, 400, refused.raw.slice(0, 400));
    assert.ok(/certificate|self.signed|verify/i.test(
                (refused.body.errors || []).join(" ")),
              JSON.stringify(refused.body));
  });

  log.info("=== " + tag + " 5. onFailure refuse: the sign-in is refused ===");
  await ok(realmApi + "/attribute-sources/update-source",
           { id: spec.sourceId, onFailure: "refuse" },
           "set onFailure refuse on " + tag);
  const denied = await authorize(browser(spec.state + "-again"),
                                 spec.state + "-s2");
  check("5. " + tag + ": a sign-in whose refusing source cannot be read " +
        "reaches the client as access_denied", function () {
    assert.ok(/[?&]error=access_denied/.test(denied.location),
              denied.status + " " + denied.location);
  });

  log.info("=== " + tag + " 6. removed ===");
  await ok(realmApi + "/attribute-sources/remove-source",
           { id: spec.sourceId }, "removed the " + tag + " source");
  log.debug("Leaving exerciseSource().");
}

async function runSource(spec) {
  log.debug("Entering runSource(). " + spec.dialect);
  try {
    const pem = await setUpDatabase(spec);
    // The same path in both containers: the runner writes it, the service
    // reads it through the `file` provider.
    fs.writeFileSync(spec.passwordFile, spec.readerPassword, { mode: 0o644 });
    await exerciseSource(spec, pem);
  } finally {
    await tearDownDatabase(spec);
  }
  log.debug("Leaving runSource().");
}

function dialectsOf(shared) {
  log.debug("Entering dialectsOf().");
  const specs = [];
  if (DB_URL) {
    specs.push({ dialect: "postgres", label: "PostgreSQL", sourceId: "hr",
      state: "pg", url: DB_URL, port: 5432, database: PG_DATABASE,
      reader: PG_READER, readerPassword: PG_PASSWORD,
      passwordFile: path.join(shared.dir, "attrsrc-" + SAFE + ".pw") });
  }
  if (MYSQL_URL) {
    specs.push({ dialect: "mysql", label: "MariaDB", sourceId: "hr-mysql",
      state: "my", url: MYSQL_URL, port: 3306, database: MY_DATABASE,
      reader: MY_READER, readerPassword: MY_PASSWORD,
      passwordFile: path.join(shared.dir, "attrsrc-" + SAFE + "-mysql.pw") });
  }
  log.debug("Leaving dialectsOf(). " + specs.length);
  return specs;
}

async function test() {
  log.debug("Entering test().");
  const shared = outboundCa.caLocation();
  if (!shared || (!DB_URL && !MYSQL_URL)) {
    log.info("SKIPPED: " + (!shared ? outboundCa.skipReason()
      : "neither STS_TEST_ATTRIBUTE_DB_URL nor " +
        "STS_TEST_ATTRIBUTE_MYSQL_URL is set, so there is no database " +
        "this job may create one in (the compose stack sets both; an AWS " +
        "target and ./run-coverage.sh do not)."));
    log.debug("Leaving test(). Skipped.");
    return;
  }
  if (!DB_URL) {
    log.info("PostgreSQL half skipped: STS_TEST_ATTRIBUTE_DB_URL is not set.");
  }
  if (!MYSQL_URL) {
    log.info("MariaDB half skipped: STS_TEST_ATTRIBUTE_MYSQL_URL is not set.");
  }
  const specs = dialectsOf(shared);

  log.info("=== 0. a realm, a person, a client, a claim ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "attribute sources " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", { identifier: CLIENT,
    kind: "oauth2-client", name: CLIENT, protocols: ["oauth2", "oidc"],
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
  // The realm's attribute policy (#396) requires givenName, sn and mail of
  // every person in product mode.
  await ok(realmApi + "/users/create", { username: ALICE, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Attr " + ALICE, givenName: "Attr", sn: "Source",
                  mail: ALICE + "@attr-source.test" } },
    "created " + ALICE);
  await ok(realmApi + "/claims/add-attribute-claim", { set: "access_token",
    name: "cost_center", attribute: "costCenter" },
    "added the cost_center attribute claim");

  for (let i = 0; i < specs.length; i++) {
    await runSource(specs[i]);
  }
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_attribute_sources FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
