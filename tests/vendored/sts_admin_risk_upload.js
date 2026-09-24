// File: sts_admin_risk_upload.js
//
// ===========================================================================
// A RISK DATASET UPLOADED AS A FILE, OVER HTTP, IN EVERY MODE (#215,
// 2026-09-24).
//
// `tests/risk_upload.js` holds `risk/risk_upload.ts` and `risk_expand.ts` to
// their rules in process. This job holds the RUNNING service to them through
// both doors — which is where the parts a unit cannot reach are: the body
// parsers leaving exactly these paths unread (`common/app.js`), the console
// gate leaving the CSRF token to the upload, the request pool piping the
// body to a worker in `single-node` and `cluster`, and the balancer:
//
//   1. THE API: a synthetic `.gz` list through `POST /admin-api/risk/upload`
//      is answered 202 while `loading`, becomes `active` in `GET
//      /admin-api/risk`, and a lookup inside it names the list.
//   2. THE CONSOLE: Monitoring → Risk draws the upload form (multipart, no
//      script, the file last); a `.zip` posted through it with a real
//      session and the page's own CSRF token is redirected back with a
//      notice and becomes `active`.
//   3. A REALM: the same upload under `/realm/<id>/admin-api/…` loads that
//      realm's operator list — the exemption reads the path after the realm
//      prefix is taken off.
//   4. THE REFUSALS: a declared length over risk.uploadMaxBytes (413, before
//      a byte is read); a zip of two files and a gzip decompression bomb,
//      each `loading` then `refused` with its reason; a console upload with
//      no CSRF token (403); the wrong body type (415); a session holding
//      Admin Read only (403 at the gate).
//
// Every file is built here from synthetic lines in 198.18.0.0/15 (RFC 2544);
// none is committed, and each run's lines carry a stamp so its versions are
// new against a store an earlier run used.
// ===========================================================================

const assert = require("assert");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js (beside this file) gives.
  appconfigProblem = e;
  appconfig = {};
}

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "sts_admin_risk_upload",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const crypto = require("crypto");
const https = require("https");
const http = require("http");
const zlib = require("zlib");
const signin = require("./console_signin");
const zipWriter = require("./zip_writer");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36) + crypto.randomBytes(3).toString("hex");
const DATASET = "iplist.operator-deny";

// N synthetic addresses in 198.18.0.0/15, from `third` on, one per line,
// with the stamp in a comment.
function listOf(n, third, what) {
  log.debug("Entering listOf().");
  const lines = ["# sts_admin_risk_upload " + STAMP + " " + what];
  for (let i = 0; i < n; i++) {
    lines.push("198.18." + (third + Math.floor(i / 250)) + "." + (i % 250));
  }
  log.debug("Leaving listOf().");
  return lines.join("\n") + "\n";
}

// TWELVE MEGABYTES OF COMMENT, random so it compresses only two to one: an
// upload of several megabytes even compressed — past the 5 MB the body
// parsers would have taken, which is the exemption under test — whose rows
// are still few enough to load in seconds in every mode.
function padding() {
  log.debug("Entering padding().");
  const lines = [];
  for (let i = 0; i < 12 * 1024 * 1024 / 66; i++) {
    lines.push("# " + crypto.randomBytes(32).toString("hex"));
  }
  log.debug("Leaving padding().");
  return lines.join("\n") + "\n";
}

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page or an empty body. The text is kept.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           location: r.headers.get("location") || "" };
}

// A file to the API door: the body is the file, the fields the query.
async function upload(prefix, query, file, type) {
  log.debug("Entering upload().");
  const q = new URLSearchParams(query).toString();
  const reply = await call("POST", base + prefix + "/admin-api/risk/upload?" +
                           q, { headers: { "Content-Type": type ||
                                           "application/octet-stream" },
                                body: file });
  log.debug("Leaving upload().");
  return reply;
}

// A version's row once it is no longer loading, read the way an operator
// reads it: GET /admin-api/risk.
async function settled(prefix, realm, version) {
  log.debug("Entering settled(). " + version);
  const deadline = Date.now() + 60000;
  for (;;) {
    const r = await call("GET", base + prefix + "/admin-api/risk?realm=" +
                         encodeURIComponent(realm));
    assert.strictEqual(r.status, 200, "GET /admin-api/risk answered " +
                       r.status + " " + r.text.slice(0, 300));
    const d = r.body.datasets.filter(function (one) {
      return one.dataset === DATASET;
    })[0] || { versions: [] };
    const v = d.versions.filter(function (one) {
      return one.version === version;
    })[0];
    if (v && v.state !== "loading") {
      log.debug("Leaving settled(). " + v.state);
      return { version: v, dataset: d };
    }
    if (Date.now() > deadline) {
      log.debug("Leaving settled(). Timed out.");
      assert.fail("version " + version + " of " + DATASET + " was still " +
                  (v ? v.state : "not recorded") + " after a minute");
    }
    await new Promise(function (resolve) { setTimeout(resolve, 500); });
  }
}

async function theApi() {
  log.debug("Entering theApi().");
  log.info("=== 1. the management API ===");
  const text = listOf(3000, 60, "api") + padding();
  const gz = zlib.gzipSync(text);
  assert.ok(gz.length > 5 * 1024 * 1024, "the fixture is " + gz.length +
            " bytes, meant to be past the body parsers' 5 MB");
  const r = await upload("", { dataset: DATASET, format: "ip-list",
                               realm: "default" }, gz, "application/gzip");
  check("POST /admin-api/risk/upload of a " + gz.length + "-byte .gz " +
        "answers 202 while the version loads, with the file's own SHA-256",
        function () {
          assert.strictEqual(r.status, 202, r.text.slice(0, 400));
          assert.strictEqual(r.body.state, "loading", r.text);
          assert.strictEqual(r.body.kind, "gzip", r.text);
          assert.strictEqual(r.body.sha256, crypto.createHash("sha256")
            .update(gz).digest("hex"), r.text);
        });
  const done = await settled("", "default", r.body.version);
  check("and it becomes active with every row", function () {
    assert.strictEqual(done.version.state, "active",
                       JSON.stringify(done.version));
    assert.strictEqual(done.version.rowCount, 3000,
                       JSON.stringify(done.version));
  });
  const look = await call("GET", base + "/admin-api/risk?realm=default" +
                          "&address=198.18.65.7");
  check("a lookup inside it names the list and the version", function () {
    assert.strictEqual(look.status, 200, look.text.slice(0, 300));
    assert.strictEqual(look.body.lookup.datasets[DATASET], r.body.version,
                       JSON.stringify(look.body.lookup));
  });
  log.debug("Leaving theApi().");
}

async function theConsole(cookie) {
  log.debug("Entering theConsole().");
  log.info("=== 2. the console ===");
  const page = await call("GET", base + "/admin/risk",
                          { headers: { Cookie: cookie || "" } });
  const FORM = /<form[^>]*id="risk-upload-form"[\s\S]*?<\/form>/;
  const form = (page.text.match(FORM) || [])[0] || "";
  check("Monitoring → Risk draws a multipart upload form with the file last " +
        "and a real submit button", function () {
          assert.strictEqual(page.status, 200, page.text.slice(0, 300));
          assert.ok(/enctype="multipart\/form-data"/.test(form), form);
          assert.ok(form.lastIndexOf('type="file"') >
                    form.lastIndexOf('name="sha256"'), form);
          assert.ok(/<button type="submit" id="risk-upload"/.test(form), form);
          assert.ok(!/<script/i.test(page.text), "a script on the page");
        });
  if (!cookie) {
    log.info("  (the console gate is off in this stack: no session, so no " +
             "CSRF token to carry)");
  }
  const token = (form.match(/name="csrf_token" value="([^"]+)"/) || [])[1] ||
                "";
  const zip = zipWriter.makeZip([
    { name: "__MACOSX/._deny.txt", data: "resource fork" },
    { name: "deny.txt", data: listOf(2500, 80, "console") + padding() }]);
  const fd = new FormData();
  if (token) {
    fd.append("csrf_token", token);
  }
  fd.append("dataset", DATASET);
  fd.append("format", "ip-list");
  fd.append("realm", "default");
  fd.append("file", new Blob([zip], { type: "application/zip" }),
            "deny.zip");
  const posted = await call("POST", base + "/admin/risk/upload",
                            { headers: { Cookie: cookie || "" }, body: fd });
  check("a " + zip.length + "-byte zip posted through it with the page's " +
        "token is redirected back with a notice", function () {
          assert.strictEqual(posted.status, 303, posted.text.slice(0, 300));
          assert.ok(/notice=/.test(posted.location), posted.location);
        });
  const version = decodeURIComponent(posted.location)
    .match(/version ([0-9a-f]{16})/)[1];
  const done = await settled("", "default", version);
  check("and the zip's one file becomes active", function () {
    assert.strictEqual(done.version.state, "active",
                       JSON.stringify(done.version));
    assert.strictEqual(done.version.rowCount, 2500,
                       JSON.stringify(done.version));
  });
  if (cookie) {
    const bare = new FormData();
    bare.append("dataset", DATASET);
    bare.append("format", "ip-list");
    bare.append("file", new Blob([listOf(3, 90, "no token")]), "x.txt");
    const refused = await call("POST", base + "/admin/risk/upload",
                               { headers: { Cookie: cookie }, body: bare });
    check("a console upload with no CSRF token is refused", function () {
      assert.strictEqual(refused.status, 403, refused.text.slice(0, 300));
    });
  }
  log.debug("Leaving theConsole().");
}

async function aRealm() {
  log.debug("Entering aRealm().");
  log.info("=== 3. a realm ===");
  const realm = "risk-up-" + STAMP;
  const made = await call("POST", base + "/admin-api/realms/create", {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: realm, domain: realm + ".example.net",
                           name: "Risk upload test " + STAMP }) });
  assert.strictEqual(made.status, 200, "creating " + realm + " answered " +
                     made.status + " " + made.text.slice(0, 300));
  const R = "/realm/" + realm;
  const r = await upload(R, { dataset: DATASET, format: "ip-list",
                              realm: realm },
                         Buffer.from(listOf(40, 100, "realm")));
  check("an upload under /realm/<id>/admin-api is answered 202", function () {
    assert.strictEqual(r.status, 202, r.text.slice(0, 400));
  });
  const done = await settled(R, realm, r.body.version);
  check("and loads that realm's own operator list", function () {
    assert.strictEqual(done.version.state, "active",
                       JSON.stringify(done.version));
    assert.strictEqual(done.dataset.realm, realm,
                       JSON.stringify(done.dataset.realm));
  });
  log.debug("Leaving aRealm().");
}

// A request that DECLARES a length and sends nothing: the refusal has to
// come from the headers alone.
function declaredOnly(length) {
  log.debug("Entering declaredOnly().");
  const u = new URL(base + "/admin-api/risk/upload?dataset=" + DATASET +
                    "&format=ip-list&realm=default");
  const mod = u.protocol === "http:" ? http : https;
  log.debug("Leaving declaredOnly().");
  return new Promise(function (resolve, reject) {
    const req = mod.request({ hostname: u.hostname, port: u.port,
                              path: u.pathname + u.search, method: "POST",
                              headers: { "Content-Type":
                                         "application/octet-stream",
                                         "Content-Length": String(length) } },
                            function (res) {
                              let text = "";
                              res.on("data", function (c) { text += c; });
                              res.on("end", function () {
                                resolve({ status: res.statusCode, text: text,
                                          connection: res.headers.connection });
                                req.destroy();
                              });
                            });
    req.on("error", reject);
    req.flushHeaders();
  });
}

async function theRefusals(readOnlyCookie) {
  log.debug("Entering theRefusals().");
  log.info("=== 4. the refusals ===");
  const over = await declaredOnly(1024 * 1024 * 1024 * 1024);
  check("a declared length over risk.uploadMaxBytes is refused before a " +
        "byte is sent, and the connection is closed", function () {
          assert.strictEqual(over.status, 413, over.text.slice(0, 300));
          assert.ok(/risk\.uploadMaxBytes/.test(over.text), over.text);
          assert.strictEqual(over.connection, "close", over.connection);
        });
  const two = zipWriter.makeZip([
    { name: "a.txt", data: listOf(3, 110, "two a") },
    { name: "b.txt", data: listOf(3, 111, "two b") }]);
  const r2 = await upload("", { dataset: DATASET, format: "ip-list",
                                realm: "default",
                                version: "two-" + STAMP },
                          two, "application/zip");
  const v2 = await settled("", "default", "two-" + STAMP);
  check("a zip of two files is refused as ambiguous, naming them", function () {
    assert.strictEqual(r2.status, 202, r2.text.slice(0, 300));
    assert.strictEqual(v2.version.state, "refused",
                       JSON.stringify(v2.version));
    assert.ok(/a\.txt, b\.txt/.test(v2.version.refusal), v2.version.refusal);
  });
  const bomb = zlib.gzipSync(Buffer.alloc(24 * 1024 * 1024, 0x61),
                             { level: 9 });
  const r3 = await upload("", { dataset: DATASET, format: "ip-list",
                                realm: "default",
                                version: "bomb-" + STAMP }, bomb);
  const v3 = await settled("", "default", "bomb-" + STAMP);
  check("a gzip decompression bomb (" + bomb.length + " bytes, 24 MiB " +
        "expanded) is refused as it expands", function () {
          assert.strictEqual(r3.status, 202, r3.text.slice(0, 300));
          assert.strictEqual(v3.version.state, "refused",
                             JSON.stringify(v3.version));
          assert.ok(/decompression bomb/.test(v3.version.refusal),
                    v3.version.refusal);
        });
  const wrongType = await upload("", { dataset: DATASET, format: "ip-list",
                                       realm: "default" },
                                 Buffer.from("198.18.0.1\n"), "text/plain");
  check("a body type the API does not take is refused 415", function () {
    assert.strictEqual(wrongType.status, 415, wrongType.text.slice(0, 300));
  });
  if (readOnlyCookie) {
    const fd = new FormData();
    fd.append("dataset", DATASET);
    fd.append("format", "ip-list");
    fd.append("file", new Blob([listOf(3, 120, "read only")]), "x.txt");
    const refused = await call("POST", base + "/admin/risk/upload",
                               { headers: { Cookie: readOnlyCookie },
                                 body: fd });
    check("a session holding Admin Read only is refused at the gate",
          function () {
            assert.strictEqual(refused.status, 403,
                               refused.text.slice(0, 300));
          });
  }
  log.debug("Leaving theRefusals().");
}

async function main() {
  log.debug("Entering main().");
  const cookie = await signin.signInToTheConsole(base, "risk-up-" + STAMP,
                                                 log, { grant: "write" });
  const reader = cookie
    ? await signin.signInToTheConsole(base, "risk-ro-" + STAMP, log,
                                      { grant: "read" })
    : null;
  await theApi();
  await theConsole(cookie || "");
  await aRealm();
  await theRefusals(reader);
  log.info("sts_admin_risk_upload: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_admin_risk_upload FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
