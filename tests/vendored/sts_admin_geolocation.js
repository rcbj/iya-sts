// File: sts_admin_geolocation.js
//
// ===========================================================================
// MONITORING → GEOLOCATION OVER HTTP, IN EVERY MODE (#255, 2026-09-26).
//
// `tests/geolocation_map.js` holds the count, the suppression and the
// picture to their rules in process, on seeded assessments and the memory
// store. This job holds the RUNNING service to them through the two doors
// an operator uses — `/admin/geolocation` and `/admin-api/geolocation` — so
// that in `single-node` and `cluster` it is the postgres driver's GROUPING
// SETS that answers:
//
//   1. THE LIVE WINDOW, the default: this job's own console sign-in is a
//      live session with an assessment, so the realm counts at least one,
//      and a count under `risk.geoMinimumCount` comes back with no number.
//   2. EVERY WINDOW AND LEVEL answers in its shape: the seven continents,
//      a continent's countries, a country's cities and what was held back.
//   3. THE REFUSALS: an unknown window, continent or country, and a country
//      named with a continent it is not in, are each a 400.
//   4. THE PAGE is drawn with the map inline, no script, the zoom trail and
//      the outlines' credit; `?format=json` is the API's answer (rule 7);
//      a refused query is a 400 page.
//
// NOTHING HERE LOADS A DATASET. A geolocation dataset is the service's, not
// the realm's, and against an AWS target it is a real one, so this job
// asserts shapes and the rules that hold whatever the addresses resolve to
// — the suite's own addresses are private and resolve to nowhere.
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
const log = bunyan.createLogger({ name: "sts_admin_geolocation",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const crypto = require("crypto");
const signin = require("./console_signin");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36) + crypto.randomBytes(3).toString("hex");
const CONTINENTS = ["africa", "antarctica", "asia", "europe",
                    "north-america", "oceania", "south-america"];

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
  return { status: r.status, body: body, text: text };
}

async function api(query) {
  log.debug("Entering api(). " + query);
  const reply = await call("GET", base + "/admin-api/geolocation" +
                           (query ? "?" + query : ""));
  log.debug("Leaving api().");
  return reply;
}

// A place's count obeys the minimum: a number at or over it, or null and
// suppressed under it.
function obeys(place, k, what) {
  log.debug("Entering obeys(). " + what);
  if (place.people === null) {
    assert.strictEqual(place.signIns, null, what + ": " +
                       JSON.stringify(place));
  } else {
    assert.ok(place.people >= k, what + " is numbered under the minimum: " +
              JSON.stringify(place));
  }
  log.debug("Leaving obeys().");
}

async function theLiveWindow(cookie) {
  log.debug("Entering theLiveWindow().");
  log.info("=== 1. the live window ===");
  const r = await api("");
  check("GET /admin-api/geolocation answers the world's live sessions by " +
        "default, under the minimum with no number", function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          const v = r.body;
          assert.strictEqual(v.window, "live", JSON.stringify(v.window));
          assert.strictEqual(v.level, "world");
          assert.ok(Number.isInteger(v.minimumCount) && v.minimumCount >= 1,
                    JSON.stringify(v.minimumCount));
          assert.ok(typeof v.liveSessions === "number", JSON.stringify(v));
          if (cookie) {
            // This job's console sign-in is one of them.
            assert.ok(v.liveSessions >= 1, JSON.stringify(v).slice(0, 400));
            assert.ok(v.total.people !== null || v.total.suppressed,
                      JSON.stringify(v.total));
          }
          obeys(v.total, v.minimumCount, "the total");
        });
  log.debug("Leaving theLiveWindow().");
}

async function everyWindowAndLevel() {
  log.debug("Entering everyWindowAndLevel().");
  log.info("=== 2. every window and level ===");
  for (const w of ["24h", "7d", "30d"]) {
    const r = await api("window=" + w);
    check("window=" + w + ": seven continents, every count at or over " +
          "the minimum or held back", function () {
            assert.strictEqual(r.status, 200, r.text.slice(0, 300));
            const v = r.body;
            assert.strictEqual(v.window, w);
            assert.deepStrictEqual(v.continents.map(function (c) {
              return c.continent;
            }), CONTINENTS);
            v.continents.concat(v.countries, [v.total, v.unknown])
              .forEach(function (p) {
                obeys(p, v.minimumCount, JSON.stringify(p.name || p));
              });
            assert.deepStrictEqual(v.cities, [],
                                   "the world lists no city");
          });
  }
  const eu = await api("window=30d&continent=europe");
  check("a continent: its countries only, and its own total", function () {
    assert.strictEqual(eu.status, 200, eu.text.slice(0, 300));
    assert.strictEqual(eu.body.level, "continent");
    assert.strictEqual(eu.body.continent.name, "Europe");
    assert.ok(eu.body.countries.every(function (c) {
      return c.continent === "europe";
    }), JSON.stringify(eu.body.countries));
  });
  const fr = await api("window=30d&country=fr");
  check("a country: its cities, each at or over the minimum, and what was " +
        "held back", function () {
          assert.strictEqual(fr.status, 200, fr.text.slice(0, 300));
          const v = fr.body;
          assert.strictEqual(v.level, "country");
          assert.strictEqual(v.country.iso, "FR");
          assert.strictEqual(v.continent.continent, "europe");
          assert.ok(v.cities.every(function (c) {
            return c.people >= v.minimumCount;
          }), JSON.stringify(v.cities));
          assert.ok(Number.isInteger(v.hidden.cities) &&
                    Number.isInteger(v.hidden.signIns),
                    JSON.stringify(v.hidden));
        });
  log.debug("Leaving everyWindowAndLevel().");
}

async function theRefusals() {
  log.debug("Entering theRefusals().");
  log.info("=== 3. the refusals ===");
  for (const q of ["window=1y", "continent=atlantis", "country=ZZ",
                   "country=FR&continent=asia"]) {
    const r = await api(q);
    check(q + " is refused", function () {
      assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    });
  }
  log.debug("Leaving theRefusals().");
}

async function thePage(cookie) {
  log.debug("Entering thePage().");
  log.info("=== 4. the page ===");
  if (!cookie) {
    log.info("  (the console gate is off in this stack: the page is " +
             "checked without a session)");
  }
  const headers = cookie ? { Cookie: cookie } : {};
  const world = await call("GET", base + "/admin/geolocation?window=30d",
                           { headers: headers });
  check("Monitoring → Geolocation is drawn with the map inline, no script " +
        "on it, and the outlines credited", function () {
          assert.strictEqual(world.status, 200, world.text.slice(0, 300));
          const at = world.text.indexOf('<svg xmlns="http://www.w3.org/2000/' +
                                        'svg" id="geo-map"');
          assert.ok(at >= 0, "no map on the page");
          const svg = world.text.slice(at, world.text.indexOf("</svg>", at));
          assert.ok(svg.indexOf("<script") < 0, "a script in the map");
          assert.ok(/continent=europe/.test(svg),
                    "no country on the world links to its continent");
          assert.ok(world.text.indexOf("Made with Natural Earth") >= 0,
                    "the outlines are not credited");
        });
  const fr = await call("GET", base + "/admin/geolocation?country=FR",
                        { headers: headers });
  check("a country's page has the zoom trail back through its continent",
        function () {
          assert.strictEqual(fr.status, 200, fr.text.slice(0, 300));
          assert.ok(fr.text.indexOf('id="geo-zoom-continent"') >= 0 &&
                    fr.text.indexOf('id="geo-zoom-world"') >= 0,
                    "no zoom trail");
        });
  const json = await call("GET", base + "/admin/geolocation?format=json&" +
                          "window=7d", { headers: headers });
  const viaApi = await api("window=7d");
  check("?format=json is the management API's answer (rule 7)",
        function () {
          assert.strictEqual(json.status, 200, json.text.slice(0, 300));
          ["window", "level", "minimumCount", "continents"]
            .forEach(function (k) {
              assert.deepStrictEqual(json.body[k], viaApi.body[k], k);
            });
        });
  const bad = await call("GET", base + "/admin/geolocation?continent=" +
                         "atlantis", { headers: headers });
  check("a refused query is a 400 page", function () {
    assert.strictEqual(bad.status, 400, bad.text.slice(0, 300));
  });
  log.debug("Leaving thePage().");
}

async function main() {
  log.debug("Entering main().");
  const admin = "geo-admin-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, admin, log,
                                                 { grant: "read" });
  await theLiveWindow(cookie || "");
  await everyWindowAndLevel();
  await theRefusals();
  await thePage(cookie || "");
  log.info("sts_admin_geolocation: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_admin_geolocation FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
