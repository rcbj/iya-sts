// File: sts_admin_closed_sets.js
//
// ===========================================================================
// EVERY CLOSED SET AN ADMINISTRATOR CAN TYPE INTO, HELD AT EVERY DOOR (#86,
// 2026-09-26).
//
// Numerous `/admin-api` and console fields accept only a fixed set of
// strings, and until #86 nothing refused any other value: the API's
// validator compiled its schemas with `enum` stripped, query parameters were
// never checked against the enums they declare, and a console form never
// reached that validator at all. The set is declared ONCE, as an `enum` in
// the OpenAPI document, and `common/closed_sets.ts` enforces it at three
// doors. This job holds the running service to all three, and to the
// settings table's own `enum` rows, which are the fourth:
//
//   1. THE REQUEST BODY. Every enum the document declares in a request
//      schema — nested members, array items and `$ref`'d components
//      included — is posted a value outside its set, and must be refused
//      400 with a sentence naming the field and every value it accepts. The
//      POSITIVE half posts a value FROM the set together with a member no
//      schema defines, so the validator refuses on that member and must say
//      nothing about the enum — which proves an accepted value is accepted
//      without the operation running. An operation whose top level accepts
//      any member is left out of the positive half, and counted.
//   2. THE QUERY STRING. Every query parameter with an enum is sent a value
//      outside it (400, the same sentence); on a GET, a value from it must
//      not be refused on that parameter.
//   3. THE CONSOLE. Every operation whose description says it mirrors a
//      `POST /admin…` control has its FLAT enums posted to each such page as
//      a real form — a console session, the page's CSRF token, the
//      operation's `action` — with a value outside the set; the console must
//      refuse it 400 `invalid_value` before any handler runs.
//   4. THE SETTINGS. Every runtime setting of type `enum` in `GET
//      /admin-api/config`, and every `csv` one carrying `csvValues` (a list
//      with one entry outside it), is set to a value outside its set through
//      `POST /admin-api/config/set-many` (refused, all-or-nothing) and through
//      the console's `set-many` on `/admin/config`; afterwards no setting
//      holds the value.
//
// Nothing here lists an endpoint or a set: both come off the document the
// service publishes, so an enum added tomorrow is probed tomorrow. The floors
// below are for the failure a discovering job has, which is not zero rows but
// SOME — an extractor that broke on one shape quietly probing a fraction.
//
// Every refusal is made before a handler runs, so nothing is written; the
// positive probes are refused on the extra member for the same reason. The
// console session is the only thing left behind (`console_signin.js`).
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
const log = bunyan.createLogger({ name: "sts_admin_closed_sets",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const signin = require("./console_signin");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const API = base + "/admin-api";

// A value no set here holds: not empty (empty is absent at two doors), not a
// word any enum could plausibly add.
const OUTSIDE = "__not-a-value-86__";
// The member no request schema defines, for the positive half.
const EXTRA = "__probe86__";
// The words `common/closed_sets.ts`'s sentence always carries.
const SENTENCE = /which is not one of the \d+ values? it accepts:/;

// The floors, set below what was measured once #86's audit had declared its
// enums (116 body enums and 154 console controls in process) so an
// enum removed on purpose does not fail the job, while an extractor that
// stopped seeing a whole shape does.
const MINIMUM_BODY_ENUMS = 100;
const MINIMUM_QUERY_ENUMS = 20;
const MINIMUM_CONSOLE_PROBES = 100;
const MINIMUM_ENUM_SETTINGS = 50;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("  ✓ " + what);
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

async function postJson(url, body) {
  log.debug("Entering postJson(). " + url);
  const r = await call("POST", url, {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  log.debug("Leaving postJson().");
  return r;
}

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  const errors = (r.body && Array.isArray(r.body.errors)) ? r.body.errors : [];
  log.debug("Leaving errorsOf().");
  return errors.join(" ");
}

// Every enum a schema declares OUTSIDE an alternative — the rule
// `common/closed_sets.ts` collects by — as { path, values }, `*` for an
// array's items. An enum inside `anyOf`/`oneOf` is enforced by ajv in the
// terms of the alternative and is not probed here.
function enumsOf(schema, components, path, out, depth) {
  log.debug("Entering enumsOf().");
  if (!schema || typeof schema !== "object" || depth > 12) {
    log.debug("Leaving enumsOf().");
    return out;
  }
  if (typeof schema.$ref === "string") {
    const m = /^#\/components\/schemas\/(.+)$/.exec(schema.$ref);
    enumsOf(m && components[m[1]], components, path, out, depth + 1);
    log.debug("Leaving enumsOf().");
    return out;
  }
  if (Array.isArray(schema.enum) && path.length) {
    out.push({ path: path.slice(), values: schema.enum.slice(),
               type: schema.type });
  }
  (schema.allOf || []).forEach(function (part) {
    enumsOf(part, components, path, out, depth + 1);
  });
  if (schema.items) {
    enumsOf(schema.items, components, path.concat("*"), out, depth + 1);
  }
  Object.keys(schema.properties || {}).forEach(function (name) {
    enumsOf(schema.properties[name], components, path.concat(name), out,
            depth + 1);
  });
  log.debug("Leaving enumsOf().");
  return out;
}

// A body holding `value` at `path`, `*` being a one-member array.
function bodyAt(path, value) {
  log.debug("Entering bodyAt().");
  let inner = value;
  for (let i = path.length - 1; i >= 0; i--) {
    if (path[i] === "*") {
      inner = [inner];
    } else {
      const o = {};
      o[path[i]] = inner;
      inner = o;
    }
  }
  log.debug("Leaving bodyAt().");
  return inner;
}

// How the refusal names a path: ajv's instance path with dots.
function spelt(path) {
  log.debug("Entering spelt().");
  log.debug("Leaving spelt().");
  return path.map(function (p) {
    return p === "*" ? "0" : p;
  }).join(".");
}

function namesEvery(text, values) {
  log.debug("Entering namesEvery().");
  log.debug("Leaving namesEvery().");
  return values.every(function (v) {
    return text.indexOf(JSON.stringify(v)) >= 0;
  });
}

// A concrete path for a documented one: a path parameter is filled with a
// name nothing holds, which reaches the operation's checks without naming
// anything real.
function concrete(path) {
  log.debug("Entering concrete().");
  log.debug("Leaving concrete().");
  return path.replace(/\{[^}]+\}|:[A-Za-z_]+/g, "probe86");
}

// The `POST /admin…` pages an operation's description says it mirrors
// (`admin_api_spec.ts` writes "**Mirrors** `…` on the admin console.").
function mirroredPages(op) {
  log.debug("Entering mirroredPages().");
  const said = /\*\*Mirrors\*\* `([^`]*)`/.exec(String(op.description || ""));
  const pages = [];
  const re = /POST (\/admin(?:\/[^\s,]*)?)/g;
  let m;
  while (said && (m = re.exec(said[1])) !== null) {
    pages.push(m[1]);
  }
  log.debug("Leaving mirroredPages().");
  return pages;
}

async function theDocument() {
  log.debug("Entering theDocument().");
  const r = await call("GET", API + "/openapi.json");
  assert.strictEqual(r.status, 200, "GET /admin-api/openapi.json: " +
                                    r.text.slice(0, 300));
  const ops = [];
  Object.keys(r.body.paths || {}).forEach(function (path) {
    Object.keys(r.body.paths[path]).forEach(function (method) {
      const op = r.body.paths[path][method];
      if (!op || typeof op !== "object" || !op.responses) {
        return;
      }
      ops.push({ path: path, method: method.toUpperCase(), op: op });
    });
  });
  log.debug("Leaving theDocument(). " + ops.length + " operation(s).");
  return { ops: ops,
           components: (r.body.components && r.body.components.schemas) ||
                       {} };
}

function requestSchemaOf(op) {
  log.debug("Entering requestSchemaOf().");
  const content = op.requestBody && op.requestBody.content;
  const json = content && (content["application/json"] ||
                           content[Object.keys(content)[0]]);
  log.debug("Leaving requestSchemaOf().");
  return (json && json.schema) || null;
}

// 1. The request body, both halves.
async function theBodies(doc) {
  log.debug("Entering theBodies().");
  log.info("=== 1. every enum in a request body ===");
  let probed = 0;
  let positives = 0;
  const openTop = [];
  for (const row of doc.ops) {
    if (row.method === "GET") {
      continue;
    }
    const schema = requestSchemaOf(row.op);
    const fields = enumsOf(schema, doc.components, [], [], 0);
    for (const f of fields) {
      const url = base + concrete(row.path);
      const where = row.method + " " + row.path + " " + f.path.join(".");
      const bad = await postJson(url, bodyAt(f.path, OUTSIDE));
      const said = errorsOf(bad);
      check(where + " refuses a value outside its set", function () {
        assert.strictEqual(bad.status, 400, where + ": " +
                           bad.text.slice(0, 400));
        assert.ok(SENTENCE.test(said) &&
                  said.indexOf('"' + spelt(f.path) + '"') >= 0 &&
                  namesEvery(said, f.values),
                  where + ": the refusal should name the field and all " +
                  f.values.length + " values; it said " + said);
      });
      probed += 1;
      if (!schema || schema.additionalProperties !== false) {
        openTop.push(where);
        continue;
      }
      const body = bodyAt(f.path, f.values[0]);
      body[EXTRA] = true;
      const good = await postJson(url, body);
      const goodSaid = errorsOf(good);
      check(where + " accepts " + JSON.stringify(f.values[0]), function () {
        assert.strictEqual(good.status, 400, where + ": the extra member " +
                           "should have been refused: " +
                           good.text.slice(0, 400));
        assert.ok(goodSaid.indexOf('"' + EXTRA + '"') >= 0, where + ": " +
                  goodSaid);
        assert.ok(!SENTENCE.test(goodSaid), where + ": a value from the set " +
                  "was refused as outside it: " + goodSaid);
      });
      positives += 1;
    }
  }
  check(probed + " body enums probed (floor " + MINIMUM_BODY_ENUMS + ")",
        function () {
          assert.ok(probed >= MINIMUM_BODY_ENUMS, "only " + probed +
                    " request-body enums were found in the document");
        });
  log.info("  " + probed + " body enums refused outside their set; " +
           positives + " accepted from it; " + openTop.length +
           " left out of the positive half (the top level takes any " +
           "member): " + openTop.join("; "));
  log.debug("Leaving theBodies().");
}

// 2. The query string.
async function theQueries(doc) {
  log.debug("Entering theQueries().");
  log.info("=== 2. every enum on a query parameter ===");
  let probed = 0;
  for (const row of doc.ops) {
    const params = (row.op.parameters || []).filter(function (p) {
      return p && p.in === "query" && p.schema &&
             (Array.isArray(p.schema.enum) ||
              (p.schema.items && Array.isArray(p.schema.items.enum)));
    });
    for (const p of params) {
      const values = p.schema.enum || p.schema.items.enum;
      const url = base + concrete(row.path) + "?" + encodeURIComponent(p.name) +
                  "=" + encodeURIComponent(OUTSIDE);
      const where = row.method + " " + row.path + " ?" + p.name;
      const bad = row.method === "GET" ? await call("GET", url)
                                       : await postJson(url, {});
      const said = errorsOf(bad);
      check(where + " refuses a value outside its set", function () {
        assert.strictEqual(bad.status, 400, where + ": " +
                           bad.text.slice(0, 400));
        assert.ok(SENTENCE.test(said) &&
                  said.indexOf('"' + p.name + '"') >= 0 &&
                  namesEvery(said, values), where + ": " + said);
      });
      probed += 1;
      if (row.method !== "GET") {
        continue;
      }
      for (const v of values) {
        const good = await call("GET", base + concrete(row.path) + "?" +
                                encodeURIComponent(p.name) + "=" +
                                encodeURIComponent(String(v)));
        check(where + "=" + v + " is not refused as outside the set",
              function () {
                assert.ok(!(good.status === 400 &&
                            SENTENCE.test(errorsOf(good))),
                          where + "=" + v + ": " + good.text.slice(0, 400));
              });
      }
    }
  }
  check(probed + " query enums probed (floor " + MINIMUM_QUERY_ENUMS + ")",
        function () {
          assert.ok(probed >= MINIMUM_QUERY_ENUMS, "only " + probed +
                    " query-parameter enums were found in the document");
        });
  log.info("  " + probed + " query enums refused outside their set.");
  log.debug("Leaving theQueries().");
}

async function csrfTokenFor(cookie) {
  log.debug("Entering csrfTokenFor().");
  const page = await call("GET", base + "/admin",
                          { headers: { Cookie: cookie } });
  const token = (page.text.match(/name="csrf_token" value="([^"]+)"/) ||
                 [])[1] || "";
  log.debug("Leaving csrfTokenFor(). " + (token ? "Found." : "None."));
  return token;
}

async function postForm(url, cookie, fields) {
  log.debug("Entering postForm(). " + url);
  const r = await call("POST", url, {
    headers: { Cookie: cookie,
               "Content-Type": "application/x-www-form-urlencoded",
               Accept: "application/json" },
    body: new URLSearchParams(fields).toString()
  });
  log.debug("Leaving postForm().");
  return r;
}

// 3. The console.
async function theConsole(doc, cookie) {
  log.debug("Entering theConsole().");
  log.info("=== 3. every console control a closed set is declared for ===");
  const token = await csrfTokenFor(cookie);
  check("the console draws a CSRF token for this session", function () {
    assert.ok(token, "no csrf_token on /admin for the signed-in session");
  });
  let probed = 0;
  for (const row of doc.ops) {
    if (row.method === "GET") {
      continue;
    }
    const pages = mirroredPages(row.op);
    if (!pages.length) {
      continue;
    }
    const flat = enumsOf(requestSchemaOf(row.op), doc.components, [], [], 0)
      .filter(function (f) {
        return f.path.length === 1 ||
               (f.path.length === 2 && f.path[1] === "*");
      });
    const action = row.path.split("/").pop();
    for (const f of flat) {
      for (const page of pages) {
        const fields = { csrf_token: token, action: action };
        fields[f.path[0]] = OUTSIDE;
        const r = await postForm(base + page, cookie, fields);
        const where = "POST " + page + " action=" + action + " " + f.path[0];
        check(where + " refuses a value outside its set", function () {
          assert.strictEqual(r.status, 400, where + ": " +
                             r.text.slice(0, 400));
          assert.strictEqual(r.body && r.body.error, "invalid_value",
                             where + ": " + r.text.slice(0, 400));
          const said = String(r.body.error_description || "");
          assert.ok(SENTENCE.test(said) && namesEvery(said, f.values),
                    where + ": " + said);
        });
        probed += 1;
      }
    }
  }
  check(probed + " console controls probed (floor " + MINIMUM_CONSOLE_PROBES +
        ")", function () {
          assert.ok(probed >= MINIMUM_CONSOLE_PROBES, "only " + probed +
                    " console controls with a closed set were found");
        });
  log.info("  " + probed + " console form fields refused outside their set.");
  log.debug("Leaving theConsole().");
}

// 4. The settings.
async function theSettings(cookie) {
  log.debug("Entering theSettings().");
  log.info("=== 4. every runtime setting of type enum ===");
  const listed = await call("GET", API + "/config");
  assert.strictEqual(listed.status, 200, listed.text.slice(0, 300));
  const all = (listed.body && (listed.body.settings || listed.body)) || [];
  // An `enum` row, and a `csv` row whose entries are held to `csvValues`;
  // for the second the probe is a list with one entry outside the set,
  // beside one from it, so the refusal is about the entry and not the list.
  const rows = (Array.isArray(all) ? all : []).filter(function (s) {
    return s && s.runtime &&
           ((s.type === "enum" && Array.isArray(s.enumValues)) ||
            (s.type === "csv" && Array.isArray(s.csvValues) &&
             s.csvValues.length));
  });
  const token = cookie ? await csrfTokenFor(cookie) : "";
  for (const s of rows) {
    const body = {};
    body[s.key] = s.type === "csv" ? s.csvValues[0] + "," + OUTSIDE : OUTSIDE;
    const r = await postJson(API + "/config/set-many", body);
    check("set-many refuses " + s.key + "=" + OUTSIDE, function () {
      assert.ok(r.status >= 400 && r.status < 500, s.key + ": " +
                r.text.slice(0, 300));
      assert.ok(r.text.indexOf(s.key) >= 0, s.key + ": the refusal should " +
                "name the setting: " + r.text.slice(0, 300));
    });
    if (cookie) {
      const fields = { csrf_token: token, action: "set-many" };
      fields[s.key] = body[s.key];
      await postForm(base + "/admin/config", cookie, fields);
    }
  }
  const after = await call("GET", API + "/config");
  const again = (after.body && (after.body.settings || after.body)) || [];
  check("no setting holds a value outside its set after both doors were " +
        "tried", function () {
          const held = (Array.isArray(again) ? again : []).filter(function (s) {
            return s && String(s.value).indexOf(OUTSIDE) >= 0;
          }).map(function (s) {
            return s.key;
          });
          assert.deepStrictEqual(held, [], "stored: " + held.join(", "));
        });
  check(rows.length + " closed-set settings probed (floor " +
        MINIMUM_ENUM_SETTINGS +
        ")", function () {
          assert.ok(rows.length >= MINIMUM_ENUM_SETTINGS, "only " +
                    rows.length + " runtime enum settings were listed");
        });
  log.info("  " + rows.length + " enum settings refused a value outside " +
           "their set.");
  log.debug("Leaving theSettings().");
}

async function main() {
  log.debug("Entering main().");
  const doc = await theDocument();
  await theBodies(doc);
  await theQueries(doc);
  const cookie = await signin.signInToTheConsole(base,
    "closed-sets-" + Date.now().toString(36), log, { grant: "write" });
  if (cookie) {
    await theConsole(doc, cookie);
  } else {
    log.info("  (no console session in this stack, so the console door is " +
             "not probed)");
  }
  await theSettings(cookie || "");
  log.info("sts_admin_closed_sets: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_admin_closed_sets FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
