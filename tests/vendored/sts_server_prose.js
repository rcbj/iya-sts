// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_server_prose.js
//
// ---------------------------------------------------------------------------
// THE PROSE THE SERVER WRITES INTO A VIEW, OVER HTTP (#543, 2026-10-12).
//
// rcbj's answers on #543: `/admin-api` translates the sentences it writes
// into a view only when the request names a language, and never in an
// OpenAPI document. Read-only, against GET /admin-api/config:
//
//   a. with no language named (or the wildcard node's fetch sends), every
//      setting reads exactly as with `Accept-Language: en`;
//   b. with `Accept-Language: fr`, a setting's label and description are
//      French, and its key, value, source and every other member are the
//      same as in English;
//   c. a language no catalog answers (`de`) reads English;
//   d. the OpenAPI document is byte-identical whatever the request names;
//   e. the answer says `Vary: Accept-Language`;
//   f. Directory → Policies (#543 phase 2): with `fr`, the password policy's
//      rule sentences — templates refilled with the profile's numbers — and
//      its field help are French, and every value of the profile is the same
//      as in English;
//   g. the module prose of phase 2b (#543): on every console page that
//      carries it — mode, realms, audit, listeners, the LDAP pages,
//      federation, SPIFFE, SCIM, PKI, encryption, secrets, database, roles,
//      the roster, delegation, devices, Kerberos, and (2c, 3) the crypto
//      report, scheduler, caches, node health, worker pools and the protocol
//      metadata — `fr` changes some strings
//      and the answer's SHAPE (its members and array lengths) not at all.
// ---------------------------------------------------------------------------
"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");

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
var log = bunyan.createLogger({ name: "sts_server_prose",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function get(url, language) {
  log.debug("Entering get(). url=" + url + " language=" + language);
  const headers = { Accept: "application/json" };
  if (language !== undefined) {
    headers["Accept-Language"] = language;
  }
  const r = await fetch(url, { headers: headers });
  const raw = await r.text();
  assert.strictEqual(r.status, 200, "GET " + url + " (" + language +
                     ") answered " + r.status + " " + raw.slice(0, 300));
  log.debug("Leaving get().");
  return { raw: raw, headers: r.headers };
}

// The members a translation may change, and the ones it never does. VALUES
// are compared nowhere: another job may change a setting between two reads.
const PROSE = ["label", "description", "restartReason", "csvValueNotes"];
const FIXED = ["key", "group", "type", "env", "appconfigPath", "default",
               "enumValues", "csvValues", "min", "max"];

function pick(row, names) {
  log.debug("Entering pick().");
  const out = {};
  names.forEach(function (name) {
    out[name] = row ? row[name] : undefined;
  });
  log.debug("Leaving pick().");
  return out;
}

// Every described setting of a /admin-api/config answer, by key.
function settingsOf(raw) {
  log.debug("Entering settingsOf().");
  const out = {};
  (JSON.parse(raw).groups || []).forEach(function (group) {
    (group.settings || []).forEach(function (row) {
      out[row.key] = row;
    });
  });
  log.debug("Leaving settingsOf(). " + Object.keys(out).length);
  return out;
}

// An answer's shape: the set of its members' paths with every array index
// folded to `[]`, values and lengths left out — two reads may differ in how
// many audit events or rows they hold, never in which members a row has.
function shapeOf(value, path, out) {
  log.debug("Entering shapeOf().");
  const into = out || new Set();
  if (Array.isArray(value)) {
    value.forEach(function (one) {
      shapeOf(one, (path || "$") + "[]", into);
    });
  } else if (value && typeof value === "object") {
    Object.keys(value).forEach(function (key) {
      shapeOf(value[key], (path || "$") + "." + key, into);
    });
  } else {
    into.add(path || "$");
  }
  log.debug("Leaving shapeOf().");
  return out ? into : Array.from(into).sort();
}

// The members of a page that are RECORDS rather than prose: what they hold
// changes between the English read and the French one whenever anything
// happens on the stack in between, and an audit event's `detail` has members
// of its own per action (`before` and `after` on a change, none on a sign-in),
// so even folded to `[]` their shape is the data's, not the page's. None of
// them is translated — an event is what happened, in the words it was
// recorded in — so leaving them out loses nothing this job asks.
//
// A NESTED MEMBER IS A DOTTED PATH, `[]` FOLDING AN ARRAY (2026-10-13): a
// node-health answer lists the processes that did not answer it, and whether
// a worker answered differs between the two reads on a busy cluster —
// `nodes[].view.processes.unanswered` appeared in one and not the other.
// `/audit`'s `knownActors` and `byAction` are maps KEYED BY DATA — who has
// acted, which actions ran — so a key appears between the reads whenever a
// new actor or action does (cluster, ccf5741a: knownActors.sts-management-api
// in one read only). `/ldap/service`'s
// `persistence.replication.retention.lastTrim` is the record of the change
// log's last trim (persistence/persistence_replication.js), held by the
// process that answers: null in one that has not trimmed — every process
// but the scheduler's leader, and the leader until the job first runs —
// and `{ at, error, … }` after, whose members differ between a trim that
// worked and one that failed. On a cluster the two reads are answered by
// whichever node the load balancer picks, so one read had it and the other
// did not (2026-10-20, batch 10); a single node changes only if the first
// trim lands between them.
const DATA = { "/audit": ["events", "knownActors", "byAction"],
               "/node-health": ["nodes[].view.processes.unanswered"],
               "/ldap/service":
                 ["persistence.replication.retention.lastTrim"] };

// Deletes `path` (dotted, `name[]` descending into every item) from `value`.
function dropPath(value, path) {
  log.debug("Entering dropPath(). " + path);
  const parts = path.split(".");
  const walk = function (node, i) {
    if (!node || typeof node !== "object") {
      return;
    }
    const part = parts[i];
    const many = /\[\]$/.test(part);
    const name = many ? part.slice(0, -2) : part;
    if (i === parts.length - 1) {
      delete node[name];
      return;
    }
    const next = node[name];
    if (many && Array.isArray(next)) {
      next.forEach(function (one) {
        walk(one, i + 1);
      });
    } else {
      walk(next, i + 1);
    }
  };
  walk(value, 0);
  log.debug("Leaving dropPath().");
}

function withoutData(page, body) {
  log.debug("Entering withoutData().");
  (DATA[page] || []).forEach(function (name) {
    if (body && typeof body === "object") {
      dropPath(body, name);
    }
  });
  log.debug("Leaving withoutData().");
  return body;
}

// Every string of an answer, in order.
function stringsOf(value, out) {
  log.debug("Entering stringsOf().");
  const into = out || [];
  if (typeof value === "string") {
    into.push(value);
  } else if (value && typeof value === "object") {
    Object.keys(value).sort().forEach(function (key) {
      stringsOf(value[key], into);
    });
  }
  log.debug("Leaving stringsOf().");
  return into;
}

async function test() {
  log.debug("Entering test().");

  log.info("=== a. no language named reads English ===");
  const english = await get(api + "/config", "en");
  const none = await get(api + "/config", undefined);
  const en = settingsOf(english.raw);
  const plain = settingsOf(none.raw);
  check("no Accept-Language reads every setting as en does", function () {
    assert.ok(Object.keys(en).length > 100, Object.keys(en).length);
    Object.keys(en).forEach(function (key) {
      assert.deepStrictEqual(pick(plain[key], PROSE), pick(en[key], PROSE),
                             key);
    });
  });

  log.info("=== b. fr reads French prose and the same values ===");
  const french = await get(api + "/config", "fr-FR, en;q=0.5");
  const fr = settingsOf(french.raw);
  let translated = 0;
  check("the same settings, and nothing but their prose differs",
    function () {
      assert.deepStrictEqual(Object.keys(fr).sort(), Object.keys(en).sort());
      Object.keys(en).forEach(function (key) {
        if (fr[key].label !== en[key].label ||
            fr[key].description !== en[key].description) {
          translated++;
        }
        assert.deepStrictEqual(pick(fr[key], FIXED), pick(en[key], FIXED),
                               key);
      });
    });
  check("most settings are translated into French", function () {
    assert.ok(translated > Object.keys(en).length / 2, translated + " of " +
              Object.keys(en).length);
    assert.notStrictEqual(fr["global.port"].label, en["global.port"].label);
  });

  log.info("=== c. a language with no catalog reads English ===");
  const german = settingsOf((await get(api + "/config", "de")).raw);
  check("de reads every setting as en does", function () {
    Object.keys(en).forEach(function (key) {
      assert.deepStrictEqual(pick(german[key], PROSE), pick(en[key], PROSE),
                             key);
    });
  });

  log.info("=== d. the OpenAPI document stays English ===");
  const specEn = await get(api + "/openapi.json", "en");
  const specFr = await get(api + "/openapi.json", "fr");
  check("openapi.json is identical whatever Accept-Language says",
    function () {
      assert.strictEqual(specFr.raw, specEn.raw);
    });

  log.info("=== e. the answer varies on Accept-Language ===");
  check("Vary names Accept-Language", function () {
    assert.ok(/accept-language/i.test(french.headers.get("vary") || ""),
              french.headers.get("vary"));
  });

  log.info("=== f. the policies page's sentences are translated ===");
  const polEn = JSON.parse((await get(api + "/policies", "en")).raw);
  const polFr = JSON.parse((await get(api + "/policies", "fr")).raw);
  check("the password policy's rules and field help are French",
    function () {
      const rulesEn = polEn.password.rules;
      const rulesFr = polFr.password.rules;
      assert.strictEqual(rulesFr.length, rulesEn.length);
      rulesEn.forEach(function (rule, i) {
        assert.notStrictEqual(rulesFr[i], rule, rule);
        // A number the template was filled with is carried over.
        (rule.match(/[0-9]+/g) || []).forEach(function (n) {
          assert.ok(rulesFr[i].indexOf(n) >= 0, rulesFr[i] + " / " + n);
        });
      });
      polEn.password.fields.forEach(function (field, i) {
        assert.notStrictEqual(polFr.password.fields[i].what, field.what,
                              field.key);
      });
    });
  check("the policies page's values are the same in both", function () {
    assert.deepStrictEqual(polFr.password.profile, polEn.password.profile);
    assert.deepStrictEqual(polFr.kinds.map(function (k) {
      return k.id + " " + k.container;
    }), polEn.kinds.map(function (k) {
      return k.id + " " + k.container;
    }));
  });

  log.info("=== g. the module prose is translated, the shape is not ===");
  const PAGES = ["/mode", "/realms", "/audit", "/listeners", "/ldap/service",
                 "/ldap/applications", "/federation", "/spiffe", "/scim",
                 "/pki", "/encryption", "/secrets", "/database", "/roles",
                 "/rbac", "/delegation", "/device-registration",
                 "/kerberos/principals", "/crypto", "/scheduler",
                 "/caches", "/node-health", "/worker-pools",
                 "/sts-metadata"];
  for (const page of PAGES) {
    const en = await fetch(api + page, { headers: { Accept:
      "application/json", "Accept-Language": "en" } });
    const fr = await fetch(api + page, { headers: { Accept:
      "application/json", "Accept-Language": "fr" } });
    const enBody = await en.text();
    const frBody = await fr.text();
    if (en.status !== 200 || fr.status !== 200) {
      // A page this stack does not draw (no database, no directory) is
      // not this job's to judge.
      log.info("  [skip] " + page + " answered " + en.status + "/" +
               fr.status);
      continue;
    }
    const a = withoutData(page, JSON.parse(enBody));
    const b = withoutData(page, JSON.parse(frBody));
    check(page + ": the same shape, and some prose in French", function () {
      assert.deepStrictEqual(shapeOf(b), shapeOf(a), page);
      const sa = stringsOf(a);
      const sb = stringsOf(b);
      const changed = sa.filter(function (one, i) {
        return one !== sb[i];
      }).length;
      assert.ok(changed > 0, page + ": no string changed");
    });
  }

  assert.ok(checks >= 12, "only " + checks + " checks ran; a section has " +
                                           "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_server_prose")
  .description("The prose the server writes into a view, over HTTP (#543).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
