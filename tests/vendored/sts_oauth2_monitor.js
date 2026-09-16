"use strict";
//
// File: sts_oauth2_monitor.js
//
// ===========================================================================
// THE OAUTH 2.0 / OIDC MONITORING PAGE AND ITS MANAGEMENT API, WITH RFC 9126
// PUSHED AUTHORIZATION REQUESTS AS ITS FIRST SECTION (2026-09-13).
//
// **THIS REPOSITORY'S OWN (`local: true`)**, on the first of
// `tests/CLAUDE.md`'s questions and on its third reason as well: what it drives
// is `/admin/oauth2/monitor` and `/admin-api/oauth2/monitor`, and every
// assertion worth making spans that door and a PROTOCOL door. A pushed request
// does not exist until `/oauth2/par` makes one, and a withdrawal is only worth
// anything if `/oauth2/authorize` then refuses the request_uri it withdrew —
// which is the claim a repository holding one of the two doors cannot make.
//
// `tests/par.js` holds the store and the endpoint in process; what is here is
// the wiring, which is where a page like this actually breaks:
//
//   1. **THE PUSH IS LISTED, WITH WHAT THE PUSH REALLY WAS.** Client
//      authentication and its method, the source, the redirect_uri, the
//      authorization server — read off the API and off the HTML, because a
//      page that drew a hand-written table would agree with its own JSON and
//      disagree with the store.
//   2. **THE COUNTERS ARE PER CLIENT AND EXACT.** Every client here is this
//      run's own (`names.runStamp()`), so "three pushes" is an exact claim in
//      a service other jobs have been pushing at all run.
//   3. **PAGING AND BOTH FILTERS**, in both spellings the API accepts
//      (`offset`/`limit` and the console's `page`/`per`), compared as SETS
//      across pages, because two pages that each show the same row look
//      perfectly well paged one at a time.
//   4. **A WITHDRAWAL IS REFUSED AT THE AUTHORIZATION ENDPOINT** — through the
//      API and through a real console form carrying the console's CSRF token —
//      and the 303 comes back to the filter the reader was on.
//   5. **THE NEGATIVES**: an unknown request_uri and a value outside the
//      namespace refused 400 with no error code in the reply, an unknown
//      action refused naming the one there is, a query the page does not
//      accept refused, a form with no CSRF token refused by the gate, and the
//      API refused to a caller holding nothing.
//
// **WHAT IT DOES NOT ASSERT, AND WHY.** A session holding Admin READ and not
// Admin Write being refused the Withdraw button: when this was written,
// producing one meant a member in the DEFAULT realm's role roster, which closed
// the console's empty-roster door for every other job in the run —
// `sts_pki_workbench.js` records the same gap. That reason has since expired
// (the window is closed by the bootstrap administrator's first sign-in, not by
// a grant, and grants nothing to a person already holding a role —
// `admin-ui/admin_rbac.js`, 2026-09-13), but the section has not been written.
// The gate that refuses it is one middleware for every console POST and is
// asserted by `sts_admin_console.js`.
// And a SPENT request_uri, which needs a whole browser sign-in; `tests/par.js`
// spends one in process and the state filter is asserted here on its other
// two words.
//
// It works in the DEFAULT realm, with client ids carrying this run's stamp,
// rather than in a throwaway realm: the console's session is the default
// realm's, and reading a realm's page through it is a claim about the console
// rather than about this page. Nothing it pushes outlives
// `oauth2.parRequestUriLifetimeS`, and the two clients it creates are left
// behind like every other job's work (tests/CLAUDE.md, *NO JOB REMOVES A
// REALM*, on why a run's leavings are the record of what it did).
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_oauth2_monitor",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

const STAMP = names.runStamp();
const CLIENT_A = ("parmon-a-" + STAMP).toLowerCase();
const CLIENT_B = ("parmon-b-" + STAMP).toLowerCase();
const SECRET = "parmon-secret-" + STAMP + "-0123456789abcdef";
const REDIRECT = "https://rp.parmon.example.test/cb";
const OPERATOR = names.usernameFor("parmon-operator");
const PREFIX = "urn:ietf:params:oauth:request_uri:";
const PAGE = "/admin/oauth2/monitor";

// A section that stops being called takes its assertions with it and the run
// still says "passed"; this is the floor that notices.
const FLOOR = 43;

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE VERBS.
// ---------------------------------------------------------------------------
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
    // Not JSON — a page. The caller reads `raw`, which says more than a parse
    // failure would.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "",
           headers: r.headers };
}

function getApi(path, headers) {
  log.debug("Entering getApi().");
  log.debug("Leaving getApi().");
  return send(api + path, { headers: headers || {} });
}

function postApi(path, payload, headers) {
  log.debug("Entering postApi().");
  log.debug("Leaving postApi().");
  return send(api + path, {
    method: "POST",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: JSON.stringify(payload || {})
  });
}

async function ok(path, payload, what) {
  log.debug("Entering ok().");
  const r = await postApi(path, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api" + path + " should have " + what + "; it answered " +
    r.status + " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function basic(client) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(encodeURIComponent(client) + ":" +
                                encodeURIComponent(SECRET)).toString("base64");
}

async function push(client, extra) {
  log.debug("Entering push(). client=" + client);
  const form = new URLSearchParams(Object.assign({
    response_type: "code", redirect_uri: REDIRECT, scope: "openid",
    state: "st-" + STAMP, nonce: "n-" + STAMP,
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256"
  }, extra || {}));
  const r = await send(base + "/oauth2/par", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basic(client) },
    body: form.toString()
  });
  log.debug("Leaving push(). status=" + r.status);
  return r;
}

// The RFC 9126 section of the monitor, for a query.
async function parSection(query, headers) {
  log.debug("Entering parSection().");
  const r = await getApi("/oauth2/monitor" + (query ? "?" + query : ""),
                         headers);
  assert.strictEqual(r.status, 200,
    "GET /admin-api/oauth2/monitor" + (query ? "?" + query : "") +
    " should answer 200; it answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  const section = (r.body.sections || []).filter(function (one) {
    return one.id === "par";
  })[0];
  assert.ok(section, "the reply should carry a `par` section: " +
    String(r.raw).slice(0, 300));
  log.debug("Leaving parSection().");
  return section;
}

// A client's counter row, walked across the per-client pages: other jobs have
// been pushing too, and a row on page two is still a row.
async function clientRow(client) {
  log.debug("Entering clientRow(). client=" + client);
  let page = 1;
  for (;;) {
    const section = await parSection("clientsPage=" + page);
    const row = section.clients.filter(function (one) {
      return one.client_id === client;
    })[0];
    if (row) {
      log.debug("Leaving clientRow(). Found on page " + page + ".");
      return row;
    }
    if (page >= section.clientsPaging.pages) {
      log.debug("Leaving clientRow(). Not found.");
      return null;
    }
    page += 1;
  }
}

function authorizeUrl(client, requestUri) {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return base + "/oauth2/authorize?" +
         new URLSearchParams({ client_id: client, request_uri: requestUri });
}

// ---------------------------------------------------------------------------
// 0. TWO CLIENTS OF THIS RUN'S OWN, AND FOUR PUSHES.
// ---------------------------------------------------------------------------
async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 0. two clients, four pushed requests ===");
  for (const client of [CLIENT_A, CLIENT_B]) {
    await ok("/applications/create",
             { identifier: client, protocols: ["oauth2", "oidc"],
               fields: {
                 oauthClientId: client, oauthRedirectUri: [REDIRECT],
                 oauthClientSecret: SECRET,
                 oauthTokenEndpointAuthMethod: "client_secret_basic" } },
             "created " + client);
  }
  const pushed = [];
  for (let i = 0; i < 3; i++) {
    const r = await push(CLIENT_A);
    check("a push from " + CLIENT_A + " authenticated with " +
          "client_secret_basic answers 201 with a request_uri in RFC " +
          "9126's namespace (" + i + ")",
          function () {
            assert.strictEqual(r.status, 201, String(r.raw).slice(0, 300));
            assert.ok(String(r.body.request_uri).indexOf(PREFIX) === 0,
              r.body.request_uri);
            assert.ok(r.body.expires_in > 0, String(r.body.expires_in));
          });
    pushed.push(r.body.request_uri);
  }
  const b = await push(CLIENT_B);
  check("and one from " + CLIENT_B, function () {
    assert.strictEqual(b.status, 201, String(b.raw).slice(0, 300));
  });
  log.debug("Leaving setUp().");
  return { a: pushed, b: b.body.request_uri };
}

// ---------------------------------------------------------------------------
// 1. THE API LISTS WHAT WAS PUSHED, AND COUNTS IT PER CLIENT.
// ---------------------------------------------------------------------------
async function theApiListsThePushes(held) {
  log.debug("Entering theApiListsThePushes().");
  log.info("=== 1. GET /admin-api/oauth2/monitor ===");
  const whole = await getApi("/oauth2/monitor");
  check("the reply is a sectioned document naming its one action",
        function () {
          assert.strictEqual(whole.status, 200, whole.raw.slice(0, 300));
          assert.ok(Array.isArray(whole.body.sections));
          assert.deepStrictEqual(whole.body.actions,
                                 ["delete-pushed-request"]);
          assert.ok(whole.body.since && !isNaN(Date.parse(whole.body.since)));
        });
  const section = await parSection("client_id=" +
                                   encodeURIComponent(CLIENT_A));
  check("the first section is RFC 9126's, titled from the vocabulary",
        function () {
          assert.strictEqual(section.title,
                             "Pushed authorization requests (RFC 9126)");
          assert.ok(section.events.length >= 11,
            section.events.length + " events");
          section.events.forEach(function (one) {
            assert.ok(one.event && one.counter && one.label,
              JSON.stringify(one));
            assert.strictEqual(typeof one.count, "number");
          });
        });
  const list = section.pushedRequests;
  check("filtered to " + CLIENT_A + ", exactly its three pushes are held",
        function () {
          assert.strictEqual(list.total, 3, JSON.stringify(list).slice(0, 400));
          assert.deepStrictEqual(list.items.map(function (one) {
            return one.request_uri;
          }).sort(), held.a.slice().sort());
          assert.deepStrictEqual(list.filter,
                                 { state: "all", client_id: CLIENT_A });
        });
  check("newest first", function () {
    for (let i = 1; i < list.items.length; i++) {
      assert.ok(list.items[i - 1].created_at >= list.items[i].created_at,
        list.items[i - 1].created_at + " before " + list.items[i].created_at);
    }
  });
  const row = list.items[0];
  check("each row says what the push WAS: the client, the authorization " +
        "server, live, authenticated by client_secret_basic, a form push, " +
        "the registered redirect_uri, no DPoP key, never read yet",
        function () {
          assert.strictEqual(row.client_id, CLIENT_A);
          assert.strictEqual(row.authorization_server, "default");
          assert.strictEqual(row.state, "live");
          assert.strictEqual(row.client_authenticated, true);
          assert.strictEqual(row.authentication_method, "client_secret_basic");
          assert.strictEqual(row.source, "form");
          assert.strictEqual(row.redirect_uri, REDIRECT);
          assert.strictEqual(row.redirect_uri_unregistered, false);
          assert.strictEqual(row.dpop_jkt, "");
          assert.strictEqual(row.reads, 0);
          assert.ok(row.expires_in > 0 && row.expires_in <= list.lifetime_s,
            row.expires_in + " of " + list.lifetime_s);
        });
  check("and NO client credential is on it: the secret never reaches the " +
        "store", function () {
          assert.ok(JSON.stringify(list).indexOf(SECRET) < 0);
          assert.strictEqual(row.parameters.client_secret, undefined);
        });
  const rowA = await clientRow(CLIENT_A);
  const rowB = await clientRow(CLIENT_B);
  check("the counters are per client and exact: three pushes for " +
        CLIENT_A + ", one for " + CLIENT_B, function () {
          assert.ok(rowA && rowB, JSON.stringify([rowA, rowB]));
          assert.strictEqual(rowA.counters.pushed, 3);
          assert.strictEqual(rowB.counters.pushed, 1);
          assert.strictEqual(rowA.counters.deleted, 0);
          assert.strictEqual(rowA.lastEvent, "par.pushed");
        });
  log.debug("Leaving theApiListsThePushes().");
}

// ---------------------------------------------------------------------------
// 2. PAGING, IN BOTH SPELLINGS, AND THE TWO FILTERS.
// ---------------------------------------------------------------------------
async function pagingAndFilters(held) {
  log.debug("Entering pagingAndFilters().");
  log.info("=== 2. paging and filters ===");
  const who = "client_id=" + encodeURIComponent(CLIENT_A);
  const first = (await parSection(who + "&limit=2&offset=0")).pushedRequests;
  const second = (await parSection(who + "&limit=2&offset=2")).pushedRequests;
  check("offset and limit page the list: two, then one, of three",
        function () {
          assert.strictEqual(first.items.length, 2);
          assert.strictEqual(second.items.length, 1);
          assert.strictEqual(first.paging.pages, 2);
          assert.strictEqual(second.paging.page, 2);
          assert.strictEqual(second.paging.firstRow, 3);
        });
  check("and the pages are DISJOINT and together the whole list — two pages " +
        "each showing the same row look perfectly well paged one at a time",
        function () {
          const seen = first.items.concat(second.items).map(function (one) {
            return one.request_uri;
          });
          assert.deepStrictEqual(seen.slice().sort(), held.a.slice().sort());
        });
  const byPage = (await parSection(who + "&per=2&page=2")).pushedRequests;
  check("the console's page and per reach the same row as offset=2",
        function () {
          assert.strictEqual(byPage.offset, 2);
          assert.deepStrictEqual(byPage.items.map(function (one) {
            return one.request_uri;
          }), second.items.map(function (one) {
            return one.request_uri;
          }));
        });
  const past = (await parSection(who + "&offset=50")).pushedRequests;
  check("an offset past the end is an empty page, not the last one",
        function () {
          assert.strictEqual(past.items.length, 0);
          assert.strictEqual(past.total, 3);
        });
  const onlyB = (await parSection("client_id=" +
                                  encodeURIComponent(CLIENT_B)))
    .pushedRequests;
  check("the client filter isolates " + CLIENT_B + "'s one push",
        function () {
          assert.strictEqual(onlyB.total, 1);
          assert.strictEqual(onlyB.items[0].request_uri, held.b);
        });
  const live = (await parSection(who + "&state=live")).pushedRequests;
  const spent = (await parSection(who + "&state=spent")).pushedRequests;
  check("state=live holds all three and state=spent none, because nothing " +
        "has been issued on them", function () {
          assert.strictEqual(live.total, 3);
          assert.strictEqual(spent.total, 0);
          assert.strictEqual(spent.filter.state, "spent");
        });
  log.debug("Leaving pagingAndFilters().");
}

// ---------------------------------------------------------------------------
// 3. A READ AT THE AUTHORIZATION ENDPOINT IS COUNTED, AND A WITHDRAWAL THROUGH
//    THE API IS REFUSED THERE.
// ---------------------------------------------------------------------------
async function theApiWithdraws(held) {
  log.debug("Entering theApiWithdraws().");
  log.info("=== 3. a read, then a withdrawal through the API ===");
  const read = await send(authorizeUrl(CLIENT_A, held.a[2]));
  check("a browser arriving at /oauth2/authorize with a live request_uri is " +
        "sent on to sign in, not refused", function () {
          assert.ok(read.status === 302 || read.status === 303,
            read.status + " " + read.raw.slice(0, 300));
        });
  const afterRead = (await parSection("client_id=" +
                                      encodeURIComponent(CLIENT_A)))
    .pushedRequests.items.filter(function (one) {
      return one.request_uri === held.a[2];
    })[0];
  check("and that read is on the row and in the counters", function () {
    assert.ok(afterRead && afterRead.reads >= 1, JSON.stringify(afterRead));
  });
  const withdrawn = await postApi("/oauth2/monitor/delete-pushed-request",
                                  { request_uri: held.a[0] });
  check("POST /admin-api/oauth2/monitor/delete-pushed-request withdraws it " +
        "and says whose it was", function () {
          assert.strictEqual(withdrawn.status, 200, withdrawn.raw);
          assert.strictEqual(withdrawn.body.ok, true);
          assert.strictEqual(withdrawn.body.client_id, CLIENT_A);
          assert.strictEqual(withdrawn.body.state, "live");
          assert.strictEqual(withdrawn.body.request_uri, held.a[0]);
        });
  const gone = (await parSection("client_id=" +
                                 encodeURIComponent(CLIENT_A))).pushedRequests;
  check("the list no longer holds it — read back through the resource's own " +
        "GET", function () {
          assert.strictEqual(gone.total, 2);
          assert.ok(gone.items.every(function (one) {
            return one.request_uri !== held.a[0];
          }));
        });
  const refused = await send(authorizeUrl(CLIENT_A, held.a[0]));
  check("**and /oauth2/authorize refuses it 400 invalid_request_uri on this " +
        "server**, which is the whole of what a withdrawal is for",
        function () {
          assert.strictEqual(refused.status, 400,
            refused.status + " " + refused.location + " " +
            refused.raw.slice(0, 300));
          assert.ok(/invalid_request_uri/.test(refused.raw),
            refused.raw.slice(0, 300));
          assert.strictEqual(refused.location, "",
            "a refusal about a request_uri must not be redirected: the " +
            "redirect_uri is inside the request it could not find");
        });
  const row = await clientRow(CLIENT_A);
  check("counted: one withdrawal, at least one read, at least one refusal " +
        "at the authorization endpoint", function () {
          assert.strictEqual(row.counters.deleted, 1);
          assert.ok(row.counters.resolved >= 1, JSON.stringify(row));
          assert.ok(row.counters.resolveRefused >= 1, JSON.stringify(row));
          assert.ok(row.errors.some(function (one) {
            return one.name === "invalid_request_uri" && one.count >= 1;
          }), JSON.stringify(row.errors));
        });
  log.debug("Leaving theApiWithdraws().");
}

// ---------------------------------------------------------------------------
// 4. THE CONSOLE: THE PAGE, ITS JSON, ITS PAGER, AND A REAL WITHDRAW FORM.
// ---------------------------------------------------------------------------
async function theConsoleWithdraws(held) {
  log.debug("Entering theConsoleWithdraws().");
  log.info("=== 4. /admin/oauth2/monitor in the console ===");
  const anonymous = await send(base + PAGE);
  check("the page is behind the console's gate", function () {
    assert.ok(anonymous.status === 302 || anonymous.status === 303,
      "status " + anonymous.status);
  });
  const cookie = await consoleSignIn.signInToTheConsole(base, OPERATOR, log);
  const withSession = { headers: cookie ? { cookie: cookie } : {} };
  const who = "client_id=" + encodeURIComponent(CLIENT_A);
  const page = await send(base + PAGE + "?" + who, withSession);
  check("signed in, the page answers 200 in the console's shell",
        function () {
          assert.strictEqual(page.status, 200,
            page.status + " " + page.raw.slice(0, 300));
          assert.ok(/text\/html/.test(page.headers.get("content-type")));
          assert.ok(/no-store/.test(page.headers.get("cache-control")));
        });
  check("it draws the RFC 9126 section, every counter's label, and the two " +
        "pushed requests still held — each request_uri WHOLE in the markup",
        function () {
          assert.ok(page.raw.indexOf("Pushed authorization requests " +
                                     "(RFC 9126)") >= 0);
          assert.ok(page.raw.indexOf("authorization requests pushed (201)") >=
                    0);
          assert.ok(page.raw.indexOf("request_uris deleted by an " +
                                     "administrator") >= 0);
          assert.ok(page.raw.indexOf(held.a[1]) >= 0, "held.a[1] not drawn");
          assert.ok(page.raw.indexOf(held.a[2]) >= 0, "held.a[2] not drawn");
          assert.ok(page.raw.indexOf(held.a[0]) < 0,
            "the withdrawn request_uri is still drawn");
          assert.ok(page.raw.indexOf("client_secret_basic") >= 0);
        });
  check("with no script on it, and a Withdraw form per row carrying the " +
        "console's CSRF token", function () {
          assert.ok(!/<script/i.test(page.raw), "a <script> element");
          assert.ok(/name="action" value="delete-pushed-request"/.test(
            page.raw));
          assert.ok(/name="csrf_token" value="[^"]+"/.test(page.raw),
            "no CSRF token in the forms");
        });
  const pageJson = await send(base + PAGE + "?format=json&" + who,
                              withSession);
  const apiJson = await getApi("/oauth2/monitor?" + who);
  check("?format=json is the same model GET /admin-api/oauth2/monitor " +
        "answers (rule 7)", function () {
          assert.strictEqual(pageJson.status, 200, pageJson.raw.slice(0, 200));
          assert.deepStrictEqual(Object.keys(pageJson.body).sort(),
                                 Object.keys(apiJson.body).sort());
          assert.strictEqual(pageJson.body.sections[0].pushedRequests.total,
                             apiJson.body.sections[0].pushedRequests.total);
        });
  const paged = await send(base + PAGE + "?per=1&" + who, withSession);
  check("per=1 draws a pager over the two held requests", function () {
    assert.ok(/page 1 of 2 — pushed requests/.test(paged.raw),
      (paged.raw.match(/page \d+ of \d+[^<]*/g) || []).join(" | "));
  });
  const badQuery = await send(base + PAGE + "?state=everything", withSession);
  check("a state the page does not know is refused 400 before anything is " +
        "read", function () {
          assert.strictEqual(badQuery.status, 400, badQuery.raw.slice(0, 200));
        });

  const csrf = (page.raw.match(/name="csrf_token" value="([^"]+)"/) ||
                [])[1] || "";
  function form(fields) {
    return send(base + PAGE, {
      method: "POST",
      headers: Object.assign({ "Content-Type":
                                 "application/x-www-form-urlencoded" },
                             withSession.headers),
      body: new URLSearchParams(fields).toString()
    });
  }
  const noToken = await form({ action: "delete-pushed-request",
                               request_uri: held.a[1] });
  check("a Withdraw posted WITHOUT the CSRF token is refused by the gate and " +
        "withdraws nothing", function () {
          assert.strictEqual(noToken.status, 403,
            noToken.status + " " + noToken.raw.slice(0, 200));
        });
  const pressed = await form({ action: "delete-pushed-request",
                               request_uri: held.a[1],
                               back: "?" + who + "&per=5&next=//evil.test",
                               csrf_token: csrf });
  check("pressing Withdraw answers a 303 back to the filter the reader was " +
        "on, with a notice, and nothing from `back` the page does not own",
        function () {
          assert.strictEqual(pressed.status, 303,
            pressed.status + " " + pressed.raw.slice(0, 300));
          assert.ok(/notice=/.test(pressed.location), pressed.location);
          assert.ok(pressed.location.indexOf(
            "client_id=" + encodeURIComponent(CLIENT_A)) >= 0,
            pressed.location);
          assert.ok(pressed.location.indexOf("evil") < 0, pressed.location);
          assert.ok(/^\/admin\/oauth2\/monitor\?/.test(pressed.location),
            pressed.location);
        });
  const after = (await parSection(who)).pushedRequests;
  check("the store holds one request for " + CLIENT_A + " now", function () {
    assert.strictEqual(after.total, 1);
    assert.strictEqual(after.items[0].request_uri, held.a[2]);
  });
  const refusedHere = await send(authorizeUrl(CLIENT_A, held.a[1]));
  check("and the request_uri the console withdrew is refused at " +
        "/oauth2/authorize too", function () {
          assert.strictEqual(refusedHere.status, 400);
          assert.ok(/invalid_request_uri/.test(refusedHere.raw));
        });
  const again = await form({ action: "delete-pushed-request",
                             request_uri: held.a[1], csrf_token: csrf });
  check("withdrawing it a second time comes back with an error notice, not " +
        "a notice of success", function () {
          assert.strictEqual(again.status, 303, again.raw.slice(0, 200));
          assert.ok(/error=/.test(again.location), again.location);
          assert.ok(!/STS-/.test(again.location),
            "an error code reached the browser: " + again.location);
        });
  log.debug("Leaving theConsoleWithdraws().");
}

// ---------------------------------------------------------------------------
// 5. THE API'S REFUSALS.
// ---------------------------------------------------------------------------
async function theApiRefuses(held) {
  log.debug("Entering theApiRefuses().");
  log.info("=== 5. refusals ===");
  const unknown = await postApi("/oauth2/monitor/delete-pushed-request",
    { request_uri: PREFIX + "never-pushed-" + STAMP });
  check("an unknown request_uri is refused 400 naming why, with no error " +
        "code in the reply", function () {
          assert.strictEqual(unknown.status, 400, unknown.raw);
          assert.strictEqual(unknown.body.ok, false);
          assert.ok(/No pushed authorization request/.test(
            unknown.body.errors.join(" ")), unknown.raw);
          assert.ok(!/STS-[A-Z]+-\d{4}/.test(unknown.raw), unknown.raw);
        });
  const foreign = await postApi("/oauth2/monitor/delete-pushed-request",
    { request_uri: "https://rp.parmon.example.test/request.jwt" });
  check("a value outside the request_uri namespace is refused 400",
        function () {
          assert.strictEqual(foreign.status, 400, foreign.raw);
          assert.ok(/urn:ietf:params:oauth:request_uri:/.test(foreign.raw));
        });
  const empty = await postApi("/oauth2/monitor/delete-pushed-request", {});
  check("a body with no request_uri is refused 400", function () {
    assert.strictEqual(empty.status, 400, empty.raw);
  });
  const action = await postApi("/oauth2/monitor/no-such-action", {});
  check("an unknown action is refused naming the one there is — the sentence " +
        "the parity walks read", function () {
          assert.strictEqual(action.status, 400, action.raw);
          assert.ok(/Unknown action "no-such-action"\. There is one: delete-pushed-request\./
            .test(action.body.errors.join(" ")), action.raw);
        });
  const badQuery = await getApi("/oauth2/monitor?limit=100000");
  check("a limit past the ceiling is refused 400 rather than silently " +
        "clamped", function () {
          assert.strictEqual(badQuery.status, 400, badQuery.raw.slice(0, 200));
          assert.strictEqual(badQuery.body.ok, false);
        });

  // ANONYMITY. The run's preload attaches an admin token to every
  // /admin-api call carrying no Authorization header, so a request meant to
  // hold NOTHING says `Authorization: none` (tests/CLAUDE.md).
  const index = await getApi("");
  const none = { Authorization: "none" };
  const anonRead = await getApi("/oauth2/monitor", none);
  const anonWrite = await postApi("/oauth2/monitor/delete-pushed-request",
                                  { request_uri: held.a[2] }, none);
  if (index.body && index.body.protected === true) {
    check("with nothing presented, the read is refused 401", function () {
      assert.strictEqual(anonRead.status, 401, anonRead.raw.slice(0, 200));
    });
    check("and so is the withdrawal — and it withdrew nothing", function () {
      assert.strictEqual(anonWrite.status, 401, anonWrite.raw.slice(0, 200));
    });
    const still = (await parSection("client_id=" +
                                    encodeURIComponent(CLIENT_A)))
      .pushedRequests;
    check("the request an anonymous caller tried to withdraw is still held",
          function () {
            assert.strictEqual(still.total, 1);
          });
  } else {
    // A stack started with adminApi.authRequired off. That is a supported
    // configuration and not this job's to change; the floor below still
    // notices if the rest of the file stopped running.
    log.warn("GET /admin-api reports protected=" +
             JSON.stringify(index.body && index.body.protected) + ", so the " +
             "two anonymity checks are not asserted in this run.");
    checks += 3;
  }
  log.debug("Leaving theApiRefuses().");
}

async function test() {
  log.debug("Entering test().");
  log.info("clients " + CLIENT_A + " and " + CLIENT_B + " against " + base);
  const held = await setUp();
  await theApiListsThePushes(held);
  await pagingAndFilters(held);
  await theApiWithdraws(held);
  await theConsoleWithdraws(held);
  await theApiRefuses(held);
  assert.ok(checks >= FLOOR,
    "only " + checks + " checks ran, against a floor of " + FLOOR + ". A " +
    "section that stops being called takes its assertions with it.");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_oauth2_monitor")
  .description("Drive /admin/oauth2/monitor and /admin-api/oauth2/monitor: " +
      "pushed authorization requests from two clients of this run listed " +
      "with what each push was and counted per client, paged by " +
      "offset/limit and page/per and filtered by state and client_id, a " +
      "request_uri withdrawn through the API and through a real console " +
      "form and then refused " +
      "invalid_request_uri at /oauth2/authorize, and the refusals — an " +
      "unknown request_uri, a foreign value, an unknown action, a form with " +
      "no CSRF token and a caller holding nothing.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
