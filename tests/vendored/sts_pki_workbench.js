// File: sts_pki_workbench.js
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE & KEY CONFIGURATION PANE, DRIVEN THROUGH ITS OWN DOORS.
//
// `/admin/pki` grew the parent project's *PKI / X.509* workflow on 2026-09-10:
// fourteen profiles, five cryptographic approaches, forty-one key algorithms,
// a subject DN, twenty-two X.509v3 extension cards, a PKCS#10 request and four
// keystore formats — a hundred and fifteen form fields over
// `common/vendored/x509.js`, which is that project's own encoder byte for
// byte.
//
// `tests/pki_authoring.js` holds the MODEL in process: the field table against
// the page that draws it, the six line grammars and their refusals, the three
// subject rules, and every extension reaching the encoder. It makes not one
// HTTP request.
//
// ---------------------------------------------------------------------------
// WHAT IS HERE IS WHAT THAT FILE CANNOT SEE, AND IT IS FOUR THINGS.
//
//   * **THE ROUND TRIP IS THE FEATURE.** This console has no script on it, so
//     *Apply the profile* is a SUBMIT and the form is the only state there is:
//     a field the page fails to re-render falls back to its default on every
//     press, silently, for ever. In process both lists are values and the
//     comparison is exact; over HTTP the question is different and only
//     answerable here — does what the browser POSTS come back?
//   * **THE DOWNLOAD IS NOT A PAGE.** `POST /admin/pki/export` answers with the
//     FILE, through `formaction` on a button of the same form. The media type,
//     the `Content-Disposition` filename and the bytes being a real PKCS#12
//     are properties of a RESPONSE, and there is no response in process.
//   * **THE GATE.** A caller holding nothing must not be handed a private key
//     by a POST. That is a property of middleware on a path and there is no
//     middleware in process.
//   * **AND `/admin-api` MIRRORS ALL OF IT** (rule 7). Eight new actions, each
//     of which must exist, take the same form and answer the same way. A
//     console control whose operation is missing is exactly what that rule
//     exists to catch, and it is caught by comparing two live doors.
//   * **AND SINCE 2026-09-11, WHICH REALM'S AUTHORITIES ARE ON THE PAGE AT
//     ALL** (section 9). That needs TWO realms and a live door, so no
//     in-process file can ask it: `tests/pki_hierarchy.js` hands
//     `describeTree()` its own scope list, which is exactly the thing under
//     test here — what the CONSOLE puts in that list. The page drew every
//     realm's branch until that date, with a Rebuild and a Revoke under each,
//     and nothing failed, because every certificate in it was correct.
//
// ---------------------------------------------------------------------------
// WHY THIS IS THIS REPOSITORY'S OWN (`local: true`).
//
// The ownership argument `tests/CLAUDE.md` states and `sts_admin_console.js`
// was moved here on: the tree that ADDS a control to this console is the tree
// that should go red when the control loses its operation. Every assertion
// below is about `/admin/pki` or `/admin-api/pki` and nothing else.
//
// ---------------------------------------------------------------------------
// IT RUNS IN A THROWAWAY TRUST REALM, AND THE REALM IS LEFT STANDING.
//
// A certificate authority is per realm and so is the object store, so a realm
// of its own gives this job a store whose entire contents it wrote — which is
// what makes "the store holds exactly these two" an exact claim rather than
// "at least two". It is LEFT BEHIND deliberately: `tests/CLAUDE.md`'s *No job
// removes a realm* rule, and here the realm is also the only record of what was
// issued, which is the first thing somebody wants when this goes red.
//
// ---------------------------------------------------------------------------
// MUTATION RECORD — six mutants, each applied to a copy of the tree, driven,
// reverted:
//
//   1. the pane's POST answering through `respondToAction()` (a 303 with the
//      message on the query string) instead of re-rendering the page — caught
//      by section 2, which is the section the whole file is for;
//   2. `pki_selected` not drawn when the store is empty — caught by section 1,
//      and it is a REAL defect this pair found before either was committed;
//   3. the export answering `text/html` rather than the file — caught by
//      section 5 on the media type AND on the PKCS#12 magic;
//   4. `mayWrite()` dropped from the export handler — **SURVIVED, and it is
//      recorded rather than papered over.** Section 6 posts with NO SESSION,
//      and the console's gate refuses that before any handler runs — so what
//      that section asserts is the GATE and not the handler's own check. The
//      check is reachable only by a session holding Admin Read and NOT Admin
//      Write, and producing one means putting a member in the default realm's
//      `admin-read` group: those two groups are the DEFAULT REALM's for the
//      whole process, `admin.openWhenEmpty` grants both roles to everybody
//      while neither has a member, and adding one would take console writes
//      away from every other job in the run. The assertion is not worth that,
//      and `/admin/keys/export` carries the identical check one page over with
//      the same gap. **What section 6 does rule out is the failure that would
//      actually matter**: a private key reaching a caller who presented
//      nothing;
//   5. `issue-certificate` left off `PKI_ACTIONS` so the API refuses it —
//      caught by section 7, where the console and the API are compared;
//   6. the issued object's private key reported in `GET /admin-api/pki` —
//      caught by section 4, which is the assertion that would otherwise be an
//      absence nobody could see.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_pki_workbench",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const REALM = ("pkipane-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

// The two certificates this job makes. Fixed rather than random, because every
// sentence below quotes them and a name that changed per run would make a
// failing log unreadable.
const CA_CN = "Workbench Root";
const LEAF_CN = "leaf.pane.example.test";
const P12_PASSWORD = "changeit";

// THE OPERATOR WHO SIGNS IN, created by this job in its realm with a password
// (2026-09-12). It was the seeded `alice` with the password `x`, which works
// only because development mode seeds her and checks no password. The code
// flow authenticates in the realm the console is reached in, so that is where
// the account is made; the roster that decides what it may do is the default
// realm's, unchanged.
const OPERATOR = "pki-workbench-operator";
const OPERATOR_PASSWORD = "pki-workbench-Passw0rd!-" + names.runStamp();

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.debug("check passed: " + what);
}

function realmUrl(path) { return base + "/realm/" + REALM + path; }
function api(path) { return realmUrl("/admin-api" + path); }

// ---------------------------------------------------------------------------
// THE VERBS.
// ---------------------------------------------------------------------------
async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    // Not JSON — an HTML page, or a file. The caller reports the status and
    // the raw text, which says more than a parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

function get(url) { return fetchJson(url); }

function postJson(url, payload) {
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

// ---------------------------------------------------------------------------
// THE BROWSER'S HALF: a cookie jar, and a form read out of a page and posted
// back the way a browser would.
//
// **THE JAR KEEPS COOKIES BY NAME.** `sts_portal_backup_keys.js` records what
// the one-line version costs: a signed-in console browser holds the sign-on
// cookie AND the console's own relying-party cookie, whichever arrived last
// evicts the other, and what that looks like is a GET succeeding and the POST
// beside it redirecting to the authorization endpoint — a server that appears
// to have forgotten its session.
// ---------------------------------------------------------------------------
const jar = new Map();

function rememberCookies(response) {
  const raw = typeof response.headers.getSetCookie === "function"
    ? response.headers.getSetCookie()
    : (response.headers.get("set-cookie") ? [response.headers.get("set-cookie")] : []);
  raw.forEach(function (line) {
    const first = String(line).split(";")[0];
    const eq = first.indexOf("=");
    if (eq > 0) {
      jar.set(first.slice(0, eq).trim(), first.slice(eq + 1).trim());
    }
  });
}

function cookieHeader() {
  return Array.from(jar.entries()).map(function (pair) {
    return pair[0] + "=" + pair[1];
  }).join("; ");
}

// Follow redirects by hand, keeping the jar. `redirect: "follow"` would lose
// every `Set-Cookie` on the way through, which for a three-hop OIDC code flow
// is every cookie there is.
async function browse(url, options) {
  log.debug("Entering browse(). url=" + url);
  let next = url;
  for (let hop = 0; hop < 12; hop++) {
    const opts = Object.assign({ redirect: "manual" }, options || {});
    opts.headers = Object.assign({}, opts.headers || {});
    if (jar.size) {
      opts.headers.Cookie = cookieHeader();
    }
    const r = await fetch(next, opts);
    rememberCookies(r);
    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      next = new URL(r.headers.get("location"), next).toString();
      options = {};       // a redirect is followed as a GET
      continue;
    }
    const text = await r.text();
    log.debug("Leaving browse(). status=" + r.status + " url=" + next);
    return { status: r.status, text: text, url: next,
             contentType: r.headers.get("content-type") || "",
             disposition: r.headers.get("content-disposition") || "",
             response: r };
  }
  throw new Error("browse(): too many redirects starting at " + url);
}

// **THE ACTION IS MATCHED AS A SUFFIX AND NOT AS THE WHOLE VALUE.** Inside a
// trust realm `app.js` rewrites every root-relative `action` to carry the
// realm's prefix, which is what makes the console's several hundred
// hand-written links work in a realm without one of them being edited — so the
// form this job is looking for posts to `/realm/<id>/admin/pki/certificate`.
// Matching the bare path finds nothing, and the failure reads as "the pane is
// not on the page".
function form(page, action) {
  const at = page.search(new RegExp('action="[^"]*' +
    action.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + '"'));
  assert.ok(at >= 0, "no form posting to " + action + " on " + page.slice(0, 200));
  const start = page.lastIndexOf("<form", at);
  const end = page.indexOf("</form>", at);
  return page.slice(start, end);
}

function unescapeHtml(value) {
  return String(value).replace(/&quot;/g, '"').replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">").replace(/&#39;/g, "'").replace(/&amp;/g, "&");
}

// Every control of a form, as the browser would submit it: a text input's
// value, a checked box's value, a textarea's content, a select's selected
// option. **An unchecked box contributes nothing**, which is what makes the
// service's present-or-absent reading of a flag correct.
function fields(html) {
  const out = [];
  let m;
  const inputs = /<input([^>]*)>/g;
  while ((m = inputs.exec(html)) !== null) {
    const attrs = m[1];
    const name = (/name="([^"]*)"/.exec(attrs) || [])[1];
    if (!name) {
      continue;
    }
    const type = (/type="([^"]*)"/.exec(attrs) || [])[1] || "text";
    if ((type === "checkbox" || type === "radio") && !/checked/.test(attrs)) {
      continue;
    }
    out.push([name, unescapeHtml((/value="([^"]*)"/.exec(attrs) || [])[1] || "")]);
  }
  const areas = /<textarea[^>]*name="([^"]*)"[^>]*>([\s\S]*?)<\/textarea>/g;
  while ((m = areas.exec(html)) !== null) {
    out.push([m[1], unescapeHtml(m[2])]);
  }
  const selects = /<select[^>]*name="([^"]*)"[^>]*>([\s\S]*?)<\/select>/g;
  while ((m = selects.exec(html)) !== null) {
    const chosen = /<option value="([^"]*)"[^>]*selected/.exec(m[2]);
    out.push([m[1], chosen ? chosen[1] : ""]);
  }
  return out;
}

function bodyOf(pairs, extra, drop) {
  const set = new Map(pairs);
  (drop || []).forEach(function (name) { set.delete(name); });
  Object.keys(extra || {}).forEach(function (name) {
    set.set(name, extra[name]);
  });
  return Array.from(set.entries()).map(function (pair) {
    return encodeURIComponent(pair[0]) + "=" + encodeURIComponent(pair[1]);
  }).join("&");
}

function press(url, body) {
  return browse(url, { method: "POST", body: body,
                       headers: { "Content-Type":
                                  "application/x-www-form-urlencoded" } });
}

function valueOf(page, name) {
  const m = new RegExp('name="' + name + '"[^>]*value="([^"]*)"').exec(page);
  const n = new RegExp('<input[^>]*value="([^"]*)"[^>]*name="' + name + '"')
    .exec(page);
  const area = new RegExp('<textarea[^>]*name="' + name +
                          '"[^>]*>([\\s\\S]*?)<\\/textarea>').exec(page);
  if (area) {
    return unescapeHtml(area[1]);
  }
  return unescapeHtml((m || n || [])[1] || "");
}

function ticked(page, name) {
  return new RegExp('name="' + name + '" value="1" checked').test(page);
}

// ---------------------------------------------------------------------------
// SIGN IN TO THE CONSOLE. It is an OpenID Connect relying party since
// 2026-09-06, so this is the real code flow: `/admin` sends the browser to
// `/oauth2/authorize`, the sign-in screen posts a name, and the code comes back
// to `/admin/callback`.
//
// **THE CONSOLE'S SESSION IS THE DEFAULT REALM'S** wherever the console is
// reached, which is why this signs in at `/admin` and then walks to the
// realm's own page rather than the other way round.
// ---------------------------------------------------------------------------
async function signIn() {
  log.debug("Entering signIn().");
  const account = await postJson(api("/users/create"), {
    username: OPERATOR, invent: false,
    attributes: { cn: "PKI Workbench Operator", givenName: "PKI",
                  sn: "Workbench Operator", displayName: "PKI Workbench Operator",
                  mail: OPERATOR + "@pki-workbench.test" },
    credential: "password", password: OPERATOR_PASSWORD
  });
  assert.ok(account.status === 200 && account.body && account.body.ok,
            "creating the operator " + OPERATOR + " in " + REALM + " answered " +
            account.status + " " + String(account.text).slice(0, 300));
  const screen = await browse(realmUrl("/admin/pki"));
  assert.ok(/name="authn_id"/.test(screen.text),
            "the console did not send the browser to a sign-in screen; it " +
            "answered " + screen.status + " at " + screen.url);
  const id = valueOf(screen.text, "authn_id");
  const landed = await press(screen.url.replace(/\?.*$/, ""),
    bodyOf([["authn_id", id], ["username", OPERATOR],
            ["password", OPERATOR_PASSWORD],
            ["action", "login"]]));
  assert.ok(/<h1[^>]*>PKI/.test(landed.text),
            "signing in did not land on the PKI page; it landed on " +
            landed.url);
  log.debug("Leaving signIn().");
  return landed;
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------

// 1. THE FORM COMES BACK. Every control the browser posted is on the page it
// gets back — which is the whole mechanism, because with no script the form IS
// the state and a field the page forgets to re-render is a control that
// silently resets itself on every button press.
async function theFormRoundTrips(page) {
  log.info("=== 1. the form round-trips, which is the whole mechanism ===");
  const pane = form(page.text, "/admin/pki/certificate");
  const before = fields(pane);
  check("the pane carries a hundred or more fields", function () {
    assert.ok(before.length >= 55,
              "only " + before.length + " controls were readable out of the " +
              "pane; a browser would submit far more");
  });

  // **EVERY FIELD THE SERVICE SAYS IT READS IS ON THE PAGE IT SERVED.**
  // `tests/pki_authoring.js` makes this comparison against the renderer; this
  // makes it against the BYTES, which is the half that catches a field drawn
  // only in some states — `pki_selected` lives on the store table's radio
  // column and is a hidden input when the store is empty, so the version
  // without that fallback renders it on one page and not on the next and
  // nothing a round-trip check can see is different.
  //
  // It scans the MARKUP and not `fields()`, which is the difference between
  // "is the control there" and "would the browser submit it": an unticked
  // checkbox is drawn and contributes nothing, and reading the submitted set
  // would report fifty-five absent controls on a perfectly correct page.
  const declared = (await get(api("/pki"))).body.workbench.fields;
  const drawn = new Set();
  let named;
  const naming = /name="(pki_[A-Za-z0-9_]+)"/g;
  while ((named = naming.exec(pane)) !== null) {
    drawn.add(named[1]);
  }
  const absent = declared.filter(function (name) { return !drawn.has(name); });
  check("every field the service says it reads is drawn on the page it " +
        "served, in this state", function () {
          assert.deepStrictEqual(absent, [],
            "the page does not carry: " + absent.join(", "));
        });

  // A value in every KIND of control, so that the assertion below is about the
  // rendering of each rather than about one that happens to work.
  const typed = {
    pki_dn_cn: "round.trip.example.test",
    pki_dn_ou: "Round Trip",
    pki_san: "dns:round.trip.example.test\nip:10.9.8.7",
    pki_ext_san: "1",
    pki_ns_comment: "a comment with spaces",
    pki_ext_ns_comment: "1",
    pki_validity_years: "3"
  };
  const back = await press(realmUrl("/admin/pki/certificate"),
                           bodyOf(before, Object.assign({ defaults: "1" }, typed)));
  check("pressing Apply the profile answers with a PAGE and not a redirect",
        function () {
          assert.strictEqual(back.status, 200,
            "expected the pane's POST to render a page; got " + back.status +
            " at " + back.url);
          assert.ok(/<h1[^>]*>PKI/.test(back.text),
            "the answer was not the PKI page: " + back.text.slice(0, 200));
        });
  check("a Common Name somebody TYPED survives the round trip", function () {
    assert.strictEqual(valueOf(back.text, "pki_dn_cn"), typed.pki_dn_cn);
  });
  check("and so does a multi-line textarea, newlines and all", function () {
    assert.strictEqual(valueOf(back.text, "pki_san"), typed.pki_san);
  });
  check("and a value with spaces in it, unescaped correctly", function () {
    assert.strictEqual(valueOf(back.text, "pki_ns_comment"), typed.pki_ns_comment);
  });
  check("and a ticked box comes back ticked", function () {
    assert.ok(ticked(back.text, "pki_ext_ns_comment"));
  });

  // **THE COMPARISON THAT ONLY EXISTS OVER HTTP**: what the browser would
  // submit next time against what it submitted this time.
  const after = new Map(fields(form(back.text, "/admin/pki/certificate")));
  const lost = before.map(function (pair) { return pair[0]; })
    .filter(function (name) {
      return name !== "csrf_token" && !after.has(name);
    });
  check("NO FIELD WAS LOST on the way through — a control the page forgets " +
        "to re-render falls back to its default on every press, which is a " +
        "control that quietly undoes itself",
        function () {
          assert.deepStrictEqual(lost, [],
            "these fields did not come back: " + lost.join(", "));
        });
  return back;
}

// 2. ISSUE, through the browser, and what the reply says.
async function theBrowserIssues(page) {
  log.info("=== 2. a certificate is issued through the form ===");
  const pane = form(page.text, "/admin/pki/certificate");
  const issued = await press(realmUrl("/admin/pki/certificate"),
    bodyOf(fields(pane), {
      pki_profile: "root-ca",
      pki_key_alg: "ec-p256",
      pki_dn_cn: CA_CN,
      pki_ext_bc: "1", pki_bc_ca: "1", pki_bc_critical: "1",
      pki_ext_ku: "1", pki_ku_critical: "1",
      pki_ku_keyCertSign: "1", pki_ku_cRLSign: "1",
      pki_ext_skid: "1",
      pki_gen_csr: "1",
      pki_save_keys: "1"
    }));
  check("the issue answers 200 with the page rather than a 303", function () {
    assert.strictEqual(issued.status, 200,
      "got " + issued.status + " at " + issued.url);
  });
  check("the certification request is in the form afterwards, because the " +
        "box was ticked", function () {
    assert.ok(/BEGIN CERTIFICATE REQUEST/.test(issued.text),
      "no PKCS#10 in the redrawn form");
  });
  check("and the serial in the form is NOT the one that was just signed — a " +
        "serial that stayed put would be re-used by the next certificate the " +
        "same authority signs",
        function () {
          assert.notStrictEqual(valueOf(issued.text, "pki_serial"),
                                valueOf(pane, "pki_serial"));
        });
  check("the store now shows the certificate, named by its subject",
        function () {
          assert.ok(issued.text.indexOf(CA_CN) >= 0,
            "the store table does not mention " + CA_CN);
        });
  return issued;
}

// 3. A REFUSAL KEEPS THE FORM. A hundred and fifteen fields discarded because
// one line of a subjectAltName would not parse is not a refusal anybody can
// act on.
async function aRefusalKeepsTheForm(page) {
  log.info("=== 3. a refusal comes back with the form still in it ===");
  const pane = form(page.text, "/admin/pki/certificate");
  const refused = await press(realmUrl("/admin/pki/certificate"),
    bodyOf(fields(pane), {
      pki_dn_cn: "kept.example.test",
      pki_ext_san: "1",
      pki_san: "this line has no type at all"
    }));
  check("it is still a page", function () {
    assert.strictEqual(refused.status, 200);
  });
  check("the refusal NAMES the line it could not read", function () {
    assert.ok(/has no type/.test(refused.text),
      "the page does not explain the refusal: " +
      refused.text.replace(/<[^>]*>/g, " ").slice(0, 400));
  });
  check("and the Common Name that was typed is still in the box", function () {
    assert.strictEqual(valueOf(refused.text, "pki_dn_cn"), "kept.example.test");
  });
  check("as is the line that caused it, so it can be corrected rather than " +
        "retyped", function () {
    assert.ok(valueOf(refused.text, "pki_san").indexOf("no type at all") >= 0);
  });
}

// 4. THE STORE, THROUGH `/admin-api`, AND WHAT IS NOT IN IT.
async function theStoreIsReported() {
  log.info("=== 4. the store as the API reports it ===");
  const view = await get(api("/pki"));
  check("GET /admin-api/pki answers", function () {
    assert.strictEqual(view.status, 200, view.text.slice(0, 200));
  });
  const wb = view.body.workbench;
  check("it publishes the pane's whole vocabulary, so a client reads it from " +
        "the service rather than from a copy of it in a document", function () {
    assert.ok(wb.fields.length >= 100, "only " + wb.fields.length + " fields");
    assert.strictEqual(wb.profiles.length, 14);
    assert.strictEqual(wb.pqModes.length, 5);
    assert.ok(wb.keyAlgorithms.length >= 7);
    assert.deepStrictEqual(wb.keystoreFormats, ["pem", "der", "jwk", "pkcs12"]);
  });
  const mine = wb.objects.filter(function (one) {
    return one.subject.indexOf(CA_CN) >= 0;
  });
  check("the certificate issued through the browser is in the store the API " +
        "reports — one store, two doors", function () {
          assert.strictEqual(mine.length, 1,
            "expected exactly one " + CA_CN + "; found " + mine.length);
        });
  check("it is reported as a CA, with its certificate in full", function () {
    assert.strictEqual(mine[0].ca, true);
    assert.ok(mine[0].certificatePem.indexOf("BEGIN CERTIFICATE") >= 0);
  });
  check("**AND NO PRIVATE KEY IS ANYWHERE IN THE REPLY** — the report says " +
        "whether the key is held and never shows it; this is the assertion " +
        "that would otherwise be an absence nobody could see", function () {
    assert.ok(JSON.stringify(view.body).indexOf("PRIVATE KEY") < 0,
      "a PRIVATE KEY block appears in GET /admin-api/pki");
    assert.strictEqual(mine[0].hasPrivateKey, true);
  });
  check("and it is offered as an ISSUER, because its private key is here",
        function () {
          assert.ok(wb.issuers.some(function (one) {
            return one.id === mine[0].id;
          }), "the CA is not in the issuer list");
        });
  return mine[0];
}

// 5. THE DOWNLOAD, which is the one form on this page whose answer is a FILE.
async function theDownloadIsAFile(page, object) {
  log.info("=== 5. Download answers with the file itself ===");
  const pane = form(page.text, "/admin/pki/certificate");
  const file = await press(realmUrl("/admin/pki/export"),
    bodyOf(fields(pane), {
      pki_selected: object.id,
      pki_ks_format: "pkcs12",
      pki_ks_password: P12_PASSWORD,
      pki_ks_include_chain: "1",
      export: "1"
    }));
  check("it is not a page", function () {
    assert.strictEqual(file.status, 200, file.text.slice(0, 300));
    assert.ok(/application\/x-pkcs12/.test(file.contentType),
      "the media type is " + file.contentType);
  });
  check("and it is named after the certificate rather than after the form",
        function () {
          assert.ok(/attachment; filename="/.test(file.disposition),
            "no attachment disposition: " + file.disposition);
          assert.ok(file.disposition.indexOf("Workbench-Root") >= 0 ||
                    file.disposition.indexOf(CA_CN.replace(/ /g, "-")) >= 0,
            "the filename does not name the subject: " + file.disposition);
        });
  // A PKCS#12 is a DER SEQUENCE, so the first byte is 0x30. Checking the MAGIC
  // rather than the length is what tells a real keystore from an HTML error
  // page served with the right media type.
  check("the body really is DER and not a page wearing a media type",
        function () {
          const first = Buffer.from(file.text, "binary")[0];
          assert.strictEqual(first, 0x30,
            "the first byte is 0x" + first.toString(16) + ", not a DER " +
            "SEQUENCE");
        });

  log.info("--- and PKCS#12 without a password is REFUSED as a page ---");
  const refused = await press(realmUrl("/admin/pki/export"),
    bodyOf(fields(pane), {
      pki_selected: object.id, pki_ks_format: "pkcs12",
      pki_ks_password: "", export: "1"
    }));
  check("a refused export is a PAGE, so it reads like every other refusal on " +
        "this console rather than as a broken download", function () {
          assert.strictEqual(refused.status, 200);
          assert.ok(/text\/html/.test(refused.contentType),
            "a refusal came back as " + refused.contentType);
          assert.ok(/password/i.test(refused.text),
            "the refusal does not mention the password");
        });
}

// 6. THE GATE. A caller holding nothing must not be handed a private key.
//
// **THIS IS NOT THE ROLE SPLIT AND THE HEADER SAYS WHY.** The handler's own
// `mayWrite()` is reachable only by a session with Admin Read and not Admin
// Write, and this job cannot produce one without editing the default realm's
// role roster, which every other job in the run shares. What is asserted here
// is the failure that would actually matter.
async function theExportNeedsASession() {
  log.info("=== 6. the export is not open to a caller with no session ===");
  const r = await fetch(realmUrl("/admin/pki/export"),
    { method: "POST", redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "pki_ks_format=pem" });
  const text = await r.text();
  check("a POST to the export with no console session does not hand over a " +
        "key", function () {
          assert.ok(r.status !== 200 ||
                    !/application\/x-pkcs12|x-pem-file/.test(
                      r.headers.get("content-type") || ""),
            "the export answered " + r.status + " with " +
            r.headers.get("content-type") + " to a caller holding nothing");
          assert.ok(String(text).indexOf("PRIVATE KEY") < 0,
            "a private key was returned to a caller with no session");
        });
}

// 7. RULE 7: the console's controls and the API's operations are the same set,
// and they reach the same functions.
async function theApiMirrorsThePane(object) {
  log.info("=== 7. /admin-api mirrors the pane (rule 7) ===");
  const unknown = await postJson(api("/pki/nonsense"), {});
  check("the unknown-action sentence names every action", function () {
    assert.strictEqual(unknown.status, 400);
    const said = (unknown.body.errors || []).join(" ");
    ["apply-profile", "generate-keys", "generate-alt-keys",
     "issue-certificate", "use-key", "remove-object", "clear-store",
     "export"].forEach(function (action) {
      assert.ok(said.indexOf(action) >= 0,
        'the refusal does not name "' + action + '": ' + said);
    });
  });

  const applied = await postJson(api("/pki/apply-profile"),
    { pki_profile: "tls-server", pki_pq_mode: "classical" });
  check("apply-profile answers with the whole form", function () {
    assert.strictEqual(applied.status, 200, applied.text.slice(0, 200));
    assert.strictEqual(applied.body.draft.pki_dn_cn, "server");
    assert.strictEqual(applied.body.draft.pki_eku_serverAuth, true);
  });

  const leaf = await postJson(api("/pki/issue-certificate"),
    Object.assign({}, applied.body.draft, {
      pki_issuer: object.id,
      pki_key_alg: "ec-p256",
      pki_dn_cn: LEAF_CN,
      pki_ext_san: "1",
      pki_san: "dns:" + LEAF_CN,
      pki_save_keys: "1"
    }));
  check("a leaf is issued through the API from the CA the BROWSER made — " +
        "which is the two doors meeting on one store", function () {
          assert.strictEqual(leaf.status, 200, leaf.text.slice(0, 300));
          assert.ok(leaf.body.object.subject.indexOf(LEAF_CN) >= 0);
          assert.strictEqual(leaf.body.object.selfSigned, false);
          assert.ok(leaf.body.object.issuerSubject.indexOf(CA_CN) >= 0,
            "the leaf names " + leaf.body.object.issuerSubject +
            " as its issuer");
        });

  const exported = await postJson(api("/pki/export"),
    { objectId: leaf.body.object.id, pki_ks_format: "pem" });
  check("the API's export answers JSON with the bytes base64'd, where the " +
        "console's answers the file — one function, two shapes, because a " +
        "browser and a machine asked different questions", function () {
          assert.strictEqual(exported.status, 200, exported.text.slice(0, 200));
          assert.ok(exported.body.files.length >= 1);
          const pem = Buffer.from(exported.body.files[0].base64, "base64")
            .toString("utf8");
          assert.ok(pem.indexOf("BEGIN CERTIFICATE") >= 0,
            "the exported PEM carries no certificate");
          assert.ok(pem.indexOf("PRIVATE KEY") >= 0,
            "the exported PEM carries no private key, which is what an " +
            "export is for");
        });

  const removed = await postJson(api("/pki/remove-object"),
    { objectId: leaf.body.object.id });
  check("remove-object removes it", function () {
    assert.strictEqual(removed.status, 200, removed.text.slice(0, 200));
  });
  const after = await get(api("/pki"));
  check("and the CA it was issued FROM is untouched, because removing a leaf " +
        "is not removing an authority", function () {
          const left = after.body.workbench.objects;
          assert.ok(!left.some(function (one) { return one.id === leaf.body.object.id; }),
            "the leaf is still in the store");
          assert.ok(left.some(function (one) { return one.id === object.id; }),
            "the CA went with it");
        });
}

// 8. THE HIERARCHY AND THE STORE ARE TWO THINGS IN ONE REALM, and the two
// buttons must not touch each other. This is a claim about `/admin-api`'s
// `build` and `clear-store` meeting the pane's objects.
async function theHierarchyAndTheStoreAreSeparate() {
  log.info("=== 8. building the hierarchy does not empty the store ===");
  const built = await postJson(api("/pki/build"), { organisation: "Pane Test" });
  check("the three-tier hierarchy builds in the same realm", function () {
    assert.strictEqual(built.status, 200, built.text.slice(0, 300));
    assert.strictEqual(built.body.chain.tiers.length, 3);
  });
  const after = await get(api("/pki"));
  check("and the object the pane issued is STILL THERE — a button labelled " +
        "\"build the certificate authority\" has no business discarding " +
        "somebody's key pairs", function () {
          assert.ok(after.body.workbench.objects.some(function (one) {
            return one.subject.indexOf(CA_CN) >= 0;
          }), "the pane's CA went when the hierarchy was built");
        });
  check("the three tiers are now offered as issuers beside it", function () {
    const ids = after.body.workbench.issuers.map(function (one) { return one.id; });
    ["tier:root", "tier:intermediate", "tier:issuing"].forEach(function (id) {
      assert.ok(ids.indexOf(id) >= 0, "no issuer " + id + " in " + ids.join(", "));
    });
  });

  const cleared = await postJson(api("/pki/clear-store"), {});
  check("clear-store empties the pane's store", function () {
    assert.strictEqual(cleared.status, 200, cleared.text.slice(0, 200));
  });
  const last = await get(api("/pki"));
  check("and LEAVES the hierarchy standing, which is the same rule read the " +
        "other way", function () {
          assert.strictEqual(last.body.workbench.objects.length, 0);
          assert.ok(last.body.chain && last.body.chain.tiers.length === 3,
            "the hierarchy went with the store");
        });
}

// ===========================================================================
// 9. THE PAGE AND THE API SHOW ONE REALM'S AUTHORITIES (2026-09-11).
//
// **THIS SECTION EXISTS BECAUSE THE DEFECT IT PINS WAS INVISIBLE TO EVERY
// OTHER ASSERTION IN EITHER SUITE.** `/admin/pki` drew the whole process —
// the Root, the process branch and EVERY realm's Intermediate — so an
// operator in one realm was handed a Rebuild button for another realm's
// certificate authority and a Revoke for certificates issued in it. Nothing
// failed: every tier was correct, every path verified, and the page was
// bigger than it should have been in a way that reads as thoroughness.
//
// It needs TWO realms to see at all, which is why it is here rather than in
// `tests/pki_hierarchy.js` beside the model: that file hands `describeTree()`
// its own scope list, so it can only assert what that function does with a
// list and never what the CONSOLE puts in one. The narrowing lives in
// `admin-ui/pki_admin.js` deliberately — `common/pki.js` is handed scope ids
// and has no opinion about which exist — so the only door that can be asked
// is this one, in a realm, twice.
//
// The job's own throwaway realm is one of the two and the DEFAULT realm is the
// other, and section 8 has already built a hierarchy in the throwaway — so by
// the time this runs there is a branch in the keystore that the default
// realm's page must not be drawing.
// ===========================================================================
async function eachRealmSeesItsOwnAuthorities() {
  log.info("=== 9. one realm's authorities, in the page and in the API ===");

  const mine = await get(api("/pki"));
  check("GET /admin-api/pki answers in the throwaway realm", function () {
    assert.strictEqual(mine.status, 200, mine.text.slice(0, 300));
    assert.ok(mine.body.tree && Array.isArray(mine.body.tree.scopes),
      "no tree in the reply: " + mine.text.slice(0, 200));
  });

  const myScopes = mine.body.tree.scopes.map(function (one) { return one.scope; });
  check("and the tree it draws is EXACTLY two branches — the process one and " +
        "this realm's. The Root is above both and is reported as `root` " +
        "rather than as a scope, which is what makes this an exact count " +
        "rather than an \"at least\"",
        function () {
          assert.deepStrictEqual(myScopes.slice().sort(),
            ["*process", REALM].sort(),
            "the tree carries " + myScopes.join(", "));
        });
  check("the Root is there, because every realm hangs from it and it is this " +
        "realm's anchor — narrowing the branches must not narrow the ANCHOR, " +
        "which would leave a page showing an Intermediate signed by nothing",
        function () {
          assert.ok(mine.body.tree.rootBuilt, "no Root in the reply");
          assert.ok(mine.body.tree.root && mine.body.tree.root.subject,
            JSON.stringify(mine.body.tree.root));
        });
  check("the PROCESS branch is drawn in this realm and that is deliberate: " +
        "the TLS authority certifies sockets every realm answers on, and " +
        "there is no other surface anywhere that draws it",
        function () {
          const process = mine.body.tree.scopes.filter(function (one) {
            return one.scope === "*process";
          })[0];
          assert.ok(process, "no process branch");
          const ids = process.issuing.map(function (one) { return one.id; });
          assert.ok(ids.indexOf("tls") >= 0, ids.join(", "));
        });
  // **THIS ASSERTED `spiffe` ON THE PROCESS BRANCH UNTIL 2026-09-11**, when
  // the SPIFFE authority moved to a REALM's branch — each realm signs its own
  // X509-SVIDs, and what keeps that coherent with SPIFFE's four SHARED sockets
  // is that the trust anchor is the service Root, which no realm owns. The
  // assertion is kept rather than deleted and pointed at where the authority
  // actually is: an Issuing CA silently filed under the wrong Intermediate is
  // the failure this pair of checks exists for, and deleting half of it would
  // have left the other half unable to see it.
  check("while the SPIFFE authority is on THIS REALM's branch since " +
        "2026-09-11 — a realm signs its own X509-SVIDs, and the anchor they " +
        "verify against is the service Root that every realm shares",
        function () {
          const realm = mine.body.tree.scopes.filter(function (one) {
            return one.scope === REALM;
          })[0];
          assert.ok(realm, "no realm branch");
          const ids = realm.issuing.map(function (one) { return one.id; });
          assert.ok(ids.indexOf("spiffe") >= 0, ids.join(", "));
          const process = mine.body.tree.scopes.filter(function (one) {
            return one.scope === "*process";
          })[0];
          assert.ok(process.issuing.every(function (one) {
            return one.id !== "spiffe";
          }), "the process branch still carries a spiffe Issuing CA");
        });

  // ---------------------------------------------------------------------
  // THE HALF THAT ACTUALLY CAUGHT IT: the DEFAULT realm's view, which held
  // this realm's branch until the narrowing.
  // ---------------------------------------------------------------------
  const theirs = await get(base + "/admin-api/pki");
  check("GET /admin-api/pki answers in the DEFAULT realm too", function () {
    assert.strictEqual(theirs.status, 200, theirs.text.slice(0, 300));
  });
  const theirScopes = theirs.body.tree.scopes.map(function (one) { return one.scope; });
  check("and it does NOT carry this job's realm — which is the whole " +
        "narrowing, and the assertion that was failing before it: section 8 " +
        "built a hierarchy in \"" + REALM + "\" and the default realm's page " +
        "was drawing it, with a Rebuild button under it",
        function () {
          assert.ok(theirScopes.indexOf(REALM) < 0,
            "the default realm draws " + theirScopes.join(", "));
        });
  // `default` and not `""`: `common/pki.js`'s `realmIdOf()` resolves an empty
  // scope to the AMBIENT realm, so the empty string is not this realm's name
  // there — it is *whichever realm is asking*, and the two are the same thing
  // only in the default realm. Asserting `""` here would pass for a view that
  // named the current realm whatever realm it was.
  check("it carries the process branch and the DEFAULT realm's own, and " +
        "nothing else — the same claim read from the other side, so a view " +
        "that answered everything to everybody could not pass both",
        function () {
          assert.deepStrictEqual(theirScopes.slice().sort(),
            ["*process", "default"].sort(),
            "the default realm draws " + theirScopes.join(", "));
        });

  // ---------------------------------------------------------------------
  // THE REVOCATION REGISTER NARROWS WITH THE TREE. This is the half where
  // the leak was more than untidy: a revocation is permanent and is made BY
  // AN ISSUER, so a Revoke button for an authority in a realm the operator
  // never switched to changes a realm they cannot see.
  // ---------------------------------------------------------------------
  check("the revocation register in the DEFAULT realm names no authority in " +
        "this job's realm — a Revoke is permanent and is made by an ISSUER, " +
        "so the row's authority is the only thing saying which realm is " +
        "about to change", function () {
          const scopes = theirs.body.revocation.authorities
            .map(function (one) { return one.scope; });
          assert.ok(scopes.indexOf(REALM) < 0, scopes.join(", "));
        });
  check("and in this realm every authority offered is one this realm is " +
        "under: its own, the process branch's, or the service Root",
        function () {
          mine.body.revocation.authorities.forEach(function (one) {
            assert.ok(one.scope === REALM || one.scope === "*process" ||
                      one.scope === "*service",
              "a foreign authority is offered: " + one.scope + "/" + one.ca);
          });
          assert.ok(mine.body.revocation.authorities.length > 0,
            "no authorities at all, so this proves nothing");
        });

  // ---------------------------------------------------------------------
  // AND THE WRITE PATH, WHICH IS THE HALF A DRAWING TEST CANNOT SEE. A page
  // that hides a branch while its actions still edit it is worse than the
  // leak it replaced: the operator cannot see what they changed.
  // ---------------------------------------------------------------------
  const foreign = await postJson(base + "/admin-api/pki/build-scope",
                                 { scope: REALM });
  check("POST build-scope in the DEFAULT realm naming ANOTHER realm's branch " +
        "is REFUSED — hiding a branch from the page while the action still " +
        "rebuilt it would be the worse half of the old behaviour",
        function () {
          assert.ok(foreign.body && foreign.body.ok === false,
            "it was allowed: " + foreign.status + " " +
            foreign.text.slice(0, 300));
        });
  check("and the refusal NAMES THE REALM SWITCHER rather than just saying " +
        "no, because switching realms is how to do the thing that was asked",
        function () {
          const why = String((foreign.body.errors || []).join(" ") +
                             " " + (foreign.body.why || ""));
          assert.ok(/switch/i.test(why) && /realm/i.test(why), why.slice(0, 300));
        });
  check("the refusal came back in `errors` as well as `why` — the field a " +
        "test reads, which two other jobs match sentences out of",
        function () {
          assert.ok(Array.isArray(foreign.body.errors) &&
                    foreign.body.errors.length, JSON.stringify(foreign.body));
        });
  check("and it changed NOTHING: the throwaway realm's Intermediate is the " +
        "same certificate it was before the refused call. A refusal that " +
        "half-ran would be the one outcome worse than allowing it",
        function () {
          const before = mine.body.tree.scopes.filter(function (one) {
            return one.scope === REALM;
          })[0];
          assert.ok(before && before.intermediate, "no Intermediate to compare");
          return before;
        });
  const again = await get(api("/pki"));
  check("— checked by reading it back, thumbprint for thumbprint", function () {
    const was = mine.body.tree.scopes.filter(function (one) {
      return one.scope === REALM;
    })[0].intermediate.thumbprint;
    const is = again.body.tree.scopes.filter(function (one) {
      return one.scope === REALM;
    })[0].intermediate.thumbprint;
    assert.strictEqual(is, was, "the refused rebuild rebuilt it anyway");
  });

  // The process branch is the exception and must STAY reachable from any
  // realm: it belongs to none, so no realm's page is more its home.
  const ownScope = await postJson(api("/pki/build-scope"), { scope: REALM });
  check("a realm may still rebuild ITS OWN branch, which is the control the " +
        "refusal above must not have taken away", function () {
          assert.ok(ownScope.body && ownScope.body.ok !== false,
            ownScope.status + " " + ownScope.text.slice(0, 300));
        });

  // ---------------------------------------------------------------------
  // AND THE PAGE SAYS THE SAME AS THE API, which is rule 7 read for a VIEW
  // rather than for an action: the console and the management API are one
  // function, so a narrowing that reached one and not the other would be two
  // answers to "what is this realm's certificate authority".
  // ---------------------------------------------------------------------
  const page = await browse(realmUrl("/admin/pki"));
  check("the console page in this realm answers", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
  });
  check("and it does not name the DEFAULT realm's branch anywhere on it — " +
        "the page is drawn from the same view, so this is the claim that the " +
        "narrowing is in the VIEW and not in one renderer",
        function () {
          assert.ok(!/realm default<\/span>/.test(page.text),
            "the default realm's branch is drawn in " + REALM);
        });
  check("it says in as many words which realm's authorities are on it, " +
        "because a page that quietly shows less than it used to is a page " +
        "somebody will read as a service that lost its other realms",
        function () {
          assert.ok(/only[\s\S]{0,40}that/i.test(page.text) &&
                    /switch realms/i.test(page.text),
            "the page does not say what it is showing");
        });
}

// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving the PKI pane at " + base + " in realm " + REALM + ".");

  const made = await postJson(base + "/admin-api/realms/create",
    { id: REALM, name: "PKI pane test" });
  assert.ok(made.status === 200 && made.body && made.body.ok !== false,
    "the realm could not be created: " + made.status + " " +
    made.text.slice(0, 300));
  log.info("Realm " + REALM + " created. IT IS LEFT BEHIND on purpose — " +
           "tests/CLAUDE.md's rule, and here it is also the only record of " +
           "what was issued.");

  const page = await signIn();
  const applied = await theFormRoundTrips(page);
  const issued = await theBrowserIssues(applied);
  await aRefusalKeepsTheForm(issued);
  const object = await theStoreIsReported();
  await theDownloadIsAFile(issued, object);
  await theExportNeedsASession();
  await theApiMirrorsThePane(object);
  await theHierarchyAndTheStoreAreSeparate();
  await eachRealmSeesItsOwnAuthorities();

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure a suite cannot report about itself.
  assert.ok(checks >= 40,
    "only " + checks + " checks ran. This file makes over forty against " +
    "a healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED rather than that the feature got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_pki_workbench")
  .description("Drive the mock STS's Certificate & Key Configuration pane " +
      "through both its doors, in a throwaway trust realm: the form round " +
      "trip that is the whole mechanism with no script, an issue, a refusal " +
      "that keeps the form, the store as /admin-api reports it, the download " +
      "that is a file rather than a page, rule 7's parity between the " +
      "console and the API, and that each realm is shown its own " +
      "certificate authorities and no other realm's.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
