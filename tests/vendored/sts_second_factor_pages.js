"use strict";
//
// File: sts_second_factor_pages.js
//
// ===========================================================================
// THE TWO SECOND-FACTOR MECHANISM PAGES, AND THE ROSTER THAT USED TO SIT
// BESIDE THEM (2026-09-10).
//
// `/admin/mfa` did two things and could only be filed by one of them: it
// edited the eight `totp.*` settings, and it drew a roster of who held a
// second factor with a Clear button on every row. It is gone, and this job is
// what the split owes:
//
//   * **`/admin/totp` and `/admin/webauthn` under Protocols** — one page per
//     MECHANISM, each with its settings and each with a report read from the
//     module that performs the algorithm.
//   * **`/admin/users`** — the roster, as columns and a `factor` filter, with
//     the per-person detail and both Clear buttons on that person's own row.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE AND NOT IN THE PARENT SUITE.
//
// The OWNERSHIP argument, which `tests/CLAUDE.md` puts before the capability
// one: every assertion is about this service's own `/admin` console or its
// `/admin-api`, and the tree that MOVES a control is the tree that should go
// red when the control lands nowhere.
//
// ---------------------------------------------------------------------------
// AND WHY IT IS NOT `tests/webauthn_policy.js`, WHICH LANDED THE SAME DAY.
//
// That file is in process and asserts what the settings module DECIDES — that
// the ceremony can never offer an algorithm the verifier cannot check, that
// the RP ID may only be widened to a real domain suffix, that the policy rows
// refuse an enrolment and never an authentication. Not one of those is
// reachable over HTTP, and not one of them says whether any of it reaches a
// PAGE.
//
// This file asserts the wiring, and the wiring is where a move like this
// actually breaks: a settings group whose page was renamed and now has none, a
// console page with no `/admin-api` operation, a column that renders `[object
// Object]`, a Clear button posting an action the handler no longer knows. Every
// one of those is invisible in process and obvious in a request.
//
// ---------------------------------------------------------------------------
// THE ASSERTION THE FILE IS REALLY FOR IS A TRANSITION, NOT A PAGE.
//
// *`/admin/totp` renders* would pass against a page with no settings on it.
// So the settings are CHANGED through `/admin-api/config/set-many` and the
// change is read back out of the MECHANISM REPORT rather than out of the
// settings block beside it — because the report is the half that is supposed
// to be derived, and a page that drew a hand-written table would agree with
// the setting it was told about and disagree with the ceremony.
//
// Every setting is restored with `reset` and not by writing the old value
// back, which is this suite's standing rule: a `set` leaves the row reading
// `source: override` even when the value is the default, and the next job in
// the run is the one that fails.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_second_factor_pages",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// A person of this run's own, so two runs against one long-lived mock never
// meet. The directory is append-only in practice and nothing here removes an
// entry — see `tests/CLAUDE.md` on why a job leaves its work behind.
var PERSON = usernameFor("second-factor");

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  ✓ " + what);
}

async function get(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // Not JSON — an HTML error page. Quoting it whole says more than a parse
    // failure would.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function post(path, payload) {
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {})
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function ok(path, payload, what) {
  const r = await post(path, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status + " " +
    JSON.stringify((r.body && r.body.errors) || r.body).slice(0, 400));
  return r.body;
}

// Put a setting back, and NEVER throw doing it. See the call sites: this runs
// in a `finally`, and a `finally` that throws replaces the failure that got you
// there. Resetting a key nobody overrode is refused 400 by design — which is
// the ordinary outcome when the section above failed before it wrote anything.
async function resetQuietly(keys) {
  for (const key of keys) {
    const r = await post("/config/reset", { key: key });
    if (r.status !== 200) {
      log.warn("  – " + key + " was not reset (" + r.status + "): " +
               JSON.stringify((r.body && r.body.errors) || r.body).slice(0, 200) +
               ". That is the expected answer where nothing overrode it.");
    }
  }
}

// The console page as a BROWSER would get it — HTML rather than `?format=json`
// — because half of what this file checks is markup. No cookie jar: the
// launchers run with the console reachable, and where it is not, the status
// says so and the section reports it rather than pretending.
async function page(path) {
  const r = await fetch(base + path, { redirect: "manual" });
  const text = await r.text();
  return { status: r.status, location: r.headers.get("location") || "",
           text: text };
}

// ---------------------------------------------------------------------------
// 0. THE PAGE THAT WENT AWAY.
//
// **AN UNROUTED PATH UNDER `/admin` DOES NOT ANSWER `Cannot GET /path`, AND
// THE FIRST VERSION OF THIS SECTION ASSERTED THAT IT DID.** The root
// CLAUDE.md's rule about Express's 404 body is real and is what
// `sts_metadata.js` reads — and it is about paths the ROUTER reaches. The
// console's gate is middleware on the whole `/admin` prefix and answers 303 to
// the OIDC code flow before any route is consulted, so every unrouted path
// under it looks exactly like every other one from out here.
//
// That is correct and it means the removal cannot be asserted from the status
// alone. **So the 303 is asserted to be THE GATE rather than a page**, by
// asking a path nobody has ever registered and requiring the same answer —
// and the claim that the page is gone is made against the console's OWN PAGE
// LIST, which is what `admin_api.js`'s parity check walks and therefore the
// list that has to be right.
// ---------------------------------------------------------------------------
async function theOldPageIsGone() {
  log.info("=== /admin/mfa is gone, and the console's page list says so ===");
  const gone = await page("/admin/mfa");
  const neverExisted = await page("/admin/no-such-page-has-ever-existed");
  check("GET /admin/mfa answers exactly as a path nobody ever registered does " +
        "— the console's gate, not a page. Asserting the status alone would " +
        "say nothing here, because that gate is middleware on the whole prefix",
    function () {
      assert.strictEqual(gone.status, neverExisted.status,
        "/admin/mfa answered " + gone.status + " and an unregistered path " +
        "answered " + neverExisted.status + ", so something is still " +
        "registered there: " + String(gone.text).slice(0, 200));
    });

  const meta = await get("/status");
  check("and the console's own page list no longer names it, while naming " +
        "the two that replaced it — which is what keeps rule 7 honest, since " +
        "that list is what the parity check walks", function () {
    const pages = (meta.body && meta.body.pages) || [];
    assert.ok(pages.length > 5, "the status reply carried no page list: " +
      JSON.stringify(meta.body).slice(0, 200));
    assert.ok(pages.indexOf("/admin/mfa") < 0,
      "/admin/mfa is still on the console's page list.");
    assert.ok(pages.indexOf("/admin/totp") >= 0,
      "/admin/totp is not on the console's page list.");
    assert.ok(pages.indexOf("/admin/webauthn") >= 0,
      "/admin/webauthn is not on the console's page list.");
  });

  // THE RESOURCE IS KEPT AND THE PAGE IS NOT, which is rule 7 read the way
  // round it usually is not — see `mgmt-api/admin_api.js`. Asserted because
  // deleting it would be the tidy-looking mistake, and because a caller's
  // script is the thing that would find out.
  const roster = await get("/mfa");
  check("GET /admin-api/mfa still answers, out of the view that absorbed it — " +
        "an API operation that worked is not worth breaking to tidy a table",
    function () {
      assert.strictEqual(roster.status, 200,
        "GET /admin-api/mfa answered " + roster.status + " " +
        String(roster.raw).slice(0, 200));
      assert.ok(Array.isArray(roster.body.people),
        "it no longer carries a `people` array, which is the shape a caller " +
        "reads: " + JSON.stringify(roster.body).slice(0, 200));
    });
}

// ---------------------------------------------------------------------------
// 1. THE SETTINGS FOUND THEIR NEW PAGE.
//
// `checkSettingHomes()` refuses a setting group with no page AT REQUIRE TIME,
// so a group renamed without its `SETTING_HOMES` row is a service that logs
// and carries on — the settings are then editable NOWHERE and every page looks
// fine. That is exactly the failure this section is for, and it is why it
// counts the rows rather than checking that the page renders.
// ---------------------------------------------------------------------------
async function theSettingsAreOnTheirPages() {
  log.info("=== the settings are drawn on the mechanism pages ===");

  const totp = await get("/totp");
  check("GET /admin-api/totp carries the eight totp.* settings", function () {
    assert.strictEqual(totp.status, 200,
      "it answered " + totp.status + " " + String(totp.raw).slice(0, 200));
    const keys = keysOf(totp.body);
    assert.ok(keys.length >= 8,
      "it drew " + keys.length + " setting(s): " + keys.join(", "));
    assert.ok(keys.every(function (k) { return /^totp\./.test(k); }),
      "and a setting that is not a totp.* row is drawn on it: " +
      keys.join(", "));
  });

  const web = await get("/webauthn");
  check("GET /admin-api/webauthn carries the thirteen webauthn.* settings — " +
        "there were NONE of these before 2026-09-10, and every ceremony " +
        "parameter was a literal in a string in authn/authn.js", function () {
    assert.strictEqual(web.status, 200,
      "it answered " + web.status + " " + String(web.raw).slice(0, 200));
    const keys = keysOf(web.body);
    assert.ok(keys.length >= 13,
      "it drew " + keys.length + " setting(s): " + keys.join(", "));
    assert.ok(keys.every(function (k) { return /^webauthn\./.test(k); }),
      "and a setting that is not a webauthn.* row is drawn on it: " +
      keys.join(", "));
  });

  // THE PAGES THEMSELVES, in a browser's shape. The JSON above proves the
  // model; this proves that a person can reach a form. Where the console needs
  // a session the launchers do not have, a redirect is the honest answer and
  // the section says so rather than asserting markup it never received.
  const drawn = await page("/admin/totp");
  if (drawn.status === 200) {
    check("and /admin/totp draws a form carrying those rows", function () {
      assert.ok(/totp\.window/.test(drawn.text),
        "the page has no totp.window control on it.");
      assert.ok(/<form/i.test(drawn.text),
        "the page draws no form at all.");
    });
    const drawnWeb = await page("/admin/webauthn");
    check("and /admin/webauthn does the same, including the CTAP rows that " +
          "are the reason it says CTAP anywhere", function () {
      assert.strictEqual(drawnWeb.status, 200,
        "/admin/webauthn answered " + drawnWeb.status);
      assert.ok(/webauthn\.residentKey/.test(drawnWeb.text),
        "the page has no webauthn.residentKey control on it.");
      assert.ok(/webauthn\.authenticatorAttachment/.test(drawnWeb.text),
        "the page has no webauthn.authenticatorAttachment control on it.");
    });
  } else {
    log.info("  – the console needs a session here (" + drawn.status +
             "), so the markup half is left to sts_admin_console.js. The " +
             "model half above is unaffected.");
  }
}

function keysOf(body) {
  const groups = (body && body.settings && body.settings.groups) || [];
  const out = [];
  groups.forEach(function (group) {
    (group.settings || []).forEach(function (row) { out.push(row.key); });
  });
  return out;
}

// ---------------------------------------------------------------------------
// 2. THE REPORT IS DERIVED, WHICH IS THE ONLY REASON EITHER PAGE IS WORTH
//    HAVING.
//
// Both pages claim their algorithm table is READ FROM THE MODULE THAT PERFORMS
// THE ALGORITHM. Reading the report on its own says nothing — a hand-written
// table is well-formed too — so this section CHANGES a setting and requires the
// report to move with it. That is the same argument `admin_api.js` makes about
// the crypto report, one page across.
// ---------------------------------------------------------------------------
async function theReportFollowsTheSettings() {
  log.info("=== the mechanism report is DERIVED and not written down ===");

  const before = await get("/webauthn");
  check("with nothing changed, the report marks the offered algorithms among " +
        "every algorithm the verifier knows — a page that listed only the two " +
        "being offered could not answer WHAT ELSE COULD I ASK FOR", function () {
    const status = before.body.status;
    assert.ok(status && Array.isArray(status.algorithms),
      "there is no algorithm table on the report: " +
      JSON.stringify(before.body.status).slice(0, 200));
    assert.ok(status.algorithms.length > 2,
      "the table lists only " + status.algorithms.length + " algorithm(s), " +
      "which is the offered set rather than the verifiable one.");
    assert.ok(status.algorithms.some(function (a) { return a.offered; }),
      "no algorithm is marked as offered at all.");
    assert.ok(status.algorithms.some(function (a) { return !a.offered; }),
      "EVERY algorithm is marked offered, so the mark distinguishes nothing.");
  });

  try {
    // FLAT, not wrapped in a `settings` member: this door takes the keys
    // themselves, because what a console form posts IS a section's fields.
    await ok("/config/set-many",
      { "webauthn.userVerification": "required",
        "webauthn.residentKey": "required",
        "webauthn.algorithms": "EdDSA" },
      "set three webauthn settings");

    const after = await get("/webauthn");
    check("USER VERIFICATION SET TO `required` FLIPS THE REPORT'S " +
          "`userVerificationEnforced` — which is the one ceremony option this " +
          "service CHECKS as well as asks for, because the UV flag is inside " +
          "the bytes the authenticator signed", function () {
      assert.strictEqual(after.body.status.userVerification, "required",
        "the report still says " + after.body.status.userVerification);
      assert.strictEqual(after.body.status.userVerificationEnforced, true,
        "the setting moved and the ENFORCED flag did not, so the page is " +
        "describing a setting rather than the ceremony.");
    });
    check("and the offered algorithm list follows the setting rather than a " +
          "table on the page", function () {
      const offered = after.body.status.algorithms
        .filter(function (a) { return a.offered; })
        .map(function (a) { return a.name; });
      assert.deepStrictEqual(offered, ["EdDSA"],
        "the report offers " + offered.join(", ") + " after being told EdDSA.");
    });
    check("and the CTAP row moves with it", function () {
      assert.strictEqual(after.body.status.residentKey, "required",
        "the resident-key setting did not reach the report.");
    });

    // THE FAILURE MODE THAT IS NOT AN ERROR: a name the verifier does not
    // know. `webauthn_policy.js` asserts the module drops it; this asserts the
    // page never reports it as offered, because a client author reading this
    // page is deciding what to test against.
    await ok("/config/set-many",
      { "webauthn.algorithms": "ES256,NOSUCHALG" },
      "set an algorithm list naming something unverifiable");
    const bad = await get("/webauthn");
    check("AN ALGORITHM THE VERIFIER CANNOT CHECK IS NEVER REPORTED AS " +
          "OFFERED — it would produce a credential that enrols perfectly and " +
          "then fails every assertion it is ever used for", function () {
      const offered = bad.body.status.algorithms
        .filter(function (a) { return a.offered; })
        .map(function (a) { return a.name; });
      assert.deepStrictEqual(offered, ["ES256"],
        "the report offers " + offered.join(", "));
      assert.ok(!bad.body.status.algorithms.some(function (a) {
        return a.name === "NOSUCHALG";
      }), "and it invented a row for it.");
    });
  } finally {
    // `reset` and NOT a set carrying the old value — see the header. Through
    // `resetQuietly()` rather than `ok()`, for a reason that cost real time
    // the first time this file ran: **a `finally` that throws REPLACES the
    // failure that got you there.** A malformed `set-many` above left nothing
    // to reset, and what the report showed was a reset complaining about an
    // override that had never been made — which says nothing at all about the
    // request that was actually wrong.
    await resetQuietly(["webauthn.userVerification", "webauthn.residentKey",
                        "webauthn.algorithms"]);
  }

  const totp = await get("/totp");
  check("the TOTP page's digest table marks the one in use the same way, from " +
        "common/totp.js", function () {
    const status = totp.body.status;
    assert.ok(status && Array.isArray(status.algorithms),
      "there is no digest table on the report.");
    const inUse = status.algorithms.filter(function (a) { return a.inUse; });
    assert.strictEqual(inUse.length, 1,
      inUse.length + " digests are marked in use, which cannot be right.");
  });
}

// ---------------------------------------------------------------------------
// 3. THE ROSTER, ON THE PAGE THAT ABSORBED IT.
//
// **THE POPULATION IS THE ASSERTION.** `/admin/users` listed identities this
// service had SEEN, and the roster it took on is about the people who have
// never signed in — so it lists this realm's DIRECTORY people too. A version
// that had merely added columns to the old list would pass every other check
// in this section and fail this one.
// ---------------------------------------------------------------------------
async function theRosterIsOnTheUsersPage() {
  log.info("=== the roster is columns on /admin/users ===");

  // WITH THE ATTRIBUTES A REAL ACCOUNT CARRIES (2026-09-12). Product mode
  // invents nothing onto an entry, so a person created with a bare username is
  // a person this suite should not be depending on. No password: this person
  // never signs in, and holding no credential at all is the state the roster
  // below is asserted against. **`credential: "none"` IS SAID, NOT ASSUMED**,
  // since a create that names no credential GENERATES a password (2026-09-12) —
  // left out, this person is `usable` and the assertion about somebody holding
  // nothing would fail describing a person who legitimately holds a password.
  await ok("/users/create", {
    username: PERSON, invent: false, credential: "none",
    attributes: { cn: "Second Factor Person " + PERSON, givenName: "Second",
                  sn: PERSON, displayName: "Second Factor Person " + PERSON,
                  mail: PERSON + "@second-factor-pages.test" }
  }, "created a person");

  const list = await get("/users?q=" + encodeURIComponent(PERSON));
  check("A PERSON WHO HAS NEVER AUTHENTICATED IS ON THE LIST, which the old " +
        "population would not have shown — and the people most likely to hold " +
        "no second factor are exactly the ones who have never signed in",
    function () {
      assert.strictEqual(list.status, 200,
        "GET /admin-api/users answered " + list.status + " " +
        String(list.raw).slice(0, 200));
      const row = (list.body.users || []).filter(function (u) {
        return u.name === PERSON;
      })[0];
      assert.ok(row, PERSON + " is not on /admin-api/users at all.");
      assert.strictEqual(row.authenticated, false,
        "they are reported as having authenticated, which they have not.");
      assert.ok(row.factors, "the row carries no `factors` object at all.");
      assert.strictEqual(row.factors.mfaRequired, false,
        "a second factor is already being demanded of a brand new person.");
      assert.strictEqual(row.factors.usable, false,
        "they are reported as able to sign in with no credential at all.");
    });

  check("and the page carries the counts over the WHOLE population rather " +
        "than over the page being shown", function () {
    assert.ok(list.body.factors, "there is no `factors` count block.");
    assert.ok(typeof list.body.factors.withSecond === "number",
      "the counts are not numbers: " + JSON.stringify(list.body.factors));
    assert.ok(list.body.known >= list.body.shown,
      "the population (" + list.body.known + ") is smaller than the page (" +
      list.body.shown + "), which cannot be right.");
  });

  // THE FILTER IS WHAT AN OPERATOR ACTUALLY COMES FOR. `none` is the query
  // "who is not protected", and it is the reason the population had to widen.
  const none = await get("/users?factor=none&q=" + encodeURIComponent(PERSON));
  check("`factor=none` finds somebody holding no second factor", function () {
    assert.strictEqual(none.status, 200, "it answered " + none.status);
    assert.ok((none.body.users || []).some(function (u) {
      return u.name === PERSON;
    }), PERSON + " holds no second factor and is not in `factor=none`.");
  });
  const any = await get("/users?factor=any&q=" + encodeURIComponent(PERSON));
  check("and `factor=any` does NOT — which is the half that makes the filter " +
        "mean something, since a filter that matched everybody would pass the " +
        "check above", function () {
    assert.ok(!(any.body.users || []).some(function (u) {
      return u.name === PERSON;
    }), PERSON + " holds no second factor and is in `factor=any`.");
  });

  // The drill-down, which is where the Clear buttons are. It has to be
  // REACHABLE for a directory-only person: this list started showing them on
  // 2026-09-10 and until the detail page learnt to answer for one, clicking a
  // name landed on "nothing here has authenticated as …".
  const detail = await get("/users?user=" + encodeURIComponent(PERSON));
  check("THE DRILL-DOWN IS REACHABLE FOR SOMEBODY THE REGISTRY HAS NEVER " +
        "SEEN — the row is on the list, so the page behind it has to answer, " +
        "and it is where both Clear buttons live", function () {
    assert.strictEqual(detail.status, 200,
      "it answered " + detail.status + " " + String(detail.raw).slice(0, 200));
    assert.strictEqual(detail.body.known, true,
      "the drill-down reports this person as unknown: " +
      JSON.stringify(detail.body).slice(0, 300));
    assert.ok(detail.body.factors,
      "the drill-down carries no `factors` block, so the MFA section is not " +
      "on it.");
    assert.ok(detail.body.factors.policy,
      "and it does not say what the realm ALLOWS, which is half of the answer " +
      "to `why can they not enrol one`.");
  });
}

// ---------------------------------------------------------------------------
// 4. THE TWO REMOVALS, THROUGH BOTH SPELLINGS.
//
// The console control moved onto `/admin/users` and a caller's script did not,
// so `POST /admin-api/mfa/clear-totp` and `POST /admin-api/users/clear-totp`
// are one switch reached two ways. Both are driven, because an operation that
// exists in the document and routes nowhere is exactly what a move like this
// produces.
//
// **NOTHING IS ENROLLED HERE AND THAT IS THE POINT.** There is deliberately no
// enrol operation on this API — enrolling means being shown a shared secret —
// so what can be asserted from here is the REFUSAL, and the refusal is the
// half that has to name the right thing. `sts_portal_totp.js` drives a clear
// that succeeds, against an enrolment it made through the portal.
// ---------------------------------------------------------------------------
async function bothSpellingsOfTheClearActionsRoute() {
  log.info("=== both spellings of the two clears reach the same switch ===");

  for (const path of ["/mfa/clear-totp", "/users/clear-totp"]) {
    const r = await post(path, { username: PERSON, user: PERSON });
    check("POST " + path + " reaches a handler and refuses, because there is " +
          "nothing enrolled — a 404 here would be an operation the document " +
          "declares and the router does not have", function () {
      assert.strictEqual(r.status, 400,
        path + " answered " + r.status + " " + String(r.raw).slice(0, 200));
      assert.strictEqual(r.body.ok, false,
        "it answered 400 with ok:true, which is a shape nothing can read.");
      assert.ok(/authenticator|enrol/i.test(JSON.stringify(r.body.errors || [])),
        "and the refusal is not about the authenticator app: " +
        JSON.stringify(r.body.errors));
    });
  }

  for (const path of ["/mfa/clear-key", "/users/clear-key"]) {
    const r = await post(path, { username: PERSON, user: PERSON,
                                 credentialId: "no-such-credential" });
    check("POST " + path + " does the same for a security key", function () {
      assert.strictEqual(r.status, 400,
        path + " answered " + r.status + " " + String(r.raw).slice(0, 200));
      assert.strictEqual(r.body.ok, false, "it answered 400 with ok:true.");
    });
  }

  // The action switch's own list, which is what
  // `sts_admin_api_operations.js`'s parity reads. A list short by one turns
  // that check off for the action it is short by, silently.
  const unknown = await post("/users/no-such-action-exists", {});
  check("and the users resource NAMES the five actions it knows, the two " +
        "clears included — that sentence is what the parity check parses, so " +
        "a list short by one turns the check off for that action", function () {
    assert.strictEqual(unknown.status, 400,
      "an unknown action answered " + unknown.status);
    const said = JSON.stringify(unknown.body.errors || []);
    assert.ok(/unknown action/i.test(said),
      "the refusal is about something other than the action: " + said);
    assert.ok(/clear-totp/.test(said) && /clear-key/.test(said),
      "the two clears are not named in it: " + said);
    assert.ok(/create/.test(said) && /set-password/.test(said) &&
              /issue-activation/.test(said),
      "and the three that were already there are not: " + said);
  });
}

// ---------------------------------------------------------------------------
// 5. THE POLICY ROWS REACH A DOOR.
//
// `tests/webauthn_policy.js` asserts `credentials.addKey()` refuses. This
// asserts the same rows are visible where an operator would read them —
// on the person's own drill-down, beside what they hold — because "what this
// realm allows" and "what this person has" are the two halves of the only
// question that page answers, and a page carrying one of them sends the reader
// to look for a bug in the other.
// ---------------------------------------------------------------------------
async function theRealmPolicyIsReportedBesideThePerson() {
  log.info("=== what the realm allows is reported beside what they hold ===");
  try {
    await ok("/config/set-many",
      { "webauthn.primaryAllowed": false, "webauthn.maxKeysPerPerson": 3 },
      "narrowed what a key may be");

    const detail = await get("/users?user=" + encodeURIComponent(PERSON));
    check("the person's own page reports the realm's policy, so `why can they " +
          "not enrol one` is answerable without opening a second page",
      function () {
        const policy = detail.body.factors.policy;
        assert.strictEqual(policy.primaryAllowed, false,
          "the page still says a primary key is allowed.");
        assert.strictEqual(policy.maxKeysPerPerson, 3,
          "the cap did not reach the page: " + JSON.stringify(policy));
      });

    const report = await get("/webauthn");
    check("and the mechanism page agrees with it — one setting, two pages, no " +
          "second copy to disagree", function () {
      assert.strictEqual(report.body.status.primaryAllowed, false,
        "the mechanism page and the person's page disagree about whether a " +
        "key may be a primary credential.");
      assert.strictEqual(report.body.status.maxKeysPerPerson, 3,
        "and about how many keys a person may hold.");
    });
  } finally {
    await resetQuietly(["webauthn.primaryAllowed", "webauthn.maxKeysPerPerson"]);
  }

  const restored = await get("/webauthn");
  check("and resetting puts both back, so nothing below this job inherits a " +
        "narrowed realm", function () {
    assert.strictEqual(restored.body.status.primaryAllowed, true,
      "webauthn.primaryAllowed is still off after the reset.");
    assert.strictEqual(restored.body.status.maxKeysPerPerson, 10,
      "the cap is still narrowed after the reset.");
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " as " + PERSON + ".");

  await theOldPageIsGone();
  await theSettingsAreOnTheirPages();
  await theReportFollowsTheSettings();
  await theRosterIsOnTheUsersPage();
  await bothSpellingsOfTheClearActionsRoute();
  await theRealmPolicyIsReportedBesideThePerson();

  // A FLOOR ON THE CHECK COUNT, for `sts_roles.js`'s reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure a suite cannot report about itself.
  assert.ok(checks >= 20,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_second_factor_pages")
  .description("Drive the two second-factor mechanism pages and the roster " +
      "that used to sit beside them: that /admin/mfa is gone from the router " +
      "and from the console's page list, that its settings are on " +
      "/admin/totp and /admin/webauthn with an operation each, that the " +
      "mechanism report FOLLOWS the settings rather than being written down, " +
      "that the roster is columns and a filter on /admin/users over a " +
      "population that now includes people who have never signed in, and " +
      "that both spellings of the two Clear actions reach one switch.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
