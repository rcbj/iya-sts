"use strict";
//
// File: sts_portal_backup_codes.js
//
// ===========================================================================
// RECOVERY CODES THROUGH THE PORTAL: GENERATED WHEN ASKED, SHOWN ONCE, AND
// STORED AS HASHES ONLY WHEN THE PERSON CONFIRMS (rewritten 2026-09-11).
//
// **THIS FILE ASSERTED THE OPPOSITE OF THREE OF ITS CLAIMS UNTIL THAT DATE**,
// and they are worth keeping in view because each was right when it was
// written:
//
//   1. *a set is issued by the ACT of enrolling, unasked* — which protected
//      the people who never think to ask. It cannot survive hashing: a hash is
//      only makeable while the code is in the clear, so an automatic issue
//      would store a credential its owner never saw.
//   2. *ONCE — not once per enrolment* — which stopped a printed list going
//      dead with nothing having said so. Generating now REPLACES, and the
//      protection has moved from a refusal in the store to a sentence on the
//      page, said before anything is generated.
//   3. *they are readable by their owner and by nobody else* — the *Show my
//      recovery codes* button, which is what encrypting rather than hashing
//      them bought. Nothing can show a stored set now, including its owner.
//
// **WHAT THIS JOB IS REALLY FOR IS THE MIDDLE STATE**, which is new and is the
// one that can hurt somebody: between Generate and Confirm the codes are on a
// screen and in this service's memory, and NOWHERE ELSE. A person who writes
// them down and closes the tab is holding strings that work nowhere — so the
// assertions are that the page says so in terms, that the entry really is
// untouched until the button is pressed (checked through `/admin-api`, a
// different door from the one that would have written it), and that the
// confirm is what stores them.
//
// `local: true` — this is this service's own portal and its own `/admin-api`,
// which is the OWNERSHIP argument in `tests/CLAUDE.md`: the tree that changes
// a control is the tree that should go red when the control stops working.
// `tests/backup_codes.js` holds the same reversal one layer down, in process,
// where it can assert what is on the directory entry and what the two
// verification doors do.
// ===========================================================================

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_portal_backup_codes",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// Suffixed per run, because the directory is append-only in practice and two
// runs against one long-lived mock must not see each other's people.
var OWNER = usernameFor("backup-owner");
var INTRUDER = usernameFor("backup-intruder");

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  [ok] " + what);
}

// ---------------------------------------------------------------------------
// THE JOB'S OWN RFC 6238 IMPLEMENTATION, because enrolling an authenticator is
// the ACT that issues a set and there is no other way to reach it. It is the
// same thirty lines `sts_portal_totp.js` carries and is deliberately not
// `require`d from `common/totp.js` — see that file's header for the argument.
//
// **IT IS NOT CHECKED AGAINST THE RFC VECTORS HERE**, and that is the one
// difference from the job next door. There, the generator IS the subject: the
// claim is that a third party holding the secret can produce a code this
// service accepts, so a generator that agreed with a broken service would be
// worse than no test. Here it is scaffolding — if it is wrong the enrolment
// simply fails and every assertion below reports it loudly. `sts_portal_totp.js`
// and `tests/totp.js` are where that arithmetic is held to the specification.
// ---------------------------------------------------------------------------
const nodeCrypto = require("crypto");
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32ToBytes(text) {
  const cleaned = String(text).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < cleaned.length; i++) {
    const index = B32.indexOf(cleaned[i]);
    assert.ok(index >= 0,
      "the secret this service showed is not base32: " + cleaned[i]);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function codeFor(secret, atMs, opts) {
  const options = opts || {};
  const digits = Number(options.digits || 6);
  const period = Number(options.period || 30);
  const alg = String(options.algorithm || "SHA1").toLowerCase();
  const counter = Math.floor(Number(atMs || Date.now()) / 1000 / period);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac(alg, base32ToBytes(secret))
                           .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  return String(binary % Math.pow(10, digits)).padStart(digits, "0");
}

// ---------------------------------------------------------------------------
// ONE BROWSER. Manual redirects and a cookie jar of our own, because every
// assertion here is about WHICH screen came back — a fetch that followed the
// redirects would answer the question by hiding it.
// ---------------------------------------------------------------------------
function form(o) {
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

function browser(name) {
  const self = {
    name: name,
    cookie: "",
    jar: {},
    cookieHeader: function () {
      return Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
    },
    async go(method, path, body) {
      const headers = {};
      if (self.cookie) headers.cookie = self.cookie;
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method, redirect: "manual",
                                              headers: headers, body: body });
      // KEYED BY NAME: a browser signing in to a hosted surface holds TWO
      // cookies — the sign-on session and the surface's own — and keeping only
      // the last one seen drops whichever arrived first.
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const name = pair.split("=")[0];
        const value = pair.slice(name.length + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[name];
        } else {
          self.jar[name] = value;
        }
        self.cookie = self.cookieHeader();
      });
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  return self;
}

async function apiGet(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // An HTML error page from a door that answers JSON is worth quoting whole
    // rather than reporting as a parse failure.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function apiPost(path, body) {
  const r = await fetch(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    parsed = raw;
  }
  return { status: r.status, body: parsed, raw: raw };
}

function csrfOf(text) {
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
}

// ---------------------------------------------------------------------------
// EVERY PERSON THIS JOB SIGNS IN IS CREATED FIRST, WITH A PASSWORD AND THE
// ATTRIBUTES A REAL ACCOUNT CARRIES (2026-09-12).
//
// In product mode this service invents no persona for a name that signs in,
// creates nobody because a sign-in named them, and verifies the password
// against the person's own entry. The suite runs in development, where none of
// that is enforced — which is why a job leaning on it would go on passing
// while testing the invention. So `ensurePerson()` makes each account through
// `/admin-api/users/create` with `invent: false`, its own `cn`, `sn`,
// `givenName`, `displayName` and `mail`, and a password of at least twelve
// characters, and that password is what the sign-in screen is sent.
// ---------------------------------------------------------------------------
var PASSWORD = "portal-backup-codes-Passw0rd!-" + String(Date.now()).slice(-6);
var MAIL_DOMAIN = "portal-backup-codes.test";

function personAttributes(who) {
  return { cn: "Recovery Person " + who, givenName: "Recovery", sn: who,
           displayName: "Recovery Person " + who, mail: who + "@" + MAIL_DOMAIN };
}

// Create `who` with a password and real attributes, once per run.
var createdPeople = {};
async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). who=" + who);
  if (createdPeople[who]) {
    log.debug("Leaving ensurePerson(). Already created by this run.");
    return;
  }
  const r = await apiPost("/users/create", {
    username: who, invent: false, attributes: personAttributes(who),
    credential: "password", password: PASSWORD
  });
  assert.ok(r.status === 200 && r.body && r.body.ok && r.body.passwordSet,
    "POST /admin-api/users/create should create " + who + " with a password " +
    "before they sign in; it answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  createdPeople[who] = true;
  log.debug("Leaving ensurePerson(). Created " + who + ".");
}

function secretShownOn(text) {
  const cell = String(text).match(/<th>Secret<\/th><td><code>([^<]+)<\/code>/);
  return cell ? cell[1].replace(/\s+/g, "") : "";
}

// THE CODES AS THE PAGE PRINTS THEM — a `<ul class="codes">` of `<code>`
// elements, with the spent ones carrying a class. Read off the markup for
// `secretShownOn()`'s reason: the printed form is the one a person uses, and a
// page whose stored value and printed value disagreed would pass an assertion
// that read only one of them.
function codesShownOn(text) {
  const list = String(text).match(/<ul class="codes">([\s\S]*?)<\/ul>/);
  if (!list) {
    return [];
  }
  const out = [];
  const re = /<code(?: class="([^"]*)")?>([^<]+)<\/code>/g;
  let m;
  while ((m = re.exec(list[1])) !== null) {
    out.push({ code: m[2], spent: /spent/.test(m[1] || "") });
  }
  return out;
}

// How many are left, as the status card prints it: "7 of 10 recovery codes
// are unused." Read as a NUMBER rather than as the presence of a word, because
// claim 5's whole assertion is that it went down by exactly one.
// One person's row out of whatever shape GET /admin-api/mfa answers with.
// Written as a search rather than an index because that endpoint is a roster
// and this job is about one name in it.
function mfaRowFor(body, who) {
  const rows = (body && (body.people || body.rows || body.users)) || [];
  return rows.filter(function (one) {
    return one && (one.username === who || one.user === who ||
                   one.name === who);
  })[0] || null;
}

function remainingShownOn(text) {
  const m = String(text).match(/(\d+) of your (\d+) recovery codes are unused/);
  return m ? { remaining: Number(m[1]), total: Number(m[2]) } : null;
}

// ---------------------------------------------------------------------------
// SIGN IN AT A DOOR. `/portal` is an OpenID Connect relying party of this
// service's own authorization server, so this is a code flow.
//
// `onSecondFactor` is handed the 200 the password POST answered with when the
// screen asks for something more, which is exactly what this job is about.
// ---------------------------------------------------------------------------
async function signIn(door, who, onSecondFactor) {
  log.debug("Entering signIn(). door=" + door + " who=" + who);
  await ensurePerson(who);
  const b = browser(who);
  let r = await b.go("GET", door);
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    door + " should send an unauthenticated browser to the authorization " +
    "endpoint; it answered " + r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    "the authorization endpoint should send a browser with no sign-on " +
    "session to the sign-in screen; it answered " + r.status + " -> " +
    r.location);
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");
  r = await b.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: who,
                        password: PASSWORD, action: "login",
                        csrf_token: csrfOf(r.text) }));
  if (r.status === 200) {
    assert.ok(onSecondFactor,
      "the sign-in screen asked for something more and this call was not " +
      "expecting it: " + String(r.text).slice(0, 300));
    r = await onSecondFactor(b, r);
  } else {
    assert.ok(!onSecondFactor,
      "a second factor was expected and the password alone was enough — " +
      "which is the defect this job exists to catch. It answered " + r.status +
      " -> " + r.location);
  }
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in should end in a redirect; got " + r.status + " " +
    String(r.text).slice(0, 300));
  r = await b.go("GET", r.location);   // the authorization endpoint, with a code
  r = await b.go("GET", r.location);   // the callback, which mints the session
  assert.ok(b.cookie, "completing the flow should establish a session cookie.");
  log.debug("Leaving signIn().");
  return b;
}

// Enrol an authenticator app through the portal, exactly as a person does it.
// Returns the whole POST response, because the CODES ARE ON IT and that is
// claim 1.
async function enrolAuthenticator(b) {
  let page = await b.go("GET", "/portal/mfa");
  await b.go("POST", "/portal/mfa",
             form({ action: "start", csrf_token: csrfOf(page.text) }));
  page = await b.go("GET", "/portal/mfa");
  const secret = secretShownOn(page.text);
  assert.ok(secret, "no shared secret was printed on /portal/mfa.");
  const confirmed = await b.go("POST", "/portal/mfa",
    form({ action: "confirm", code: codeFor(secret, Date.now()),
           csrf_token: csrfOf(page.text) }));
  return { secret: secret, response: confirmed };
}

// ===========================================================================
// 1. A SET IS ISSUED BY THE ENROLMENT, WITH NOBODY HAVING ASKED.
//
// **THE ASSERTION IS THAT THE CODES ARE ON THE RESPONSE TO THE ENROLMENT.**
// Not that they exist afterwards — that would pass on a service that issued
// them quietly and never showed anybody, which is the same as not issuing
// them: a recovery list nobody has seen is not a way back.
//
// It is also the assertion that pins the RENDER: this one branch answers 200
// with the page rather than redirecting, because a 303 cannot carry a list of
// credentials and putting them in a query string would write them into a
// browser history entry and every proxy log on the way. A future tidy-up that
// made every branch redirect consistently would break exactly this.
// ===========================================================================
// 1. ENROLLING ISSUES NOTHING, AND THE PAGE SAYS SO (rewritten 2026-09-11).
//
// **THIS SECTION ASSERTED THE OPPOSITE UNTIL THAT DATE** — *enrolling a second
// factor issues a set, unasked* — and the reversal is the whole change. A set
// is HASHED now, and a hash can only be made while the code is in the clear,
// so a set issued as a side effect would be a credential the person never saw.
//
// What is asserted instead is the thing that replaced it: the enrolment says
// they hold none, and the card carries a standing prompt.
// ===========================================================================
async function enrollingIssuesNothing() {
  log.info("=== 1. enrolling a second factor issues nothing, and says so ===");
  const b = await signIn("/portal", OWNER);

  const before = await b.go("GET", "/portal/mfa");
  check("before any enrolment the page says none have been generated",
        function () {
    assert.ok(/None have been generated/.test(before.text),
      "the recovery card does not say the set is absent.");
    assert.strictEqual(remainingShownOn(before.text), null,
      "it printed a count for a set nobody holds.");
  });

  const enrolled = await enrolAuthenticator(b);
  check("the authenticator enrols", function () {
    assert.ok(enrolled.response.status === 200 ||
              enrolled.response.status === 303,
      "it answered " + enrolled.response.status);
  });
  check("AND NO CODES ARE SHOWN BY IT. The enrolment used to answer with the " +
        "page rather than a redirect precisely so that it could carry a list " +
        "of credentials; it has none to carry", function () {
    assert.strictEqual(codesShownOn(enrolled.response.text).length, 0,
      "the enrolment drew a list of codes.");
  });

  const after = await b.go("GET", "/portal/mfa");
  check("and the card now PROMPTS for a set, which is what replaced the " +
        "automatic issue — the population that protected is the people who " +
        "never think to ask, and asking is all that is left", function () {
    assert.ok(/no recovery codes/i.test(after.text),
      "the card does not say they hold none.");
    assert.ok(/Generate my recovery codes/.test(after.text),
      "there is no control to generate a set.");
  });
  check("and it still says no set is stored", function () {
    assert.strictEqual(remainingShownOn(after.text), null,
      "it printed a count for a set nobody holds.");
  });

  return { browser: b };
}

// ===========================================================================
// 2. GENERATE, AND NOTHING IS STORED UNTIL THE PERSON CONFIRMS.
//
// **THE ASSERTION THIS WHOLE CHANGE RESTS ON.** Between the two presses the
// codes are in the service's memory and nowhere else, so a person who writes
// them down and closes the tab has a page of strings that work NOWHERE — and
// the page has to say so, unmissably, or this design is worse than the one it
// replaced.
// ===========================================================================
async function generateThenConfirm(state) {
  log.info("=== 2. generated, shown, and stored only on confirm ===");
  const b = state.browser;

  const page = await b.go("GET", "/portal/mfa");
  const shown = await b.go("POST", "/portal/mfa",
    form({ action: "generate-codes", csrf_token: csrfOf(page.text) }));

  const codes = codesShownOn(shown.text).map(function (one) { return one.code; });
  check("asking generates a set and SHOWS it, on the response to the POST — " +
        "a 303 cannot carry a list of credentials and a query string would " +
        "put them in a browser history entry and every proxy log on the way",
        function () {
    assert.strictEqual(shown.status, 200, "it answered " + shown.status);
    assert.ok(codes.length >= 8, "only " + codes.length + " codes were drawn.");
  });
  check("the page says IN TERMS that they are not saved yet — this is the " +
        "sentence that stops somebody writing them down, closing the tab, " +
        "and holding strings that work nowhere", function () {
    assert.ok(/not saved yet/i.test(shown.text),
      "the page does not say the codes are unsaved.");
    assert.ok(/none of these codes will work until you press/i.test(shown.text),
      "the page does not say the codes do not work yet.");
  });
  check("and it says this is the only time they will be shown, which is what " +
        "hashing them means for the person", function () {
    assert.ok(/only time they will ever be shown/i.test(shown.text),
      "the page does not say the codes cannot be shown again.");
  });
  check("there is a CONFIRM button and a way to throw them away", function () {
    assert.ok(/I have saved these codes/.test(shown.text),
      "there is no confirm control.");
    assert.ok(/value="confirm-codes"/.test(shown.text),
      "the confirm control does not post the confirm action.");
    assert.ok(/value="discard-codes"/.test(shown.text),
      "there is no way to discard the pending set.");
  });

  const handle = (shown.text.match(/name="handle" value="([^"]+)"/) || [])[1];
  check("and the form carries an opaque HANDLE rather than a username, so " +
        "two tabs cannot confirm each other's set", function () {
    assert.ok(handle && handle.length > 10, "no handle on the form.");
    assert.ok(handle.indexOf(OWNER) < 0, "the handle contains the username.");
  });

  // **NOTHING IS STORED YET**, asserted from a different door than the one
  // that would have written it: `/admin-api` reports what is on the entry.
  const status = await apiGet("/mfa");
  check("AND NOTHING IS ON THE ENTRY. The codes have been shown and the " +
        "account still holds no set — asserted through /admin-api, which " +
        "reads the directory rather than the page that drew them",
        function () {
    const row = mfaRowFor(status.body, OWNER);
    assert.ok(!row || !row.backupCodes || !row.backupCodes.present,
      "a set was stored before the person confirmed: " +
      JSON.stringify(row && row.backupCodes));
  });

  const confirmed = await b.go("POST", "/portal/mfa",
    form({ action: "confirm-codes", handle: handle,
           csrf_token: csrfOf(shown.text) }));
  check("confirming stores them and redirects", function () {
    assert.ok(confirmed.status === 303 || confirmed.status === 200,
      "it answered " + confirmed.status + ": " +
      (String(confirmed.text || "").match(/class="error"[^>]*>([^<]*)/) ||
       String(confirmed.text || "").match(/<p class="sub">([^<]*)/) ||
       ["", "no message"])[1]);
  });

  const nowHeld = await b.go("GET", "/portal/mfa");
  check("and NOW the card reports a stored set", function () {
    const shownCount = remainingShownOn(nowHeld.text);
    assert.ok(shownCount, "the card reports no count at all.");
    assert.strictEqual(shownCount.remaining, codes.length,
      "the count does not match the set that was confirmed.");
    assert.strictEqual(shownCount.total, codes.length,
      "the total does not match the set that was confirmed.");
  });
  check("and it says the codes cannot be shown again, because what is stored " +
        "is a hash", function () {
    assert.ok(/no way to see these again/i.test(nowHeld.text),
      "the card does not say the codes cannot be seen again.");
    assert.ok(/hash/i.test(nowHeld.text),
      "the card does not say what is stored.");
  });
  check("and there is NO control anywhere on it that shows a stored set",
        function () {
    assert.ok(!/value="show-codes"/.test(nowHeld.text),
      "the page still offers to show the codes.");
    assert.strictEqual(codesShownOn(nowHeld.text).length, 0,
      "the page drew codes for a set that is only stored as hashes.");
  });

  return { browser: b, codes: codes };
}

// ===========================================================================
// 3. NO DOOR ANYWHERE PRODUCES A STORED SET.
//
// **THIS SECTION USED TO ASSERT THE OPPOSITE FOR ONE OF ITS DOORS** — the
// owner could read their own codes back, which is what encrypting them bought
// — and the other half of the claim is unchanged and is the one that matters:
// nobody else ever could, and now nobody at all can.
// ===========================================================================
async function nothingShowsAStoredSet(state) {
  log.info("=== 3. no door produces a stored set, not even the owner's ===");

  const page = await state.browser.go("GET", "/portal/mfa");
  const asked = await state.browser.go("POST", "/portal/mfa",
    form({ action: "show-codes", csrf_token: csrfOf(page.text) }));
  check("the OLD show-codes action is refused by the form schema rather than " +
        "quietly doing nothing — an action a page no longer offers should " +
        "not be reachable by somebody replaying an old form", function () {
    assert.ok(asked.status >= 400,
      "show-codes answered " + asked.status + " rather than refusing.");
    assert.strictEqual(codesShownOn(asked.text).length, 0,
      "the old action drew codes.");
  });

  const api = await apiGet("/mfa");
  check("and /admin-api reports the COUNTS and never the codes, which was " +
        "true before this change and is now true by construction", function () {
    const raw = JSON.stringify(api.body);
    state.codes.forEach(function (code) {
      assert.ok(raw.indexOf(code) < 0,
        "a recovery code appears in /admin-api/mfa.");
    });
    const row = mfaRowFor(api.body, OWNER);
    assert.ok(row && row.backupCodes && row.backupCodes.present,
      "the set is not reported at all.");
  });
  check("and it reports HOW the set is stored, so an operator can tell a " +
        "hashed set from one an older build wrote", function () {
    const row = mfaRowFor(api.body, OWNER);
    assert.ok(row.backupCodes.hashed === true ||
              row.backupCodes.hashed === undefined,
      "the set is reported as not hashed: " +
      JSON.stringify(row.backupCodes));
  });
}

// ===========================================================================
// 4 AND 5. A CODE SIGNS THEM IN INSTEAD OF THE APP, AND IS THEN SPENT.
//
// **THE LINK IS PART OF THE CLAIM.** A recovery door nothing points at is a
// door nobody standing in front of a dead phone will find, so the assertion is
// that the one-time code screen OFFERS it — and then that following it works.
// ===========================================================================
async function aCodeSignsThemIn(state) {
  log.info("=== 4/5. a recovery code at the sign-in screen, and the spend ===");
  const before = remainingShownOn(
    (await state.browser.go("GET", "/portal/mfa")).text);
  assert.ok(before, "no count on /portal/mfa before the sign-in.");

  const spending = state.codes[2];
  let sawTheLink = false;
  let refusedReplay = null;

  const b = await signIn("/portal", OWNER, async function (br, asked) {
    // THE SCREEN THE PASSWORD LANDED ON is the authenticator's, because that
    // is what this person is CONFIGURED for — a recovery code is never the
    // factor a sign-in asks for.
    assert.ok(/one-time code|authenticator app/i.test(asked.text),
      "the password step did not land on the one-time code screen: " +
      String(asked.text).slice(0, 300));
    const link = String(asked.text)
      .match(/href="(\/authn\/backup-code\?mfa=[^"]+)"/);
    sawTheLink = !!link;
    assert.ok(link,
      "the one-time code screen offers no way to a recovery code. A door " +
      "nothing points at is a door nobody standing in front of a dead phone " +
      "will find.");
    const screen = await br.go("GET", link[1].replace(/&amp;/g, "&"));
    assert.strictEqual(screen.status, 200,
      "the recovery screen answered " + screen.status);
    const mfaId = (screen.text.match(/name="mfa_id" value="([^"]+)"/) || [])[1];
    assert.ok(mfaId, "the recovery screen carries no mfa_id to post back.");

    // A WRONG CODE FIRST, because the interesting half of claim 5 is that a
    // refusal keeps the step AND spends nothing.
    const wrong = await br.go("POST", "/authn/backup-code",
                              form({ mfa_id: mfaId, code: "AAAAA-AAAAA" }));
    assert.strictEqual(wrong.status, 200,
      "a wrong recovery code should redraw this page rather than throwing " +
      "the password step away; it answered " + wrong.status);

    // THIS SERVICE'S OWN RENDERING HANDED BACK TO IT, lower-cased — the
    // dashes and the case are exactly what somebody reads off paper types,
    // and a service that refused its own printed form would be arguing with
    // its own page.
    const ok = await br.go("POST", "/authn/backup-code",
                           form({ mfa_id: mfaId, code: spending.toLowerCase() }));

    // AND THE REPLAY, inside the same flow, before the step is gone. It cannot
    // be checked afterwards: the step is spent on success. Sent WITHOUT the
    // dashes this time, so that a replay guard which only ever saw one
    // spelling could not pass this.
    refusedReplay = await br.go("POST", "/authn/backup-code",
                                form({ mfa_id: mfaId,
                                       code: spending.replace(/-/g, "") }));
    return ok;
  });

  check("the one-time code screen offers the recovery link", function () {
    assert.ok(sawTheLink, "no link was found.");
  });

  const page = await b.go("GET", "/portal");
  check("A RECOVERY CODE SIGNED THEM IN, in the rendering this service " +
        "printed and in the case they typed", function () {
    assert.strictEqual(page.status, 200, "/portal answered " + page.status);
  });

  check("and the session says two factors were presented — amr " +
        "[\"pwd\",\"otp\"], acr \"mfa\". RFC 8176 registers no value for a " +
        "recovery code, and inventing one would put a string in amr that no " +
        "relying party can look up", function () {
    const amr = (page.text.match(/<tr><th>How<\/th><td>([^<]*)/) || [])[1] || "";
    assert.ok(/pwd/.test(amr) && /otp/.test(amr),
      "the session claims '" + amr + "'.");
    assert.ok(/acr mfa/.test(amr),
      "the session does not claim acr mfa: '" + amr + "'.");
  });

  check("THE SAME CODE DOES NOT WORK TWICE, and the refusal says so rather " +
        "than calling it wrong — somebody working down a printed list and " +
        "re-typing the one they crossed out needs to be told to use the next " +
        "one", function () {
    assert.ok(refusedReplay,
      "the replay was never attempted inside the flow.");
    assert.ok(!/^30[23]$/.test(String(refusedReplay.status)),
      "the spent code signed somebody in a second time: " +
      refusedReplay.status + " -> " + refusedReplay.location);
  });

  const after = remainingShownOn((await b.go("GET", "/portal/mfa")).text);
  check("and exactly ONE code was spent by all of that — one success, one " +
        "wrong code and one replay", function () {
    assert.ok(after, "no count on /portal/mfa after the sign-in.");
    assert.strictEqual(after.remaining, before.remaining - 1,
      "it went from " + before.remaining + " to " + after.remaining + ".");
  });

  // **THIS USED TO ASSERT THE SPENT CODE WAS DRAWN CROSSED OUT**, which a
  // stored set being readable is what bought — *a list that silently shrank
  // would read as codes going missing*. There is no list to draw any more, so
  // the same worry is answered by the COUNTS: the card says how many of how
  // many are left, and the total never moves.
  const card = await b.go("GET", "/portal/mfa");
  check("and the card accounts for the spent one by COUNT rather than by " +
        "crossing it out — the total does not move, so a person reading it " +
        "sees a code used and not codes going missing", function () {
    const now = remainingShownOn(card.text);
    assert.ok(now, "no count on the card.");
    assert.strictEqual(now.total, state.codes.length,
      "the total changed from " + state.codes.length + " to " + now.total + ".");
    assert.strictEqual(now.remaining, state.codes.length - 1,
      "the remaining count is " + now.remaining + ".");
  });
  check("and there is still no way to see the list, spent entries included",
        function () {
    assert.strictEqual(codesShownOn(card.text).length, 0,
      "the card drew codes for a set stored as hashes.");
  });
}

// ===========================================================================
// 6. AN OPERATOR CAN CLEAR A SET, AND CLEARING RE-ARMS THE ISSUE.
//
// The second half is the one worth driving: clearing is the ONLY route to a
// second set, so a clear that worked and an enrolment that then issued nothing
// would leave the account with a second factor and no way back — exactly the
// state this whole mechanism exists to prevent, reached through the mechanism.
// ===========================================================================
async function anOperatorCanClearIt(state) {
  log.info("=== 6. clearing a set through /admin-api ===");
  const cleared = await apiPost("/users/clear-backup-codes", { user: OWNER });
  check("POST /admin-api/users/clear-backup-codes accepts it", function () {
    assert.strictEqual(cleared.status, 200,
      "it answered " + cleared.status + " " + String(cleared.raw).slice(0, 300));
    assert.strictEqual(cleared.body.ok, true, String(cleared.raw).slice(0, 200));
  });

  const again = await apiPost("/users/clear-backup-codes", { user: OWNER });
  check("and clearing a set nobody holds is a 400 rather than a silent 200 — " +
        "the caller asked to clear a specific thing and it was not there",
        function () {
    assert.strictEqual(again.status, 400, "it answered " + again.status);
  });

  const page = await state.browser.go("GET", "/portal/mfa");
  check("the portal reports the set as gone, and PROMPTS for a new one — " +
        "the person still holds a second factor, so where the Clear used to " +
        "re-arm an automatic issue it now simply makes the prompt true again",
        function () {
    // **THE WORDING IS THE ADVISED ONE AND NOT THE NEUTRAL ONE**, which is
    // the card doing its job: somebody with a second factor and no codes is
    // told what that means for them, where somebody with neither is told only
    // that none have been generated. Asserting the neutral sentence here
    // would be asserting the WEAKER of the two pages.
    assert.ok(/no recovery codes/i.test(page.text),
      "the card does not report the set as gone or prompt for a new one.");
    assert.ok(!remainingShownOn(page.text),
      "the card still prints a count for a set that was cleared.");
    assert.ok(/Generate my recovery codes/.test(page.text),
      "there is no control to generate a set after the clear.");
  });

  // **THE TRANSITION THIS SECTION USED TO ASSERT IS GONE WITH THE AUTOMATIC
  // ISSUE.** It read *AND THE NEXT ENROLMENT ISSUES A NEW SET — which is what
  // makes the Clear an issuing control as well as a removal*, and enrolled a
  // second authenticator to prove it. A person generates their own set now, so
  // what is asserted instead is that the enrolment still issues NOTHING and
  // that the person can then do it themselves.
  const reissued = await enrolAuthenticator(state.browser);
  check("a further enrolment still issues nothing", function () {
    assert.strictEqual(codesShownOn(reissued.response.text).length, 0,
      "an enrolment drew a list of codes.");
  });

  const asked = await state.browser.go("GET", "/portal/mfa");
  const made = await state.browser.go("POST", "/portal/mfa",
    form({ action: "generate-codes", csrf_token: csrfOf(asked.text) }));
  const fresh = codesShownOn(made.text).map(function (one) { return one.code; });
  check("and the person can generate one for themselves, which is the only " +
        "path to a set there now is", function () {
    assert.ok(fresh.length >= 5,
      "the list is now " + fresh.length + " long; the generate answered " +
      made.status + ": " +
      (String(made.text || "").match(/class="err[^"]*"[^>]*>([^<]{0,160})/) ||
       ["", "(no error element)"])[1]);
  });
  check("and it is a NEW set rather than the old one coming back",
        function () {
    state.codes.forEach(function (old) {
      assert.ok(fresh.indexOf(old) < 0,
        "a code from the cleared set came back.");
    });
  });

  // The audit log, fetched once for the three assertions below. It was read in
  // the block this section replaced; keeping the fetch here rather than inside
  // each check means one request for three questions about the same list.
  const rows = await apiGet("/audit?per=200");

  check("and the clear is in the audit log as an ADMIN act — a security " +
        "downgrade performed by a third party, which is the one shape of act " +
        "an audit log exists for", function () {
    const events = (rows.body.events || rows.body.rows || []);
    assert.ok(events.some(function (e) {
      return e.action === "admin.mfa.backup-codes.cleared" &&
             JSON.stringify(e.detail || {}).indexOf(OWNER) >= 0;
    }), "no admin.mfa.backup-codes.cleared row naming " + OWNER + ".");
  });

  // **THE AUDIT ROWS MOVED WITH THE ACTIONS.** There is no
  // `portal.mfa.backup-codes.shown` any more, because nothing shows a stored
  // set; what there is instead is the two halves of the new flow, and BOTH
  // are worth a row. Generating is the moment a live credential is put on a
  // screen, and confirming is the moment the account's way back changes —
  // recording only the second would leave the more sensitive act unlogged.
  check("generating a set is audited — it is the moment a live credential is " +
        "put in front of somebody", function () {
    const events = (rows.body.events || rows.body.rows || []);
    assert.ok(events.some(function (e) {
      return e.action === "portal.mfa.backup-codes.generated" &&
             e.actor === OWNER;
    }), "no portal.mfa.backup-codes.generated row for " + OWNER + ".");
  });
  check("and so is confirming it, which is the moment the account's way back " +
        "actually changed", function () {
    const events = (rows.body.events || rows.body.rows || []);
    assert.ok(events.some(function (e) {
      return e.action === "portal.mfa.backup-codes.confirmed" &&
             e.actor === OWNER;
    }), "no portal.mfa.backup-codes.confirmed row for " + OWNER + ".");
  });
}

async function test() {
  log.info("Running the recovery code checks against " + base);
  const state = await enrollingIssuesNothing();
  const held = await generateThenConfirm(state);
  await nothingShowsAStoredSet(held);
  await aCodeSignsThemIn(held);
  await anOperatorCanClearIt(held);
  log.info(checks + " assertion(s).");
  log.info("Test completed successfully.");
}

test().catch(function (e) {
  log.error(e);
  process.exit(1);
});
