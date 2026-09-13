"use strict";
//
// File: sts_portal_directory_attributes.js
//
// ===========================================================================
// THE ACCOUNT PAGE SHOWS THE PERSON'S DIRECTORY ENTRY, AGAINST THE SCHEMA —
// AND SHOWS NOTHING ELSE THAT IS ON IT.
//
// `/portal`'s Overview answers *what does this identity provider know about
// you*, and until 2026-09-11 it answered out of the SESSION: a username, a
// subject, and whichever of `email` and `name` the sign-in happened to carry.
// It draws every standard inetOrgPerson attribute now.
//
// Five claims, and the last one is the reason the other four are not enough:
//
//   1. **IT READS THE DIRECTORY AND NOT THE SESSION.** An attribute written
//      over SCIM — which the sign-in never carried and could not have — is on
//      the page.
//   2. **EVERY STANDARD ATTRIBUTE IS ACCOUNTED FOR**, set or not, under the
//      three object classes a person here carries. A page showing only what
//      happens to be set answers half the question.
//   3. **`userPassword` IS NAMED AND NEVER PRINTED.** It is on the `person`
//      MAY list, so a faithful reading of the schema puts it on the page.
//   4. **A BINARY ATTRIBUTE IS A SIZE AND NEVER OCTETS.**
//   5. **THE `sts` CREDENTIALS ARE NOT ON THE PAGE AT ALL**, and this is the
//      assertion that pins the DESIGN rather than the output. The obvious
//      implementation of this feature is to iterate the stored attributes;
//      this service stores a TOTP shared secret, a set of recovery codes, a
//      WebAuthn credential and an activation token on the very same entry. So
//      the job enrols an authenticator and then requires that the secret
//      appears nowhere in the HTML. **Claims 1 to 4 all pass against the
//      dump-the-entry implementation. Only this one fails.**
//
// And a sixth, which every page in this application owes: one signed-in person
// cannot read another's entry, whatever they put in the request.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE, WHICH IS THE FIRST QUESTION tests/CLAUDE.md ASKS.
//
// `local: true`. It drives this service's own `/portal` — the OWNERSHIP
// argument: the tree that adds a section to that page is the tree that should
// go red when the section stops drawing it.
//
// **AND IT IS NOT COVERED BY `tests/inetorgperson.js` NEXT DOOR**, which holds
// the schema itself — that the list is the union of the three classes, that
// the two refusals refuse. That file cannot see a page which never calls it, a
// slot nothing fills, or a session whose name reaches the directory lookup
// from a request parameter.
// ===========================================================================

const assert = require("assert");
const { usernameFor } = require("./random_username.js");
const nodeCrypto = require("crypto");

// ---------------------------------------------------------------------------
// THIRTY LINES OF RFC 4226 OVER RFC 6238, carried rather than required from
// `common/totp.js` — `sts_dpop.js`'s rule, and `sts_portal_totp.js` is where
// the same lines are checked against the specification's own vectors.
//
// **IT IS HERE FOR A FIXTURE RATHER THAN FOR A CLAIM**, which is the only
// reason this file does not check it against those vectors too: section 5
// needs a CONFIRMED authenticator enrolment, because that is what puts a
// readable shared secret onto the entry — and an enrolment that is merely
// STARTED writes nothing at all. The first version of this job started one and
// asserted that the secret was not on the account page, which passed against a
// page that dumped the entry, because there was nothing on the entry to dump.
// ---------------------------------------------------------------------------
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

function codeFor(secret) {
  const counter = Math.floor(Date.now() / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = nodeCrypto.createHmac("sha1", base32ToBytes(secret))
                           .update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
                 ((digest[offset + 1] & 0xff) << 16) |
                 ((digest[offset + 2] & 0xff) << 8) |
                 (digest[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, "0");
}

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_portal_directory_attributes",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var OWNER = usernameFor("dir-owner");
var INTRUDER = usernameFor("dir-intruder");

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  [ok] " + what);
}

// ---------------------------------------------------------------------------
// ONE BROWSER. Manual redirects and a cookie jar of our own, KEYED BY NAME: a
// browser signed in to a hosted surface holds TWO cookies — the sign-on
// session and the surface's own — and keeping only the last one seen drops
// whichever arrived first.
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
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const nm = pair.split("=")[0];
        const value = pair.slice(nm.length + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[nm];
        } else {
          self.jar[nm] = value;
        }
        self.cookie = self.cookieHeader();
      });
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  return self;
}

// THE SCIM CALLER IS A PERSON THIS JOB CREATES, and its Basic credential is
// that person's username and password (2026-09-12). Product mode verifies a
// SCIM Basic credential against the named person's own `userPassword`, so a
// made-up name with a word nothing checks is a credential only development
// accepts. The account is made on first use, by `ensurePerson()` below.
const SCIM_CALLER = usernameFor("dir-scim-caller");
const ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

async function scim(method, path, payload) {
  await ensurePerson(SCIM_CALLER);
  const auth = "Basic " +
    Buffer.from(SCIM_CALLER + ":" + PASSWORD).toString("base64");
  const r = await fetch(base + "/scim/v2" + path, {
    method: method,
    headers: { "Content-Type": "application/scim+json",
               "Accept": "application/scim+json",
               "Authorization": auth },
    body: payload === undefined ? undefined : JSON.stringify(payload)
  });
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

function csrfOf(text) {
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
}

// The management API taking JSON, for creating the person before they sign in.
async function apiPost(path, payload) {
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // An HTML page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
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
//
// **IT ALSO MAKES CLAIM 1 SHARPER.** The entry now holds exactly what was
// typed here, so an attribute that SCIM writes afterwards is the only way it
// can arrive on the page — nothing a sign-in invented is there to be mistaken
// for it.
// ---------------------------------------------------------------------------
var PASSWORD = "portal-directory-Passw0rd!-" + String(Date.now()).slice(-6);
var MAIL_DOMAIN = "portal-directory.test";

function personAttributes(who) {
  return { cn: "Directory Person " + who, givenName: "Directory", sn: who,
           displayName: "Directory Person " + who, mail: who + "@" + MAIL_DOMAIN };
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

// ---------------------------------------------------------------------------
// SIGN IN AT `/portal`, which is an OpenID Connect relying party of this
// service's own authorization server — so this is a code flow.
// ---------------------------------------------------------------------------
async function signIn(who) {
  log.debug("Entering signIn(). who=" + who);
  await ensurePerson(who);
  const b = browser(who);
  let r = await b.go("GET", "/portal");
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    "/portal should send an unauthenticated browser to the authorization " +
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
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in should end in a redirect; got " + r.status + " " +
    String(r.text).slice(0, 300));
  r = await b.go("GET", r.location);   // the authorization endpoint, with a code
  r = await b.go("GET", r.location);   // the callback, which mints the session
  assert.ok(b.cookie, "completing the flow should establish a session cookie.");
  log.debug("Leaving signIn().");
  return b;
}

// ---------------------------------------------------------------------------
// WHAT THE PAGE DREW, taken out of the markup.
//
// The LDAP name and the RFC are printed under every value in a `div.attr`
// precisely so that somebody can read them before going to write the attribute
// over LDAP — so that is what this parses. Reading the `<th>` LABEL instead
// would tie the job to wording, which is the thing about a page most likely to
// change for good reasons.
// ---------------------------------------------------------------------------
function sectionOf(text) {
  // **SLICED BETWEEN TWO MARKERS RATHER THAN MATCHED TO A CLOSING TAG.** The
  // first version of this ended at the first `</div>`, which is the one that
  // closes the `<div class="attr">` under the very first value — so it
  // returned one row and the whole job asserted against a twentieth of the
  // page. HTML nests; a regex does not, and the honest way to take a region
  // out of it is two landmarks.
  const html = String(text);
  const from = html.indexOf('<h3 class="dirhead">Your directory entry</h3>');
  if (from < 0) {
    return "";
  }
  // The next card's heading. There is exactly one `<h2>` after this section
  // (`How you sign in`), and it is outside the card this section is in.
  const to = html.indexOf("<h2>", from);
  return to < 0 ? html.slice(from) : html.slice(from, to);
}

// Every attribute the section names, mapped to what was drawn in its cell.
function attributesOn(text) {
  const section = sectionOf(text);
  const out = new Map();
  // Each row is  <th …>Label</th><td>VALUE<div class="attr"><code>name</code>…
  const re = /<td>([\s\S]*?)<div class="attr"><code>([^<]+)<\/code>/g;
  let m;
  while ((m = re.exec(section)) !== null) {
    out.set(m[2], m[1]);
  }
  return out;
}

// Which object classes the section drew, in order.
function classesOn(text) {
  const section = sectionOf(text);
  const out = [];
  const re = /<h3 class="dirclass" title="[^"]*"><code>([^<]+)<\/code>/g;
  let m;
  while ((m = re.exec(section)) !== null) {
    out.push(m[1]);
  }
  return out;
}

// ===========================================================================
// 1 AND 2. THE DIRECTORY, AND THE WHOLE SCHEMA.
// ===========================================================================
async function itDrawsTheDirectory() {
  log.info("=== 1/2. the entry, and every standard attribute ===");

  // SIGN IN FIRST, so the entry exists: a person gets one the first time they
  // authenticate. That ordering is the feature rather than an accident of the
  // fixture — the page is about somebody this service has met.
  const b = await signIn(OWNER);
  const before = await b.go("GET", "/portal");
  check("the Overview draws the directory section", function () {
    assert.strictEqual(before.status, 200, "/portal answered " + before.status);
    assert.ok(sectionOf(before.text),
      "there is no 'Your directory entry' section on the page: " +
      String(before.text).slice(0, 400));
  });

  check("and it names the entry's DN, so a reader knows what to go and " +
        "ldapsearch", function () {
    assert.ok(/<th>Directory entry<\/th><td><code>[^<]*uid=/.test(before.text),
      "no DN is drawn on the page.");
  });

  const classes = classesOn(before.text);
  check("THE THREE OBJECT CLASSES ARE THE HEADINGS, in inheritance order — " +
        "'the inetOrgPerson attributes' IS the union of three classes, and a " +
        "reader who does not know that learns it from the page", function () {
    assert.deepStrictEqual(classes,
      ["person", "organizationalPerson", "inetOrgPerson"],
      "the page drew: " + JSON.stringify(classes));
  });

  const drawn = attributesOn(before.text);
  check("EVERY ATTRIBUTE OF ALL THREE IS ACCOUNTED FOR, set or not — a page " +
        "showing only what happens to be set answers half of *what does this " +
        "provider know about me*", function () {
    // The names the schema requires of every person, the ones an ordinary
    // directory holds, and one from each class that this fixture will never
    // set — so the assertion is about the LIST rather than about this entry.
    ["cn", "sn", "userPassword", "seeAlso", "description",
     "title", "postalAddress", "x121Address", "teletexTerminalIdentifier",
     "uid", "mail", "displayName", "departmentNumber", "employeeType",
     "manager", "secretary", "pager", "carLicense", "preferredLanguage",
     "labeledURI", "x500UniqueIdentifier", "jpegPhoto", "userPKCS12"]
      .forEach(function (name) {
        assert.ok(drawn.has(name),
          "the page does not name " + name + ". It drew " + drawn.size +
          " attribute(s).");
      });
    assert.ok(drawn.size >= 50,
      "the page names only " + drawn.size + " attributes; the three classes " +
      "have fifty between them.");
  });

  check("the ones this person does not hold are drawn as NOT SET rather than " +
        "left out", function () {
    assert.ok(/not set/.test(String(drawn.get("carLicense") || "")),
      "carLicense is drawn as: " + String(drawn.get("carLicense")).slice(0, 120));
  });

  check("and the empty ones are behind a <details> fold, which is MARKUP and " +
        "not script — every page of this portal is script-src 'none'",
        function () {
    assert.ok(/<details><summary>/.test(sectionOf(before.text)),
      "the unset attributes are not folded; fifty rows of nothing is a wall.");
    assert.ok(!/<script/i.test(before.text),
      "the Overview has grown a script.");
  });

  return b;
}

// ===========================================================================
// 1, PROPERLY. **AN ATTRIBUTE THE SIGN-IN NEVER CARRIED.**
//
// Written over SCIM, which is a door with no session in it at all, so a page
// reading the session cannot possibly show it. That is what makes this the
// assertion for claim 1 rather than the section merely existing.
// ===========================================================================
async function itReadsTheEntryAndNotTheSession(b) {
  log.info("=== 1. an attribute SCIM wrote, which no session carried ===");

  const found = await scim("GET",
    "/Users?filter=" + encodeURIComponent('userName eq "' + OWNER + '"'));
  assert.strictEqual(found.status, 200,
    "SCIM search answered " + found.status + " " +
    String(found.raw).slice(0, 300));
  const id = ((found.body.Resources || [])[0] || {}).id;
  assert.ok(id, "SCIM cannot find " + OWNER + ": " +
                String(found.raw).slice(0, 300));

  const patched = await scim("PATCH", "/Users/" + encodeURIComponent(id), {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations: [
      { op: "replace", path: "title", value: "Chief Probe Officer" },
      { op: "replace", path: "userType", value: "contractor" },
      { op: "replace", path: ENTERPRISE + ":department", value: "Probing" }
    ]
  });
  check("SCIM writes three attributes onto the entry", function () {
    assert.ok(patched.status === 200 || patched.status === 204,
      "the PATCH answered " + patched.status + " " +
      String(patched.raw).slice(0, 300));
  });

  const after = await b.go("GET", "/portal");
  const drawn = attributesOn(after.text);
  check("AND ALL THREE ARE ON THE ACCOUNT PAGE — none of them was in the " +
        "session, and SCIM has no session in it at all, so a page reading " +
        "the session could not show any of them", function () {
    assert.ok(/Chief Probe Officer/.test(String(drawn.get("title"))),
      "title is drawn as: " + String(drawn.get("title")).slice(0, 160));
    assert.ok(/contractor/.test(String(drawn.get("employeeType"))),
      "employeeType is drawn as: " +
      String(drawn.get("employeeType")).slice(0, 160));
    assert.ok(/Probing/.test(String(drawn.get("departmentNumber"))),
      "departmentNumber is drawn as: " +
      String(drawn.get("departmentNumber")).slice(0, 160));
  });

  check("and the SCIM spelling is not what is shown — the page names the " +
        "LDAP attribute, because that is what somebody reading this on a mock " +
        "is about to go and write", function () {
    assert.ok(!attributesOn(after.text).has("userType"),
      "the page names SCIM's `userType` rather than the directory's " +
      "`employeeType`.");
  });
}

// ===========================================================================
// 3 AND 4. THE TWO KINDS THAT MAY NOT BE RENDERED.
// ===========================================================================
async function theRefusalsHold(b) {
  log.info("=== 3/4. the password, and the binary attributes ===");

  // A PASSWORD, through the management API, so there is something in
  // `userPassword` to refuse to print.
  const set = await fetch(api + "/users/set-password", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user: OWNER, password: "A-probe-Passw0rd!" })
  });
  assert.ok(set.status === 200,
    "setting a password answered " + set.status);

  const page = await b.go("GET", "/portal");
  const drawn = attributesOn(page.text);

  check("`userPassword` IS ON THE PAGE — it is on the `person` MAY list, and " +
        "a faithful reading of the schema puts it there", function () {
    assert.ok(drawn.has("userPassword"),
      "the page does not name userPassword at all, which is a list that has " +
      "quietly stopped being the schema.");
  });

  check("AND IT IS NAMED RATHER THAN PRINTED — 'set', and a sentence saying " +
        "what is really in it", function () {
    const cell = String(drawn.get("userPassword"));
    assert.ok(/set/.test(cell), "it is drawn as: " + cell.slice(0, 200));
    assert.ok(/scrypt/.test(cell),
      "the cell does not say what is stored there: " + cell.slice(0, 200));
  });

  check("and the password itself is nowhere in the HTML", function () {
    assert.ok(String(page.text).indexOf("A-probe-Passw0rd!") < 0,
      "the page carries the password that was just set.");
  });

  // A BINARY ATTRIBUTE. `jpegPhoto` over SCIM's `photos` member is not a
  // mapping this service makes, so it goes on through the management API's
  // create door if it will take it — and where it will not, the assertion
  // below still holds on the EMPTY case, which is the one every ordinary
  // person is in.
  check("a binary attribute is drawn as a size or as not set, and never as " +
        "octets — `userPKCS12` conventionally carries a PRIVATE KEY, which is " +
        "why the refusal is on the KIND rather than on a list of names",
        function () {
    ["jpegPhoto", "photo", "audio", "userCertificate", "userSMIMECertificate",
     "userPKCS12"].forEach(function (name) {
      const cell = String(drawn.get(name) || "");
      assert.ok(drawn.has(name), "the page does not name " + name + ".");
      assert.ok(/not set/.test(cell) || /bytes of binary/.test(cell),
        name + " is drawn as: " + cell.slice(0, 200));
    });
  });
}

// ===========================================================================
// 5. THE ASSERTION THAT PINS THE DESIGN.
//
// **CLAIMS 1 TO 4 ALL PASS AGAINST A PAGE THAT DUMPS THE ENTRY.** This one
// does not, and it is the whole reason `common/inetorgperson.js` is a fixed
// list rather than an iteration: this service writes four `sts`-prefixed
// CREDENTIALS onto the same object the schema attributes live on, and one of
// them — the TOTP shared secret — can be read back and used.
//
// So: enrol an authenticator, then require that the secret is nowhere in the
// HTML, and that none of the four attribute names is either.
// ===========================================================================
async function theCredentialsAreNotOnIt(b) {
  log.info("=== 5. the sts credentials are not on the page ===");

  // ---------------------------------------------------------------------
  // FIRST, PUT THEM ON THE ENTRY. **THE FIXTURE IS THE HARD PART OF THIS
  // SECTION AND THE FIRST VERSION GOT IT WRONG.** It only STARTED an
  // authenticator enrolment — which holds the secret in memory and writes
  // nothing — so the assertion below passed against a page that dumped the
  // entry, because the entry had nothing on it to dump. An assertion that
  // passes for the wrong reason is worse than none.
  //
  // Two credentials, of the two kinds this service stores beside the schema
  // attributes: an ACTIVATION TOKEN, which is hashed, and a CONFIRMED TOTP
  // ENROLMENT, whose shared secret is readable in development mode and is
  // therefore the one that would really be leaked.
  // ---------------------------------------------------------------------
  const issued = await fetch(api + "/users/issue-activation", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user: OWNER })
  });
  check("an activation link is issued, so `stsActivationToken` is on the entry",
        function () {
    assert.strictEqual(issued.status, 200,
      "issuing one answered " + issued.status);
  });

  let page = await b.go("GET", "/portal/mfa");
  await b.go("POST", "/portal/mfa",
             form({ action: "start", csrf_token: csrfOf(page.text) }));
  page = await b.go("GET", "/portal/mfa");
  const secret = ((page.text.match(
    /<th>Secret<\/th><td><code>([^<]+)<\/code>/) || [])[1] || "")
    .replace(/\s+/g, "");
  assert.ok(secret.length > 10, "no shared secret was shown on /portal/mfa.");
  const confirmed = await b.go("POST", "/portal/mfa",
    form({ action: "confirm", code: codeFor(secret),
           csrf_token: csrfOf(page.text) }));
  check("AND AN AUTHENTICATOR ENROLMENT IS CONFIRMED, which is what actually " +
        "writes `stsTotpCredential` — a shared secret this service can read " +
        "back, and the one thing on that entry a leak would really cost",
        function () {
    assert.ok(confirmed.status === 200 || confirmed.status === 303,
      "the confirmation answered " + confirmed.status + " " +
      String(confirmed.text).slice(0, 300));
    assert.ok(!/class="err"/.test(confirmed.text),
      "the confirmation came back with an error on it: " +
      String(confirmed.text).slice(0, 300));
  });

  // THE SECRET REALLY IS ON THE ENTRY NOW, asserted through a door that says
  // so rather than assumed — otherwise this whole section is back to passing
  // because there was nothing to find.
  // `?user=` and not `?q=`: that resource answers a LIST without it and ONE
  // identity in full with it, and what this needs is the one identity's
  // factors.
  const held = await fetch(api + "/users?user=" + encodeURIComponent(OWNER));
  const one = await held.json();
  check("the management API agrees that an authenticator is enrolled, so the " +
        "attribute is genuinely on the entry this page is drawn from — " +
        "without this the section below passes because there was nothing to " +
        "leak, which is how its first version passed against a page that " +
        "dumped the entry", function () {
    assert.strictEqual(held.status, 200,
      "/admin-api/users answered " + held.status);
    const factors = one.factors || one.mfa || one;
    assert.strictEqual(factors.totp, true,
      "no authenticator is enrolled for " + OWNER + ": " +
      JSON.stringify(one).slice(0, 400));
  });

  const overview = await b.go("GET", "/portal");
  check("**THE SHARED SECRET IS NOWHERE ON THE ACCOUNT PAGE.** This is the " +
        "assertion the whole design is for: every other check in this file " +
        "passes against a page that iterates the stored attributes, and this " +
        "one does not", function () {
    assert.ok(String(overview.text).indexOf(secret) < 0,
      "the Overview carries this person's TOTP shared secret.");
  });

  check("and neither is any of this service's own credential attributes, by " +
        "NAME or by value — the page draws a FIXED LIST, so an attribute this " +
        "service invents cannot arrive on it by accident", function () {
    const whole = String(overview.text);
    ["stsTotpCredential", "stsBackupCodes", "stsWebauthnCredential",
     "stsActivationToken", "stsActivationExpires",
     // The RFC 7523 signing key pair a person may hold (2026-09-11). The
     // private half is the third attribute in this directory that can be read
     // back and USED, so it belongs on this list beside the authenticator's
     // secret and the recovery codes — and the public five belong on it too,
     // because the page draws a FIXED LIST and an attribute arriving on it by
     // accident is the defect this section exists to catch, whatever that
     // attribute happens to hold.
     "stsAssertionPrivateKey", "stsAssertionJwks", "stsAssertionCertificate",
     "stsAssertionCertificateChain", "stsAssertionKid",
     "stsAssertionExpiresAt", "stsAssertionIssuer",
     "stsassertionprivatekey", "stsassertionjwks", "stsassertioncertificate",
     "stsassertioncertificatechain", "stsassertionkid",
     "stsassertionexpiresat", "stsassertionissuer",
     // The stored spellings too: this directory lower-cases every attribute
     // name on the way in, so a dump of the entry would print THESE rather
     // than the canonical ones above.
     "ststotpcredential", "stsbackupcodes", "stswebauthncredential",
     "stsactivationtoken", "stsactivationexpires"].forEach(function (name) {
      assert.ok(whole.indexOf(name) < 0,
        "the Overview mentions " + name + ", which is a credential this " +
        "service stores beside the schema attributes.");
    });
  });
}

// ===========================================================================
// 6. ONE PERSON CANNOT READ ANOTHER'S ENTRY.
//
// The rule at the top of `portal/portal.js`: no route here takes an identity
// from the request. This is the newest reader of the directory in that file
// and therefore the newest place that rule could have been broken — a
// `username` honoured here would be every attribute of anybody's account, to
// anybody signed in.
// ===========================================================================
async function oneUserCannotReadAnother() {
  log.info("=== 6. the identity is the session's and there is no parameter ===");
  const intruder = await signIn(INTRUDER);
  const theirs = await intruder.go("GET",
    "/portal?user=" + encodeURIComponent(OWNER) +
    "&username=" + encodeURIComponent(OWNER));
  check("a signed-in person naming somebody else in the query gets THEIR OWN " +
        "entry", function () {
    assert.strictEqual(theirs.status, 200,
      "/portal answered " + theirs.status);
    assert.ok(String(theirs.text).indexOf(INTRUDER) >= 0,
      "the page does not name the person who is signed in.");
    assert.ok(String(sectionOf(theirs.text)).indexOf("Chief Probe Officer") < 0,
      "the intruder was shown " + OWNER + "'s job title.");
  });

  check("and their own DN is the one drawn, not the one they asked for",
        function () {
    const dn = (theirs.text.match(
      /<th>Directory entry<\/th><td><code>([^<]+)<\/code>/) || [])[1] || "";
    assert.ok(dn.indexOf(INTRUDER) >= 0,
      "the DN drawn is " + dn + ", for a browser signed in as " + INTRUDER);
  });
}

async function test() {
  log.info("Running the /portal directory-attribute checks against " + base);
  const b = await itDrawsTheDirectory();
  await itReadsTheEntryAndNotTheSession(b);
  await theRefusalsHold(b);
  await theCredentialsAreNotOnIt(b);
  await oneUserCannotReadAnother();
  log.info(checks + " assertion(s).");
  log.info("Test completed successfully.");
}

test().catch(function (e) {
  log.error(e);
  process.exit(1);
});
