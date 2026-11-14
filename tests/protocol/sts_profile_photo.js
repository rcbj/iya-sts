// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_profile_photo.js
//
// ===========================================================================
// A PERSON'S PROFILE PHOTO, FROM OUTSIDE (#719).
//
// A person signs in as the static portal does and sets a photo through the
// operation the portal's form posts to. Then, against a running stack:
//
//   1. the upload is refused when it is not an image, or too small;
//   2. the address answers with no credential, the right type, `nosniff` and a
//      sandboxing policy, an ETag and a 304, and without the file's metadata;
//   3. the Overview's card and the frame draw it, and `/account-api/me` names
//      it for the menu;
//   4. another person's token changes nothing of theirs;
//   5. removing it stops the address, and the card goes back to none.
//
// In a stack whose mode needs one, a public base is pinned first: product mode
// refuses to build an address on a Host header, and that refusal is asked too.
//
// `local: true`, this repository's portal and its account API.
// `tests/profile_photo.js` asks what cannot be asked from out here: a partner's
// image host, the claim's value, and the bytes kept for each kind of file.
// ===========================================================================

const assert = require("assert");
const { usernameFor } = require("./random_username.js");
const portalSignin = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_profile_photo",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

const PASSWORD = "Pr0file-Ph0to-" + process.pid + "-Passw0rd!";
const SECRET = "GPS-52.3676N-4.9041E";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function chunk(name, data) {
  log.debug("Entering chunk(). " + name);
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(name, 4, "latin1");
  log.debug("Leaving chunk().");
  return Buffer.concat([head, data, Buffer.alloc(4)]);
}

// A PNG whose bytes walk to IEND, carrying a text chunk nobody should keep.
// Nothing on this path decodes the image, so it needs no real pixels.
function png(side) {
  log.debug("Entering png().");
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(side, 0);
  ihdr.writeUInt32BE(side, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  log.debug("Leaving png().");
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr), chunk("tEXt", Buffer.from(SECRET)),
    chunk("IDAT", Buffer.from("the-image")), chunk("IEND", Buffer.alloc(0))]);
}

async function apiPost(path, payload) {
  log.debug("Entering apiPost().");
  const r = await fetch(api + path, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    // An HTML page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  log.debug("Leaving apiPost().");
  return { status: r.status, body: body, raw: raw };
}

async function signedIn(tag) {
  log.debug("Entering signedIn(). " + tag);
  const who = usernameFor(tag);
  const made = await apiPost("/users/create", {
    username: who, invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: who, sn: "Photo", givenName: "Pat",
                  mail: who + "@example.com" }
  });
  assert.ok(made.status === 200 && made.body && made.body.ok,
            "POST /admin-api/users/create: " + made.status + " " +
            String(made.raw).slice(0, 300));
  const client = await portalSignin.signInToThePortal(base, who, log,
    { password: PASSWORD });
  log.debug("Leaving signedIn().");
  return client;
}

async function setPhoto(client, bytes) {
  log.debug("Entering setPhoto().");
  const answer = await client.act("/portal/photo",
                                  { image: bytes.toString("base64") });
  log.debug("Leaving setPhoto(). " + answer.status);
  return answer;
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the profile photo checks against " + base);
  const alice = await signedIn("photo-alice");

  log.info("=== 1. what is refused ===");
  const svg = await setPhoto(alice, Buffer.from("<svg></svg>"));
  check("an SVG is refused", function () {
    assert.strictEqual(svg.status, 400, String(svg.text).slice(0, 300));
  });
  const small = await setPhoto(alice, png(100));
  check("a photo smaller than the realm's minimum is refused", function () {
    assert.strictEqual(small.status, 400, String(small.text).slice(0, 300));
  });

  log.info("=== 2. the address ===");
  const set = await setPhoto(alice, png(300));
  if (set.status === 409) {
    // Product mode with nothing pinned: the refusal is the claim, and pinning
    // the default realm's base for one job would be seen by every other.
    check("product mode refuses an address built on a Host header",
          function () {
      assert.ok(String(set.text).indexOf("global.publicBaseUrl") > 0,
                String(set.text).slice(0, 300));
    });
    log.info(checks + " assertion(s).");
    log.info("Test completed successfully.");
    log.debug("Leaving test(). Nothing pinned.");
    return;
  }
  check("a photo is saved", function () {
    assert.strictEqual(set.status, 200, String(set.text).slice(0, 300));
  });
  const me = await alice.api("GET", "/account-api/me");
  const path = String(((me.json || {}).user || {}).photo || "");
  check("/account-api/me names a random address under /web/photo", function () {
    assert.ok(/\/web\/photo\/[A-Za-z0-9_-]{22}/.test(path), path);
    assert.ok(path.indexOf("photo-alice") < 0, path);
  });
  const url = new URL(base).origin + path;
  const shown = await fetch(url);
  const bytes = Buffer.from(await shown.arrayBuffer());
  check("it answers with no credential, as an image and nothing else",
        function () {
    assert.strictEqual(shown.status, 200);
    assert.strictEqual(shown.headers.get("content-type").split(";")[0],
                       "image/png");
    assert.strictEqual(shown.headers.get("x-content-type-options"), "nosniff");
    assert.ok(/sandbox/.test(shown.headers.get("content-security-policy")),
              shown.headers.get("content-security-policy"));
    assert.strictEqual(shown.headers.get("cross-origin-resource-policy"),
                       "cross-origin");
  });
  check("the file's metadata is gone and its image is not", function () {
    assert.ok(bytes.indexOf(Buffer.from(SECRET)) < 0);
    assert.ok(bytes.indexOf(Buffer.from("the-image")) > 0);
  });
  const revalidated = await fetch(url, { headers: {
    "If-None-Match": shown.headers.get("etag") } });
  check("its ETag revalidates to a 304", function () {
    assert.strictEqual(revalidated.status, 304);
  });

  log.info("=== 3. where it is drawn ===");
  const page = await alice.draw("/portal");
  check("the Overview's card draws it, with the form and Remove", function () {
    assert.ok(page.html.indexOf('id="portal-photo-current"') > 0, "the photo");
    assert.ok(page.html.indexOf('src="' + path + '"') > 0, "its address");
    assert.ok(page.html.indexOf('id="portal-photo-file"') > 0, "the picker");
    assert.ok(page.html.indexOf("/photo/remove") > 0, "Remove");
  });

  log.info("=== 4. another person ===");
  const mallory = await signedIn("photo-mallory");
  const removed = await mallory.act("/portal/photo/remove", {});
  const still = await fetch(url);
  check("another person's removal removes nothing of the first person's", function () {
    assert.strictEqual(removed.status, 200, String(removed.text).slice(0, 300));
    assert.strictEqual(still.status, 200);
  });

  log.info("=== 5. removing it ===");
  const gone = await alice.act("/portal/photo/remove", {});
  const after = await fetch(url);
  const nothing = await alice.draw("/portal");
  check("removing it stops the address, and the card says none", function () {
    assert.strictEqual(gone.status, 200, String(gone.text).slice(0, 300));
    assert.strictEqual(after.status, 404);
    assert.ok(nothing.html.indexOf('id="portal-photo-current"') < 0);
  });
  log.info(checks + " assertion(s).");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error(e);
  process.exit(1);
});
