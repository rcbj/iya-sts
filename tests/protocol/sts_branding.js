// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_branding.js
//
// ---------------------------------------------------------------------------
// A REALM'S SIGN-IN APPEARANCE OVER THE WIRE (#717).
//
// D12 (#444): carries over `tests/branding.js`'s routes and write rules,
// `tests/branding_api.js`'s two doors, and `tests/branding_surfaces.js`'s
// shells, so they stay covered when the Node runtime is replaced. In a
// throwaway realm it leaves behind, through `/admin-api/branding` only:
//
//   A. A REALM THAT SET NOTHING is not customised: its view says so with the
//      old colours, and none of its shells (the front door, the federation
//      card, the portal) links a theme or carries a brand attribute.
//   B. THE WRITE RULES: a pale text on the white card refused (the core's
//      sentence; STS-AUTHN-0544 on the audit) and nothing written; a colour
//      that is not one refused by name; an unknown action naming all three.
//   C. A THEME: a dark card with light text and a light accent, legal only
//      together, saved together; `theme.css` carries them and the derived
//      tones, cached for good only under its digest; every shell links it
//      after the card (or its own stylesheet) under the realm's prefix and
//      carries the layout and the escaped name; the default realm is not
//      touched.
//   D. THE LOGO: no alternative text (0548), bytes that are no image 415
//      (0545), over the cap 413 (0546), sides under 16 (0547); a PNG kept,
//      served nosniff and sandboxed with an ETag and a 304; the text cannot
//      be emptied while it is held; a link must be https (0551); removed,
//      the realm's logo is 404 (0549), and a second removal has nothing to
//      remove; the upload and the removal audited under the token's
//      subject, the caller the gate handed the act.
//   E. THE PREVIEW: a colour that is not one 400 (0550), otherwise drawn
//      with its layout and its preview stylesheet; its one form posts with
//      autocomplete off.
//
// OWNED HERE (local: true): this repository's own management API and its
// public pages.
// ---------------------------------------------------------------------------

const assert = require("assert");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_branding",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("brand-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const PREFIX = "/realm/" + REALM;
const API = base + PREFIX + "/admin-api";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const bytes = Buffer.from(await r.arrayBuffer());
  const raw = bytes.toString("utf8");
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page, a stylesheet or an image; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, headers: r.headers, body: body, raw: raw,
           bytes: bytes };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(API + "/audit?per=500&code=" + encodeURIComponent(code));
  const rows = (r.body && (r.body.events || r.body.rows)) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// The code a refusal recorded, read where an operator reads it: the realm's
// audit log. A refusal's answer never names one.
async function sawCode(code, before) {
  log.debug("Entering sawCode(). " + code);
  let after = await codeCount(code);
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(code);
  }
  log.debug("Leaving sawCode(). " + before + " -> " + after);
  return after > before;
}

// A refusal whose code is read back off the audit log, and which itself
// names no code.
async function refusedWith(code, act) {
  log.debug("Entering refusedWith(). " + code);
  const before = await codeCount(code);
  const r = await act();
  assert.ok(!/STS-[A-Z0-9]+-\d{4}/.test(r.raw),
            "a refusal named an error code: " + r.raw.slice(0, 300));
  assert.ok(await sawCode(code, before),
            "the audit log never recorded " + code + " for an answer " +
            r.status + " " + r.raw.slice(0, 300));
  log.debug("Leaving refusedWith().");
  return r;
}

// A PNG's signature and IHDR are all the check reads.
function png(width, height, padding) {
  log.debug("Entering png().");
  const b = Buffer.alloc(64);
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(b, 0);
  b.writeUInt32BE(13, 8);
  b.write("IHDR", 12, "latin1");
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  log.debug("Leaving png().");
  return padding ? Buffer.concat([b, Buffer.alloc(padding)]) : b;
}

function logo(bytes, alt, type) {
  log.debug("Entering logo().");
  log.debug("Leaving logo().");
  return send(API + "/branding/logo" +
              (alt === null ? "" : "?alt=" + encodeURIComponent(alt)),
              { method: "POST",
                headers: { "Content-Type": type || "image/png" },
                body: bytes });
}

function htmlTag(raw) {
  log.debug("Entering htmlTag().");
  log.debug("Leaving htmlTag().");
  return (String(raw).match(/<html[^>]*>/) || [""])[0];
}

function links(raw) {
  log.debug("Entering links().");
  log.debug("Leaving links().");
  return (String(raw).match(/<link rel="stylesheet" href="[^"]*">/g) || [])
    .map(function (tag) {
      return tag.replace(/^.*href="/, "").replace(/">$/, "");
    });
}

// The three shells the appearance reaches: the card family (the
// federation page), the front door and the portal, each with its own
// stylesheet.
const SHELLS = [
  { path: "/federation", own: "/web/card.css" },
  { path: "/", own: "/web/card.css" },
  { path: "/portal", own: "/portal/portal.css" }
];

async function shells(prefix) {
  log.debug("Entering shells().");
  const out = [];
  for (const one of SHELLS) {
    const r = await send(base + prefix + one.path);
    assert.strictEqual(r.status, 200, prefix + one.path + " answered " +
                       r.status);
    out.push({ path: one.path, own: one.own, html: htmlTag(r.raw),
               links: links(r.raw) });
  }
  log.debug("Leaving shells().");
  return out;
}

async function sectionA() {
  log.debug("Entering sectionA().");
  log.info("=== A. a realm that set nothing ===");
  const view = await send(API + "/branding");
  check("its view is not customised and carries the old colours, under " +
        "its own realm and preview address", function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
    assert.strictEqual(view.body.customised, false);
    assert.strictEqual(view.body.layout, "centered");
    assert.strictEqual(view.body.logo, null);
    assert.deepStrictEqual(view.body.colours, { accent: "#12107c",
      page: "#f4f4f7", card: "#ffffff", text: "#222222" });
    assert.strictEqual(view.body.derived.muted, "#666666");
    assert.strictEqual(view.body.realm, REALM);
    assert.strictEqual(view.body.previewUrl,
                       PREFIX + "/web/branding/preview");
    assert.strictEqual(view.body.contrast.required, 4.5);
  });
  const drawn = await shells(PREFIX);
  check("no shell links a theme or carries a brand attribute", function () {
    drawn.forEach(function (one) {
      assert.ok(!one.links.some(function (l) {
        return /theme\.css/.test(l);
      }), one.path + " " + JSON.stringify(one.links));
      assert.ok(!/data-sts-layout|data-sts-brand/.test(one.html),
                one.path + " " + one.html);
    });
  });
  const css = await send(base + PREFIX + "/web/card.css");
  check("the card names its colours through custom properties falling " +
        "back to the old literals", function () {
    assert.ok(/var\(--sts-accent,#12107c\)/.test(css.raw), "accent");
    assert.ok(/\.card\{background:var\(--sts-card,#fff\)/.test(css.raw),
              "card");
    assert.ok(/html\[data-sts-layout=split\]/.test(css.raw), "split rule");
    assert.ok(!/background:#f4f4f7/.test(css.raw), "a bare page colour");
  });
  const portal = await send(base + PREFIX + "/portal/portal.css");
  check("so does the portal's own stylesheet", function () {
    assert.strictEqual(portal.status, 200);
    assert.ok(/var\(--sts-accent,#12107c\)/.test(portal.raw),
              portal.raw.slice(0, 300));
  });
  log.debug("Leaving sectionA().");
}

async function sectionB() {
  log.debug("Entering sectionB().");
  log.info("=== B. the write rules ===");
  const pale = await refusedWith("STS-AUTHN-0544", function () {
    return postJson(API + "/branding/save", { "branding.textColor": "#eeeeee" });
  });
  check("pale text on the white card is refused with the contrast it has",
        function () {
    assert.strictEqual(pale.status, 400, pale.raw.slice(0, 300));
    assert.ok(/contrast of 1\.16:1 against the card/.test(pale.raw) &&
              /WCAG 2\.2 AA asks at least 4\.5:1/.test(pale.raw),
              pale.raw.slice(0, 400));
  });
  const after = await send(API + "/branding");
  check("and nothing was written", function () {
    assert.strictEqual(after.body.colours.text, "#222222");
  });
  const word = await postJson(API + "/branding/save",
                              { "branding.accentColor": "red" });
  check("a colour that is not one is refused, naming the setting",
        function () {
    assert.strictEqual(word.status, 400, word.raw.slice(0, 300));
    assert.ok(/branding\.accentColor/.test(word.raw), word.raw.slice(0, 300));
  });
  const unknown = await postJson(API + "/branding/nope", {});
  check("an unknown action names all three, logo among them", function () {
    assert.strictEqual(unknown.status, 400);
    assert.deepStrictEqual(unknown.body.errors, ["Unknown action \"nope\". " +
      "The three are: save, logo, remove-logo."]);
  });
  log.debug("Leaving sectionB().");
}

async function sectionC() {
  log.debug("Entering sectionC().");
  log.info("=== C. a theme ===");
  const saved = await ok(API + "/branding/save", {
    "branding.cardColor": "#111111", "branding.textColor": "#eeeeee",
    "branding.accentColor": "#8ab4f8", "branding.layout": "split",
    "branding.displayName": "Acme <Corp>" }, "saved a dark theme");
  check("colours legal only together are judged together and saved",
        function () {
    assert.deepStrictEqual(saved.saved.slice().sort(), ["branding.accentColor",
      "branding.cardColor", "branding.displayName", "branding.layout",
      "branding.textColor"]);
  });
  const view = await send(API + "/branding");
  check("the view is customised, with quieter tones still AA on the card",
        function () {
    assert.strictEqual(view.body.customised, true);
    assert.strictEqual(view.body.layout, "split");
    assert.strictEqual(view.body.derived.onAccent, "#000000");
    assert.ok(view.body.contrast.text >= 4.5 &&
              view.body.contrast.accent >= 4.5, JSON.stringify(view.body));
  });
  const drawn = await shells(PREFIX);
  let themeHref = "";
  check("every shell links the realm's theme after its own stylesheet, " +
        "under its prefix and digest, with the layout and the escaped name",
        function () {
    drawn.forEach(function (one) {
      const own = one.links.indexOf(PREFIX + one.own);
      const at = one.links.findIndex(function (l) {
        return /^\/realm\/[^/]+\/web\/theme\.css\?v=[0-9a-f]{16}$/.test(l);
      });
      assert.ok(own >= 0 && at > own, one.path + " " +
                JSON.stringify(one.links));
      assert.ok(one.links[at].indexOf(PREFIX + "/web/theme.css") === 0);
      themeHref = one.links[at];
      assert.ok(/data-sts-layout="split"/.test(one.html) &&
                /data-sts-brand-name="Acme &lt;Corp&gt;"/.test(one.html),
                one.path + " " + one.html);
    });
  });
  const pinned = await send(base + themeHref);
  const loose = await send(base + PREFIX + "/web/theme.css");
  check("theme.css carries the colours and derived tones, and is cached for " +
        "good only under its own digest", function () {
    assert.strictEqual(pinned.status, 200);
    assert.ok(/--sts-card:#111111/.test(pinned.raw) &&
              /--sts-text:#eeeeee/.test(pinned.raw) &&
              /--sts-accent:#8ab4f8/.test(pinned.raw) &&
              /--sts-on-accent:#000000/.test(pinned.raw), pinned.raw);
    assert.ok(/immutable/.test(pinned.headers.get("cache-control")),
              pinned.headers.get("cache-control"));
    assert.strictEqual(loose.headers.get("cache-control"), "no-cache");
    assert.strictEqual(loose.raw, pinned.raw);
  });
  const front = await send(base + "/");
  check("the default realm is untouched by another realm's theme",
        function () {
    assert.ok(!/data-sts-layout|data-sts-brand/.test(htmlTag(front.raw)),
              htmlTag(front.raw));
    assert.ok(!links(front.raw).some(function (l) {
      return /theme\.css/.test(l);
    }), JSON.stringify(links(front.raw)));
  });
  log.debug("Leaving sectionC().");
}

async function sectionD() {
  log.debug("Entering sectionD().");
  log.info("=== D. the logo ===");
  const noAlt = await refusedWith("STS-AUTHN-0548", function () {
    return logo(png(64, 32), null);
  });
  check("a logo without alternative text is refused", function () {
    assert.strictEqual(noAlt.status, 400, noAlt.raw.slice(0, 300));
  });
  const markup = await refusedWith("STS-AUTHN-0545", function () {
    return logo(Buffer.from("<html><script>x</script></html>"), "Acme");
  });
  check("bytes that are not an image are 415, whatever was declared",
        function () {
    assert.strictEqual(markup.status, 415, markup.raw.slice(0, 300));
  });
  const huge = await refusedWith("STS-AUTHN-0546", function () {
    return logo(png(64, 32, 300000), "Acme");
  });
  check("a logo over the cap is 413", function () {
    assert.strictEqual(huge.status, 413, huge.raw.slice(0, 300));
  });
  const tiny = await refusedWith("STS-AUTHN-0547", function () {
    return logo(png(8, 8), "Acme");
  });
  check("sides under 16 pixels are refused", function () {
    assert.strictEqual(tiny.status, 400, tiny.raw.slice(0, 300));
  });
  const kept = await logo(png(64, 32), "Acme");
  check("a PNG with its text is kept, and the answer carries no bytes",
        function () {
    assert.strictEqual(kept.status, 200, kept.raw.slice(0, 300));
    assert.ok(!/"data"/.test(kept.raw), kept.raw.slice(0, 300));
  });
  const view = await send(API + "/branding");
  check("the view holds its text and its address under the realm's prefix",
        function () {
    assert.strictEqual(view.body.logoAlt, "Acme");
    assert.ok(view.body.logo && view.body.logo.type === "image/png" &&
              view.body.logo.width === 64, JSON.stringify(view.body.logo));
    assert.ok(String(view.body.logo.src).indexOf(PREFIX +
              "/web/branding/logo?v=") === 0, JSON.stringify(view.body.logo));
  });
  const served = await send(base + view.body.logo.src);
  check("the logo is served as its own type, nosniff and sandboxed, with " +
        "an ETag", function () {
    assert.strictEqual(served.status, 200);
    assert.strictEqual(served.headers.get("content-type"), "image/png");
    assert.strictEqual(served.headers.get("x-content-type-options"),
                       "nosniff");
    assert.ok(/sandbox/.test(served.headers.get("content-security-policy")),
              served.headers.get("content-security-policy"));
    assert.ok(served.headers.get("etag"), "no ETag");
    assert.strictEqual(served.bytes.length, 64);
  });
  const again = await send(base + view.body.logo.src, {
    headers: { "If-None-Match": served.headers.get("etag") } });
  check("and answers 304 to its own ETag", function () {
    assert.strictEqual(again.status, 304);
  });
  const portal = await send(base + PREFIX + "/portal");
  check("the shell carries the logo's address and its text", function () {
    const tag = htmlTag(portal.raw);
    assert.ok(/data-sts-brand-logo="\/web\/branding\/logo\?v=[0-9a-f]{16}"/
      .test(tag) && /data-sts-brand-alt="Acme"/.test(tag), tag);
  });
  const emptied = await refusedWith("STS-AUTHN-0548", function () {
    return postJson(API + "/branding/save", { "branding.logoAlt": "" });
  });
  check("the text cannot be emptied while the logo is held", function () {
    assert.strictEqual(emptied.status, 400);
  });
  const plain = await refusedWith("STS-AUTHN-0551", function () {
    return postJson(API + "/branding/save",
                    { "branding.logoLinkUrl": "http://acme.example" });
  });
  check("a link that is not https is refused", function () {
    assert.strictEqual(plain.status, 400);
  });
  await ok(API + "/branding/save",
           { "branding.logoLinkUrl": "https://acme.example/" },
           "kept an https link");
  const linked = await send(base + PREFIX + "/portal");
  check("an https one is kept and drawn on the shell", function () {
    assert.ok(/data-sts-brand-link="https:\/\/acme\.example\/"/
      .test(htmlTag(linked.raw)), htmlTag(linked.raw));
  });
  const removed = await ok(API + "/branding/remove-logo", {},
                           "removed the logo");
  const gone = await refusedWith("STS-AUTHN-0549", function () {
    return send(base + PREFIX + "/web/branding/logo");
  });
  check("removed, a realm with no logo answers 404", function () {
    assert.ok(removed.removed !== false, JSON.stringify(removed));
    assert.strictEqual(gone.status, 404);
  });
  const twice = await postJson(API + "/branding/remove-logo", {});
  check("a second removal has nothing to remove", function () {
    assert.ok(twice.status === 200 && twice.body &&
              twice.body.removed === false, twice.raw.slice(0, 300));
  });
  const emptiedNow = await postJson(API + "/branding/save",
                                    { "branding.logoAlt": "" });
  check("with no logo, its text may be emptied", function () {
    assert.ok(emptiedNow.status === 200 && emptiedNow.body.ok === true,
              emptiedNow.raw.slice(0, 300));
  });
  const audit = await send(API + "/audit?per=500");
  const rows = ((audit.body && audit.body.events) || []).filter(function (e) {
    return e.action === "branding.logo";
  });
  check("the upload and the removal are audited under the gate's caller, " +
        "never a name from the body", function () {
    assert.ok(rows.some(function (e) {
      return /the logo was removed/.test(e.summary) &&
             e.actor === "sts-api-client";
    }), JSON.stringify(rows).slice(0, 600));
    assert.ok(rows.some(function (e) {
      return /logo of 64x32 pixels and 64 bytes was uploaded/
        .test(e.summary) && e.actor === "sts-api-client";
    }), JSON.stringify(rows).slice(0, 600));
  });
  log.debug("Leaving sectionD().");
}

async function sectionE() {
  log.debug("Entering sectionE().");
  log.info("=== E. the preview ===");
  const bad = await refusedWith("STS-AUTHN-0550", function () {
    return send(base + PREFIX + "/web/branding/preview?accent=url(x)");
  });
  check("a preview of a colour that is not one is refused", function () {
    assert.strictEqual(bad.status, 400);
  });
  const drawn = await send(base + PREFIX + "/web/branding/preview?accent=" +
                           "%238ab4f8&layout=banner");
  check("otherwise it is drawn with its layout and its preview stylesheet",
        function () {
    assert.strictEqual(drawn.status, 200);
    assert.ok(/data-sts-layout="banner"/.test(drawn.raw), htmlTag(drawn.raw));
    assert.ok(/theme\.css\?preview=1&amp;accent=%238ab4f8&amp;layout=banner/
      .test(drawn.raw), drawn.raw.slice(0, 600));
  });
  const forms = drawn.raw.match(/<form\b[^>]*>/g) || [];
  check("its one form is method=post with autocomplete off, and its " +
        "password field is off and disabled", function () {
    assert.strictEqual(forms.length, 1, forms.join(" "));
    assert.ok(/method="post"/.test(forms[0]) &&
              /autocomplete="off"/.test(forms[0]), forms[0]);
    assert.ok(/<input type="password" id="pv-pass" autocomplete="off" disabled>/
      .test(drawn.raw));
  });
  log.debug("Leaving sectionE().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. the throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Branding " + STAMP },
    "created the realm");
  await sectionA();
  await sectionB();
  await sectionC();
  await sectionD();
  await sectionE();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

async function main() {
  log.debug("Entering main().");
  try {
    await test();
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main().");
    process.exit(1);
  }
}

main();
