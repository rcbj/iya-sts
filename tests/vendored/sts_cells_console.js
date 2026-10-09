// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_cells_console.js
//
// ===========================================================================
// THE ADMIN CONSOLE AT CELL B (#98, 2026-09-28).
//
// Since the #446 cutover the console is a STATIC PAGE that signs in in the
// browser, as the public client `sts-admin-console`: the code flow with
// PKCE S256 at the authorization server of the origin it was opened at, a
// DPoP-bound token for that origin's `/admin-api`, and every page drawn
// from its operation's answer (console_signin.js does the same at one
// service). A browser the network sends to cell B opens the console THERE;
// the job is that browser, and answers every hop a Location names on the
// service's public name — cell A's, here — AT CELL B (the test-only
// resolver override, #98 section 9). For an administrator homed at cell B:
//
//   1. `GET /admin/cells` at cell B answers the console's document; the
//      console's authorization request is made at cell B, the administrator
//      signs in there — the offered second factor ignored, as
//      console_signin.js does (#246) — and the code that comes back to the
//      console's callback is redeemed at cell B for a DPoP-bound token.
//   2. `/admin/cells`, drawn at cell B from its operation's answer by the
//      console's own renderers, names cell B as this cell and cell A in its
//      jurisdiction, reachable.
//
// `local: true`: this repository's own console, against a stack only this
// repository's launcher builds. It declines to run in every mode but
// `cells`. The administrator is left in the default realm, holding Admin
// Read, with a password only this process knew.
// ===========================================================================
"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const expectation = require("./expectation.js");
const kit = require("./cells_kit.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

const log = require("bunyan").createLogger({ name: "sts_cells_console",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const ADMIN = "cells-console-" + STAMP;
const PASSWORD = "Cells-console-" +
  nodeCrypto.randomBytes(9).toString("base64url") + "-Aa1!";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// An address the service built, on its public name, answered at cell B.
function atB(cells, url) {
  log.debug("Entering atB().");
  const publicOrigin = new URL(cells.a).origin;
  const u = new URL(url);
  const out = u.origin === publicOrigin
    ? new URL(cells.b).origin + u.pathname + u.search : url;
  log.debug("Leaving atB().");
  return out;
}

// A DPoP key and its RFC 9449 proofs (ES256, r || s), as the console's page
// makes one per load; console_signin.js holds the same few lines.
function dpopKey() {
  log.debug("Entering dpopKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const state = { nonce: "" };
  log.debug("Leaving dpopKey().");
  return {
    keepNonce: function (response) {
      const nonce = response.headers.get("dpop-nonce");
      if (nonce) {
        state.nonce = nonce;
      }
    },
    proof: function (method, url, accessToken) {
      const enc = function (obj) {
        return Buffer.from(JSON.stringify(obj)).toString("base64url");
      };
      const claims = { jti: nodeCrypto.randomBytes(16).toString("base64url"),
                       htm: method, htu: String(url).replace(/[?#].*$/, ""),
                       iat: Math.floor(Date.now() / 1000) };
      if (accessToken) {
        claims.ath = nodeCrypto.createHash("sha256").update(accessToken)
          .digest("base64url");
      }
      if (state.nonce) {
        claims.nonce = state.nonce;
      }
      const input = enc({ typ: "dpop+jwt", alg: "ES256", jwk: publicJwk }) +
                    "." + enc(claims);
      return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
        { key: pair.privateKey, dsaEncoding: "ieee-p1363" })
        .toString("base64url");
    }
  };
}

// A DPoP-bound request, retried once with the server's nonce.
async function dpopFetch(key, method, url, token, init) {
  log.debug("Entering dpopFetch(). " + method + " " + url);
  let r = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const headers = Object.assign({ dpop: key.proof(method, url, token) },
                                  (init && init.headers) || {});
    if (token) {
      headers.authorization = "DPoP " + token;
    }
    r = await fetch(url, Object.assign({}, init || {},
                                       { method: method, headers: headers }));
    key.keepNonce(r);
    const retry = r.status === 400 || r.status === 401
      ? /use_dpop_nonce/.test(String(r.headers.get("www-authenticate") || "") +
                              (r.status === 400 ? await r.clone().text()
                                                : ""))
      : false;
    if (!retry) {
      break;
    }
  }
  log.debug("Leaving dpopFetch(). " + r.status);
  return r;
}

// The console's renderers as a browser loads them (console_signin.js's
// arrangement): the image build's `admin-ui/console.bundle.js`, run with no
// require, process or Buffer.
function consoleBundle() {
  log.debug("Entering consoleBundle().");
  const fs = require("fs");
  const path = require("path");
  const vm = require("vm");
  const code = fs.readFileSync(path.join(__dirname, "..", "..", "admin-ui",
                                         "console.bundle.js"), "utf8");
  log.debug("Leaving consoleBundle().");
  return vm.runInContext(code + "\n;StsConsole;", vm.createContext({}),
                         { filename: "console.bundle.js" });
}

// The console's sign-in, walked at cell B, as its page makes it there.
// Answers every hop, the jar and the token.
async function signInAtB(cells) {
  log.debug("Entering signInAtB().");
  const jar = new kit.Jar();
  const hops = [];
  const key = dpopKey();
  const origin = new URL(cells.b).origin;
  const opened = await kit.browse(jar, cells.b + "/admin/cells");
  hops.push({ url: cells.b + "/admin/cells", status: opened.status,
              location: opened.location, set: opened.set });
  const pair = kit.pkce();
  const state = nodeCrypto.randomBytes(16).toString("base64url");
  const redirectUri = origin + "/admin/callback";
  const resource = origin + "/admin-api";
  let at = origin + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "sts-admin-console",
    redirect_uri: redirectUri,
    scope: "openid admin:read admin:write admin:console",
    state: state, code_challenge: pair.challenge,
    code_challenge_method: "S256", resource: resource }).toString();
  let signedIn = false;
  let code = "";
  for (let i = 0; i < 16 && !code; i++) {
    const r = await kit.browse(jar, at);
    hops.push({ url: at, status: r.status, location: r.location,
                set: r.set });
    if (r.status >= 300 && r.status < 400 && r.location) {
      at = atB(cells, r.location);
      const back = new URL(at);
      if (/\/admin\/callback$/.test(back.pathname)) {
        // THE CONSOLE'S CALLBACK is its own page: what it does with the
        // code — the token request — is done below, as its page does it.
        hops.push({ url: at, status: 0, location: "", set: [] });
        code = back.searchParams.get("code") || "";
      }
      continue;
    }
    const fields = kit.signInFields(r.text);
    if (r.status === 200 && fields.authnId && !signedIn) {
      signedIn = true;
      const screen = new URL(at);
      const posted = await kit.browse(jar, screen.origin + screen.pathname,
        { form: { authn_id: fields.authnId, username: ADMIN,
                  password: PASSWORD, action: "login",
                  csrf_token: fields.csrf } });
      hops.push({ url: screen.origin + screen.pathname,
                  status: posted.status, location: posted.location,
                  set: posted.set });
      let next = posted;
      // THE OFFERED SECOND FACTOR (#246): an administrator with none is
      // shown the set-up step, and Ignore finishes the sign-in.
      const setupId = next.status === 200 &&
        /id="mfa-setup-ignore"/.test(next.text)
        ? (next.text.match(/name="mfa_id" value="([^"]+)"/) || [])[1] || ""
        : "";
      if (setupId) {
        next = await kit.browse(jar, screen.origin + "/authn/mfa-setup",
          { form: { mfa_id: setupId, action: "ignore" } });
        hops.push({ url: screen.origin + "/authn/mfa-setup",
                    status: next.status, location: next.location,
                    set: next.set });
      }
      assert.ok(next.status >= 300 && next.status < 400 && next.location,
        "signing in at cell B answered " + next.status + " " +
        kit.said(next.text));
      at = atB(cells, next.location);
      continue;
    }
    log.debug("Leaving signInAtB(). Stopped on " + r.status + ".");
    return { jar: jar, hops: hops, opened: opened, token: "", key: key,
             last: r };
  }
  let token = "";
  let answered = { status: 0, text: "no code came back" };
  if (code) {
    const tokenUrl = origin + "/oauth2/token";
    const r = await dpopFetch(key, "POST", tokenUrl, "", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code: code,
        redirect_uri: redirectUri, client_id: "sts-admin-console",
        code_verifier: pair.verifier, resource: resource }).toString() });
    hops.push({ url: tokenUrl, status: r.status, location: "", set: [] });
    const text = await r.text();
    answered = { status: r.status, text: text };
    try {
      token = JSON.parse(text).access_token || "";
    } catch (e) {
      log.debug("Caught in signInAtB(): " + ((e && e.message) || e));
      // Not JSON: the refusal's text is reported as it came.
      token = "";
    }
  }
  log.debug("Leaving signInAtB().");
  return { jar: jar, hops: hops, opened: opened, token: token, key: key,
           last: answered, origin: origin };
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "cell B to draw the console at.");
    log.debug("Leaving test(). Skipped.");
    return;
  }

  const made = await kit.createPerson(cells.b, ADMIN, PASSWORD, "");
  check("the administrator is created at cell B, homed there", function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  });
  const granted = await kit.api(cells.b, "POST", "/rbac/grant",
                                { username: ADMIN, role: "read" });
  check("and given Admin Read at cell B", function () {
    assert.strictEqual(granted.status, 200, granted.raw.slice(0, 300));
  });

  log.info("=== 1. the console's sign-in, at cell B ===");
  const walked = await signInAtB(cells);
  const trail = JSON.stringify(walked.hops.map(function (h) {
    return h.status + " " + new URL(h.url).host + new URL(h.url).pathname;
  }));
  check("the walk went through the console's authorization request and " +
        "callback, every hop at cell B", function () {
          assert.ok(walked.hops.some(function (h) {
            return /\/oauth2\/authorize$/.test(new URL(h.url).pathname);
          }), trail);
          assert.ok(walked.hops.some(function (h) {
            return /\/admin\/callback$/.test(new URL(h.url).pathname);
          }), trail);
          const bHost = new URL(cells.b).host;
          assert.ok(walked.hops.every(function (h) {
            return new URL(h.url).host === bHost;
          }), trail);
        });
  check("the console's code is redeemed at cell B for its DPoP-bound token",
        function () {
          assert.ok(walked.token, "no token; " + trail + " " +
            walked.last.status + " " + kit.said(walked.last.text));
        });

  log.info("=== 2. /admin/cells, drawn at cell B ===");
  check("GET /admin/cells at cell B answers the console's document",
        function () {
          assert.strictEqual(walked.opened.status, 200,
                             kit.said(walked.opened.text));
          assert.ok(/console\.js/.test(walked.opened.text),
                    kit.said(walked.opened.text));
        });
  // THE PAGE, as the console draws it at cell B: its operation asked with
  // the console's token, the answer drawn by the console's renderers.
  const table = consoleBundle();
  // IN THE READER'S LANGUAGE (#539), as the console's runtime draws it: the
  // shell's `locale` member, built into this bundle's translator and made
  // its default.
  const shell = await dpopFetch(walked.key, "GET",
                                walked.origin + "/admin-api/console",
                                walked.token, {});
  const shellJson = await shell.json().catch(function () {
    return null;
  });
  const translator = shellJson && shellJson.locale && table.messages
    ? table.messages.WebTranslator.fromData(shellJson.locale) : null;
  if (translator) {
    table.messages.WebTranslator.setDefault(function () {
      return translator;
    });
  }
  const row = table.pageFor("/admin/cells");
  const operationUrl = walked.origin + row.operation;
  const asked = await dpopFetch(walked.key, "GET", operationUrl,
                                walked.token, {});
  const answer = await asked.json().catch(function () {
    return null;
  });
  const page = { status: asked.status,
                 text: asked.status === 200 && answer
                   ? table.render("/admin/cells", answer,
                                  table.kit.context({}, false,
                                                    translator || undefined))
                     || ""
                   : "" };
  check("its operation answers at cell B and the page is drawn", function () {
    assert.strictEqual(page.status, 200, page.status + " at " +
                       operationUrl);
    assert.ok(/<h2>The cells<\/h2>/.test(page.text), kit.said(page.text));
  });
  check("it names " + cells.ids.b + " as this cell, in " +
        cells.jurisdictions.b, function () {
          assert.ok(new RegExp("<th>" + cells.ids.b +
                               " <small>\\(this cell\\)</small></th><td>" +
                               cells.jurisdictions.b + "</td>")
            .test(page.text), kit.said(page.text));
        });
  check("and " + cells.ids.a + ", in " + cells.jurisdictions.a +
        ", reachable", function () {
          assert.ok(new RegExp("<th>" + cells.ids.a + "</th><td>" +
                               cells.jurisdictions.a + "</td><td>yes, ")
            .test(page.text), kit.said(page.text));
        });

  assert.ok(checks >= 7, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_console")
  .description("an administrator homed at cell B signs in to /admin " +
      "through cell B, and /admin/cells draws both cells.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
