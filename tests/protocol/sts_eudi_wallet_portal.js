// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_eudi_wallet_portal.js
//
// ===========================================================================
// THE USER PORTAL WITH A REAL WALLET (#668): the eudi-dev wallet, from
// rcbj/eudi-dev, driven through its own web UI in Chrome beside the portal.
//
// Every other wallet in this suite is this repository's own — `wallet_kit.js`,
// the wallet modules in this directory — or the OpenID conformance suite.
// Each was written against this service, from the same reading of the
// specifications. This job hands the portal's offers and sign-in requests to
// a wallet written by somebody else, the way a person would: a link on a
// page, a consent dialog, a Transaction Code typed in. The flow is the one
// run by hand on 2026-10-17 (the ticket has it), as a job:
//
//   1. ADD A CREDENTIAL. `/portal/wallet` makes an IdentityCredential offer
//      (dc+sd-jwt, cross-device); "Open in web wallet" opens it in the
//      wallet; the Transaction Code goes into the wallet's consent dialog.
//      The wallet stores the batch (`oid4vci.batchSize` copies), each copy
//      naming its own index in this realm's Token Status List, the portal
//      lists one row per copy with the same index, and every index is VALID.
//   2. SIGN IN WITH IT. Signed out, the sign-in screen's "Sign in with a
//      wallet", then "Open your web wallet", then Approve: the wallet follows
//      the Verifier's redirect and the person is in the portal. The session
//      is recorded as an OpenID4VP sign-in, and nothing was revoked by it.
//   3. REMOVE IT. One copy by its own Remove, the rest by Remove all.
//   4. REVOKED IN THE PUBLISHED LIST. Every copy's index is INVALID in the
//      list the realm publishes, decoded here (zlib, then `bits` per entry);
//      and a wallet sign-in with the removed credential — which the wallet,
//      in its default debug mode, still offers — is refused naming the
//      index (STS-VC-0072 on the audit row). Then the job deletes the
//      copies from the wallet, as the portal tells a holder to.
//   5. SELF-ISSUED IDS. `/portal/self-issued` enrols the wallet's key with a
//      SIOPv2 request (an ID Token only); the subject is a JWK Thumbprint
//      URI; "Sign in with a self-issued ID" signs the person in (a SIOPv2
//      session); Remove takes the key off; and the next SIOPv2 sign-in is
//      refused (STS-VC-0091 on the audit row).
//
// THE WALLET IS A CHILD OF THIS JOB, NOT A CONTAINER. `tests/Dockerfile`
// builds `eudi` (its `eudi-wallet` stage, a pinned commit of rcbj/eudi-dev's
// `main`) into the tests image, and this job starts `eudi wallet serve` on a
// free loopback port with an empty state directory of its own. Its web UI is
// opened by the Chrome this job starts in the same container, so
// `http://127.0.0.1:<port>` is an address both can use and nothing else
// needs one; the service never dials the wallet (the wallet pulls the offer
// and posts its answers). So it runs wherever the tests image runs — every
// local mode, the coverage run, an AWS target — with no compose service and
// no launcher variable. The wallet verifies this service's certificate
// (`--tls-verify`) against the run's own anchor, `NODE_EXTRA_CA_CERTS`.
//
// A THROWAWAY REALM, LEFT STANDING (*No job removes a realm*). Its web wallet
// is this job's wallet (`oid4vci.walletUrl`, the two paths the eudi wallet
// takes offers and requests at), and its self-issued sign-in is on. The
// default realm is not touched, so no other job meets a web wallet it did
// not configure. The person is the job's own, created through `/admin-api`
// with a password the service generates.
//
// THE TRAPS THE HAND RUN MET, and what this job does about each:
//   * Headless Chrome's own User-Agent is scored `automated-client` (HIGH)
//     and refuses the sign-in (#666): a desktop Chrome's is set.
//   * A global logout revokes the credentials issued on the session (#659):
//     "signed out" here is the browser forgetting its cookies, which ends
//     nothing on the service.
//   * A SIOPv2 sign-in is labelled "OpenID4VP (a wallet)" on the portal
//     (#667): the session row's `protocol` is asserted, not the label.
//   * The wallet in debug mode still offers a revoked credential: section 4
//     relies on it, then deletes the copies through the wallet's API.
//
// ONE BROWSER, SERIALLY (`browser: true`, lane `main`).
//
// OWNED HERE (local: true): this repository's portal, credential issuer,
// Verifier and status list.
// ===========================================================================

"use strict";

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { Builder, By } = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");
const browserFlags = require("./browser_flags.js");
const names = require("./random_username.js");
const facts = require("./service_facts.js");

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
var log = bunyan.createLogger({ name: "sts_eudi_wallet_portal",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("eudi668-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                .slice(0, 31)
                                                .replace(/-+$/, "");
const base = root + "/realm/" + REALM;
const api = base + "/admin-api";
const HOLDER = names.usernameFor("eudi-holder");
const CONFIGURATION = "IdentityCredential";
// The binary the tests image carries (`tests/Dockerfile`, stage
// `eudi-wallet`); a hand run names its own.
const WALLET_BIN = process.env.STS_EUDI_WALLET_BIN ||
                   "/opt/eudi-wallet/eudi";
// Where the eudi wallet takes a Credential Offer and an OpenID4VP request
// (`GET /credential-offer`, and `/authorize` — the wallet's routes).
const WALLET_OFFER_PATH = "/credential-offer";
const WALLET_REQUEST_PATH = "/authorize";
// A DESKTOP CHROME'S USER-AGENT: headless Chrome's own names itself
// HeadlessChrome, which the risk engine scores as an automated client and
// refuses the sign-in for (#666).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const WAIT_MS = 30000;
const JWK_THUMBPRINT_URI = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
const STATUS_NAMES = { 0: "VALID", 1: "INVALID", 2: "SUSPENDED" };

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// ---------------------------------------------------------------------------
// HTTP: `/admin-api` (the run's preload attaches its token), the published
// status list, and the wallet's own API.
// ---------------------------------------------------------------------------
async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page or a token; the caller reads `text`.
    json = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, json: json, text: text,
           type: r.headers.get("content-type") || "" };
}

async function ok(url, payload, what) {
  log.debug("Entering ok(). " + what);
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && (!r.json || r.json.ok !== false),
            what + ": POST " + url + " answered " + r.status + " " +
            r.text.slice(0, 400));
  log.info("  " + what);
  log.debug("Leaving ok().");
  return r.json || {};
}

// The realm's audit rows carrying an error code, and its session rows about
// the holder: what a refusal and a sign-in leave behind, where a page's
// label could say something else (#667).
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  const body = r.json && typeof r.json === "object" ? r.json : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// The holder's `session.start` rows. Optionally only those not in `before`
// (an earlier answer of this function), told apart by `seq`.
async function sessionRows(before) {
  log.debug("Entering sessionRows().");
  const r = await send(api + "/audit?per=500");
  assert.strictEqual(r.status, 200, "GET " + api + "/audit answered " +
                     r.status + " " + r.text.slice(0, 300));
  const body = r.json && typeof r.json === "object" ? r.json : {};
  const seen = new Set((before || []).map(function (row) {
    return row.seq;
  }));
  const rows = (body.rows || body.events || []).filter(function (row) {
    return row.action === "session.start" && row.actor === HOLDER &&
           !seen.has(row.seq);
  });
  log.debug("Leaving sessionRows(). " + rows.length);
  return rows;
}

// What a sign-in's session row says verified (`oid4vc/vc_signin.ts`'s
// note): a presentation of a credential this realm issued, or a
// self-issued ID Token signed by an enrolled key. The row's `protocol` and
// `detail.method` cannot tell the two apart (both read "a wallet", #667).
function notesOf(rows) {
  log.debug("Entering notesOf().");
  log.debug("Leaving notesOf().");
  return rows.map(function (row) {
    return String((row.detail || {}).note || "");
  });
}

function b64uJson(segment) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return JSON.parse(Buffer.from(String(segment), "base64url").toString());
}

// A TOKEN STATUS LIST (draft-ietf-oauth-status-list), read as a relying
// party reads it: the `statuslist+jwt` the reference names, its
// `status_list.lst` inflated (zlib) and each index's `bits` read least
// significant first.
async function statusesAt(uri, indices) {
  log.debug("Entering statusesAt(). " + uri);
  const r = await send(uri, { headers: {
    Accept: "application/statuslist+jwt" } });
  assert.strictEqual(r.status, 200, "GET " + uri + " answered " + r.status +
                     " " + r.text.slice(0, 300));
  const parts = r.text.trim().split(".");
  assert.strictEqual(parts.length, 3, "the status list is not a compact " +
                     "JWS: " + r.text.slice(0, 200));
  const header = b64uJson(parts[0]);
  const payload = b64uJson(parts[1]);
  const list = payload.status_list || {};
  const bits = Number(list.bits);
  assert.ok([1, 2, 4, 8].indexOf(bits) >= 0, "status_list.bits is " +
            list.bits);
  const bytes = zlib.inflateSync(Buffer.from(String(list.lst), "base64url"));
  const per = 8 / bits;
  const out = {};
  indices.forEach(function (idx) {
    const byte = bytes[Math.floor(idx / per)];
    assert.ok(byte !== undefined, "index " + idx + " is past the list's " +
              bytes.length * per + " entries");
    out[idx] = (byte >> ((idx % per) * bits)) & ((1 << bits) - 1);
  });
  log.debug("Leaving statusesAt().");
  return { typ: header.typ, type: r.type, sub: payload.sub, bits: bits,
           statuses: out };
}

// Until every index reads `want`, or the bound: a list is signed when it is
// asked for, but a revocation may reach the publishing process a moment
// after the Remove's answer (another worker, another node).
async function statusesBecome(uri, indices, want) {
  log.debug("Entering statusesBecome(). want=" + want);
  const until = Date.now() + WAIT_MS;
  let seen = null;
  for (;;) {
    seen = await statusesAt(uri, indices);
    const all = indices.every(function (idx) {
      return seen.statuses[idx] === want;
    });
    if (all || Date.now() > until) {
      break;
    }
    await sleep(1000);
  }
  log.debug("Leaving statusesBecome().");
  return seen;
}

// ---------------------------------------------------------------------------
// THE WALLET: `eudi wallet serve`, a child of this job.
// ---------------------------------------------------------------------------
function freePort() {
  log.debug("Entering freePort().");
  return new Promise(function (resolve, reject) {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", function () {
      const port = server.address().port;
      server.close(function () {
        log.debug("Leaving freePort(). " + port);
        resolve(port);
      });
    });
  });
}

// The anchor this run trusts the service with (`tools/run-report.js` writes
// it and names it in NODE_EXTRA_CA_CERTS), handed to the wallet so that it
// verifies the issuer and the Verifier rather than skipping the check.
function serviceAnchor() {
  log.debug("Entering serviceAnchor().");
  const file = process.env.STS_EUDI_WALLET_CA ||
               process.env.NODE_EXTRA_CA_CERTS || "";
  assert.ok(file && fs.existsSync(file), "no anchor for the service's " +
            "certificate: NODE_EXTRA_CA_CERTS is " +
            JSON.stringify(process.env.NODE_EXTRA_CA_CERTS || "") +
            " (the runner sets it; a hand run sets STS_EUDI_WALLET_CA)");
  log.debug("Leaving serviceAnchor(). " + file);
  return file;
}

async function startWallet() {
  log.debug("Entering startWallet().");
  assert.ok(fs.existsSync(WALLET_BIN), "the eudi wallet is not at " +
            WALLET_BIN + " — tests/Dockerfile's eudi-wallet stage puts it " +
            "there; a hand run sets STS_EUDI_WALLET_BIN");
  const port = await freePort();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-wallet-668-"));
  const url = "http://127.0.0.1:" + port;
  const args = ["wallet", "serve", "--port", String(port),
                "--listen", "127.0.0.1", "--base-url", url,
                "--wallet-dir", dir, "--storage", "file",
                "--mode", "debug", "--no-open", "--no-register",
                "--tls-verify", "--tls-ca", serviceAnchor(),
                // THE SERVICE IS ON A PRIVATE ADDRESS IN EVERY STACK
                // (2026-11-03): `sts` on the suite's bridge is 172.30.0.10,
                // and the wallet refuses to dial a private network unless
                // told it may — "connections to internal address … are not
                // allowed", so it never read the issuer's metadata and the
                // offer stopped at the consent page on its first suite run.
                "--allow-private-networks"];
  // Nothing of the runner's environment that the wallet reads as a flag
  // (EUDI_DEV_*), and no auto-accept: every consent is pressed in Chrome.
  const env = {};
  Object.keys(process.env).forEach(function (k) {
    if (!/^EUDI_DEV_/.test(k)) {
      env[k] = process.env[k];
    }
  });
  env.HOME = dir;
  const child = childProcess.spawn(WALLET_BIN, args,
    { env: env, stdio: ["ignore", "pipe", "pipe"] });
  const lines = [];
  const keep = function (chunk) {
    String(chunk).split("\n").forEach(function (one) {
      if (one.trim()) {
        lines.push(one);
        log.debug("eudi: " + one);
      }
    });
    if (lines.length > 400) {
      lines.splice(0, lines.length - 400);
    }
  };
  child.stdout.on("data", keep);
  child.stderr.on("data", keep);
  let exited = null;
  child.on("exit", function (code, signal) {
    exited = { code: code, signal: signal };
  });
  const until = Date.now() + WAIT_MS;
  for (;;) {
    if (exited) {
      throw new Error("the eudi wallet exited (" + JSON.stringify(exited) +
                      ") before it answered:\n" + lines.join("\n"));
    }
    try {
      const r = await fetch(url + "/healthz");
      if (r.status === 200) {
        break;
      }
    } catch (e) {
      log.debug("Caught in startWallet(): " + ((e && e.message) || e));
      // Not listening yet; asked again below.
    }
    if (Date.now() > until) {
      child.kill("SIGKILL");
      throw new Error("the eudi wallet did not answer " + url +
                      "/healthz in " + WAIT_MS + " ms:\n" + lines.join("\n"));
    }
    await sleep(250);
  }
  let version = "";
  try {
    version = JSON.stringify((await send(url + "/api/version")).json);
  } catch (e) {
    log.debug("Caught in startWallet(): " + ((e && e.message) || e));
    // The version is for the log only.
  }
  log.info("The eudi wallet answers at " + url + " " + version);
  log.debug("Leaving startWallet().");
  return {
    url: url, dir: dir, lines: lines,
    stop: function () {
      log.debug("Entering stop().");
      if (!exited) {
        child.kill("SIGTERM");
      }
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch (e) {
        log.debug("Caught in stop(): " + ((e && e.message) || e));
        // A temporary directory left behind is not a failure of the run.
      }
      log.debug("Leaving stop().");
    }
  };
}

// What the wallet's API lists. A BATCH IS ONE ENTRY THERE (`batch`,
// `batch_size`, and the status reference of the copy it would present
// next), as its UI draws one card for it.
async function walletListing(wallet) {
  log.debug("Entering walletListing().");
  const r = await send(wallet.url + "/api/credentials");
  assert.strictEqual(r.status, 200, "the wallet's GET /api/credentials " +
                     "answered " + r.status + " " + r.text.slice(0, 300));
  const listed = Array.isArray(r.json) ? r.json
    : ((r.json && (r.json.credentials || r.json.items)) || []);
  log.debug("Leaving walletListing(). " + listed.length);
  return listed;
}

// THE COPIES OF A BATCH, from the wallet's own state file: its API shows a
// batch as one credential, and each copy is a credential of its own with
// its own status-list index — what the portal's one row per copy is
// compared with. The directory is this job's (`--wallet-dir`, `--storage
// file`), so the file is read rather than asked of anything.
function walletCopies(wallet) {
  log.debug("Entering walletCopies().");
  const found = [];
  const walk = function (dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach(function (one) {
      const at = path.join(dir, one.name);
      if (one.isDirectory()) {
        walk(at);
      } else if (one.name === "wallet.json") {
        found.push(at);
      }
    });
  };
  walk(wallet.dir);
  assert.strictEqual(found.length, 1, "the wallet's state directory " +
                     wallet.dir + " holds " + found.length +
                     " wallet.json files");
  const state = JSON.parse(fs.readFileSync(found[0], "utf8"));
  const copies = state.credentials || [];
  log.debug("Leaving walletCopies(). " + copies.length);
  return copies;
}

// The issuer-signed JWT of an SD-JWT VC (everything before the first `~`).
function issuerClaims(raw) {
  log.debug("Entering issuerClaims().");
  const jwt = String(raw || "").split("~")[0];
  const parts = jwt.split(".");
  assert.strictEqual(parts.length, 3, "not an SD-JWT: " +
                     String(raw).slice(0, 120));
  log.debug("Leaving issuerClaims().");
  return { header: b64uJson(parts[0]), payload: b64uJson(parts[1]) };
}

// ---------------------------------------------------------------------------
// THE BROWSER.
// ---------------------------------------------------------------------------
async function newBrowser(wallet) {
  log.debug("Entering newBrowser().");
  const options = new chrome.Options();
  options.addArguments("--headless=new", "--no-sandbox",
      "--disable-dev-shm-usage", "--window-size=1400,1200",
      "--user-agent=" + AGENT);
  browserFlags.addBrowserAccessFlags(options, base, [wallet.url]);
  const driver = await new Builder().forBrowser("chrome")
      .setChromeOptions(options).build();
  log.debug("Leaving newBrowser().");
  return driver;
}

// Until the expression (run in the page) is truthy; its value.
async function until(driver, expression, what, ms) {
  log.debug("Entering until(). " + what);
  const bound = Date.now() + (ms || WAIT_MS);
  let last = null;
  for (;;) {
    try {
      last = await driver.executeScript("return (" + expression + ");");
    } catch (e) {
      log.debug("Caught in until(): " + ((e && e.message) || e));
      // A page between two documents; asked again below.
      last = null;
    }
    if (last) {
      log.debug("Leaving until().");
      return last;
    }
    if (Date.now() > bound) {
      const at = await driver.getCurrentUrl();
      let text = "";
      try {
        text = await driver.executeScript(
          "return document.body ? document.body.innerText : '';");
      } catch (e) {
        log.debug("Caught in until(): " + ((e && e.message) || e));
        // The page's text is for the message only.
      }
      throw new Error("timed out waiting for " + what + " at " + at +
                      "\n--- the page says ---\n" +
                      String(text || "").slice(0, 1500));
    }
    await sleep(300);
  }
}

async function click(driver, selector) {
  log.debug("Entering click(). " + selector);
  const element = await driver.findElement(By.css(selector));
  await driver.executeScript(
    "arguments[0].scrollIntoView({block: 'center'});", element);
  await element.click();
  log.debug("Leaving click().");
}

async function hrefOf(driver, selector) {
  log.debug("Entering hrefOf(). " + selector);
  const href = await driver.executeScript(
    "var a = document.querySelector(arguments[0]);" +
    "return a ? a.href : '';", selector);
  log.debug("Leaving hrefOf().");
  return String(href || "");
}

// A page of the portal drawn for a signed-in person: under the realm's
// `/portal`, past the callback, with the shell's runtime done.
function portalDrawn(pathname) {
  log.debug("Entering portalDrawn().");
  log.debug("Leaving portalDrawn().");
  return "location.pathname.indexOf(" +
    JSON.stringify("/realm/" + REALM + pathname) + ") === 0 && " +
    "location.pathname.indexOf('/portal/callback') < 0 && " +
    "!document.querySelector('#username') && " +
    "document.body && document.body.innerText.length > 40";
}

// THE BROWSER FORGETS ITS SIGN-IN: the service's cookies and the portal's
// storage go, and nothing is ended on the service. A global logout would
// revoke the credentials issued on the session (#659), which is a different
// test.
async function forget(driver) {
  log.debug("Entering forget().");
  await driver.get(base + "/.well-known/openid-configuration");
  await driver.manage().deleteAllCookies();
  await driver.executeScript(
    "try { sessionStorage.clear(); localStorage.clear(); } catch (e) {}");
  log.debug("Leaving forget().");
}

// The wallet's consent dialog, open and ready: its text, for the log and
// the assertions about what it asks.
async function walletConsent(driver, what) {
  log.debug("Entering walletConsent(). " + what);
  await until(driver,
    "document.querySelector('#consent-overlay.active') && " +
    "document.querySelector('#consent-approve') && " +
    "!document.querySelector('#consent-approve').disabled",
    "the wallet's consent dialog (" + what + ")");
  const text = String(await driver.executeScript(
    "var d = document.querySelector('#consent-dialog');" +
    "return d ? d.innerText : '';") || "");
  log.info("  the wallet asks (" + what + "): " +
           text.replace(/\s+/g, " ").slice(0, 400));
  log.debug("Leaving walletConsent().");
  return text;
}

async function passwordSignIn(driver, password) {
  log.debug("Entering passwordSignIn().");
  await driver.get(base + "/portal");
  await until(driver, "document.querySelector('#username')",
              "the sign-in screen");
  await driver.findElement(By.css("#username")).sendKeys(HOLDER);
  await driver.findElement(By.css("#password")).sendKeys(password);
  await click(driver, "#kc-login");
  // A person with no second factor may be offered one; it is skipped.
  const where = await until(driver,
    "document.querySelector('#mfa-setup-ignore') ? 'mfa' : " +
    "((" + portalDrawn("/portal") + ") ? 'portal' : '')",
    "the portal after the password");
  if (where === "mfa") {
    await click(driver, "#mfa-setup-ignore");
    await until(driver, portalDrawn("/portal"), "the portal after MFA set-up");
  }
  log.debug("Leaving passwordSignIn().");
}

// From the sign-in screen: the option `id` (wallet-signin, siop-signin), its
// wait page, the web wallet, and Approve. Answers the consent dialog's text.
async function walletSignIn(driver, wallet, id) {
  log.debug("Entering walletSignIn(). " + id);
  await driver.get(base + "/portal");
  await until(driver, "document.querySelector('#" + id + "')",
              "#" + id + " on the sign-in screen");
  await click(driver, "#" + id);
  await until(driver, "document.querySelector('#wallet-web')",
              "the wait page's web wallet link");
  const web = await hrefOf(driver, "#wallet-web");
  check("the wait page hands the request to this realm's web wallet (" +
        id + ")", function () {
    assert.ok(web.indexOf(wallet.url + WALLET_REQUEST_PATH + "?") === 0,
              web);
  });
  await driver.get(web);
  const asked = await walletConsent(driver, id);
  await click(driver, "#consent-approve");
  log.debug("Leaving walletSignIn().");
  return asked;
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function prepare(wallet) {
  log.debug("Entering prepare().");
  const product = await facts.isProduct(root + "/admin-api");
  log.info("=== 0. a throwaway realm " + REALM + " (" +
           (product ? "product" : "development") + "), its web wallet " +
           wallet.url + " ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "eudi-dev wallet " + STAMP },
    "created the realm");
  const settings = [
    ["oid4vci.walletUrl", wallet.url],
    ["oid4vci.walletIssuancePath", WALLET_OFFER_PATH],
    ["oid4vp.walletUrl", wallet.url],
    ["oid4vp.walletPresentationPath", WALLET_REQUEST_PATH],
    ["oid4vp.signIn", true],
    ["oid4vp.signInSelfIssued", true]];
  for (const one of settings) {
    await ok(api + "/config/set", { key: one[0], value: one[1] },
             "set " + one[0]);
  }
  // A PASSWORD THE SERVICE GENERATES, as an administrator's create gives a
  // person one; product mode checks it.
  const made = await ok(api + "/users/create", { username: HOLDER,
    invent: false, credential: "generate",
    attributes: { cn: "eudi " + HOLDER, givenName: "Eudi", sn: "Holder",
                  mail: HOLDER + "@eudi668.test" } }, "created " + HOLDER);
  assert.ok(made.password, "the create generated no password: " +
            JSON.stringify(made).slice(0, 300));
  const batch = Number(await facts.setting(api, "oid4vci.batchSize")) || 1;
  log.debug("Leaving prepare(). batch=" + batch);
  return { password: made.password, batch: batch };
}

async function addCredential(driver, wallet, state) {
  log.debug("Entering addCredential().");
  log.info("=== 1. " + HOLDER + " signs in and adds a credential to the " +
           "eudi wallet ===");
  await passwordSignIn(driver, state.password);
  await driver.get(base + "/portal/wallet");
  await until(driver, "document.querySelector('#wallet-make')",
              "the offer form on /portal/wallet");
  const chosen = await driver.executeScript(
    "var r = document.querySelector('input[name=configuration][value=' +" +
    " JSON.stringify(arguments[0]) + ']');" +
    "if (!r) { return ''; } r.click();" +
    "r.dispatchEvent(new Event('change', {bubbles: true}));" +
    "var s = document.querySelector('#wallet-alg');" +
    "if (s) {" +
    "  var o = Array.prototype.filter.call(s.options, function (x) {" +
    "    return !x.disabled && /^ES(256|384)$/.test(x.value); });" +
    "  if (o.length) { s.value = o[0].value;" +
    "    s.dispatchEvent(new Event('change', {bubbles: true})); }" +
    "  return r.value + ' ' + s.value; }" +
    "return r.value;", CONFIGURATION);
  check("the portal offers " + CONFIGURATION + " (" + chosen + ")",
        function () {
    assert.ok(String(chosen).indexOf(CONFIGURATION) === 0, chosen);
  });
  await click(driver, "#wallet-make");
  await until(driver, "document.querySelector('#tx_code') && " +
              "document.querySelector('#open_in_web_wallet')",
              "the offer, its Transaction Code and its web wallet link");
  const txCode = String(await driver.executeScript(
    "return document.querySelector('#tx_code').textContent.trim();"));
  const web = await hrefOf(driver, "#open_in_web_wallet");
  check("the offer is handed to this realm's web wallet, with a " +
        "Transaction Code", function () {
    assert.ok(web.indexOf(wallet.url + WALLET_OFFER_PATH + "?") === 0, web);
    assert.ok(/^\d{4,12}$/.test(txCode), txCode);
  });
  await driver.get(web);
  await until(driver, "document.querySelector('#offer-tx-code-input') && " +
              "document.querySelector('#offer-tx-code-input').offsetParent",
              "the wallet's Transaction Code box");
  await walletConsent(driver, "the offer");
  await driver.findElement(By.css("#offer-tx-code-input")).sendKeys(txCode);
  await click(driver, "#consent-approve");

  // THE WALLET HOLDS THE BATCH: one entry in its API, `batch_size` copies
  // in its store.
  const bound = Date.now() + WAIT_MS;
  let listed = [];
  for (;;) {
    listed = await walletListing(wallet);
    if (listed.length || Date.now() > bound) {
      break;
    }
    await sleep(500);
  }
  check("the wallet lists the credential once, a batch of " + state.batch +
        " (oid4vci.batchSize), its signature valid", function () {
    assert.strictEqual(listed.length, 1,
                       JSON.stringify(listed).slice(0, 600) + "\n" +
                       wallet.lines.slice(-30).join("\n"));
    assert.strictEqual(Number(listed[0].batch_size || 1), state.batch,
                       JSON.stringify(listed[0]).slice(0, 600));
    assert.strictEqual(listed[0].format, "dc+sd-jwt");
    assert.strictEqual((listed[0].signature || {}).self_consistent, true,
                       JSON.stringify(listed[0].signature));
  });
  // The store is written after the API answers; it is waited for.
  let stored = [];
  for (;;) {
    stored = walletCopies(wallet);
    if (stored.length >= state.batch || Date.now() > bound) {
      break;
    }
    await sleep(500);
  }
  check("the wallet's store holds " + state.batch + " copies of one batch",
        function () {
    assert.strictEqual(stored.length, state.batch,
                       stored.map(function (c) {
                         return c.id;
                       }).join(", "));
    stored.forEach(function (c) {
      assert.ok(c.batch_group && c.batch_group === stored[0].batch_group,
                c.id + " " + c.batch_group);
    });
  });
  const copies = stored.map(function (one) {
    const claims = issuerClaims(one.raw);
    const ref = ((claims.payload.status || {}).status_list) || {};
    return { walletId: one.id, alg: claims.header.alg,
             typ: claims.header.typ, vct: claims.payload.vct,
             idx: Number(ref.idx), uri: String(ref.uri || "") };
  });
  log.info("  copies: " + JSON.stringify(copies));
  check("each copy is a dc+sd-jwt signed with the algorithm chosen",
        function () {
    copies.forEach(function (c) {
      assert.strictEqual(c.typ, "dc+sd-jwt", JSON.stringify(c));
      assert.ok(String(chosen).indexOf(c.alg) > 0, c.alg + " / " + chosen);
    });
  });
  check("each copy names its own index in this realm's Token Status List",
        function () {
    copies.forEach(function (c) {
      assert.ok(Number.isInteger(c.idx) && c.idx >= 0, JSON.stringify(c));
      assert.ok(c.uri.indexOf(base + "/") === 0, c.uri);
      assert.strictEqual(c.uri, copies[0].uri);
    });
    const distinct = new Set(copies.map(function (c) {
      return c.idx;
    }));
    assert.strictEqual(distinct.size, copies.length,
                       JSON.stringify(copies));
  });
  const indices = copies.map(function (c) {
    return c.idx;
  });
  const fresh = await statusesAt(copies[0].uri, indices);
  check("the published list is a statuslist+jwt and every copy is VALID",
        function () {
    assert.strictEqual(fresh.typ, "statuslist+jwt");
    assert.ok(/statuslist\+jwt/.test(fresh.type), fresh.type);
    assert.strictEqual(fresh.sub, copies[0].uri);
    indices.forEach(function (idx) {
      assert.strictEqual(fresh.statuses[idx], 0,
                         "index " + idx + " is " + fresh.statuses[idx]);
    });
  });

  // THE PORTAL LISTS THE SAME COPIES.
  await driver.get(base + "/portal/wallet");
  await until(driver, "document.querySelectorAll('#wallet-issued " +
              "tr[data-credential]').length >= " + state.batch,
              "one row per copy on /portal/wallet");
  const rows = await driver.executeScript(
    "return Array.prototype.map.call(document.querySelectorAll(" +
    "'#wallet-issued tr[data-credential]'), function (tr) {" +
    "  return tr.textContent; });");
  check("/portal/wallet lists one row per copy, each with the index the " +
        "wallet's copy names", function () {
    assert.strictEqual(rows.length, state.batch, JSON.stringify(rows));
    indices.forEach(function (idx) {
      assert.ok(rows.some(function (text) {
        return new RegExp("(^|\\D)" + idx + "(\\D|$)").test(text);
      }), "no row names index " + idx + ": " + JSON.stringify(rows));
    });
  });
  log.debug("Leaving addCredential().");
  return { uri: copies[0].uri, indices: indices, copies: copies,
           walletId: listed[0].id };
}

async function signInWithIt(driver, wallet, issued) {
  log.debug("Entering signInWithIt().");
  log.info("=== 2. signed out, " + HOLDER + " signs in with the wallet ===");
  await forget(driver);
  const before = await sessionRows();
  const asked = await walletSignIn(driver, wallet, "wallet-signin");
  check("the wallet is shown a signed x509_hash request for the Identity " +
        "Credential it holds", function () {
    assert.ok(/x509_hash:/.test(asked), asked.slice(0, 300));
    assert.ok(/Identity Credential/.test(asked), asked.slice(0, 300));
  });
  check("the wallet is asked to disclose the subject and nothing else",
        function () {
    assert.ok(/1 of 1 field\s*sub\b/.test(asked), asked.slice(0, 600));
  });
  await until(driver, portalDrawn("/portal"),
              "the portal after the wallet's answer");
  const notes = notesOf(await sessionRows(before));
  check("the sign-in started one session, from a verified presentation of " +
        "the credential this realm issued", function () {
    assert.strictEqual(notes.length, 1, JSON.stringify(notes));
    assert.ok(/^A verifiable presentation of a credential this realm/
              .test(notes[0]), notes[0]);
  });
  const after = await statusesAt(issued.uri, issued.indices);
  check("signing in revoked nothing: every copy is still VALID", function () {
    issued.indices.forEach(function (idx) {
      assert.strictEqual(after.statuses[idx], 0, "index " + idx);
    });
  });
  log.debug("Leaving signInWithIt().");
}

async function removeIt(driver, issued) {
  log.debug("Entering removeIt().");
  log.info("=== 3. " + HOLDER + " removes the credential on /portal/wallet " +
           "===");
  await driver.get(base + "/portal/wallet");
  await until(driver, "document.querySelector('#wallet-issued " +
              "tr[data-credential] button.danger')",
              "a copy's Remove on /portal/wallet");
  const first = String(await driver.executeScript(
    "document.querySelectorAll('#wallet-issued details').forEach(" +
    "  function (d) { d.open = true; });" +
    "return document.querySelector('#wallet-issued tr[data-credential]')" +
    ".getAttribute('data-credential');"));
  await click(driver, "#wallet-issued tr[data-credential=" +
              JSON.stringify(first) + "] button.danger");
  await until(driver,
    "(function () { var tr = document.querySelector(" +
    "'#wallet-issued tr[data-credential=' + " + JSON.stringify(
      JSON.stringify(first)) + " + ']');" +
    "return tr && !tr.querySelector('button.danger') && " +
    "/remov/i.test(tr.textContent); })()",
    "the first copy drawn as removed");
  const others = await driver.executeScript(
    "return document.querySelectorAll('#wallet-issued " +
    "tr[data-credential] button.danger').length;");
  check("one copy removed by its own Remove; the others still offer one",
        function () {
    assert.strictEqual(others, issued.indices.length - 1);
  });
  await until(driver, "document.querySelector('#wallet-issued " +
              "tr[data-issuance] button.danger')",
              "Remove all on the issuance");
  await click(driver, "#wallet-issued tr[data-issuance] button.danger");
  const rows = await until(driver,
    "(function () { var all = document.querySelectorAll(" +
    "'#wallet-issued tr[data-credential]');" +
    "var done = Array.prototype.every.call(all, function (tr) {" +
    "  return !tr.querySelector('button.danger') && " +
    "    /remov/i.test(tr.textContent); });" +
    "return all.length && done && Array.prototype.map.call(all," +
    "  function (tr) { return tr.textContent; }); })()",
    "every copy drawn as removed");
  check("every copy reads \"Removed by you\" on /portal/wallet", function () {
    assert.strictEqual(rows.length, issued.indices.length);
    rows.forEach(function (text) {
      assert.ok(/Removed by you/i.test(text), text);
    });
  });
  log.debug("Leaving removeIt().");
}

async function revokedInTheList(driver, wallet, issued) {
  log.debug("Entering revokedInTheList().");
  log.info("=== 4. every copy INVALID in the published list, and the " +
           "removed credential refused ===");
  const seen = await statusesBecome(issued.uri, issued.indices, 1);
  check("every copy's index went from VALID to INVALID", function () {
    issued.indices.forEach(function (idx) {
      assert.strictEqual(seen.statuses[idx], 1, "index " + idx + " is " +
                         STATUS_NAMES[seen.statuses[idx]]);
    });
  });
  // THE WALLET STILL OFFERS IT (its debug mode does not read the list), so
  // the Verifier is the one that refuses: at its response endpoint, with
  // OpenID4VP's error answer — a 400 whose `error_description` names the
  // index, and no `redirect_uri`, so the wallet stays where it is and shows
  // the failure, which is where the person reads it.
  await forget(driver);
  const refusedBefore = await codeCount("STS-VC-0072");
  const before = await sessionRows();
  await walletSignIn(driver, wallet, "wallet-signin");
  await until(driver,
    "location.href.indexOf(" + JSON.stringify(wallet.url) + ") === 0 && " +
    "/Response: 400/.test(document.body.innerText)",
    "the wallet showing the Verifier's refusal");
  const said = (await send(wallet.url + "/api/log")).text;
  const named = /Token Status List index (\d+) is INVALID/.exec(said || "");
  check("the Verifier refuses the removed credential, naming its INVALID " +
        "index to the wallet", function () {
    assert.ok(named, "the wallet's log does not carry the reason: " +
              String(said).slice(-1500));
    assert.ok(issued.indices.indexOf(Number(named[1])) >= 0, named[1] +
              " / " + JSON.stringify(issued.indices));
  });
  const refusedAfter = await codeCount("STS-VC-0072");
  check("the refusal is recorded under STS-VC-0072", function () {
    assert.ok(refusedAfter > refusedBefore, refusedAfter + " / " +
              refusedBefore);
  });
  const signedIn = await sessionRows(before);
  check("nobody was signed in by it", function () {
    assert.strictEqual(signedIn.length, 0, JSON.stringify(notesOf(signedIn)));
  });

  // THE HOLDER DELETES THE CREDENTIAL, as the portal tells them to: one
  // DELETE, which takes every copy of the batch (the wallet's own rule).
  const r = await send(wallet.url + "/api/credentials/" +
                       encodeURIComponent(issued.walletId),
                       { method: "DELETE" });
  check("the wallet deletes the removed credential", function () {
    assert.ok(r.status >= 200 && r.status < 300, "DELETE " +
              issued.walletId + " answered " + r.status + " " +
              r.text.slice(0, 200));
  });
  const left = await walletListing(wallet);
  const bound = Date.now() + WAIT_MS;
  let leftCopies = [];
  for (;;) {
    leftCopies = walletCopies(wallet);
    if (!leftCopies.length || Date.now() > bound) {
      break;
    }
    await sleep(500);
  }
  check("the wallet holds nothing, and no copy, once it is deleted",
        function () {
    assert.strictEqual(left.length, 0, JSON.stringify(left).slice(0, 300));
    assert.strictEqual(leftCopies.length, 0,
                       JSON.stringify(leftCopies).slice(0, 300));
  });
  log.debug("Leaving revokedInTheList().");
}

async function selfIssued(driver, wallet, state) {
  log.debug("Entering selfIssued().");
  log.info("=== 5. a self-issued ID: enrol, sign in, remove, refused ===");
  await forget(driver);
  await passwordSignIn(driver, state.password);
  await driver.get(base + "/portal/self-issued");
  await until(driver, "document.querySelector('#siop-enrol')",
              "Enrol on /portal/self-issued");
  await click(driver, "#siop-enrol");
  await until(driver, "document.querySelector('#wallet-web')",
              "the enrolment's web wallet link");
  const web = await hrefOf(driver, "#wallet-web");
  await driver.get(web);
  const asked = await walletConsent(driver, "the SIOPv2 enrolment");
  // THE WALLET HOLDS NO CREDENTIAL HERE (section 4 deleted it), so what the
  // dialog can show is the request alone: signed by this realm's Verifier,
  // asking for no credential — the self-issued ID Token is the wallet's own.
  check("the enrolment shows the wallet a signed request from this realm's " +
        "Verifier that asks for no credential", function () {
    assert.ok(/x509_hash:/.test(asked) && /Signed/.test(asked),
              asked.slice(0, 300));
    assert.ok(!/SD-JWT|Identity Credential|field/.test(asked),
              asked.slice(0, 300));
  });
  await click(driver, "#consent-approve");
  const subject = String(await until(driver,
    "location.pathname.indexOf('/portal/self-issued') >= 0 && " +
    "/enrolled=1/.test(location.search) && " +
    "document.querySelector('code.subject') && " +
    "document.querySelector('code.subject').getAttribute('title')",
    "the enrolled subject on /portal/self-issued"));
  check("the enrolled subject is a JWK Thumbprint URI", function () {
    assert.ok(subject.indexOf(JWK_THUMBPRINT_URI) === 0, subject);
  });

  await forget(driver);
  const before = await sessionRows();
  await walletSignIn(driver, wallet, "siop-signin");
  await until(driver, portalDrawn("/portal"),
              "the portal after the SIOPv2 sign-in");
  const notes = notesOf(await sessionRows(before));
  check("the self-issued sign-in started one session, from an ID Token " +
        "signed by the enrolled key", function () {
    assert.strictEqual(notes.length, 1, JSON.stringify(notes));
    assert.ok(notes[0].indexOf("A self-issued ID Token signed by " +
                               subject + ",") === 0, notes[0]);
  });

  await driver.get(base + "/portal/self-issued");
  await until(driver, "document.querySelector('code.subject') && " +
              "document.querySelector('form button.danger')",
              "the enrolled key's Remove");
  await click(driver, "form button.danger");
  const notice = String(await until(driver,
    "document.querySelector('#siop-none') && " +
    "document.body.innerText", "the key removed"));
  check("Remove takes the key off and says it no longer signs in",
        function () {
    assert.ok(/no longer signs you in/i.test(notice), notice.slice(0, 500));
  });

  await forget(driver);
  const refusedBefore = await codeCount("STS-VC-0091");
  const beforeRefusal = await sessionRows();
  await walletSignIn(driver, wallet, "siop-signin");
  // THE WALLET IS SENT BACK TO THE WAIT PAGE WITH NO `response_code`: the
  // Verifier mints one only for an answer that signs somebody in, so the
  // page has nothing to collect and goes on saying it waits. Its own words
  // say what to do — "check now" — and that asks the status operation,
  // which answers the refusal (403, STS-VC-0091) the page then draws.
  const landed = await until(driver,
    "((" + portalDrawn("/portal") + ") && 'portal') || " +
    "(location.href.indexOf(" + JSON.stringify(base) + ") === 0 && " +
    "location.pathname.indexOf('/authn/wallet/wait') >= 0 && " +
    "!/response_code=/.test(location.search) && " +
    "document.querySelector('#wallet-check') && 'wait')",
    "the wait page the wallet returns to");
  check("the removed key signs nobody in: the wallet is sent back to the " +
        "wait page, not to the portal", function () {
    assert.strictEqual(landed, "wait");
  });
  await click(driver, "#wallet-check");
  const said = String(await until(driver,
    "/not enrolled/.test(document.body.innerText) && " +
    "document.body.innerText",
    "the refusal of the removed key on the wait page"));
  log.info("  the wait page says: " + said.replace(/\s+/g, " ")
                                          .slice(0, 300));
  check("Check now on the wait page draws the refusal: the key is not " +
        "enrolled for anybody", function () {
    assert.ok(said.indexOf(subject) >= 0, said.slice(0, 600));
  });
  const refusedAfter = await codeCount("STS-VC-0091");
  check("the SIOPv2 refusal is recorded under STS-VC-0091", function () {
    assert.ok(refusedAfter > refusedBefore, refusedAfter + " / " +
              refusedBefore);
  });
  const signedIn = await sessionRows(beforeRefusal);
  check("nobody was signed in by the removed key", function () {
    assert.strictEqual(signedIn.length, 0,
                       JSON.stringify(notesOf(signedIn)));
  });
  log.debug("Leaving selfIssued().");
}

async function test() {
  log.debug("Entering test().");
  const wallet = await startWallet();
  let driver = null;
  try {
    const state = await prepare(wallet);
    driver = await newBrowser(wallet);
    const issued = await addCredential(driver, wallet, state);
    await signInWithIt(driver, wallet, issued);
    await removeIt(driver, issued);
    await revokedInTheList(driver, wallet, issued);
    await selfIssued(driver, wallet, state);
  } finally {
    if (driver) {
      try {
        await driver.quit();
      } catch (e) {
        log.debug("Caught in test(): " + ((e && e.message) || e));
        // A browser that will not quit does not change the verdict.
      }
    }
    wallet.stop();
  }
  log.info("Test completed successfully. " + checks + " check(s) passed. " +
           "Realm " + REALM + " and " + HOLDER + " are left in place.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_eudi_wallet_portal FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
