// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_oid4vc_wallet.js
//
// ===========================================================================
// THE NATIVE OID4VC WALLET (#694): rcbj/oid4vc-wallet, the Linux desktop
// wallet, driven from its command line against this realm's issuer, its
// Verifier and its self-issued sign-in.
//
// `sts_eudi_wallet_portal.js` (#668) hands the portal to a web wallet in a
// browser. This job hands the same surfaces to a wallet that runs on the
// person's own computer, through the three commands its #10 gave it so that
// nothing needs a window:
//
//   oid4vc-wallet accept  <openid-credential-offer://…> --tx-code <code>
//   oid4vc-wallet present <openid4vp://…|siopv2://…> --approve|--refuse
//   oid4vc-wallet self-issued [--subject jwk|did:jwk|did:key|did:web:…]
//
// The job is the person's browser (a cookie jar, the sign-in surface's own
// API, `wallet_signin.js`) and the wallet is the person's wallet: every
// request it answers is the one the wait page hands it, and what it prints
// back — the Verifier's redirect — is followed in that browser, as the
// wallet's guide tells a person to do.
//
//   1. AN OFFER ACCEPTED. `/portal/wallet` makes an IdentityCredential offer
//      (`POST /account-api/credentials/offers`); `accept` redeems it with the
//      Transaction Code and stores the batch, `oid4vci.batchSize` copies of
//      `dc+sd-jwt`, each naming its own index in this realm's Token Status
//      List; the portal lists the same copies, and every index is VALID.
//   2. AN OPENID4VP SIGN-IN, APPROVED: a relying party's authorization
//      request, the screen's wallet sign-in, `present --approve`; one
//      session, from a verified presentation, and a code redeemed for an ID
//      Token about the person. Nothing was revoked by it.
//   3. AN OPENID4VP SIGN-IN, REFUSED: `present --refuse`; the wallet tells
//      the Verifier it declined, no code reaches the relying party, and
//      nobody is signed in.
//   4. SELF-ISSUED IDS, THREE SUBJECTS OF ONE KEY: the JWK thumbprint,
//      `did:jwk` and `did:key`, each enrolled on `/portal/self-issued` by a
//      `present --approve` of the enrolment request with `--subject`, each
//      the subject `self-issued` prints, each signing the person in over
//      `siopv2://`; then the thumbprint removed, and its sign-in refused
//      (STS-VC-0091), nobody signed in.
//   5. A did:web THIS REALM PUBLISHES, ITS KEY IN THE WALLET (#1291, wallet
//      custody): `did_act=publish` proved with the wallet's key; the
//      document names that key; `self-issued --subject <the did:web>` and a
//      sign-in with it.
//   6. A REVOKED CREDENTIAL REFUSED: Remove all on the portal; every index
//      INVALID in the published list; the wallet, which reads no status
//      list, still presents a copy, and the Verifier refuses it
//      (STS-VC-0072), nobody signed in.
//
// THE WALLET IS A CHILD OF THIS JOB, NOT A CONTAINER, AND NEVER THE DESKTOP'S.
// `tests/Dockerfile` builds `oid4vc-wallet` (its `oid4vc-wallet` stage, a
// pinned commit of rcbj/oid4vc-wallet's `main`) into the tests image. Every
// command runs with an environment this job writes from nothing: a throwaway
// HOME (and the XDG directories under it), no session bus, and its storage
// key in a file of that HOME (OID4VC_WALLET_KEY_FILE) — so a hand run on a
// desktop can never reach the person's key ring or real wallet files, which
// is rcbj's rule. The wallet verifies this service's certificate against the
// run's own anchor (`NODE_EXTRA_CA_CERTS`, handed over as SSL_CERT_FILE,
// which its TLS stack reads in place of the system store); it makes no
// loopback exception for the names a stack's service has. The service never
// dials the wallet, so there is no compose service and no launcher variable.
//
// A THROWAWAY REALM, LEFT STANDING (*No job removes a realm*), in the stack's
// mode, on a host of two labels or more that it pins as its own base
// (`dottedRoot()`, below: the wallet refuses a did:web on a single label).
//
// OWNED HERE (local: true): this repository's portal, credential issuer,
// Verifier, self-issued sign-in, published DIDs and status list.
// ===========================================================================

"use strict";

const assert = require("assert");
const childProcess = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const consentScreen = require("./consent_screen.js");
const portalSignin = require("./portal_signin.js");
const walletSignin = require("./wallet_signin.js");
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
var log = bunyan.createLogger({ name: "sts_oid4vc_wallet",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
// The service as the run reaches it: realms are created here.
const serviceRoot = String(process.env.OID4VCI_ISSUER_URL ||
                           stsUrl.replace(/\/sts\/?$/, ""))
  .replace(/\/+$/, "");

// THE REALM'S OWN ROOT, A HOST OF TWO LABELS OR MORE. A did:web names the
// host its realm publishes on, and the wallet refuses one of a single label
// (`did:web:sts%3A8081:…`) — so where the run reaches the service by one
// (`sts`, `sts-lb`), the realm runs on `<host>.example.com`, which the test
// stacks map to the same address for the runner (docker-compose-run-tests.yml's
// `tests`, `extra_hosts`) and the certificate already names, and pins it as
// its `global.publicBaseUrl`. A dotted host (an AWS target) is used as it is;
// a hand run names its own with STS_OID4VC_WALLET_SERVICE_URL.
function dottedRoot(url) {
  log.debug("Entering dottedRoot().");
  if (process.env.STS_OID4VC_WALLET_SERVICE_URL) {
    log.debug("Leaving dottedRoot(). Named.");
    return String(process.env.STS_OID4VC_WALLET_SERVICE_URL)
      .replace(/\/+$/, "");
  }
  const u = new URL(url);
  if (u.hostname.indexOf(".") < 0) {
    u.hostname = u.hostname + ".example.com";
  }
  log.debug("Leaving dottedRoot(). " + u.host);
  return u.origin;
}

var root = dottedRoot(serviceRoot);
const STAMP = names.runStamp();
const REALM = ("wallet694-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                  .slice(0, 31)
                                                  .replace(/-+$/, "");
const base = root + "/realm/" + REALM;
// THE MANAGEMENT API ON THE RUN'S OWN ROOT, not the realm's: the run's
// token names `serviceRoot` as its issuer, and RFC 9068 refuses it at
// another host name (an issuer is an address).
const mgmtBase = serviceRoot + "/realm/" + REALM;
const api = mgmtBase + "/admin-api";
const HOLDER = names.usernameFor("wallet694-holder");
const PASSWORD = "Wallet694-holder-" + crypto.randomBytes(9)
  .toString("base64url") + "-Aa1!";
const CLIENT_ID = "sts-oid4vc-wallet-rp";
const REDIRECT_URI = "https://rp.sts-oid4vc-wallet.example.test/cb";
const CONFIGURATION = "IdentityCredential";
// The binary the tests image carries (`tests/Dockerfile`, stage
// `oid4vc-wallet`); a hand run names its own build.
const WALLET_BIN = process.env.STS_OID4VC_WALLET_BIN ||
                   "/opt/oid4vc-wallet/oid4vc-wallet";
const WALLET_TIMEOUT_MS = 60000;
const WAIT_MS = 30000;
const JWK_THUMBPRINT_URI = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
const STATUS_NAMES = { 0: "VALID", 1: "INVALID", 2: "SUSPENDED" };
const FLOOR = 30;

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

function b64uJson(segment) {
  log.debug("Entering b64uJson().");
  log.debug("Leaving b64uJson().");
  return JSON.parse(Buffer.from(String(segment), "base64url").toString());
}

function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  log.debug("Leaving payloadOf().");
  return b64uJson(String(jwt).split(".")[1]);
}

// ---------------------------------------------------------------------------
// HTTP: a browser is a cookie jar; `/admin-api` is reached with the run's
// preload attaching its token.
// ---------------------------------------------------------------------------
function jar(seed) {
  log.debug("Entering jar().");
  const cookies = {};
  String(seed || "").split(/;\s*/).forEach(function (pair) {
    const eq = pair.indexOf("=");
    if (eq > 0) {
      cookies[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
    }
  });
  log.debug("Leaving jar().");
  return {
    header: function header() {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(cookies).map(function (k) {
        return k + "=" + cookies[k];
      }).join("; ");
    },
    take: function take(response) {
      log.debug("Entering take().");
      const set = typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie() : [];
      set.forEach(function (line) {
        const pair = line.split(";")[0];
        const eq = pair.indexOf("=");
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        if (/Max-Age=0/i.test(line) || value === "") {
          delete cookies[name];
        } else {
          cookies[name] = value;
        }
      });
      log.debug("Leaving take().");
      return set;
    }
  };
}

async function hop(who, method, url, opts) {
  log.debug("Entering hop(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  let body;
  if (o.form) {
    body = new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (who && who.header()) {
    headers.cookie = who.header();
  }
  const r = await fetch(url, { method: method, headers: headers, body: body,
                               redirect: "manual" });
  if (who) {
    who.take(r);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in hop(): " + ((e && e.message) || e));
    // Not JSON — a page or a token; the caller reads `text`.
    json = null;
  }
  const location = r.headers.get("location") || "";
  log.debug("Leaving hop(). " + r.status);
  return { status: r.status, text: text, json: json,
           type: r.headers.get("content-type") || "",
           location: location ? new URL(location, url).toString() : "" };
}

async function ok(url, payload, what) {
  log.debug("Entering ok(). " + what);
  const r = await hop(null, "POST", url, { json: payload || {} });
  assert.ok(r.status === 200 && (!r.json || r.json.ok !== false),
            what + ": POST " + url + " answered " + r.status + " " +
            r.text.slice(0, 400));
  log.info("  " + what);
  log.debug("Leaving ok().");
  return r.json || {};
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  await ok(api + "/config/set", { key: key, value: value },
           "set " + key + " in the realm");
  log.debug("Leaving setting().");
}

// The realm's audit rows carrying an error code.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await hop(null, "GET", api + "/audit?per=500&code=" +
                      encodeURIComponent(code));
  const body = r.json && typeof r.json === "object" ? r.json : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

// The holder's `session.start` rows, optionally only those not in `before`
// (an earlier answer of this function), told apart by `seq`.
async function sessionRows(before) {
  log.debug("Entering sessionRows().");
  const r = await hop(null, "GET", api + "/audit?per=500");
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
// note): its `protocol` cannot tell SIOPv2 from a presentation (#667).
function notesOf(rows) {
  log.debug("Entering notesOf().");
  log.debug("Leaving notesOf().");
  return rows.map(function (row) {
    return String((row.detail || {}).note || "");
  });
}

// Whether a session note says the sign-in was a self-issued ID Token signed
// by `subject`. AN AUDIT ROW SHORTENS A LONG NOTE (`common/audit.js`: the
// text cut, then "… (N characters)"), and a did:jwk alone is longer than
// the cut, so a shortened note is compared as far as it goes.
function namesSignedBy(note, subject) {
  log.debug("Entering namesSignedBy().");
  const full = "A self-issued ID Token signed by " + subject;
  const shown = String(note).replace(/… \(\d+ characters\)$/, "");
  const cut = shown !== String(note);
  log.debug("Leaving namesSignedBy(). cut=" + cut);
  return shown.indexOf(full) === 0 ||
         (cut && shown.length > 60 && full.indexOf(shown) === 0);
}

// A TOKEN STATUS LIST (draft-ietf-oauth-status-list), read as a relying
// party reads it: the `statuslist+jwt` the reference names, its
// `status_list.lst` inflated (zlib) and each index's `bits` read least
// significant first.
async function statusesAt(uri, indices) {
  log.debug("Entering statusesAt(). " + uri);
  const r = await hop(null, "GET", uri, { headers: {
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
  return { typ: header.typ, type: r.type, sub: payload.sub, statuses: out };
}

// Until every index reads `want`, or the bound: a revocation may reach the
// publishing process a moment after the Remove's answer (another worker,
// another node).
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
// THE WALLET: `oid4vc-wallet`, one command at a time, in a HOME of its own.
// ---------------------------------------------------------------------------

// The anchor this run trusts the service with (`tools/run-report.js` writes
// it and names it in NODE_EXTRA_CA_CERTS).
function serviceAnchor() {
  log.debug("Entering serviceAnchor().");
  const file = process.env.STS_OID4VC_WALLET_CA ||
               process.env.NODE_EXTRA_CA_CERTS || "";
  assert.ok(file && fs.existsSync(file), "no anchor for the service's " +
            "certificate: NODE_EXTRA_CA_CERTS is " +
            JSON.stringify(process.env.NODE_EXTRA_CA_CERTS || "") +
            " (the runner sets it; a hand run sets STS_OID4VC_WALLET_CA)");
  log.debug("Leaving serviceAnchor(). " + file);
  return file;
}

function newWallet() {
  log.debug("Entering newWallet().");
  assert.ok(fs.existsSync(WALLET_BIN), "the native wallet is not at " +
            WALLET_BIN + " — tests/Dockerfile's oid4vc-wallet stage puts " +
            "it there; a hand run sets STS_OID4VC_WALLET_BIN");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "oid4vc-wallet-694-"));
  // AN ENVIRONMENT WRITTEN FROM NOTHING, not the runner's minus a few
  // names: whatever is not here — DBUS_SESSION_BUS_ADDRESS, DISPLAY, the
  // runner's own XDG directories — the wallet cannot reach, so its storage
  // key goes to the file and nowhere else, and its files to this HOME.
  const env = {
    PATH: process.env.PATH || "/usr/bin:/bin",
    HOME: home,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    XDG_DATA_HOME: path.join(home, ".local", "share"),
    XDG_STATE_HOME: path.join(home, ".local", "state"),
    XDG_CACHE_HOME: path.join(home, ".cache"),
    LANG: "C.UTF-8",
    OID4VC_WALLET_KEY_FILE: path.join(home, "storage.key"),
    SSL_CERT_FILE: serviceAnchor()
  };
  const run = function run(args) {
    log.debug("Entering run(). " + args[0]);
    return new Promise(function (resolve) {
      childProcess.execFile(WALLET_BIN, args,
        { env: env, timeout: WALLET_TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 },
        function (err, stdout, stderr) {
          const code = err ? (typeof err.code === "number" ? err.code : -1)
                           : 0;
          let json = null;
          try {
            json = JSON.parse(String(stdout).trim());
          } catch (e) {
            log.debug("Caught in run(): " + ((e && e.message) || e));
            // Not JSON: the command failed before it printed its answer,
            // and its stderr says why; the caller asserts on `code`.
            json = null;
          }
          log.info("  oid4vc-wallet " + args[0] + " exited " + code +
                   (stderr ? " — " + String(stderr).trim().slice(0, 400)
                           : ""));
          log.debug("Leaving run(). " + code);
          resolve({ code: code, json: json, stdout: String(stdout),
                    stderr: String(stderr) });
        });
    });
  };
  log.debug("Leaving newWallet(). " + home);
  return {
    home: home,
    run: run,
    stop: function stop() {
      log.debug("Entering stop().");
      try {
        fs.rmSync(home, { recursive: true, force: true });
      } catch (e) {
        log.debug("Caught in stop(): " + ((e && e.message) || e));
        // A temporary directory left behind is not a failure of the run.
      }
      log.debug("Leaving stop().");
    }
  };
}

// `self-issued --subject <s> --json`: the subject a sign-in would send.
async function subjectOf(wallet, subject) {
  log.debug("Entering subjectOf(). " + subject);
  const r = await wallet.run(["self-issued", "--subject", subject, "--json"]);
  assert.ok(r.code === 0 && r.json && r.json.subject, "self-issued " +
            subject + " answered " + r.code + " " + r.stdout.slice(0, 300) +
            " " + r.stderr.slice(0, 300));
  log.debug("Leaving subjectOf(). " + r.json.subject);
  return r.json;
}

// `present <uri> --approve|--refuse [--subject s] --json`.
async function present(wallet, uri, approve, subject) {
  log.debug("Entering present().");
  const args = ["present", uri, approve ? "--approve" : "--refuse", "--json"];
  if (subject) {
    args.push("--subject", subject);
  }
  const r = await wallet.run(args);
  log.info("  the wallet says: " + JSON.stringify(r.json ||
                                                  r.stdout.slice(0, 300)));
  log.debug("Leaving present(). " + r.code);
  return r;
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
// THE SIGN-IN SURFACE, AS THE PERSON'S BROWSER DRIVES IT.
// ---------------------------------------------------------------------------

// A wallet transaction started from the browser `who` — `query` is
// `wallet_signin.start()`'s (`authn`, `siop`, `enrol`, `did_act`) — handed to
// the wallet as the wait page hands it (`view.sameDevice`), the wallet's
// answer given, and the redirect it prints followed back in `who`: the wait
// page's collection. Answers { door, said, collected }.
async function throughTheWallet(wallet, who, query, approve, subject) {
  log.debug("Entering throughTheWallet().");
  const started = await walletSignin.start(base, who, query);
  assert.strictEqual(started.door.status, 303, "the wallet transaction " +
                     "did not start: " + started.door.status + " " +
                     String(started.door.text).slice(0, 300));
  assert.ok(started.view && started.view.sameDevice, "the wait page hands " +
            "the wallet nothing: " + String(started.waiting &&
                                            started.waiting.text)
                                       .slice(0, 300));
  const said = await present(wallet, started.view.sameDevice, approve,
                             subject);
  const back = said.json && said.json.redirect_uri;
  const collected = await walletSignin.collect(base, who,
                                               back || started.waitUrl);
  log.debug("Leaving throughTheWallet(). " + collected.status);
  return { door: started.door, started: started, said: said,
           collected: collected };
}

// A relying party's sign-in through the screen's wallet option (`siop` for
// the self-issued one), answered by the wallet, followed to the code and
// the code redeemed. Answers { said, collected, tokens }.
async function signIn(wallet, siop, approve, subject) {
  log.debug("Entering signIn(). siop=" + !!siop);
  const who = jar();
  const verifier = crypto.randomBytes(32).toString("base64url");
  const authorized = await hop(who, "GET", base + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, scope: "openid",
      // FRESH PER REQUEST: RFC 9700 section 2.1.1 (product mode) refuses a
      // nonce a redeemed code already carried.
      state: crypto.randomBytes(12).toString("base64url"),
      nonce: crypto.randomBytes(12).toString("base64url"),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256" }).toString());
  const authnId = new URL(authorized.location || base, base).searchParams
    .get("authn") || "";
  await hop(who, "GET", authorized.location);
  const query = { authn: authnId };
  if (siop) {
    query.siop = "1";
  }
  const out = await throughTheWallet(wallet, who, query, approve, subject);
  let at = out.collected.status === 303 ? out.collected.location : "";
  for (let n = 0; n < 6 && at && at.indexOf(root) === 0 &&
                  !consentScreen.isConsentScreen(at); n += 1) {
    at = (await hop(who, "GET", at)).location;
  }
  if (at) {
    const settled = await consentScreen.settleAuthorization({
      base: base, location: at, cookie: who.header() });
    at = settled.location || at;
  }
  const code = at && at.indexOf(REDIRECT_URI) === 0
    ? new URL(at).searchParams.get("code") : null;
  const tokens = code ? await hop(null, "POST", base + "/oauth2/token", {
    form: { grant_type: "authorization_code", code: code,
            redirect_uri: REDIRECT_URI, client_id: CLIENT_ID,
            code_verifier: verifier } }) : null;
  log.debug("Leaving signIn(). code=" + !!code);
  return { said: out.said, collected: out.collected, tokens: tokens,
           landed: at };
}

function idTokenSub(signedIn) {
  log.debug("Entering idTokenSub().");
  assert.ok(signedIn.tokens, "no code reached the relying party: " +
            signedIn.collected.status + " " +
            String(signedIn.collected.text).slice(0, 300) + " / " +
            signedIn.landed);
  assert.strictEqual(signedIn.tokens.status, 200,
                     signedIn.tokens.text.slice(0, 300));
  log.debug("Leaving idTokenSub().");
  return String(payloadOf(signedIn.tokens.json.id_token).sub);
}

// ---------------------------------------------------------------------------
// THE SECTIONS.
// ---------------------------------------------------------------------------
async function prepare() {
  log.debug("Entering prepare().");
  const product = await facts.isProduct(serviceRoot + "/admin-api");
  log.info("=== 0. a throwaway realm " + REALM + " (" +
           (product ? "product" : "development") + ") ===");
  await ok(serviceRoot + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "native wallet " + STAMP },
    "created the realm");
  // ITS OWN BASE, PINNED (dottedRoot(), above), in both modes: product
  // mints a DID only on a pinned base (#1291), and every address the realm
  // hands the wallet — its issuer, its Verifier's request and response — is
  // then on the name the wallet will accept in a did:web.
  await setting("global.publicBaseUrl", root);
  // The portal's seeded client was registered when the realm was made, on
  // the starting value, and a pinned base learns nothing: its callback is
  // registered here, as an operator standing a realm up would
  // (`sts_admin_client_policies.js`'s reason).
  await ok(api + "/applications/add",
           { application: "sts-user-portal", attribute: "oauthRedirectUri",
             value: base + "/portal/callback" },
           "registered the realm portal's callback on its pinned base");
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason:
  // this job's browser is node's fetch, which no risk model should be asked
  // to like.
  await setting("risk.assessSignIns", false);
  await setting("oid4vp.signIn", true);
  await setting("oid4vp.signInSelfIssued", true);
  await setting("did.personPublishing", true);
  await registry.provision(mgmtBase, {
    identifier: CLIENT_ID, name: "#694 relying party",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: CLIENT_ID,
              oauthGrantType: ["authorization_code"],
              oauthTokenEndpointAuthMethod: "none",
              oauthConfidential: "FALSE",
              oauthRedirectUri: [REDIRECT_URI],
              oauthResponseType: ["code"],
              oauthScope: ["openid"], oauthAllowedScope: ["openid"] },
    why: "the relying party sts_oid4vc_wallet.js signs its holder in for"
  });
  await registry.ensurePerson(mgmtBase, HOLDER, PASSWORD);
  const signedIn = await registry.authorizationCode(base, {
    clientId: CLIENT_ID, redirectUri: REDIRECT_URI, username: HOLDER,
    password: PASSWORD, scope: "openid" });
  const browser = jar(signedIn.cookie);
  const portal = await portalSignin.signInToThePortal(base, HOLDER, null,
    { cookie: browser.header() });
  const batch = Number(await facts.setting(api, "oid4vci.batchSize")) || 1;
  log.debug("Leaving prepare(). batch=" + batch);
  return { product: product, browser: browser, portal: portal,
           batch: batch };
}

async function acceptOffer(wallet, state) {
  log.debug("Entering acceptOffer().");
  log.info("=== 1. an offer on /portal/wallet, accepted by the wallet ===");
  const made = await state.portal.act("/portal/wallet",
    { configuration: CONFIGURATION, mode: "cross-device" });
  assert.ok(made.status === 200 && made.json && made.json.offer,
            "the portal's offer: " + made.status + " " +
            String(made.text).slice(0, 300));
  const offer = made.json.offer;
  const uri = String((offer.byValue || {}).offerUri || "");
  check("the portal answers an offer by value, and its Transaction Code " +
        "beside it", function () {
    assert.ok(uri.indexOf("openid-credential-offer://?credential_offer=") ===
              0, uri.slice(0, 200));
    assert.ok(/^\d{4,12}$/.test(String(offer.txCode)), offer.txCode);
  });
  const accepted = await wallet.run(["accept", uri, "--tx-code",
                                     String(offer.txCode), "--json"]);
  const stored = Array.isArray(accepted.json) ? accepted.json : [];
  check("accept redeems the offer and stores the batch, " + state.batch +
        " copies (oid4vci.batchSize)", function () {
    assert.strictEqual(accepted.code, 0, accepted.stderr.slice(0, 600));
    assert.strictEqual(stored.length, state.batch,
                       JSON.stringify(stored).slice(0, 600));
    stored.forEach(function (one) {
      assert.strictEqual(one.format, "dc+sd-jwt", JSON.stringify(one)
        .slice(0, 300));
      assert.strictEqual(one.issuer, base, one.issuer);
    });
  });
  const listed = await wallet.run(["credentials", "--json"]);
  check("the wallet's own list holds the same copies", function () {
    assert.strictEqual(listed.code, 0, listed.stderr.slice(0, 300));
    const ids = JSON.stringify(listed.json);
    stored.forEach(function (one) {
      assert.ok(ids.indexOf(one.id) >= 0, one.id + " not in " +
                ids.slice(0, 400));
    });
  });
  const copies = stored.map(function (one) {
    const claims = issuerClaims(one.document);
    const ref = ((claims.payload.status || {}).status_list) || {};
    return { walletId: one.id, typ: claims.header.typ,
             vct: claims.payload.vct, idx: Number(ref.idx),
             uri: String(ref.uri || "") };
  });
  log.info("  copies: " + JSON.stringify(copies));
  check("each copy names its own index in this realm's Token Status List",
        function () {
    copies.forEach(function (c) {
      assert.strictEqual(c.typ, "dc+sd-jwt", JSON.stringify(c));
      assert.ok(Number.isInteger(c.idx) && c.idx >= 0, JSON.stringify(c));
      assert.ok(c.uri.indexOf(base + "/") === 0, c.uri);
      assert.strictEqual(c.uri, copies[0].uri);
    });
    assert.strictEqual(new Set(copies.map(function (c) {
      return c.idx;
    })).size, copies.length, JSON.stringify(copies));
  });
  const indices = copies.map(function (c) {
    return c.idx;
  });
  const fresh = await statusesAt(copies[0].uri, indices);
  check("the published list is a statuslist+jwt and every copy is VALID",
        function () {
    assert.strictEqual(fresh.typ, "statuslist+jwt");
    assert.strictEqual(fresh.sub, copies[0].uri);
    indices.forEach(function (idx) {
      assert.strictEqual(fresh.statuses[idx], 0, "index " + idx + " is " +
                         STATUS_NAMES[fresh.statuses[idx]]);
    });
  });
  const page = await state.portal.page("/portal/wallet");
  const issued = ((page.json || {}).issued || [])[0] || {};
  const portalIndices = (issued.copies || []).map(function (c) {
    return Number(c.statusIndex);
  }).sort(function (a, b) {
    return a - b;
  });
  check("/portal/wallet lists the issuance with one copy per index the " +
        "wallet's copies name", function () {
    assert.deepStrictEqual(portalIndices, indices.slice().sort(
      function (a, b) {
        return a - b;
      }), JSON.stringify(issued).slice(0, 600));
  });
  log.debug("Leaving acceptOffer().");
  return { uri: copies[0].uri, indices: indices, issuanceId: issued.id };
}

async function presentationApproved(wallet, state, issued) {
  log.debug("Entering presentationApproved().");
  log.info("=== 2. an OpenID4VP sign-in, approved ===");
  const before = await sessionRows();
  const signedIn = await signIn(wallet, false, true);
  check("present --approve answers the Verifier and prints the way back",
        function () {
    assert.strictEqual(signedIn.said.code, 0, signedIn.said.stderr
      .slice(0, 400));
    assert.strictEqual(signedIn.said.json.ok, true);
    assert.ok(signedIn.said.json.redirect_uri, JSON.stringify(
      signedIn.said.json));
  });
  const sub = idTokenSub(signedIn);
  // THE HOLDER'S urn:uuid, as this first sign-in names them: every later
  // sign-in is compared with it.
  check("the relying party's ID Token names a person by urn:uuid",
        function () {
    assert.ok(/^urn:uuid:/.test(sub), sub);
  });
  const notes = notesOf(await sessionRows(before));
  check("one session, from a verified presentation of the credential this " +
        "realm issued", function () {
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
  log.debug("Leaving presentationApproved().");
  return sub;
}

async function presentationRefused(wallet) {
  log.debug("Entering presentationRefused().");
  log.info("=== 3. an OpenID4VP sign-in, refused in the wallet ===");
  const before = await sessionRows();
  const refused = await signIn(wallet, false, false);
  check("present --refuse tells the Verifier, and exits as asked",
        function () {
    assert.strictEqual(refused.said.code, 0, refused.said.stderr
      .slice(0, 400));
    assert.strictEqual(refused.said.json.answered, true,
                       JSON.stringify(refused.said.json));
  });
  check("no code reaches the relying party", function () {
    assert.strictEqual(refused.tokens, null, refused.landed);
  });
  const signedIn = await sessionRows(before);
  check("nobody was signed in by the refusal", function () {
    assert.strictEqual(signedIn.length, 0,
                       JSON.stringify(notesOf(signedIn)));
  });
  log.debug("Leaving presentationRefused().");
}

async function enrol(wallet, state, subject, query) {
  log.debug("Entering enrol(). " + subject);
  const q = Object.assign({ siop: "1", enrol: "1" }, query || {});
  const out = await throughTheWallet(wallet, state.browser, q, true,
                                     subject);
  log.debug("Leaving enrol(). " + out.collected.status);
  return out;
}

async function enrolled(state) {
  log.debug("Entering enrolled().");
  const page = await state.portal.page("/portal/self-issued");
  assert.strictEqual(page.status, 200, String(page.text || "")
    .slice(0, 300));
  log.debug("Leaving enrolled().");
  return ((page.json || {}).subjects || []).map(function (one) {
    return one.subject;
  });
}

async function selfIssued(wallet, state, sub) {
  log.debug("Entering selfIssued().");
  log.info("=== 4. self-issued IDs: a JWK thumbprint, did:jwk, did:key ===");
  const kinds = [
    { flag: "jwk", type: "jkt", prefix: JWK_THUMBPRINT_URI },
    { flag: "did:jwk", type: "did", prefix: "did:jwk:" },
    { flag: "did:key", type: "did", prefix: "did:key:z" }];
  const subjects = {};
  for (const kind of kinds) {
    const told = await subjectOf(wallet, kind.flag);
    subjects[kind.flag] = told.subject;
    const out = await enrol(wallet, state, kind.flag);
    const now = await enrolled(state);
    check("the " + kind.flag + " subject self-issued prints is enrolled by " +
          "the wallet's answer to the enrolment request", function () {
      assert.ok(told.subject.indexOf(kind.prefix) === 0, told.subject);
      assert.strictEqual(out.collected.status, 303,
                         String(out.collected.text).slice(0, 300));
      assert.ok(/\/portal\/self-issued\?enrolled=1/.test(
        out.collected.location), out.collected.location);
      assert.ok(now.indexOf(told.subject) >= 0, JSON.stringify(now));
    });
    const before = await sessionRows();
    const signedIn = await signIn(wallet, true, true, kind.flag);
    const got = idTokenSub(signedIn);
    const notes = notesOf(await sessionRows(before));
    check("the " + kind.flag + " subject signs the holder in over SIOPv2",
          function () {
      assert.strictEqual(got, sub);
      assert.strictEqual(notes.length, 1, JSON.stringify(notes));
      assert.ok(namesSignedBy(notes[0], told.subject), notes[0]);
    });
  }
  check("the three subjects are three names of the wallet's one key",
        function () {
    const thumbprint = subjects.jwk.slice(JWK_THUMBPRINT_URI.length);
    const jwk = JSON.parse(Buffer.from(subjects["did:jwk"]
      .slice("did:jwk:".length), "base64url").toString());
    const mine = crypto.createHash("sha256").update(JSON.stringify(
      { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
      .digest("base64url");
    assert.strictEqual(mine, thumbprint, JSON.stringify(jwk));
  });

  log.info("  the thumbprint removed on /portal/self-issued, then refused");
  const removed = await state.portal.act("/portal/self-issued",
    { action: "remove", subject: subjects.jwk });
  check("Remove takes the thumbprint off the list", function () {
    assert.ok(removed.status === 200 && removed.json &&
              removed.json.ok !== false, String(removed.text).slice(0, 300));
  });
  const left = await enrolled(state);
  check("the thumbprint is no longer listed, the two DIDs still are",
        function () {
    assert.ok(left.indexOf(subjects.jwk) < 0, JSON.stringify(left));
    assert.ok(left.indexOf(subjects["did:jwk"]) >= 0, JSON.stringify(left));
    assert.ok(left.indexOf(subjects["did:key"]) >= 0, JSON.stringify(left));
  });
  const refusedBefore = await codeCount("STS-VC-0091");
  const before = await sessionRows();
  const refused = await signIn(wallet, true, true, "jwk");
  const refusedAfter = await codeCount("STS-VC-0091");
  const signedIn = await sessionRows(before);
  check("the removed thumbprint signs nobody in, recorded under " +
        "STS-VC-0091", function () {
    assert.strictEqual(refused.tokens, null, refused.landed);
    assert.strictEqual(signedIn.length, 0,
                       JSON.stringify(notesOf(signedIn)));
    assert.ok(refusedAfter > refusedBefore, refusedAfter + " / " +
              refusedBefore);
  });
  log.debug("Leaving selfIssued().");
  return subjects;
}

async function publishedDids() {
  log.debug("Entering publishedDids().");
  const r = await hop(null, "GET", api + "/users/published-dids?user=" +
                      encodeURIComponent(HOLDER));
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving publishedDids().");
  return r.json.dids || [];
}

async function didWeb(wallet, state, sub, subjects) {
  log.debug("Entering didWeb().");
  log.info("=== 5. a did:web this realm publishes, its key in the wallet ===");
  await setting("did.personCustody", "wallet");
  const made = await enrol(wallet, state, "did:jwk", { did_act: "publish" });
  const mine = (await publishedDids()).filter(function (one) {
    return one.custody === "wallet" && one.state === "active";
  })[0] || {};
  const thumbprint = subjects.jwk.slice(JWK_THUMBPRINT_URI.length);
  check("the wallet's answer to did_act=publish publishes a did:web whose " +
        "version 1 is the wallet's key", function () {
    assert.strictEqual(made.collected.status, 303,
                       String(made.collected.text).slice(0, 300));
    assert.ok(/\/portal\/self-issued\?did=published/.test(
      made.collected.location), made.collected.location);
    assert.strictEqual(String(mine.did).split(":realm:")[0], "did:web:" +
      new URL(root).host.replace(/:/g, "%3A"), JSON.stringify(mine));
    assert.strictEqual(mine.versions[0].keys[0].id, thumbprint,
                       JSON.stringify(mine.versions));
  });
  const told = await subjectOf(wallet, mine.did);
  const doc = await hop(null, "GET", told.did_document_url || "");
  check("self-issued names the did:web, and the realm serves its document " +
        "where the wallet says it must be, naming the same key", function () {
    assert.strictEqual(told.subject, mine.did);
    assert.strictEqual(told.did_document_url, base + "/users/" + mine.rid +
                       "/did.json");
    assert.strictEqual(doc.status, 200, doc.text.slice(0, 300));
    assert.deepStrictEqual(doc.json.authentication,
                           [mine.did + "#" + thumbprint]);
  });
  const before = await sessionRows();
  const signedIn = await signIn(wallet, true, true, mine.did);
  const got = idTokenSub(signedIn);
  const notes = notesOf(await sessionRows(before));
  check("the did:web signs the holder in over SIOPv2", function () {
    assert.strictEqual(got, sub);
    assert.strictEqual(notes.length, 1, JSON.stringify(notes));
    assert.ok(namesSignedBy(notes[0], mine.did), notes[0]);
  });
  log.debug("Leaving didWeb().");
}

async function revoked(wallet, state, issued) {
  log.debug("Entering revoked().");
  log.info("=== 6. Remove all on /portal/wallet, and the copy refused ===");
  const removed = await state.portal.act("/portal/remove-wallet-credential",
                                         { id: issued.issuanceId });
  check("Remove all revokes every copy of the issuance", function () {
    assert.ok(removed.status === 200 && removed.json, String(removed.text)
      .slice(0, 300));
    assert.strictEqual(removed.json.scope, "issuance");
    assert.strictEqual(removed.json.removed, issued.indices.length);
  });
  const seen = await statusesBecome(issued.uri, issued.indices, 1);
  check("every copy's index went from VALID to INVALID", function () {
    issued.indices.forEach(function (idx) {
      assert.strictEqual(seen.statuses[idx], 1, "index " + idx + " is " +
                         STATUS_NAMES[seen.statuses[idx]]);
    });
  });
  // THE WALLET READS NO STATUS LIST, so it still presents a copy, and the
  // Verifier is the one that refuses it.
  const refusedBefore = await codeCount("STS-VC-0072");
  const before = await sessionRows();
  const refused = await signIn(wallet, false, true);
  const refusedAfter = await codeCount("STS-VC-0072");
  const signedIn = await sessionRows(before);
  check("the wallet presents a revoked copy and the Verifier refuses it, " +
        "recorded under STS-VC-0072", function () {
    // What the wallet reports: it answered, the Verifier did not accept it
    // (OpenID4VP's 400 at the response endpoint, with no way back), and the
    // command fails as a presentation that did not go through.
    const said = refused.said.json || {};
    assert.strictEqual(refused.said.code, 2, refused.said.stderr
      .slice(0, 300));
    assert.ok(said.answered === true && said.ok === false &&
              !said.redirect_uri && /HTTP 400/.test(said.message),
              JSON.stringify(said));
    assert.strictEqual(refused.tokens, null, refused.landed);
    assert.ok(refusedAfter > refusedBefore, refusedAfter + " / " +
              refusedBefore);
  });
  check("nobody was signed in by the revoked copy", function () {
    assert.strictEqual(signedIn.length, 0,
                       JSON.stringify(notesOf(signedIn)));
  });
  log.debug("Leaving revoked().");
}

async function test() {
  log.debug("Entering test().");
  const wallet = newWallet();
  try {
    const version = await wallet.run(["--version", "--json"]);
    log.info("The native wallet: " + WALLET_BIN + " " +
             (version.stdout || "").trim().slice(0, 200));
    const state = await prepare();
    const issued = await acceptOffer(wallet, state);
    const sub = await presentationApproved(wallet, state, issued);
    await presentationRefused(wallet);
    const subjects = await selfIssued(wallet, state, sub);
    await didWeb(wallet, state, sub, subjects);
    await revoked(wallet, state, issued);
  } finally {
    wallet.stop();
  }
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; the floor " +
            "is " + FLOOR);
  log.info("Test completed successfully. " + checks + " check(s) passed. " +
           "Realm " + REALM + " and " + HOLDER + " are left in place.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_oid4vc_wallet FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
