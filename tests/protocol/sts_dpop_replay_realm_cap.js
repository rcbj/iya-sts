// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_dpop_replay_realm_cap.js
//
// ===========================================================================
// A REALM'S oauth2.dpopReplayCacheSize IS CONSULTED AT THE DPoP CHECK, IN A
// DISPATCHED WORKER (#1299).
//
// The #1299 fuzz run filled the DPoP replay history (STS-OAUTH-0554) about
// four minutes into every admin-api cell, in two realms at once, although each
// realm carried oauth2.dpopReplayCacheSize=200000 — a fill consistent with the
// cap in force being the process DEFAULT (10000), not the realm's override. The
// fuzz stack's process-env floor hides that: with the process value also raised,
// STS-OAUTH-0554 goes to zero whether or not the realm override is consulted, so
// the fuzz run cannot tell the two apart. If a worker is reading the PROCESS
// value rather than the ambient realm's, that is a product bug far beyond DPoP —
// a dispatched worker ignoring a per-realm runtime setting.
//
// So this proves it directly, through dispatched workers (the suite runs this in
// single-node and cluster, where /oauth2/token is answered by a request worker).
// It sets a LOW cap (100) on a realm of its own through config/set, leaving the
// PROCESS cap untouched, and sends distinct valid DPoP proofs past it: the realm
// starts refusing with STS-OAUTH-0554 at its own cap, not at 10000. A second
// realm left at the default goes on accepting well past 100 — so the low cap was
// the first realm's alone, which is the isolation half.
//
// The DPoP client is written HERE, not borrowed from the service or from
// tests/protocol/dpop.js, for sts_dpop.js's reason: a shared misunderstanding
// would make the test pass against a server nobody else can talk to. ES256 only
// — the point is distinct jti values filling the history, not algorithm breadth.
//
// local: true (MANIFEST): the setting, the per-realm store and the gate are this
// service's own. It needs no browser. The admin-api calls carry the run's token
// through the preloaded fetch shim (tests/tools/attach-admin-token.js), as every
// local job's do.
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

let appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  appconfigProblem = e;
  appconfig = {};
}
const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "sts_dpop_replay_realm_cap",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

// The low cap one realm carries. min is 100 (config.js), so this is the
// smallest a realm can be set to and the fastest to fill.
const LOW_CAP = 100;
// Enough past the low cap to see it refuse, and nowhere near the 10000 default,
// so the second realm (left at the default) accepts every one.
const MARGIN = 15;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    json = null;
  }
  log.debug("Leaving send().");
  return { status: r.status, headers: r.headers, text: text, json: json };
}

async function apiOk(url, body, what) {
  log.debug("Entering apiOk().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + url + " answered " + r.status + " " +
            r.text.slice(0, 400));
  log.debug("Leaving apiOk().");
  return r.json;
}

// --- A self-contained ES256 DPoP client ------------------------------------

function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64url");
}

// A fresh P-256 key, with ONLY the JWK members RFC 7638 names for EC in the
// thumbprint input, so the header the proof carries is the canonical one.
function newEcKey() {
  log.debug("Entering newEcKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  log.debug("Leaving newEcKey().");
  return { privateKey: pair.privateKey,
    publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}

// A DPoP proof for the token endpoint, with a FRESH jti each call (distinct
// jti values are what fill the realm's replay history). ES256.
function makeProof(key, htu, nonce) {
  log.debug("Entering makeProof().");
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: key.publicJwk };
  const payload = {
    jti: b64u(crypto.randomBytes(16)),
    htm: "POST",
    htu: String(htu).split("?")[0].split("#")[0],
    iat: Math.floor(Date.now() / 1000)
  };
  if (nonce) {
    payload.nonce = nonce;
  }
  const signingInput = b64u(JSON.stringify(header)) + "." +
    b64u(JSON.stringify(payload));
  const signature = crypto.sign("sha256",
    Buffer.from(signingInput, "ascii"),
    { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  log.debug("Leaving makeProof().");
  return signingInput + "." + b64u(signature);
}

// True when a token-endpoint answer is the replay-history-full refusal, by its
// OWN sentence (STS-OAUTH-0554 is recorded, never sent, so the code is not on
// the wire): a 400 invalid_dpop_proof whose description names the full history.
function isReplayFull(r) {
  log.debug("Entering isReplayFull().");
  const full = r.status === 400 && r.json &&
    r.json.error === "invalid_dpop_proof" &&
    /replay history|full of live proofs|remember another/i
      .test(String(r.json.error_description || ""));
  log.debug("Leaving isReplayFull(). " + full);
  return full;
}

// Sends one client_credentials token request carrying a fresh DPoP proof, and
// handles a single use_dpop_nonce challenge (off by default, but a realm could
// turn it on): the retry carries a fresh jti and so still fills the history by
// one. Returns { full } — whether the realm refused for a full replay history.
async function sendProof(tokenUrl, key, clientId, secret) {
  log.debug("Entering sendProof().");
  const form = function (over) {
    return new URLSearchParams(Object.assign({
      grant_type: "client_credentials", client_id: clientId,
      client_secret: secret }, over || {})).toString();
  };
  let r = await send(tokenUrl, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
      DPoP: makeProof(key, tokenUrl) },
    body: form() });
  if (r.status === 400 && r.json && r.json.error === "use_dpop_nonce") {
    const nonce = r.headers.get("DPoP-Nonce") || "";
    r = await send(tokenUrl, { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded",
        DPoP: makeProof(key, tokenUrl, nonce) },
      body: form() });
  }
  log.debug("Leaving sendProof(). " + r.status);
  return { full: isReplayFull(r), status: r.status, text: r.text };
}

// Creates a realm (optionally with a cap override) and a confidential client
// that may use client_credentials, and returns its token endpoint and client.
async function realmWithClient(id, capOverride) {
  log.debug("Entering realmWithClient(). " + id);
  const realmApi = base + "/realm/" + id + "/admin-api";
  const realmBase = base + "/realm/" + id;
  await apiOk(api + "/realms/create",
    { id: id, domain: id + ".example.net", name: "DPoP replay cap " + id },
    "created the realm " + id);
  if (typeof capOverride === "number") {
    // Through config/set — the runtime door a dispatched worker must honour,
    // not a create-time override — leaving the PROCESS cap untouched.
    await apiOk(realmApi + "/config/set",
      { key: "oauth2.dpopReplayCacheSize", value: capOverride },
      "set the realm's DPoP replay cap to " + capOverride);
  }
  const clientId = (id + "-client").slice(0, 40);
  const secret = "cap-secret-" + String(Date.now()).slice(-8) +
    "-0123456789abcdef0123456789abcdef";
  await apiOk(realmApi + "/applications/create", {
    identifier: clientId, kind: "oauth2-client", name: clientId,
    protocols: ["oauth2"],
    fields: { oauthClientId: [clientId], oauthClientSecret: secret,
      oauthGrantType: ["client_credentials"],
      oauthTokenEndpointAuthMethod: "client_secret_post" } },
    "registered the client in " + id);
  log.debug("Leaving realmWithClient(). " + id);
  return { tokenUrl: realmBase + "/oauth2/token", clientId: clientId,
    secret: secret };
}

// Sends `count` distinct proofs and returns the 1-based index of the first
// replay-history-full refusal, or 0 if none was refused for that reason.
async function fillUntilFull(where, count) {
  log.debug("Entering fillUntilFull(). " + count);
  const key = newEcKey();
  let firstFull = 0;
  for (let i = 1; i <= count; i++) {
    const r = await sendProof(where.tokenUrl, key, where.clientId,
      where.secret);
    if (r.full) {
      firstFull = i;
      log.info("  first STS-OAUTH-0554 at proof " + i);
      break;
    }
    // A proof that was refused for anything OTHER than a full history is a
    // harness fault, not a cap: the proof must be accepted (or the grant
    // answered) so its jti is stored. A 200 or a non-DPoP refusal is fine; a
    // DPoP refusal that is not fullness means the proof itself was rejected.
    if (r.status === 400 && /invalid_dpop_proof/.test(r.text)) {
      throw new Error("a proof was refused for a reason other than a full " +
        "history at " + where.tokenUrl + ": " + r.text.slice(0, 300));
    }
  }
  log.debug("Leaving fillUntilFull(). firstFull=" + firstFull);
  return firstFull;
}

async function test() {
  log.debug("Entering test().");
  log.info("Proving oauth2.dpopReplayCacheSize is per-realm at " + base);

  const slug = function (name) {
    return usernameFor(name).replace(/[^a-z0-9-]/g, "").slice(0, 30);
  };
  const lowId = slug("dpopcaplow");
  const defId = slug("dpopcapdef");

  // ===========================================================================
  // 1. A REALM WITH A LOW CAP REFUSES AT ITS OWN CAP, NOT THE PROCESS DEFAULT.
  // ===========================================================================
  const low = await realmWithClient(lowId, LOW_CAP);
  const firstFull = await fillUntilFull(low, LOW_CAP + MARGIN);
  check("the realm with oauth2.dpopReplayCacheSize=" + LOW_CAP +
    " refuses (STS-OAUTH-0554) once its OWN cap is reached, not the " +
    "process default of 10000 — so the dispatched worker read the realm's " +
    "override", function () {
    assert.ok(firstFull > 0, "no proof was refused for a full history in " +
      (LOW_CAP + MARGIN) + " proofs; the cap in force is not " + LOW_CAP +
      " (if it were the process default of 10000, this is the worker " +
      "IGNORING the per-realm setting — a product bug)");
    // The refusal lands at the realm's cap, not far above it. Starting from an
    // empty history, proofs 1..LOW_CAP store a jti each and proof LOW_CAP+1 is
    // refused; a small tolerance covers nothing but an internal proof.
    assert.ok(firstFull >= LOW_CAP - 5 && firstFull <= LOW_CAP + 3,
      "the first full-history refusal was at proof " + firstFull +
      ", not near the realm's cap of " + LOW_CAP);
  });

  // ===========================================================================
  // 2. A SECOND REALM AT THE DEFAULT GOES ON ACCEPTING PAST THE LOW CAP.
  // ===========================================================================
  const def = await realmWithClient(defId, null);
  const defFull = await fillUntilFull(def, LOW_CAP + MARGIN);
  check("a second realm with no override accepts well past " + LOW_CAP +
    " proofs — the low cap was the first realm's alone (per-realm " +
    "isolation)", function () {
    assert.strictEqual(defFull, 0,
      "the default-cap realm refused for a full history at proof " + defFull +
      "; its cap should be the process default (10000), far above " +
      (LOW_CAP + MARGIN) + " — the low cap leaked between realms");
  });

  assert.ok(checks >= 2, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_dpop_replay_realm_cap")
  .description("oauth2.dpopReplayCacheSize is a per-realm cap, consulted at " +
    "the DPoP replay check in a dispatched worker (STS-OAUTH-0554).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
    "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
