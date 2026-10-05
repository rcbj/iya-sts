// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oid4vci_preauth_subject.js
//
// ---------------------------------------------------------------------------
// AN OPENID4VCI PRE-AUTHORIZED CODE IS REDEEMED FOR A TOKEN ABOUT THE PERSON
// THE OFFER NAMED (#158, 2026-10-05), over the wire.
//
// A cross-device Credential Offer from `/issuer/offer?mode=cross-device`,
// redeemed at the token endpoint by a wallet that names no client (OID4VCI
// section 6.1's anonymous access), returned an access token with
// `"sub": ""` and `"client_id": ""` — both REQUIRED by RFC 9068 section 2.2,
// and the empty subject an anonymous token about a named person. The offer
// recorded whom it was for when it was MINTED, and in development that is
// `oid4vci.offerUsername`, who may have no entry yet.
//
// In a throwaway realm it leaves behind:
//
//   * development: `oid4vci.offerUsername` is a person with NO entry when the
//     offer is minted — the case that produced the empty `sub`; the entry
//     appears at redemption, and the token must carry its subject;
//   * product: the offer page requires a sign-on session and mints the offer
//     for the person signed in;
//
// and in both, the access token's `sub` is the `urn:uuid:` subject the same
// person's ID Token carries, and its `client_id` is the defined value for an
// anonymous wallet, never an empty string.
//
// OWNED HERE (local: true): this repository's credential issuer.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_oid4vci_preauth_subject",
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
const REALM = ("vci158-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const R = "/realm/" + REALM;
const base = root + R;
const api = base + "/admin-api";
const PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
// `oauth-oidc/oauth2.ts`'s ANONYMOUS_WALLET_CLIENT_ID.
const ANONYMOUS_WALLET = "urn:sts:oid4vci:anonymous-wallet";
const SECRET = "vci-158-" + nodeCrypto.randomBytes(9).toString("hex");
const CLIENT = "vci158-rp-" + STAMP.toLowerCase();
const REDIRECT = "https://rp.vci158.example.test/cb";
const PASSWORD = "Vci-158-" + nodeCrypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const HOLDER = names.usernameFor("v158-holder");
// A desktop browser's User-Agent, with this job's name on the end: product
// mode scores an automated client's first sign-in as a risk (#62).
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_oid4vci_preauth_subject/1.0 (" + STAMP + ")";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

function postForm(url, fields) {
  log.debug("Entering postForm().");
  log.debug("Leaving postForm().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(fields) });
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

// One browser, with a cookie jar.
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = { "User-Agent": AGENT };
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const url = /^https?:\/\//i.test(path) ? path : root + path;
      const r = await fetch(url, { method: method, redirect: "manual",
                                   headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Max-Age=0/i.test(String(one)) ||
            /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      const text = await r.text();
      const location = r.headers.get("location") || "";
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, text: text,
               location: location ? new URL(location, url).toString() : "" };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

// Follows redirects from `path`, signing in as HOLDER where the sign-in
// screen appears, until a page answers 200 or a redirect leaves for `stopAt`.
async function follow(b, path, stopAt) {
  log.debug("Entering follow(). " + path);
  let r = await b.go("GET", path);
  for (let n = 0; n < 16; n += 1) {
    if (stopAt && r.location.indexOf(stopAt) === 0) {
      break;
    }
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = HOLDER;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await b.go("POST", R + "/authn/login", form(fields));
      continue;
    }
    if (r.status !== 302 && r.status !== 303) {
      break;
    }
    r = await b.go("GET", r.location);
  }
  log.debug("Leaving follow(). " + r.status);
  return r;
}

function decode(token) {
  log.debug("Entering decode().");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(String(token).split(".")[1], "base64url")
    .toString("utf8"));
}

// A code flow for CLIENT in browser `b`, redeemed: the ID Token's claims.
async function idTokenOf(b) {
  log.debug("Entering idTokenOf().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const params = { response_type: "code", client_id: CLIENT,
    redirect_uri: REDIRECT, scope: "openid", state: "st",
    nonce: "n-" + nodeCrypto.randomBytes(6).toString("hex"),
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"), code_challenge_method: "S256" };
  const r = await follow(b, R + "/oauth2/authorize?" + form(params),
                         REDIRECT);
  const code = r.location.indexOf(REDIRECT) === 0
    ? new URL(r.location).searchParams.get("code") : "";
  assert.ok(code, "the code flow reaches the client: " + r.status + " " +
            r.location + " " + r.text.slice(0, 300));
  const redeemed = await postForm(base + "/oauth2/token", {
    grant_type: "authorization_code", code: code, redirect_uri: REDIRECT,
    client_id: CLIENT, client_secret: SECRET, code_verifier: verifier });
  assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 300));
  assert.ok(redeemed.body.id_token, "an ID Token: " +
            redeemed.raw.slice(0, 300));
  log.debug("Leaving idTokenOf().");
  return decode(redeemed.body.id_token);
}

// A cross-device offer from the realm's offer page in browser `b`: its
// pre-authorized code, and the Transaction Code the page shows the person
// (`oid4vc/vc_offers.ts`, renderOfferQrPage()).
async function crossDeviceOffer(b) {
  log.debug("Entering crossDeviceOffer().");
  const page = await follow(b, R + "/issuer/offer?mode=cross-device");
  assert.strictEqual(page.status, 200, "the offer page: " + page.status +
                     " " + page.location + " " + page.text.slice(0, 300));
  const decoded = page.text.replace(/&amp;/g, "&");
  const link = (decoded.match(/id="open_in_wallet" href="([^"]+)"/) ||
                [])[1] || "";
  const txCode = (decoded.match(/id="tx_code">([^<]*)</) || [])[1] || "";
  const carried = /[?&]credential_offer=([^&]+)/.exec(link);
  assert.ok(carried, "the offer page links the offer by value: " +
            link.slice(0, 300));
  const offer = JSON.parse(decodeURIComponent(carried[1]));
  const grant = (offer.grants || {})[PRE_AUTH] || {};
  assert.ok(grant["pre-authorized_code"], "the offer carries a " +
            "pre-authorized code: " + JSON.stringify(offer).slice(0, 400));
  log.debug("Leaving crossDeviceOffer().");
  return { code: grant["pre-authorized_code"], txCode: txCode };
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(root + "/admin-api");
  log.info("=== 0. a throwaway realm " + REALM + " (" +
           (product ? "product" : "development") + ") ===");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "OID4VCI 158 " + STAMP },
    "created the realm");
  await ok(api + "/applications/create", { identifier: CLIENT,
    kind: "oauth2-client", name: CLIENT, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["openid"],
              oauthRedirectUri: [REDIRECT],
              oauthGrantType: ["authorization_code"],
              oauthResponseType: ["code"] } },
    "created the relying party");
  await ok(api + "/consent/grant-global-consent",
           { client: CLIENT, scope: "openid" }, "consented openid");
  await ok(api + "/config/set", { key: "oid4vci.offerUsername",
                                  value: HOLDER },
           "made " + HOLDER + " the realm's offer username");

  const b = browser();
  let idToken = null;
  if (product) {
    log.info("=== 1. product: " + HOLDER + " signs in, then asks for the " +
             "offer ===");
    await ok(api + "/users/create", { username: HOLDER, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: "VCI " + HOLDER, givenName: "VCI", sn: "Holder",
                    mail: HOLDER + "@vci158.test" } }, "created " + HOLDER);
    idToken = await idTokenOf(b);
  } else {
    log.info("=== 1. development: the offer is minted for " + HOLDER +
             ", who has no entry yet ===");
  }
  const offer = await crossDeviceOffer(b);

  log.info("=== 2. an anonymous wallet redeems it ===");
  const redeemed = await postForm(base + "/oauth2/token", {
    grant_type: PRE_AUTH, "pre-authorized_code": offer.code,
    tx_code: offer.txCode });
  check("the pre-authorized code is redeemed with no client_id", function () {
    assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 400));
    assert.ok(redeemed.body && redeemed.body.access_token,
              redeemed.raw.slice(0, 400));
  });
  const access = decode(redeemed.body.access_token);
  if (!idToken) {
    idToken = await idTokenOf(b);
  }
  check("the access token's sub is a urn:uuid: subject, not empty",
        function () {
    assert.ok(/^urn:uuid:/i.test(String(access.sub || "")),
              JSON.stringify(access).slice(0, 600));
  });
  check("the access token's sub is the person's ID Token sub", function () {
    assert.strictEqual(access.sub, idToken.sub,
                       "access " + access.sub + " / ID Token " + idToken.sub);
  });
  check("the access token names the person the offer was made for",
        function () {
    assert.strictEqual(access.username, HOLDER,
                       JSON.stringify(access).slice(0, 600));
  });
  check("the access token's client_id is the anonymous wallet's defined " +
        "value, not an empty string", function () {
    assert.strictEqual(access.client_id, ANONYMOUS_WALLET,
                       JSON.stringify(access).slice(0, 600));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_oid4vci_preauth_subject FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
