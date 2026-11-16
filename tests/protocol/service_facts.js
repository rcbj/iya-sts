// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: service_facts.js
//
// ---------------------------------------------------------------------------
// WHAT THE SERVICE UNDER TEST ACTUALLY IS, ASKED RATHER THAN ASSUMED
// (2026-09-18).
//
// Jobs wrote down what a development stack is — `EXAMPLE.COM`, the KDC's one
// shared password, a mode where nothing is checked — and were right for as long
// as that was the only thing they ran against. The suite runs against deployed
// services now (deploy/aws/run-suite.sh; testidp is PRODUCT mode, with its own
// Kerberos realm and base DN), and a job that guesses those facts fails with a
// message about the guess. So a job asks: every effective setting is on
// `GET /admin-api/config`, in the realm the given API base names.
//
// A LOCAL HELPER (tests/vendored/MANIFEST.js), owned here. The /admin-api token
// is attached by the runner (tests/tools/attach-admin-token.js).
// ---------------------------------------------------------------------------
const log = require("bunyan").createLogger({ name: "service_facts",
  level: process.env.LOG_LEVEL || "info" });

const cache = {};

// A SENSITIVE PARAMETER IS MASKED ON `GET /admin-api/config` (#1478), and these
// are the development fixtures a job signs in or derives keys with. A
// deployment that changes one is product mode, where no job reads them.
const MASKED_FIXTURES = {
  "krb5.userPassword": "password!",
  "krb5.servicePassword": "service-account-password",
  "krb5.autoServicePassword": "auto-service-password",
  "krb5.krbtgtPassword": "krbtgt-mock-password",
  "scim.digestPassword": "password!"
};

// Every setting of the realm `apiBase` (…/admin-api or …/realm/x/admin-api)
// names, as { key: value }. Read once per API base per process.
async function settings(apiBase) {
  log.debug("Entering settings(). " + apiBase);
  if (!cache[apiBase]) {
    const r = await fetch(apiBase + "/config",
                          { headers: { Accept: "application/json" } });
    if (r.status !== 200) {
      log.debug("Leaving settings(). Refused.");
      throw new Error("GET " + apiBase + "/config answered " + r.status +
                      "; a job cannot tell what the service is without it.");
    }
    const body = await r.json();
    const out = {};
    (body.groups || []).forEach(function (group) {
      (group.settings || []).forEach(function (row) {
        out[row.key] = row.masked ? MASKED_FIXTURES[row.key] : row.value;
      });
    });
    cache[apiBase] = out;
  }
  log.debug("Leaving settings().");
  return cache[apiBase];
}

async function setting(apiBase, key) {
  log.debug("Entering setting(). " + key);
  const all = await settings(apiBase);
  log.debug("Leaving setting().");
  return all[key];
}

// `global.mode` is "product" — passwords are verified, nothing is invented,
// and the development test controls are refused.
async function isProduct(apiBase) {
  log.debug("Entering isProduct().");
  const mode = await setting(apiBase, "global.mode");
  log.debug("Leaving isProduct(). " + mode);
  return String(mode) === "product";
}

// ---------------------------------------------------------------------------
// A REALM'S MODE AS THE FRONT PROCESS SEES IT, WAITED FOR (GitHub Actions run
// 43884417831, mariadb mode).
//
// `config/set global.mode` is answered by a request worker, and the front
// process, which holds the socket, learns of it from the change log about a
// second later. Until then the front names the realm's cookies by the OLD
// mode (`common/cookie_wire.ts`): a development realm switched to product
// had a cookie written unprefixed on one answer, and the front, caught up,
// dropped it as unprefixed on the next. `sts_est_attestation_freshness`
// lost its nonce cookie ("The request carried no EST nonce cookie") and
// `sts_development_only_settings` its session cookie (the sign-in screen
// again instead of a code), each within a second of the switch.
//
// What the front decides there it decides at the same point for HSTS
// (`mode.omitsStrictTransportSecurity()` beside `mode.prefixesCookies()`, both
// `!isProduct()` of the realm the request is in), so a response's
// Strict-Transport-Security header is the front's view, observed. A job that
// switches a realm's mode and then drives a browser through it waits for that
// header to agree, three answers in a row (a cluster has a front per node).
//
// Bounded and NOT an assertion: a target behind an edge that ends TLS (the
// front never sends HSTS there) or adds its own header never agrees, and
// the job then runs as it did before this wait existed.
// ---------------------------------------------------------------------------
async function awaitFrontMode(realmBase, product, timeoutMs) {
  log.debug("Entering awaitFrontMode(). " + realmBase + " " + product);
  if (!/^https:/.test(String(realmBase))) {
    log.debug("Leaving awaitFrontMode(). Not over TLS: no HSTS to read.");
    return false;
  }
  const deadline = Date.now() + (timeoutMs || 15000);
  let agreed = 0;
  while (Date.now() < deadline) {
    let hsts = null;
    try {
      const r = await fetch(realmBase +
                            "/.well-known/openid-configuration");
      hsts = !!r.headers.get("strict-transport-security");
      await r.arrayBuffer();
    } catch (e) {
      log.debug("Caught in awaitFrontMode(): " + ((e && e.message) || e));
    }
    agreed = hsts === !!product ? agreed + 1 : 0;
    if (agreed >= 3) {
      log.debug("Leaving awaitFrontMode(). Agreed.");
      return true;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 200);
    });
  }
  log.info("awaitFrontMode(): the front process's answers at " + realmBase +
           " did not show " + (product ? "product" : "development") +
           " mode within " + (timeoutMs || 15000) + " ms; going on.");
  log.debug("Leaving awaitFrontMode(). Gave up.");
  return false;
}

module.exports = { settings: settings, setting: setting,
                   isProduct: isProduct, awaitFrontMode: awaitFrontMode };
