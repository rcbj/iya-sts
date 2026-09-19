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
        out[row.key] = row.value;
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

module.exports = { settings: settings, setting: setting,
                   isProduct: isProduct };
