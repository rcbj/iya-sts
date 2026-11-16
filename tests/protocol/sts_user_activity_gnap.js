// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_user_activity_gnap.js
//
// ---------------------------------------------------------------------------
// A PERSON'S PAGE SHOWS A GNAP GRANT THEY APPROVED, OVER THE WIRE.
//
// `sts_user_activity_every_mechanism.js`'s contract for GNAP (rcbj,
// 2026-11-16), in a job of its own because its access type is the TEST
// PEER's resource server (`gnap_flow.js`, `peer: true`) and a run with no
// peer — an AWS target — skips the whole job, which must not take the other
// mechanisms with it. In a throwaway development realm, one fresh person
// approves a redirect-interaction grant from an independent client instance
// (`gnap_client.js`), and `GET /admin-api/users?user=` then holds:
//
//   1. the sign-in at the interaction on the Authentication attempts tab;
//   2. the sign-on session it started on Sessions & tokens, with the GNAP
//      access token under it (a `jwt-signed` token is recorded with the
//      session it was approved on);
//   3. the grant on the GNAP grants tab (`gnapGrants`).
//
// OWNED HERE (local: true): this repository's console model of a person.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
const log = require("bunyan").createLogger({
  name: "sts_user_activity_gnap", level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("uamgnap").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const PASSWORD = "Uag-" + nodeCrypto.randomBytes(15).toString("base64url");
const h = require("./gnap_flow.js").harness({ base: base, realm: REALM,
                                              password: PASSWORD, log: log,
                                              peer: true });
// How long the page may take to show what was just done: the registers are
// written behind the request and read by whichever worker answers.
const SETTLE_MS = 15000;

// The person's page, asked until `done(json)` or SETTLE_MS passes.
async function settled(who, done) {
  log.debug("Entering settled(). " + who);
  const until = Date.now() + SETTLE_MS;
  let json = {};
  for (;;) {
    const r = await h.apiGet(h.realmApi + "/users?user=" +
                             encodeURIComponent(who));
    json = (r && (r.body || r.json)) || {};
    if (done(json) || Date.now() > until) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
  log.debug("Leaving settled().");
  return json;
}

async function test() {
  log.debug("Entering test().");
  await h.createRealm("GNAP user activity");
  await h.setting("gnap.continueWaitS", 0);
  await h.setting("risk.assessSignIns", false);
  await h.usePeer();
  const who = usernameFor("uag");
  await h.ensurePerson(who);
  const client = new gnap.Client({ key: gnap.newKey("ES256") });
  const flow = await h.redirectGrant(client, who,
    { client: h.grantBody(client, null, "user activity job").client });
  h.check("the grant is released with an access token", function () {
    assert.ok(flow.released && flow.released.access_token,
              JSON.stringify(flow.released).slice(0, 300));
  });

  const json = await settled(who, function (j) {
    const sessions = [].concat(j.sessions || []);
    return [].concat(j.authenticationEvents || []).length > 0 &&
      sessions.some(function (s) {
        return [].concat(s.tokens || []).length > 0;
      }) && [].concat(j.gnapGrants || []).length > 0;
  });
  const said = JSON.stringify({
    events: [].concat(json.authenticationEvents || []).map(function (e) {
      return e.action + "/" + e.protocol;
    }),
    sessions: [].concat(json.sessions || []).map(function (s) {
      return [].concat(s.tokens || []).map(function (t) {
        return t.grant || t.kind;
      });
    }),
    gnapGrants: [].concat(json.gnapGrants || []).length
  });
  h.check("1. the Authentication attempts tab lists the sign-in at the " +
          "interaction", function () {
    assert.ok([].concat(json.authenticationEvents || []).some(function (e) {
      return e.action === "authentication";
    }), said);
  });
  h.check("2. Sessions & tokens lists the session and the GNAP token under " +
          "it", function () {
    assert.ok([].concat(json.sessions || []).some(function (s) {
      return [].concat(s.tokens || []).some(function (t) {
        return t.grant === "gnap";
      });
    }), said);
  });
  h.check("3. the GNAP grants tab lists the grant", function () {
    assert.ok([].concat(json.gnapGrants || []).length >= 1, said);
  });
  log.debug("Leaving test().");
}

test().then(function () {
  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
