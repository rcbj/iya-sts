// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: gnap_wire_kit.js
//
// ===========================================================================
// THE PLUMBING OF THE D12 GNAP JOBS (#444, phase 8) — A HELPER, NOT A JOB.
//
// The phase 8 GNAP jobs carry the in-process `tests/gnap_*.js` files over
// the wire. Each needs a throwaway realm per mode (`oauth_wire_kit.js`'s
// `realm()`, so its id carries the run's STAMP and `removeRealms()` finds
// it), `gnap_flow.js`'s resource-owner harness bound to that realm (the
// sign-in screen, the approval page over `/gnap-api`, the redirect dance),
// application entries written through `/admin-api` with the keys of
// `gnap_client.js` — the independent client written from the RFCs — and a
// resource server introspecting with its own key. The code a refusal
// records is read off `/admin-api/audit` by the oauth kit.
//
// `gnap_flow.js` installs a REGISTRAR on `gnap_client.js` that files every
// unseen key on an entry before its first request; these jobs are about
// which key is registered where, so `gnapRealm()` takes it off again and
// every entry is written by the job itself.
//
// OWNED HERE (MANIFEST.js's LOCAL_HELPERS).
// ===========================================================================

const assert = require("assert");
const gnap = require("./gnap_client.js");
const flowLib = require("./gnap_flow.js");

function gnapKit(K) {
  const log = K.log;
  log.debug("Entering gnapKit().");

  // A REALM AND ITS HARNESS. `mode` is development or product; product's
  // sign-in is a password with `authn.allowOptionalSecondFactor` on, the
  // in-process `['pwd']` session.
  async function gnapRealm(prefix, mode, overrides, password) {
    log.debug("Entering gnapRealm(). " + prefix);
    const id = await K.realm(prefix, mode, Object.assign({
      "authn.allowOptionalSecondFactor": true,
      "gnap.continueWaitS": 0 }, overrides || {}));
    const h = flowLib.harness({ base: K.base, realm: id,
                                password: password, log: log });
    gnap.setRegistrar(null);
    log.debug("Leaving gnapRealm(). " + id);
    return { id: id, h: h };
  }

  function client(alg) {
    log.debug("Entering client().");
    log.debug("Leaving client().");
    return new gnap.Client({ key: gnap.newKey(alg || "ES256") });
  }

  // An application entry; `key` (a Client) is registered as its gnapKey.
  async function entry(h, identifier, kind, key, fields) {
    log.debug("Entering entry(). " + identifier);
    const f = Object.assign({}, fields || {});
    if (key) {
      f.gnapKey = JSON.stringify(key.keyObject());
    }
    const r = await h.ok(h.realmApi + "/applications/create", {
      identifier: identifier, name: identifier, kind: kind,
      protocols: ["gnap"], fields: f }, "created " + identifier);
    log.debug("Leaving entry().");
    return r;
  }

  // A resource server declaring `types` (each a set-access-type body
  // without `application`).
  async function resourceServer(h, identifier, key, uri, types) {
    log.debug("Entering resourceServer(). " + identifier);
    await entry(h, identifier, "gnap-resource-server", key,
                { gnapResourceServerUri: uri });
    for (const one of types || []) {
      await h.ok(h.realmApi + "/applications/set-access-type",
                 Object.assign({ application: identifier }, one),
                 "declared " + one.type + " on " + identifier);
    }
    log.debug("Leaving resourceServer().");
  }

  function introspect(h, rs, value, extra) {
    log.debug("Entering introspect().");
    log.debug("Leaving introspect().");
    return rs.send("POST", h.realmBase + "/gnap/introspect", { json:
      Object.assign({ access_token: value,
                      resource_server: { key: rs.keyObject() } },
                    extra || {}) });
  }

  // A grant request with no interaction (a client trusted to skip).
  function direct(h, c, access, extra) {
    log.debug("Entering direct().");
    log.debug("Leaving direct().");
    return c.send("POST", h.GRANT, { json: Object.assign({
      access_token: { access: access },
      client: { key: c.keyObject() } }, extra || {}) });
  }

  // The GNAP error code of an answer (section 3.6).
  function errorOf(r) {
    log.debug("Entering errorOf().");
    const e = r && r.json && r.json.error;
    log.debug("Leaving errorOf().");
    return e && typeof e === "object" ? e.code : (e || "");
  }

  // A scheduler job run in a realm and waited for (the run is queued, 202).
  async function runJob(id, job) {
    log.debug("Entering runJob(). " + job);
    const r = await K.send(K.rb(id) + "/admin-api/scheduler/run",
                           { json: { job: job, realm: id } });
    assert.ok((r.status === 200 || r.status === 202) && r.json && r.json.ok,
              job + " did not run: " + K.shown(r));
    let detail = null;
    for (let i = 0; i < 150; i += 1) {
      const d = await K.send(K.rb(id) + "/admin-api/scheduler?run=" +
                             encodeURIComponent(r.json.runId));
      detail = (d.json && d.json.detail) || null;
      if (detail && (detail.state === "succeeded" ||
                     detail.state === "failed")) {
        break;
      }
      await K.sleep(200);
    }
    assert.ok(detail && detail.state === "succeeded",
              job + " did not succeed: " +
              JSON.stringify(detail).slice(0, 400));
    log.debug("Leaving runJob().");
    return detail;
  }

  // An application entry as `/admin-api/applications` answers it.
  async function application(h, identifier) {
    log.debug("Entering application(). " + identifier);
    const r = await K.send(h.realmApi + "/applications?application=" +
                           encodeURIComponent(identifier));
    log.debug("Leaving application(). " + r.status);
    return (r.json && (r.json.application || r.json)) || null;
  }

  log.debug("Leaving gnapKit().");
  return { gnap: gnap, gnapRealm: gnapRealm, client: client, entry: entry,
           resourceServer: resourceServer, introspect: introspect,
           direct: direct, errorOf: errorOf, runJob: runJob,
           application: application };
}

module.exports = { gnapKit: gnapKit };
