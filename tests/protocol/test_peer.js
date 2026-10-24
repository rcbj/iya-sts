// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: test_peer.js
//
// ===========================================================================
// THE JOBS' SIDE OF THE TEST PEER (#586).
//
// `tests/peer/` is a separate container on the test stack that plays the far
// party of a protocol — a SAML 2.0 service provider, a SAML 1.1 and a
// WS-Federation relying party, an RFC 9470 and a GNAP resource server, an SSF
// receiver — in place of the service's own demo endpoints, which are
// development only (#585). This module is what a job does with it:
//
//   * `available()` / `skipReason()`: whether this run has a peer at all.
//     ./run-tests.sh names it (`STS_TEST_PEER_URL`) in every local mode; an
//     AWS target names none, and a job that needs the peer is SKIPPED by the
//     runner (`testPeer: true` in MANIFEST.js) or skips the sections that
//     need it, saying so with this sentence.
//   * `tenant(id, realmBase)`: configures a TENANT of the peer for one realm
//     — the realm's base URL and the anchors the peer trusts the service's
//     TLS with (the service Root and whatever this runner trusts, read the
//     way `saml_peer_kit.js` reads them) — and answers what the peer made
//     for it: an entityID, return addresses, a signing certificate, a GNAP
//     key, a push URL. A job starts from a known state (#586): it creates the
//     realm, configures a tenant for it, and REGISTERS what came back as an
//     ordinary application, through `/admin-api` — the peer is trusted for
//     nothing it was not registered for.
//   * the `…Fields()` builders: those registrations' attributes, one per
//     role, so every job spells them the same way.
//   * `received()` / `waitFor()`: the peer's readback — what reached it, and
//     what it made of it — so a job asserts on what arrived at the far end.
//
// The token `/admin-api` needs is the runner's preload's
// (`tests/tools/attach-admin-token.js`), which attaches it by path; nothing
// here sends one to the peer.
//
// A LOCAL HELPER (MANIFEST.js), owned here. Node built-ins and bunyan.
// ===========================================================================

const fs = require("fs");
const nodeCrypto = require("crypto");

const log = require("bunyan").createLogger({ name: "test_peer",
  level: process.env.LOG_LEVEL || "info" });

function url() {
  log.debug("Entering url().");
  log.debug("Leaving url().");
  return String(process.env.STS_TEST_PEER_URL || "").replace(/\/+$/, "");
}

function available() {
  log.debug("Entering available().");
  log.debug("Leaving available().");
  return url() !== "";
}

// The sentence a skipping job or section logs.
function skipReason(what) {
  log.debug("Entering skipReason().");
  log.debug("Leaving skipReason().");
  return "SKIPPED" + (what ? " (" + what + ")" : "") + ": there is no test " +
    "peer in this run (STS_TEST_PEER_URL is unset). ./run-tests.sh starts " +
    "one in every local mode; an AWS target has none, so the far party of " +
    "this protocol is unchecked here (#586).";
}

// A unique tenant id: the prefix and some randomness, in the peer's alphabet.
function tenantId(prefix) {
  log.debug("Entering tenantId().");
  log.debug("Leaving tenantId().");
  return String(prefix || "t").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 60) +
    "-" + nodeCrypto.randomBytes(5).toString("hex");
}

async function call(method, path, body) {
  log.debug("Entering call(). " + method + " " + path);
  const r = await fetch(url() + path, {
    method: method, redirect: "manual",
    headers: body === undefined ? {} :
      { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON: `text` carries it into any message.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, json: json, text: text };
}

// The peer is STARTED before the runner, not awaited healthy (the compose
// file argues it), so the first job to want it waits here — and says which
// container to read if it never answers.
let up = false;
async function waitUntilUp(timeoutMs) {
  log.debug("Entering waitUntilUp().");
  const deadline = Date.now() + (timeoutMs || 60000);
  let last = "";
  while (!up && Date.now() < deadline) {
    try {
      const r = await call("GET", "/health");
      up = r.status === 200;
      last = r.status + " " + r.text.slice(0, 120);
    } catch (e) {
      log.debug("Caught in waitUntilUp(): " + ((e && e.message) || e));
      // Not listening yet; asked again below.
      last = e.message;
    }
    if (!up) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 500);
      });
    }
  }
  if (!up) {
    log.debug("Leaving waitUntilUp(). Never answered.");
    throw new Error("the test peer at " + url() + " did not answer " +
                    "/health (" + last + "); read `docker logs` on the " +
                    "test-peer container");
  }
  log.debug("Leaving waitUntilUp().");
}

// The anchors the peer trusts the service with: the service Root, which
// every certificate the service presents chains to, and whatever this runner
// was handed as NODE_EXTRA_CA_CERTS (the main port's certificate, re-read by
// run-report.js before each job; in the cluster mode every node's).
async function serviceAnchors(base) {
  log.debug("Entering serviceAnchors().");
  let pem = "";
  try {
    const r = await fetch(String(base).replace(/\/+$/, "") +
                          "/pki/ca/service/root.cer");
    if (r.status === 200) {
      pem += new nodeCrypto.X509Certificate(
        Buffer.from(await r.arrayBuffer())).toString() + "\n";
    }
  } catch (e) {
    log.debug("Caught in serviceAnchors(): " + ((e && e.message) || e));
    // The runner's own anchors below are what the peer then has; a peer
    // that cannot verify the service says so on every call it fails.
  }
  if (process.env.NODE_EXTRA_CA_CERTS) {
    try {
      pem += fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS, "utf8");
    } catch (e) {
      log.debug("Caught in serviceAnchors(): " + ((e && e.message) || e));
      // Unreadable: the Root alone, above.
    }
  }
  log.debug("Leaving serviceAnchors().");
  return pem;
}

// Configures a tenant of the peer for `realmBase` (the realm's own base
// URL; `base` the service's, where the Root is published). `extra` carries
// a role's configuration: { saml: { entityId }, wsfed: { realm },
// stepUp: { resources }, gnap: { type }, ssf: { authorizationHeader,
// audience } }. Answers the tenant's view.
async function tenant(id, realmBase, base, extra) {
  log.debug("Entering tenant(). " + id);
  await waitUntilUp();
  const body = Object.assign({ realmBase: realmBase,
                               serviceCaPem: await serviceAnchors(
                                 base || realmBase) }, extra || {});
  const r = await call("PUT", "/peer/tenants/" + encodeURIComponent(id),
                       body);
  if (r.status !== 200 || !r.json || !r.json.ok) {
    log.debug("Leaving tenant(). Refused.");
    throw new Error("configuring the test peer's tenant " + id + " answered " +
                    r.status + " " + r.text.slice(0, 300));
  }
  log.debug("Leaving tenant().");
  return r.json;
}

// The records a role made on a tenant after `since` (a sequence number).
async function received(id, role, since) {
  log.debug("Entering received(). " + id + " " + role);
  const r = await call("GET", "/peer/tenants/" + encodeURIComponent(id) +
                       "/received?role=" + encodeURIComponent(role || "") +
                       "&since=" + Number(since || 0));
  if (r.status !== 200 || !r.json) {
    log.debug("Leaving received(). " + r.status);
    throw new Error("the test peer's readback for " + id + " answered " +
                    r.status + " " + r.text.slice(0, 200));
  }
  log.debug("Leaving received(). " + r.json.events.length);
  return r.json;
}

// The sequence number a role has reached, to read only what comes after.
async function mark(id) {
  log.debug("Entering mark().");
  const r = await received(id, "", 0);
  log.debug("Leaving mark(). " + r.last);
  return r.last;
}

// The first record of `role` after `since` that `predicate` accepts, waiting
// up to `timeoutMs` — delivery to the peer is asynchronous for the SSF push.
// Answers null when none came; every record seen is on `out.seen`.
async function waitFor(id, role, since, predicate, timeoutMs, out) {
  log.debug("Entering waitFor(). " + id + " " + role);
  const deadline = Date.now() + (timeoutMs || 10000);
  for (;;) {
    const got = await received(id, role, since);
    if (out) {
      out.seen = got.events;
    }
    const hit = got.events.filter(predicate || function () {
      return true;
    })[0];
    if (hit || Date.now() >= deadline) {
      log.debug("Leaving waitFor(). " + (hit ? "Found." : "None."));
      return hit || null;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 250);
    });
  }
}

// ---------------------------------------------------------------------------
// THE REGISTRATIONS, one builder per role: the attributes of the
// application a job creates for a tenant in its realm.
// ---------------------------------------------------------------------------
function saml2Fields(view) {
  log.debug("Entering saml2Fields().");
  log.debug("Leaving saml2Fields().");
  return { samlEntityId: [view.saml.entityId],
           samlAssertionConsumerService: [view.urls.saml2Acs],
           samlSigningCertificate: [view.saml.certB64] };
}

function saml11Fields(view) {
  log.debug("Entering saml11Fields().");
  log.debug("Leaving saml11Fields().");
  return { samlEntityId: [view.saml.entityId],
           samlAssertionConsumerService: [view.urls.saml11Acs],
           samlSigningCertificate: [view.saml.certB64] };
}

function wsfedFields(view, realm) {
  log.debug("Entering wsfedFields().");
  log.debug("Leaving wsfedFields().");
  return { wsfedRealm: [realm], wsfedReplyUrl: [view.urls.wsfedReply] };
}

// A GNAP resource server: the tenant's key, and the address its resources
// are under — a right naming a location there, or of a type it declares and
// naming none, is audienced to it.
function gnapResourceServerFields(view) {
  log.debug("Entering gnapResourceServerFields().");
  log.debug("Leaving gnapResourceServerFields().");
  return { gnapKey: JSON.stringify(view.gnap.key),
           gnapResourceServerUri: view.gnap.rsUri };
}

// The limits a spend right may carry, as the demonstration type declared
// them (`gnap/gnap_rights.ts`), so the approval page draws the same
// controls for the peer's type.
const SPEND_LIMITS = JSON.stringify({
  type: "object",
  properties: {
    amount: { type: ["string", "number"] },
    currency: { type: "string" },
    count: { type: "integer", minimum: 0 },
    receiver: { type: ["string", "array"] },
    interval: { type: "string" },
    window: { type: "object" }
  },
  additionalProperties: false
});

module.exports = {
  url: url,
  available: available,
  skipReason: skipReason,
  tenantId: tenantId,
  waitUntilUp: waitUntilUp,
  serviceAnchors: serviceAnchors,
  tenant: tenant,
  received: received,
  mark: mark,
  waitFor: waitFor,
  saml2Fields: saml2Fields,
  saml11Fields: saml11Fields,
  wsfedFields: wsfedFields,
  gnapResourceServerFields: gnapResourceServerFields,
  SPEND_LIMITS: SPEND_LIMITS
};
