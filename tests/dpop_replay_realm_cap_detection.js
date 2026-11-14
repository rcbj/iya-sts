// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: dpop_replay_realm_cap_detection.js
//
// ===========================================================================
// THE PER-REALM DPoP CAP JOB'S DETECTION LOGIC, AGAINST A STUBBED SERVER, NO
// STACK (#1299, iya-sts-60's mutation guard).
//
// tests/protocol/sts_dpop_replay_realm_cap.js answers the real question — does
// a DISPATCHED worker consult a realm's oauth2.dpopReplayCacheSize — and that
// takes single-node/cluster. What CAN be held with no stack is the job's own
// DETECTION LOGIC: that it recognises the STS-OAUTH-0554 refusal by its
// sentence (the code is never on the wire), returns the index of the FIRST
// such refusal, and returns 0 when none ever arrives. A job whose isReplayFull()
// never recognised a refusal, or always did, would pass the HTTP job vacuously
// — exactly the mutation this file catches: against an always-accepting server
// it must report NO cap was reached, and against a refusing one it must report
// the right index.
//
// It requires the JOB (its real functions, not a copy — the whole point) and
// drives them against a tiny http stub. require.main is not this module, so the
// job does not run its own HTTP test or parse argv.
//
// Mutation-tested against the job's isReplayFull(): always-true fails 6 of the
// 7 assertions (an accepted answer read as a refusal, and fillUntilFull
// reporting a cap at proof 1 against a server that always accepts); always-false
// makes fillUntilFull throw on the real refusal (the harness-fault guard),
// which is red. Reverted clean.
// ===========================================================================

const assert = require("assert");
const http = require("http");
const job = require("./protocol/sts_dpop_replay_realm_cap.js");

// A stub token endpoint. `responder(count)` returns { status, body } for the
// count-th request (1-based); the stub ignores the DPoP proof and the form —
// this tests the CLIENT's reading of the answer, not any server. Resolves
// { url, close }.
function stubServer(responder) {
  return new Promise(function (resolve) {
    let count = 0;
    const server = http.createServer(function (req, res) {
      count += 1;
      const chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        const answer = responder(count);
        res.writeHead(answer.status,
          { "Content-Type": "application/json" });
        res.end(typeof answer.body === "string"
          ? answer.body : JSON.stringify(answer.body));
      });
    });
    server.listen(0, "127.0.0.1", function () {
      const port = server.address().port;
      resolve({
        url: "http://127.0.0.1:" + port + "/oauth2/token",
        close: function () {
          return new Promise(function (done) { server.close(done); });
        }
      });
    });
  });
}

const ACCEPT = { status: 200,
  body: { access_token: "stub", token_type: "DPoP", expires_in: 300 } };
// The STS-OAUTH-0554 sentence, as oauth-oidc/dpop.ts writes it into the
// invalid_dpop_proof description.
const FULL = { status: 400, body: { error: "invalid_dpop_proof",
  error_description: "This server cannot remember another DPoP proof right " +
    "now: its replay history for this realm is full of live proofs, and " +
    "forgetting one would let it be replayed. Retry shortly with a fresh " +
    "proof." } };
// A DPoP refusal that is NOT fullness — a proof the server rejected on its
// merits. The job must treat this as a harness fault, never as a cap.
const BAD_PROOF = { status: 400, body: { error: "invalid_dpop_proof",
  error_description: "The DPoP proof signature did not verify." } };

const CLIENT = { clientId: "stub-client", secret: "stub-secret" };

async function run(t) {
  t.log.debug("Entering run().");

  // 1. isReplayFull() reads the refusal by its SENTENCE, not the status alone.
  t.check(job.isReplayFull({ status: FULL.status, json: FULL.body,
    text: JSON.stringify(FULL.body) }) === true,
    "a 400 invalid_dpop_proof naming a full replay history is recognised");
  t.check(job.isReplayFull({ status: 200, json: ACCEPT.body,
    text: JSON.stringify(ACCEPT.body) }) === false,
    "an accepted (200) answer is not a full-history refusal");
  t.check(job.isReplayFull({ status: BAD_PROOF.status, json: BAD_PROOF.body,
    text: JSON.stringify(BAD_PROOF.body) }) === false,
    "a DPoP refusal that is not about a full history is not recognised as one");
  t.check(job.isReplayFull({ status: 400,
    json: { error: "invalid_request" },
    text: "{\"error\":\"invalid_request\"}" }) === false,
    "an unrelated 400 is not a full-history refusal");

  // 2. Against an ALWAYS-ACCEPTING server, fillUntilFull() reports NO cap was
  // reached (0). This is the mutation guard: a job whose isReplayFull() always
  // answered true would return 1 here, and the HTTP job's "firstFull > 0" would
  // then pass against a server that never refused — a false green.
  const accepting = await stubServer(function () { return ACCEPT; });
  try {
    const none = await job.fillUntilFull(
      { tokenUrl: accepting.url, clientId: CLIENT.clientId,
        secret: CLIENT.secret }, 10);
    t.equal(none, 0,
      "fillUntilFull reports no full-history refusal against a server that " +
      "always accepts");
  } finally {
    await accepting.close();
  }

  // 3. Against a server that accepts the first two and then refuses for a full
  // history, fillUntilFull() returns the index of the FIRST refusal (3). A job
  // whose isReplayFull() always answered false would return 0 here.
  const refusingAt3 = await stubServer(function (count) {
    return count >= 3 ? FULL : ACCEPT;
  });
  try {
    const at = await job.fillUntilFull(
      { tokenUrl: refusingAt3.url, clientId: CLIENT.clientId,
        secret: CLIENT.secret }, 10);
    t.equal(at, 3,
      "fillUntilFull returns the index of the first full-history refusal");
  } finally {
    await refusingAt3.close();
  }

  // 4. A DPoP refusal that is NOT fullness is a harness fault, not a cap:
  // fillUntilFull throws rather than reporting a cap at that index, so a broken
  // proof can never be read as the realm's cap.
  const badProof = await stubServer(function () { return BAD_PROOF; });
  let threw = false;
  try {
    await job.fillUntilFull(
      { tokenUrl: badProof.url, clientId: CLIENT.clientId,
        secret: CLIENT.secret }, 10);
  } catch (e) {
    threw = true;
    t.log.debug("fillUntilFull threw as expected: " + e.message);
  } finally {
    await badProof.close();
  }
  t.check(threw,
    "fillUntilFull throws on a non-fullness DPoP refusal rather than " +
    "reporting it as a cap");

  t.log.debug("Leaving run().");
}

module.exports = {
  name: "dpop_replay_realm_cap_detection",
  describe: "the per-realm DPoP cap job reads the STS-OAUTH-0554 refusal " +
    "correctly (no stack)",
  run: run
};
