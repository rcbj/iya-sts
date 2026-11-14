// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_bcl.js
//
// ===========================================================================
// AN OPENID CONNECT BACK-CHANNEL LOGOUT 1.0 RECEIVER (#293, WP3, 2026-10-13):
// the relying party's `backchannel_logout_uri`, which no job had — the
// Logout Token was asserted only in process (`tests/backchannel_logout.js`)
// and by the conformance plan's own client.
//
// `POST /t/{tenant}/bcl`, reached over the peer's TLS listener: product mode
// delivers only over https with the receiver's certificate verified (#171),
// so a job names the peer's CA in the realm's `federation.outboundCaFile`.
// A job tells the tenant the client_id the token is addressed to (`bcl:
// { clientId }` on the tenant's PUT) and registers this endpoint as that
// client's `oauthBackchannelLogoutUri`.
//
// What it checks, as section 2.6 says a relying party must, and records
// whatever the verdict:
//
//   * the body is a form carrying `logout_token` (section 2.5);
//   * the token is a compact JWS typed `logout+jwt` (section 2.4) — an
//     encrypted one is refused here, since the tenant holds no key;
//   * its signature verifies under a key at the `jwks_uri` the realm's
//     OpenID configuration names, and its `iss` is that document's issuer;
//   * its `aud` holds the tenant's client_id, it carries `iat` and `jti`,
//     its `events` has the back-channel logout member as a JSON object, it
//     names `sub` or `sid`, and it carries no `nonce` (section 2.4);
//   * its `jti` has not been seen before (section 2.6 step 8's replay
//     check, per tenant).
//
// A good token is answered 200 with `Cache-Control: no-store` (section
// 2.8); a refusal is 400 with `error` and `error_description`.
// ===========================================================================

const util = require("./peer_util.js");
const jwt = require("./peer_jwt.js");

const log = util.logger("peer_bcl");

const EVENT = "http://schemas.openid.net/event/backchannel-logout";
const MAX_JTIS = 2000;

// The realm's OpenID configuration: its issuer and jwks_uri. Cached.
async function configurationOf(tenant) {
  log.debug("Entering configurationOf().");
  if (tenant.bcl.configuration) {
    log.debug("Leaving configurationOf(). Cached.");
    return tenant.bcl.configuration;
  }
  const url = tenant.realmBase + "/.well-known/openid-configuration";
  const r = await util.outbound("GET", url, { ca: tenant.serviceCaPem });
  if (r.status !== 200 || !r.json || !r.json.issuer || !r.json.jwks_uri) {
    log.debug("Leaving configurationOf(). " + r.status);
    throw new Error("the OpenID configuration at " + url + " answered " +
                    r.status);
  }
  tenant.bcl.configuration = { issuer: r.json.issuer,
                               jwksUri: r.json.jwks_uri };
  log.debug("Leaving configurationOf().");
  return tenant.bcl.configuration;
}

function refusal(tenant, description, seen) {
  log.debug("Entering refusal().");
  tenant.record("bcl", Object.assign({ ok: false, status: 400,
                                       error: "invalid_request",
                                       description: description }, seen));
  log.debug("Leaving refusal().");
  return { status: 400, body: { error: "invalid_request",
                                error_description: description },
           headers: { "Cache-Control": "no-store" } };
}

// What section 2.4 asks of the claims, as a list of what is wrong.
function claimProblems(tenant, claims, conf) {
  log.debug("Entering claimProblems().");
  const problems = [];
  if (claims.iss !== conf.issuer) {
    problems.push("iss is " + claims.iss + ", not " + conf.issuer);
  }
  const aud = [].concat(claims.aud || []);
  if (tenant.bcl.clientId && aud.indexOf(tenant.bcl.clientId) < 0) {
    problems.push("aud " + JSON.stringify(claims.aud) + " does not hold " +
                  tenant.bcl.clientId);
  }
  if (typeof claims.iat !== "number") {
    problems.push("no iat");
  }
  if (!claims.jti) {
    problems.push("no jti");
  }
  const event = (claims.events || {})[EVENT];
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    problems.push("events does not hold " + EVENT + " as a JSON object");
  }
  if (!claims.sub && !claims.sid) {
    problems.push("neither sub nor sid");
  }
  if (Object.prototype.hasOwnProperty.call(claims, "nonce")) {
    problems.push("a nonce, which a Logout Token must not carry");
  }
  log.debug("Leaving claimProblems(). " + problems.length);
  return problems;
}

async function logout(tenant, request) {
  log.debug("Entering logout().");
  const seen = { contentType: request.headers["content-type"] || null };
  if (!/x-www-form-urlencoded/i.test(seen.contentType || "")) {
    log.debug("Leaving logout(). Media type.");
    return refusal(tenant, "The body is " + seen.contentType + ", not a " +
                   "form (section 2.5).", seen);
  }
  const token = String(util.formOf(request.body).logout_token || "").trim();
  if (!token) {
    log.debug("Leaving logout(). No token.");
    return refusal(tenant, "No logout_token in the form.", seen);
  }
  if (token.split(".").length === 5) {
    log.debug("Leaving logout(). Encrypted.");
    return refusal(tenant, "An encrypted Logout Token, which this receiver " +
                   "holds no key to open.", Object.assign(seen,
                   { encrypted: true }));
  }
  let decoded;
  try {
    decoded = jwt.decode(token);
  } catch (e) {
    log.debug("Caught in logout(): " + ((e && e.message) || e));
    // Not a JWS: refused as malformed, with what was wrong.
    log.debug("Leaving logout(). Not a JWS.");
    return refusal(tenant, "The logout_token is not a JWS: " + e.message,
                   seen);
  }
  seen.header = decoded.header;
  seen.claims = decoded.claims;
  if (String(decoded.header.typ || "").toLowerCase() !== "logout+jwt" &&
      String(decoded.header.typ || "").toLowerCase() !==
        "application/logout+jwt") {
    log.debug("Leaving logout(). typ.");
    return refusal(tenant, "The token's typ is \"" + decoded.header.typ +
                   "\", not logout+jwt (section 2.4).", seen);
  }
  const conf = await configurationOf(tenant);
  const verdict = await jwt.verify(tenant.bcl.jwks, conf.jwksUri,
                                   tenant.serviceCaPem, decoded);
  seen.signatureValid = verdict.ok;
  if (!verdict.ok) {
    log.debug("Leaving logout(). Signature.");
    return refusal(tenant, "The token's signature: " + verdict.why, seen);
  }
  const problems = claimProblems(tenant, decoded.claims, conf);
  if (problems.length) {
    log.debug("Leaving logout(). Claims.");
    return refusal(tenant, "Section 2.4: " + problems.join("; ") + ".",
                   Object.assign(seen, { problems: problems }));
  }
  if (tenant.bcl.jtis.has(decoded.claims.jti)) {
    log.debug("Leaving logout(). Replay.");
    return refusal(tenant, "The jti " + decoded.claims.jti + " was seen " +
                   "before (section 2.6).", Object.assign(seen,
                   { replay: true }));
  }
  tenant.bcl.jtis.set(decoded.claims.jti, Date.now());
  if (tenant.bcl.jtis.size > MAX_JTIS) {
    tenant.bcl.jtis.delete(tenant.bcl.jtis.keys().next().value);
  }
  tenant.record("bcl", Object.assign({ ok: true, status: 200 }, seen));
  log.debug("Leaving logout(). Accepted.");
  return { status: 200, body: null,
           headers: { "Cache-Control": "no-store" } };
}

function configure(tenant, asked) {
  log.debug("Entering configure().");
  const given = asked || {};
  const before = tenant.bcl || {};
  tenant.bcl = {
    clientId: given.clientId ? String(given.clientId)
                             : (before.clientId || ""),
    // Kept across a reconfiguration, so a replay is still a replay.
    jtis: before.jtis || new Map(),
    configuration: null,
    jwks: {}
  };
  log.debug("Leaving configure().");
}

module.exports = { configure: configure, logout: logout, EVENT: EVENT };
