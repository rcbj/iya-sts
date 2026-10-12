// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_ssf.js
//
// ===========================================================================
// AN SSF 1.0 RECEIVER'S PUSH ENDPOINT (RFC 8935) (#586), in place of the
// service's own `/ssf/receive`, which is development only (#585).
//
// `POST /t/{tenant}/ssf/push`, reached over the peer's TLS listener: product
// mode pushes only over https with the receiver's certificate verified
// (#171), so a job names the peer's CA in the realm's `ssf.pushCaFile`.
//
// What it checks, as a receiver must (RFC 8417, RFC 8935, SSF 1.0 section
// 4.1), and records whatever the verdict:
//
//   * the `Authorization` header is the stream's `authorization_header`,
//     when the tenant was given one — 401 `authentication_failed` otherwise;
//   * the body is `application/secevent+jwt`, a compact JWS explicitly typed
//     `secevent+jwt` (section 4.1.1);
//   * its signature verifies under a key at the `jwks_uri` the realm's SSF
//     configuration document names, and its `iss` is that document's
//     `issuer` (`invalid_key`, `invalid_issuer`);
//   * its `aud`, when the tenant was told the stream's (`invalid_audience`).
//
// A good SET is answered 202 with an empty body, RFC 8935 section 2.3's
// success; a refusal is 400 with `err` and `description` (section 2.4).
// ===========================================================================

const util = require("./peer_util.js");
const jwt = require("./peer_jwt.js");

const log = util.logger("peer_ssf");

// The realm's SSF configuration: its issuer and jwks_uri. Cached.
async function configurationOf(tenant) {
  log.debug("Entering configurationOf().");
  if (tenant.ssf.configuration) {
    log.debug("Leaving configurationOf(). Cached.");
    return tenant.ssf.configuration;
  }
  const url = tenant.realmBase + "/.well-known/ssf-configuration";
  const r = await util.outbound("GET", url, { ca: tenant.serviceCaPem });
  if (r.status !== 200 || !r.json || !r.json.issuer || !r.json.jwks_uri) {
    log.debug("Leaving configurationOf(). " + r.status);
    throw new Error("the SSF configuration at " + url + " answered " +
                    r.status);
  }
  tenant.ssf.configuration = { issuer: r.json.issuer,
                               jwksUri: r.json.jwks_uri };
  log.debug("Leaving configurationOf().");
  return tenant.ssf.configuration;
}

function refusal(tenant, status, err, description, seen) {
  log.debug("Entering refusal(). " + err);
  tenant.record("ssf", Object.assign({ ok: false, status: status, err: err,
                                       description: description }, seen));
  log.debug("Leaving refusal().");
  return { status: status, body: { err: err, description: description } };
}

async function push(tenant, request) {
  log.debug("Entering push().");
  const seen = { authorization: request.headers.authorization ? "present"
                                                              : "absent",
                 contentType: request.headers["content-type"] || null };
  if (tenant.ssf.authorizationHeader &&
      request.headers.authorization !== tenant.ssf.authorizationHeader) {
    log.debug("Leaving push(). Authorization.");
    return refusal(tenant, 401, "authentication_failed", "The " +
                   "Authorization header is not the one this stream was " +
                   "given.", seen);
  }
  if (!/^application\/secevent\+jwt\b/i.test(seen.contentType || "")) {
    log.debug("Leaving push(). Media type.");
    return refusal(tenant, 400, "invalid_request", "The body is " +
                   seen.contentType + ", not application/secevent+jwt.",
                   seen);
  }
  let decoded;
  try {
    decoded = jwt.decode(request.body.toString("utf8").trim());
  } catch (e) {
    log.debug("Caught in push(): " + ((e && e.message) || e));
    // Not a JWS: refused as malformed, with what was wrong.
    log.debug("Leaving push(). Not a JWS.");
    return refusal(tenant, 400, "invalid_request", "The body is not a " +
                   "SET: " + e.message, seen);
  }
  seen.header = decoded.header;
  seen.claims = decoded.claims;
  seen.eventTypes = Object.keys(decoded.claims.events || {});
  if (!/^(application\/)?secevent\+jwt$/i.test(
    String(decoded.header.typ || ""))) {
    log.debug("Leaving push(). typ.");
    return refusal(tenant, 400, "invalid_request", "The SET's typ is \"" +
                   decoded.header.typ + "\", not secevent+jwt (SSF 1.0 " +
                   "section 4.1.1).", seen);
  }
  const conf = await configurationOf(tenant);
  tenant.ssf.jwks = tenant.ssf.jwks || {};
  const verdict = await jwt.verify(tenant.ssf.jwks, conf.jwksUri,
                                   tenant.serviceCaPem, decoded);
  seen.signatureValid = verdict.ok;
  if (!verdict.ok) {
    log.debug("Leaving push(). Signature.");
    return refusal(tenant, 400, "invalid_key", "The SET's signature: " +
                   verdict.why, seen);
  }
  if (decoded.claims.iss !== conf.issuer) {
    log.debug("Leaving push(). Issuer.");
    return refusal(tenant, 400, "invalid_issuer", "The SET's iss is " +
                   decoded.claims.iss + ", not " + conf.issuer + ".", seen);
  }
  if (tenant.ssf.audience &&
      [].concat(decoded.claims.aud || []).indexOf(tenant.ssf.audience) < 0) {
    log.debug("Leaving push(). Audience.");
    return refusal(tenant, 400, "invalid_audience", "The SET's aud is " +
                   JSON.stringify(decoded.claims.aud) + ", not " +
                   tenant.ssf.audience + ".", seen);
  }
  tenant.record("ssf", Object.assign({ ok: true, status: 202 }, seen));
  log.debug("Leaving push(). Accepted.");
  return { status: 202, body: null };
}

function configure(tenant, asked) {
  log.debug("Entering configure().");
  const given = asked || {};
  tenant.ssf = {
    authorizationHeader: given.authorizationHeader
      ? String(given.authorizationHeader) : "",
    audience: given.audience ? String(given.audience) : ""
  };
  log.debug("Leaving configure().");
}

module.exports = { configure: configure, push: push };
