// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_stepup.js
//
// ===========================================================================
// AN RFC 9470 RESOURCE SERVER (#586), in place of the service's stand-in at
// `/oauth2/step-up/resource/{application}`, which is development only
// (#585).
//
// `GET|POST /t/{tenant}/step-up/{resource}`. A resource is configured on the
// tenant by the job — its audience and what it requires of the
// authentication behind a token (`acr_values`, `max_age`) — exactly what the
// job also writes on the resource's application entry, because a real API
// knows its own requirement and the authorization server learns it only from
// the challenge.
//
// What it does, in order, and what the stand-in did, so the job's
// assertions read the same:
//
//   1. no such resource: 404 `invalid_request`;
//   2. no token: 401 `invalid_token`, no step-up auth-params;
//   3. the token is an RFC 9068 `at+jwt` from the tenant's realm, signed by a
//      key at the `jwks_uri` its RFC 8414 metadata names, unexpired, from
//      that issuer, addressed to this resource's audience (section 4) — or
//      401 `invalid_token`, naming the resource;
//   4. RFC 9470 section 3: `acr` one of the required values and `auth_time`
//      within `max_age`, or 401 with
//      `Bearer error="insufficient_user_authentication",
//      error_description="…", acr_values="…", max_age="…"`;
//   5. 200, and what it decided on — the token's own claims about the
//      authentication, read back to the person who presented it.
//
// A sender-constrained token (a `cnf` claim) is refused at step 3: this
// resource server checks no DPoP or mutual-TLS proof, and accepting one
// without would be the bearer use RFC 9449 exists to stop.
// ===========================================================================

const util = require("./peer_util.js");
const jwt = require("./peer_jwt.js");

const log = util.logger("peer_stepup");

const SKEW_S = 120;

// The realm's RFC 8414 metadata: its issuer and its jwks_uri. Cached on the
// tenant.
async function metadataOf(tenant) {
  log.debug("Entering metadataOf().");
  if (tenant.stepUp.metadata) {
    log.debug("Leaving metadataOf(). Cached.");
    return tenant.stepUp.metadata;
  }
  const url = tenant.realmBase + "/.well-known/oauth-authorization-server";
  const r = await util.outbound("GET", url, { ca: tenant.serviceCaPem });
  if (r.status !== 200 || !r.json || !r.json.issuer || !r.json.jwks_uri) {
    log.debug("Leaving metadataOf(). " + r.status);
    throw new Error("the authorization server metadata at " + url +
                    " answered " + r.status);
  }
  tenant.stepUp.metadata = { issuer: r.json.issuer,
                             jwksUri: r.json.jwks_uri };
  log.debug("Leaving metadataOf().");
  return tenant.stepUp.metadata;
}

function quoted(text) {
  log.debug("Entering quoted().");
  log.debug("Leaving quoted().");
  return "\"" + String(text).replace(/["\\]/g, "") + "\"";
}

// The answer, recorded. `decision` is what the job reads back.
function answer(tenant, name, status, decision, body, challenge) {
  log.debug("Entering answer(). " + status + " " + decision);
  tenant.record("step-up", { ok: status === 200, resource: name,
                             status: status, decision: decision,
                             error: body.error || null,
                             token: body.token || null });
  const headers = {};
  if (challenge) {
    headers["WWW-Authenticate"] = challenge;
  }
  log.debug("Leaving answer().");
  return { status: status, body: body, headers: headers };
}

function refused(tenant, name, why) {
  log.debug("Entering refused().");
  const description = "The resource \"" + name + "\" refuses this token: " +
                      why;
  log.debug("Leaving refused().");
  return answer(tenant, name, 401, "refused",
                { error: "invalid_token", error_description: description },
                "Bearer error=\"invalid_token\", error_description=" +
                quoted(description));
}

async function resource(tenant, name, authorization) {
  log.debug("Entering resource(). " + name);
  const config = (tenant.stepUp.resources || {})[name];
  if (!config) {
    log.debug("Leaving resource(). No such resource.");
    return answer(tenant, name, 404, "unknown",
                  { error: "invalid_request", error_description: "No " +
                    "resource \"" + String(name).slice(0, 200) + "\" is " +
                    "configured on this resource server." }, null);
  }
  const m = /^(Bearer)\s+(\S+)$/i.exec(String(authorization || "").trim());
  if (!m) {
    log.debug("Leaving resource(). No token.");
    return refused(tenant, name, "no Bearer access token was presented.");
  }
  let decoded;
  try {
    decoded = jwt.decode(m[2]);
  } catch (e) {
    log.debug("Caught in resource(): " + ((e && e.message) || e));
    // Not a JWT at all: RFC 9068 tokens are, so it is not one of them.
    log.debug("Leaving resource(). Not a JWT.");
    return refused(tenant, name, "it is not a JWT (" + e.message + ").");
  }
  const typ = String(decoded.header.typ || "").toLowerCase();
  if (typ !== "at+jwt" && typ !== "application/at+jwt") {
    log.debug("Leaving resource(). Wrong typ.");
    return refused(tenant, name, "its typ is \"" + decoded.header.typ +
                   "\", not at+jwt (RFC 9068 section 4).");
  }
  const meta = await metadataOf(tenant);
  tenant.stepUp.jwks = tenant.stepUp.jwks || {};
  const verdict = await jwt.verify(tenant.stepUp.jwks, meta.jwksUri,
                                   tenant.serviceCaPem, decoded);
  if (!verdict.ok) {
    log.debug("Leaving resource(). Signature.");
    return refused(tenant, name, "its signature: " + verdict.why);
  }
  const claims = decoded.claims;
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== meta.issuer) {
    log.debug("Leaving resource(). Issuer.");
    return refused(tenant, name, "it was issued by " + claims.iss +
                   ", not " + meta.issuer + ".");
  }
  if (typeof claims.exp !== "number" || claims.exp + SKEW_S <= now) {
    log.debug("Leaving resource(). Expired.");
    return refused(tenant, name, "it has expired.");
  }
  if ([].concat(claims.aud || []).indexOf(config.audience) < 0) {
    log.debug("Leaving resource(). Audience.");
    return refused(tenant, name, "it is addressed to " +
                   JSON.stringify(claims.aud) + ", not to " +
                   config.audience + ".");
  }
  if (claims.cnf) {
    log.debug("Leaving resource(). Sender-constrained.");
    return refused(tenant, name, "it is sender-constrained (cnf), and this " +
                   "resource server checks no proof of possession.");
  }
  const acrValues = String(config.acr_values || "").split(/\s+/)
    .filter(Boolean);
  const maxAge = config.max_age === undefined || config.max_age === null
    ? null : Number(config.max_age);
  const age = typeof claims.auth_time === "number"
    ? now - claims.auth_time : null;
  let unmet = "";
  if (acrValues.length && acrValues.indexOf(String(claims.acr || "")) < 0) {
    unmet = "the authentication behind it (acr \"" + (claims.acr || "") +
            "\") is not one this resource requires (" +
            acrValues.join(", ") + ").";
  } else if (maxAge !== null && (age === null || age > maxAge)) {
    unmet = "the authentication behind it is " + age + " second(s) old, " +
            "and this resource accepts at most " + maxAge + ".";
  }
  if (unmet) {
    let challenge = "Bearer error=\"insufficient_user_authentication\", " +
                    "error_description=" + quoted(unmet);
    if (acrValues.length) {
      challenge += ", acr_values=" + quoted(acrValues.join(" "));
    }
    if (maxAge !== null) {
      challenge += ", max_age=" + quoted(String(maxAge));
    }
    log.debug("Leaving resource(). Challenged.");
    return answer(tenant, name, 401, "challenged",
                  { error: "insufficient_user_authentication",
                    error_description: unmet }, challenge);
  }
  log.debug("Leaving resource(). Met.");
  return answer(tenant, name, 200, "met", {
    resource: name,
    requirement: { acr_values: acrValues.join(" ") || null,
                   max_age: maxAge },
    met: true,
    token: {
      client_id: claims.client_id || null,
      sub: claims.sub || null,
      acr: claims.acr || null,
      amr: claims.amr || null,
      auth_time: claims.auth_time || null,
      authenticated_seconds_ago: age,
      scheme: m[1]
    }
  }, null);
}

module.exports = { resource: resource };
