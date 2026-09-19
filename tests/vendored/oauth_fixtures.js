"use strict";
//
// File: oauth_fixtures.js
//
// ---------------------------------------------------------------------------
// WHAT A REAL DEPLOYMENT WOULD HAVE REGISTERED, FOR THE JOBS THAT DRIVE THE
// AUTHORIZATION ENDPOINT (2026-09-18).
//
// A job that starts an authorization request as a client_id nobody created,
// with a redirect URI nobody registered and no PKCE, works in DEVELOPMENT mode
// only because the service makes all three up. PRODUCT mode — what a real
// deployment runs, and what testidp.iyasec.io runs — refuses each of them, and
// the job then stops at its first request with an answer about the fixture
// rather than about the thing it tests. So the client is registered first and
// the request carries PKCE, in BOTH modes: `sts_consent.js`'s argument, that a
// job which worked only because the service made things up would be testing
// the making-up.
//
// A LOCAL HELPER (tests/vendored/MANIFEST.js), owned here. It requires only
// node's crypto; the /admin-api token is attached to its requests by the
// runner (tests/tools/attach-admin-token.js), as to every job's.
// ---------------------------------------------------------------------------
const nodeCrypto = require("crypto");

const log = require("bunyan").createLogger({ name: "oauth_fixtures",
  level: process.env.LOG_LEVEL || "info" });

// A PUBLIC client — token_endpoint_auth_method "none" — for the redirect URIs
// given, created through `<apiBase>/applications/create` in the realm
// `apiBase` names. Public because every job using this reaches the sign-in
// screen from a browser-shaped request; product mode holds a public client to
// PKCE with S256, which `pkce()` supplies. A name already in the registry is
// not a failure (a second run, or a kept stack): what is asserted is that the
// entry exists afterwards.
async function publicClient(apiBase, identifier, redirectUris, extraFields) {
  log.debug("Entering publicClient(). " + identifier);
  const fields = Object.assign({
    oauthClientId: identifier,
    oauthRedirectUri: [].concat(redirectUris || []),
    oauthTokenEndpointAuthMethod: "none"
  }, extraFields || {});
  const r = await fetch(apiBase + "/applications/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: identifier, name: identifier,
                           protocols: ["oauth2", "oidc"], fields: fields })
  });
  const text = await r.text();
  if (r.status !== 200 && !/already in this registry/i.test(text)) {
    log.debug("Leaving publicClient(). Refused.");
    throw new Error("could not register the OAuth client " + identifier +
                    " at " + apiBase + ": " + r.status + " " +
                    text.slice(0, 300));
  }
  log.debug("Leaving publicClient().");
  return identifier;
}

// An RFC 7636 pair: `challenge` and `method` go on the authorization request,
// `verifier` on the token request.
function pkce() {
  log.debug("Entering pkce().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  log.debug("Leaving pkce().");
  return { verifier: verifier, challenge: challenge, method: "S256" };
}

module.exports = { publicClient: publicClient, pkce: pkce };
