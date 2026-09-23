"use strict";
//
// File: sts_metadata_anonymous.js
//
// ===========================================================================
// EVERY METADATA DOCUMENT THIS SERVICE PUBLISHES, FETCHED BY A STRANGER.
//
// One property, over every protocol family at once: **the document a client
// has to read BEFORE it can do anything is readable by a client that has
// nothing.** No cookie, no Authorization header, no client certificate, no
// prior request. Twenty-three documents — fourteen protocol families and the
// service's own `/realms` — and the same four questions asked of each: the
// status, the media type, the shape, and what the response tried to give the
// caller besides the document.
//
// ---------------------------------------------------------------------------
// WHY THIS IS WORTH A JOB OF ITS OWN.
//
// Metadata is the one endpoint in a protocol family that is read by somebody
// who cannot yet authenticate. That is not a nicety, it is the order of
// operations: an OIDC relying party is configured with an issuer and finds the
// token endpoint in the discovery document; a SCIM client reads
// /ServiceProviderConfig to learn WHICH schemes it may authenticate with; a
// SAML service provider reads the IdP's metadata to learn the certificate it
// will verify assertions against. **A gate in front of any of them is a
// bootstrap deadlock** — the client must already know the answer to the
// question it is asking — and it does not present as a refusal of the document
// somebody was reading, it presents as a client that cannot be configured at
// all, three layers away from the change that caused it.
//
// And this service acquires gates. Since 2026-09-05: the whole /xacml surface
// (XACML_USER), the three endpoints a remote PEP lives on plus POST /xacml/pip
// (REMOTE_PEPS), /admin-api's access token, and /admin's own OIDC code flow.
// Each of those landed as a middleware on a path prefix or as a resource in
// the `access-control` policy, and **the failure mode being guarded here is
// one of them widening by a segment and taking a discovery document with it**.
// The other jobs in this suite would not see it: each drives one family, and
// each authenticates first because that is what it is there to do. This one
// authenticates as nobody, on purpose, and it is the only job in either suite
// that does.
//
// ---------------------------------------------------------------------------
// WHAT "ANONYMOUS" IS ASSERTED TO MEAN, AND WHY IT IS FOUR THINGS.
//
//   1. **200, without a redirect.** `redirect: "manual"` on every request in
//      this file, and a 3xx is a FAILURE rather than something to follow. That
//      is not fastidiousness: /admin/sts-metadata answers 303 to
//      /oauth2/authorize, which answers 200 with a sign-in screen — so a
//      checker that follows redirects and looks at the final status reports
//      that the gated console page is open to strangers. The controls in
//      section 3 are what proves this file does not.
//   2. **The media type the specification names.** A discovery document served
//      as text/html is a service that answered a stranger with an error page
//      and a 200, which several of these endpoints can do.
//   3. **A shape.** Enough of each document to know it is that document and
//      not a stub: the issuer this service claims, the endpoints it points at,
//      a non-empty key set, a signature on the SAML metadata. `must()` on each
//      row below carries it, and a row with no shape check would be a row that
//      passes on an empty JSON object.
//   4. **NOTHING ELSE.** No `Set-Cookie` — a document a stranger reads must
//      not start a session for them — and `Cache-Control: no-store`, because
//      every one of these documents describes key material that this service
//      regenerates on every start in development mode (root CLAUDE.md,
//      *Signing keys, and any document that publishes one*, which states the
//      no-store rule). A cached copy outlives the key it names, and what
//      that produces at the far end is a client verifying today's signatures
//      against yesterday's certificate. **`/sts/cert` was the one document
//      here without that header** and this job is what found it; the header
//      and the reason are now in `ws-trust/wstrust.ts` beside the route.
//
// ---------------------------------------------------------------------------
// A BAD CREDENTIAL IS NOT THE ABSENCE OF ONE, AND SCIM IS THE ONE ROW WHERE
// THAT SHOWS.
//
// Section 2 re-fetches every document with `Authorization: Bearer
// not-a-real-token`. Twenty answer 200 exactly as before — a public
// document does not become private because the caller mumbled — and the three
// SCIM discovery endpoints answer 401. **That is asserted rather than
// tolerated, in both directions**, because it is a documented decision and not
// an accident: `scim/scim_auth.ts`'s authenticate() states the order it
// resolves in, and its first rule is that a credential which was PRESENTED and
// FAILED is always a refusal even where none was required — so that a client
// testing its expired-token path cannot get a 200 because the endpoint would
// also have accepted nobody. The two rules meet on exactly these three paths
// and the answer is deliberate. A row's `badCredential` field is where each
// side of that is recorded, so a future change to either has to come here and
// say which one it is.
//
// ---------------------------------------------------------------------------
// WHAT THIS JOB DOES NOT COVER, SAID OUT LOUD BECAUSE THE HEADING IS "EVERY".
//
//   * **The LDAP rootDSE**, which is genuinely this family's metadata document
//     — RFC 4512 section 5.1, read by an anonymous client before it binds. It
//     is on the directory's own socket, which `docker-compose.yml` publishes
//     nowhere, so reaching it costs what `sts_directory_bulk_load_ldap.js`
//     costs: `STS_LDAP_URL` from both launchers and a failure naming the
//     variable when neither is there. That is a launcher change rather than a
//     test, so this job asserts the HTTP surface and `NO_PUBLIC_METADATA`
//     below records the reason against the family rather than leaving LDAP
//     looking covered.
//   * **The realm-prefixed copies.** Every document here has one per trust
//     realm and `common/CLAUDE.md` argues the mechanism; nothing about the
//     GATE differs between them, and `tests/realm_isolation.js` and
//     `sts_xacml_endpoints.js` are where per-realm behaviour is asserted.
//   * **A configured federation relationship's metadata.** Section 5 asks for
//     one that does not exist and requires a 404 — which is the whole of what
//     this job can say about it, and is the interesting half: 404 rather than
//     401 is how you know the surface is ungated, and `federation/CLAUDE.md`'s
//     "the gate is on the SIGNER, not on the subject" is the reason it must be.
//
// ---------------------------------------------------------------------------
// WHY IT IS THIS REPOSITORY'S OWN (`local: true`).
//
// `tests/CLAUDE.md` asks whether the thing under test can be driven over HTTP,
// and this plainly can be — which would put it in the parent project's suite.
// It is here on `sts_route_inputs.js`'s argument, which is the third one:
// **section 6 reads THIS WORKING TREE'S source.** The family list it checks
// coverage against is `sts_metadata.ts`'s own `PROTOCOLS`, and the well-known
// paths in section 7 are the ones this tree REGISTERS — so adding a
// protocol family, or a well-known document to an existing one,
// fails this job until somebody says here whether it publishes something a
// stranger may read. A copy over there would read the pinned `sts/` gitlink
// and check a family list that is not the one running.
//
// ---------------------------------------------------------------------------
// ONE THING IT LEAVES BEHIND, AND IT IS THE ENDPOINT'S DOCUMENTED BEHAVIOUR.
//
// Section 4 fetches the issuer-path forms of the OAuth documents, which names
// an authorization-server profile — and `oauth2.js`'s profileFromPath() says
// why that CREATES one: fetching the metadata is accessing the authorization
// server, and a name that could be read from and not seen on the console would
// be the one somebody is actually using. So a profile called
// `metadata-anon-probe` appears on /admin/authorization-servers after this job
// runs. It is named for the job on this suite's usual argument — a row a
// person finds later should say which test made it.
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { Command, Option } = require("commander");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_metadata_anonymous",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// run-report.js decides a job needs the mock by looking for these names, so
// the read is what enlists this file rather than an entry in a list somewhere.
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = (process.env.OID4VCI_ISSUER_URL ||
            stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");

// The repository root, from this file. `tests/vendored/` -> `../..`.
const ROOT = path.resolve(__dirname, "..", "..");

// The authorization-server profile section 4 names. See the header for why
// asking for it brings it into being.
const PROBE_PROFILE = "metadata-anon-probe";

// ---------------------------------------------------------------------------
// THE ONE `Set-Cookie` THAT IS NOT THE SERVICE ANSWERING, AND WHY IT IS NAMED
// HERE RATHER THAN TOLERATED (2026-09-11).
//
// "Reading a public document must not begin a session" is the assertion below,
// and it is right. What it measured was `Set-Cookie` — which in `dispatch`
// mode is not only the service's: `common/request_pool.js` is a load balancer
// in front of N workers and it appends a STICKY-ROUTING COOKIE to a response
// whose request arrived with nothing to route it by. Every document in the
// table below is such a request, so this job went red in that mode and green
// in the two single-process ones, over a cookie no handler set and no handler
// can see.
//
// It is not a session and the distinction is the whole of this block. It names
// a worker; it is opaque; nothing is authorized by it; anybody may forge one
// and the most they achieve is choosing which of three identical processes
// answers them; and the pool STRIPS it from the request before a worker sees
// it, so it cannot become a credential later. The same response behind nginx's
// `sticky` or an ALB's `AWSALB` would carry exactly the same thing, and nobody
// would call that a defect in the metadata endpoint.
//
// **THE NAME IS READ OFF THE MODULE THAT SETS IT** rather than written down
// here, for this file's own reason — the PROTOCOLS table in section 6 is read
// the same way. A rename in `request_pool.js` must not silently widen this
// exemption into "any cookie at all"; if the constant stops being findable the
// exemption closes and every document goes back to allowing none.
//
// EVERYTHING ELSE STILL FAILS. A session cookie, a CSRF token, a relying-party
// cookie, anything a handler set — the assertion is unchanged for all of it,
// which is what it was written for.
// ---------------------------------------------------------------------------
const POOL_COOKIE = (function () {
  let source = "";
  try {
    source = fs.readFileSync(path.join(ROOT, "common", "request_pool.js"),
                             "utf8");
  } catch (e) {
    log.debug("Caught in a callback in module scope: " +
              ((e && e.message) || e));
    // Not readable from here. The exemption closes rather than widening — see
    // the block above.
    return "";
  }
  const found = /const POOL_COOKIE = '([^']+)'/.exec(source);
  return found ? found[1] : "";
})();

// What a document actually set, with the pool's routing pin taken out. A
// document that set nothing else answers "".
function applicationCookies(header) {
  log.debug("Entering applicationCookies().");
  const list = String(header || "").split(/,(?=[^;]+=)/)
    .map(function (one) { return one.trim(); })
    .filter(function (one) {
      if (!one) {
        return false;
      }
      return !(POOL_COOKIE && one.indexOf(POOL_COOKIE + "=") === 0);
    });
  log.debug("Leaving applicationCookies().");
  return list.join(", ");
}

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("check passed: " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE MEDIA TYPES, once each, so that two rows claiming "json" cannot come to
// mean two different things.
// ---------------------------------------------------------------------------
const JSON_TYPE = /^application\/json\b/;
const SCIM_TYPE = /^application\/scim\+json\b/;
const DID_TYPE = /^application\/did\+json\b/;
const SAML_TYPE = /^application\/samlmetadata\+xml\b/;
const XML_TYPE = /^application\/xml\b/;
const TEXT_TYPE = /^text\/plain\b/;

// ---------------------------------------------------------------------------
// A JWK THAT IS A PUBLIC KEY, and the members that would say otherwise.
//
// Every document below that carries keys carries PUBLIC ones, and this is the
// list of what a private one would have in it: RSA's five secret members, the
// EC/OKP scalar, the symmetric value, and `priv` — which is the one worth
// naming, because the post-quantum keys in this service's JWKS are `kty: AKP`
// (RFC 9794's shape) and their private half is not `d`. A check written for
// RSA and EC alone would pass over eleven ML-DSA and SLH-DSA keys.
// ---------------------------------------------------------------------------
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "priv"];

function privateMembersIn(jwk) {
  log.debug("Entering privateMembersIn().");
  log.debug("Leaving privateMembersIn().");
  return PRIVATE_JWK_MEMBERS.filter(function (m) {
    return Object.prototype.hasOwnProperty.call(jwk || {}, m);
  });
}

// A key set, whatever wraps it: the complaint list for "these are public keys
// and there is at least one of them".
function publicKeySet(keys, where) {
  log.debug("Entering publicKeySet().");
  const bad = [];
  if (!Array.isArray(keys) || keys.length === 0) {
    bad.push(where + " carries no keys at all, so a client configured from " +
             "it can verify nothing");
    log.debug("Leaving publicKeySet().");
    return bad;
  }
  keys.forEach(function (k, i) {
    if (!k || !k.kty) {
      bad.push(where + " key " + i + " has no kty");
    }
    const secret = privateMembersIn(k);
    if (secret.length) {
      bad.push(where + " key " + i + " (" + (k.kid || k.kty) + ") CARRIES A " +
               "PRIVATE COMPONENT: " + secret.join(", ") + ". This document " +
               "is served to anybody who can reach the port.");
    }
  });
  log.debug("Leaving publicKeySet().");
  return bad;
}

// A PEM certificate, and not a private key. `/sts/cert` and
// `/tls/server-certificate` both publish one, and the failure worth catching
// is not a malformed document — it is the wrong half of the pair.
function certificatePem(text, where) {
  log.debug("Entering certificatePem().");
  const bad = [];
  if (!/-----BEGIN CERTIFICATE-----/.test(String(text))) {
    bad.push(where + " is not a PEM certificate");
  }
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(String(text))) {
    bad.push(where + " CONTAINS A PRIVATE KEY, and this endpoint needs no " +
             "credential to read");
  }
  log.debug("Leaving certificatePem().");
  return bad;
}

// ---------------------------------------------------------------------------
// THE DOCUMENTS.
//
// `family` is the name of a card in `sts_metadata.ts`'s PROTOCOLS — checked in
// both directions in section 6, so a row here cannot name a family this
// service does not claim and a family cannot arrive without an answer to
// "what does a stranger read first".
//
// `badCredential` is 'ignored' or 'refused' and is the header's argument in a
// field. `must` returns a list of complaints; an empty list is a pass.
// ---------------------------------------------------------------------------
const DOCUMENTS = [
  // -- OAuth 2.0 / OpenID Connect -----------------------------------------
  { family: "OAuth2 / OIDC", spec: "RFC 8414",
    path: "/.well-known/oauth-authorization-server",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.issuer !== base) {
        bad.push("issuer is " + d.issuer + " and the document was fetched " +
                 "from " + base + "; RFC 8414 section 3.3 makes a conforming " +
                 "client reject that");
      }
      if (!d.token_endpoint) { bad.push("no token_endpoint"); }
      if (!d.jwks_uri) { bad.push("no jwks_uri"); }
      if (!Array.isArray(d.grant_types_supported) ||
          !d.grant_types_supported.length) {
        bad.push("no grant_types_supported");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "OAuth2 / OIDC", spec: "OpenID Connect Discovery 1.0",
    path: "/.well-known/openid-configuration",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.issuer !== base) { bad.push("issuer is " + d.issuer); }
      if (!d.authorization_endpoint) { bad.push("no authorization_endpoint"); }
      if (!d.userinfo_endpoint) { bad.push("no userinfo_endpoint"); }
      if (!d.jwks_uri) { bad.push("no jwks_uri"); }
      // The two specifications this service implements that have no document
      // of their own: they are members of this one, and a client learns of
      // them here or not at all.
      if (!Array.isArray(d.dpop_signing_alg_values_supported)) {
        bad.push("no dpop_signing_alg_values_supported — RFC 9449 is " +
                 "advertised in this document and nowhere else");
      }
      if (d.tls_client_certificate_bound_access_tokens === undefined) {
        bad.push("no tls_client_certificate_bound_access_tokens — RFC 8705 " +
                 "is advertised in this document and nowhere else");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "OAuth2 / OIDC", spec: "RFC 7517 / RFC 9794", path: "/oauth2/jwks",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      log.debug("Leaving must().");
      return publicKeySet(d.keys, "the JWKS");
    } },

  // -- Verifiable credentials, and the DID documents behind them ----------
  { family: "Verifiable Credentials (OID4VCI / OID4VP)", spec: "OpenID4VCI 1.0",
    path: "/.well-known/openid-credential-issuer",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.credential_issuer !== base) {
        bad.push("credential_issuer is " + d.credential_issuer);
      }
      if (!d.credential_endpoint) { bad.push("no credential_endpoint"); }
      const configs = d.credential_configurations_supported || {};
      if (!Object.keys(configs).length) {
        bad.push("credential_configurations_supported is empty, so a wallet " +
                 "reading this can ask for nothing");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "Verifiable Credentials (OID4VCI / OID4VP)",
    spec: "SD-JWT VC (draft-ietf-oauth-sd-jwt-vc)",
    path: "/.well-known/jwt-vc-issuer",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.issuer !== base) { bad.push("issuer is " + d.issuer); }
      if (!d.jwks_uri && !d.jwks) {
        bad.push("neither jwks_uri nor jwks, which is the whole content of " +
                 "this document");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "Verifiable Credentials (OID4VCI / OID4VP)", spec: "W3C DID Core",
    path: "/.well-known/did.json",
    type: DID_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (!/^did:web:/.test(String(d.id || ""))) {
        bad.push("id is " + d.id + " and a did:web document must be named by " +
                 "the host it was fetched from");
      }
      const methods = d.verificationMethod || [];
      if (!Array.isArray(methods) || !methods.length) {
        bad.push("no verificationMethod");
      }
      methods.forEach(function (m, i) {
        const secret = privateMembersIn((m && m.publicKeyJwk) || {});
        if (secret.length) {
          bad.push("verificationMethod " + i + " carries " + secret.join(", "));
        }
      });
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "Verifiable Credentials (OID4VCI / OID4VP)",
    spec: "DIF well-known DID configuration",
    path: "/.well-known/did-configuration.json",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (!d["@context"]) { bad.push("no @context"); }
      if (!Array.isArray(d.linked_dids) || !d.linked_dids.length) {
        bad.push("no linked_dids, which is the only claim this document makes");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "Verifiable Credentials (OID4VCI / OID4VP)",
    spec: "Data Integrity BBS Cryptosuites", path: "/bbs/keys/1",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.type !== "Multikey") { bad.push("type is " + d.type); }
      if (!d.publicKeyMultibase) { bad.push("no publicKeyMultibase"); }
      if (d.secretKeyMultibase) {
        bad.push("CARRIES secretKeyMultibase, and this endpoint needs no " +
                 "credential to read");
      }
      log.debug("Leaving must().");
      return bad;
    } },

  // -- Shared Signals ------------------------------------------------------
  { family: "Shared Signals", spec: "OpenID SSF 1.0",
    path: "/.well-known/ssf-configuration",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.issuer !== base) { bad.push("issuer is " + d.issuer); }
      if (!d.jwks_uri) { bad.push("no jwks_uri"); }
      if (!d.configuration_endpoint) { bad.push("no configuration_endpoint"); }
      if (!Array.isArray(d.delivery_methods_supported) ||
          !d.delivery_methods_supported.length) {
        bad.push("no delivery_methods_supported, so a receiver cannot know " +
                 "whether to expect push or poll");
      }
      log.debug("Leaving must().");
      return bad;
    } },

  // -- GNAP (2026-09-12) ----------------------------------------------------
  // RFC 9767 section 3.1: what a RESOURCE SERVER reads before it can call
  // introspection or registration — both of which it must then proof with its
  // own key, which is exactly the bootstrap order this file exists to protect.
  // The grant endpoint's own discovery is OPTIONS /gnap, which is not a GET and
  // is driven by tests/vendored/sts_gnap_core.js.
  { family: "GNAP", spec: "RFC 9767", path: "/.well-known/gnap-as-rs",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.grant_request_endpoint !== base + "/gnap") {
        bad.push("grant_request_endpoint is " + d.grant_request_endpoint);
      }
      if (!d.introspection_endpoint) { bad.push("no introspection_endpoint"); }
      if (!Array.isArray(d.key_proofs_supported) ||
          !d.key_proofs_supported.length) {
        bad.push("no key_proofs_supported, so a resource server cannot know " +
                 "how to sign its introspection call");
      }
      if (!Array.isArray(d.token_formats_supported) ||
          !d.token_formats_supported.length) {
        bad.push("no token_formats_supported");
      }
      log.debug("Leaving must().");
      return bad;
    } },

  // -- The two SAML profiles, which are two implementations ----------------
  { family: "SAML 2.0", spec: "SAML 2.0 metadata", path: "/saml2/metadata",
    type: SAML_TYPE, json: false, badCredential: "ignored",
    must: function (text) {
      log.debug("Entering must().");
      const bad = [];
      if (!/<md:EntityDescriptor[\s>]/.test(text)) {
        bad.push("no EntityDescriptor");
      }
      if (!/entityID="[^"]+"/.test(text)) { bad.push("no entityID"); }
      if (!/<md:IDPSSODescriptor[\s>]/.test(text)) {
        bad.push("no IDPSSODescriptor — which is the element CLAUDE.md says " +
                 "lives here and not in the WS-Federation document");
      }
      if (!/protocolSupportEnumeration="urn:oasis:names:tc:SAML:2\.0:protocol"/
          .test(text)) {
        bad.push("the IDPSSODescriptor does not claim SAML 2.0");
      }
      if (!/<ds:Signature[\s>]/.test(text)) {
        bad.push("UNSIGNED. A service provider takes this service's signing " +
                 "certificate out of this document, and it is fetched by " +
                 "somebody who cannot yet check anything else");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "SAML 1.1", spec: "SAML 1.1 metadata", path: "/saml11/metadata",
    type: SAML_TYPE, json: false, badCredential: "ignored",
    must: function (text) {
      log.debug("Entering must().");
      const bad = [];
      if (!/<md:EntityDescriptor[\s>]/.test(text)) {
        bad.push("no EntityDescriptor");
      }
      if (!/protocolSupportEnumeration="urn:oasis:names:tc:SAML:1\.1:protocol"/
          .test(text)) {
        bad.push("the IDPSSODescriptor does not claim SAML 1.1, which is the " +
                 "one member that tells this document from /saml2/metadata");
      }
      if (!/<ds:Signature[\s>]/.test(text)) { bad.push("UNSIGNED"); }
      log.debug("Leaving must().");
      return bad;
    } },

  // -- WS-Federation and WS-Trust ------------------------------------------
  { family: "WS-Federation", spec: "WS-Federation 1.2",
    path: "/FederationMetadata/2007-06/FederationMetadata.xml",
    type: XML_TYPE, json: false, badCredential: "ignored",
    must: function (text) {
      log.debug("Entering must().");
      const bad = [];
      if (!/<EntityDescriptor[\s>]/.test(text)) {
        bad.push("no EntityDescriptor");
      }
      if (!/fed:SecurityTokenServiceType/.test(text)) {
        bad.push("no RoleDescriptor of type fed:SecurityTokenServiceType, " +
                 "which is what makes this a WS-Federation document rather " +
                 "than a SAML one");
      }
      if (!/PassiveRequestorEndpoint/.test(text)) {
        bad.push("no PassiveRequestorEndpoint, so a relying party reading " +
                 "this has nowhere to send anybody");
      }
      if (!/<ds:Signature[\s>]/.test(text)) { bad.push("UNSIGNED"); }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "WS-Trust", spec: "WS-Trust 1.3", path: "/sts/cert",
    type: TEXT_TYPE, json: false, badCredential: "ignored",
    // THE ONLY "METADATA" THIS FAMILY HAS. WS-Trust's own discovery is
    // WS-MetadataExchange, which this service does not implement, so the
    // certificate a client verifies issued tokens against is the whole of
    // what it can read before it sends anything.
    must: function (text) {
      log.debug("Entering must().");
      log.debug("Leaving must().");
      return certificatePem(text, "the WS-Trust STS certificate");
    } },

  // -- SPIFFE --------------------------------------------------------------
  { family: "SPIFFE", spec: "SPIFFE Trust Domain and Bundle",
    path: "/spiffe/bundle",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    // ANONYMOUS BY SPECIFICATION rather than by this service's permissiveness:
    // a bundle endpoint is what a workload in ANOTHER trust domain reads, and
    // it holds no credential this domain would recognise.
    must: function (d) {
      log.debug("Entering must().");
      const bad = publicKeySet(d.keys, "the trust bundle");
      const uses = (d.keys || []).map(function (k) { return k.use; });
      if (!uses.some(function (u) {
        return u === "x509-svid" || u === "jwt-svid";
      })) {
        bad.push("no key is marked x509-svid or jwt-svid, so nothing in this " +
                 "bundle is usable as a SPIFFE root");
      }
      log.debug("Leaving must().");
      return bad;
    } },

  // -- SCIM: the three discovery endpoints, open by design -----------------
  { family: "SCIM", spec: "RFC 7643 section 5",
    path: "/scim/v2/ServiceProviderConfig",
    type: SCIM_TYPE, json: true, badCredential: "refused",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if ((d.schemas || []).indexOf(
          "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig") < 0) {
        bad.push("schemas does not name ServiceProviderConfig");
      }
      if (!Array.isArray(d.authenticationSchemes) ||
          !d.authenticationSchemes.length) {
        bad.push("no authenticationSchemes — which is the reason this " +
                 "document is readable without a credential at all: it is " +
                 "where a client learns HOW to authenticate");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "SCIM", spec: "RFC 7643 section 6", path: "/scim/v2/ResourceTypes",
    type: SCIM_TYPE, json: true, badCredential: "refused",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      const ids = (d.Resources || []).map(function (r) { return r.id; });
      if (ids.indexOf("User") < 0) { bad.push("no User resource type"); }
      if (ids.indexOf("Group") < 0) { bad.push("no Group resource type"); }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "SCIM", spec: "RFC 7643 section 7", path: "/scim/v2/Schemas",
    type: SCIM_TYPE, json: true, badCredential: "refused",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      const ids = (d.Resources || []).map(function (r) { return r.id; });
      if (ids.indexOf("urn:ietf:params:scim:schemas:core:2.0:User") < 0) {
        bad.push("no core User schema");
      }
      log.debug("Leaving must().");
      return bad;
    } },

  // -- Certificate enrollment (2026-09-13) ----------------------------------
  // What each protocol's client reads BEFORE it holds anything: ACME's
  // directory, EST's CA certificates, SCEP's capability list. All three are
  // anonymous by specification — the credential each protocol uses is bound to
  // an entry that the document says nothing about.
  { family: "ACME", spec: "RFC 8555 section 7.1.1",
    path: "/enroll/acme/directory",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      ["newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"]
        .forEach(function (member) {
          if (typeof d[member] !== "string" ||
              d[member].indexOf(base + "/enroll/acme/") !== 0) {
            bad.push(member + " is " + d[member] + ", not an address under " +
                     base + "/enroll/acme/");
          }
        });
      if (!d.meta || d.meta.externalAccountRequired !== true) {
        bad.push("meta.externalAccountRequired is not true, and every " +
                 "account here is bound to a directory entry by one");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "EST", spec: "RFC 7030 section 4.1",
    path: "/.well-known/est/cacerts",
    type: /^application\/pkcs7-mime\b/, json: false,
    badCredential: "ignored",
    must: function (text) {
      log.debug("Entering must().");
      const bad = [];
      const compact = String(text).replace(/\s+/g, "");
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
        bad.push("the body is not base64 (RFC 7030 section 4.1.3)");
      } else if (Buffer.from(compact, "base64")[0] !== 0x30) {
        bad.push("the body does not decode to a DER SEQUENCE, so it is not a " +
                 "certs-only CMS message");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "SCEP", spec: "RFC 8894 section 3.5.2",
    path: "/enroll/scep?operation=GetCACaps",
    type: TEXT_TYPE, json: false, badCredential: "ignored",
    // GetCACaps rather than GetCACert: the second is a binary CMS message this
    // table's text reader would mangle, and the first is what a client asks
    // for first anyway, to learn which the second may be encrypted with.
    must: function (text) {
      log.debug("Entering must().");
      const caps = String(text).split(/\r?\n/).map(function (one) {
        return one.trim();
      }).filter(function (one) { return !!one; });
      const bad = [];
      ["POSTPKIOperation", "SHA-256", "AES"].forEach(function (cap) {
        if (caps.indexOf(cap) < 0) {
          bad.push("the capability " + cap + " is not advertised");
        }
      });
      log.debug("Leaving must().");
      return bad;
    } },

  // -- The main port's own certificate -------------------------------------
  // (The 8443/9443 listeners that also presented it were deleted 2026-09-16.)
  { family: "PKI / X.509", spec: "RFC 5280", path: "/tls/server-certificate",
    type: TEXT_TYPE, json: false, badCredential: "ignored",
    // The listener certificate, with its chain and the service Root since
    // 2026-09-11, and regenerated per start in development mode — so the
    // document a client builds its truststore from has to be fetchable before
    // that client trusts anything.
    must: function (text) {
      log.debug("Entering must().");
      log.debug("Leaving must().");
      return certificatePem(text, "the server certificate");
    } },

  // -- The public crypto metadata document (#42, 2026-09-22) ---------------
  // Every signer generation of the realm with its chain, anonymous in both
  // modes because it holds public material only — which is what the rows
  // check: a JWK with no private member, and no PEM private key anywhere.
  { family: "PKI", spec: "this service's own",
    path: "/crypto/metadata.json",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (d.issuer !== base) {
        bad.push("issuer is " + d.issuer + " and the document was fetched " +
                 "from " + base);
      }
      const units = Array.isArray(d.units) ? d.units : [];
      if (!units.some(function (u) { return u.unit === "jose:RS256"; }) ||
          !units.some(function (u) { return u.unit === "xml:RS256"; })) {
        bad.push("the jose:RS256 and xml:RS256 units are not both listed");
      }
      const jwks = [];
      units.forEach(function (u) {
        (u.keys || []).forEach(function (k) {
          if (!k.kid || !k.state) {
            bad.push(u.unit + " has a key with no kid or state");
          }
          if (k.jwk) {
            jwks.push(k.jwk);
          }
        });
      });
      bad.push.apply(bad, publicKeySet(jwks, "the crypto metadata"));
      if (/PRIVATE KEY/.test(JSON.stringify(d))) {
        bad.push("the crypto metadata CONTAINS A PRIVATE KEY");
      }
      log.debug("Leaving must().");
      return bad;
    } },
  { family: "PKI", spec: "this service's own",
    path: "/crypto/metadata.xml",
    type: XML_TYPE, json: false, badCredential: "ignored",
    must: function (text) {
      log.debug("Entering must().");
      const bad = [];
      if (!/<cm:CryptoMetadata\b[^>]*xmlns:cm="urn:iya:sts:crypto-metadata:1"/
        .test(String(text))) {
        bad.push("the root is not cm:CryptoMetadata in its own namespace");
      }
      if (/PRIVATE KEY/.test(String(text))) {
        bad.push("the crypto metadata CONTAINS A PRIVATE KEY");
      }
      log.debug("Leaving must().");
      return bad;
    } },

  // -- The service's own directory of realms -------------------------------
  // NOT a protocol family (`sts_metadata.ts` files it under `Service`), and it
  // is here because it is the document a client reads to discover the OTHER
  // documents' prefixes. `GET /realms` is ungated on purpose — common/CLAUDE.md
  // calls it "the ungated directory a client discovers
  // them from" — and nothing else asserts that it still is.
  { family: null, spec: "this service's own", path: "/realms",
    type: JSON_TYPE, json: true, badCredential: "ignored",
    must: function (d) {
      log.debug("Entering must().");
      const bad = [];
      if (!Array.isArray(d.realms) || !d.realms.length) {
        bad.push("no realms listed, and the default realm is always one of " +
                 "them");
      }
      if (!d.realms.some(function (r) { return r.id === "default"; })) {
        bad.push("the default realm is not in the list");
      }
      log.debug("Leaving must().");
      return bad;
    } }
];

// ---------------------------------------------------------------------------
// THE CONTROLS: four surfaces that must NOT answer a stranger.
//
// They are what makes section 1 mean anything. The failure this guards against
// is not in the service, it is in THIS FILE: a fetch that follows redirects, a
// status compared loosely, a body checked for a substring that a sign-in page
// also contains — any of which would report the whole surface open and go
// green for ever. Each of these four refuses in a DIFFERENT WAY on purpose, so
// one relaxed comparison cannot pass all four.
// ---------------------------------------------------------------------------
const CONTROLS = [
  // ---------------------------------------------------------------------
  // **THIS ROW SENDS A HEADER, AND WITHOUT IT THIS CONTROL WAS A FIXTURE
  // THAT COULD NOT FAIL.** `tests/tools/attach-admin-token.js` is PRELOADED
  // into every job by `run-report.js` (`--require`, through NODE_OPTIONS):
  // it patches `fetch` and `http/https.request` to attach the run's
  // /admin-api access token to any request to that API which does not
  // already carry an Authorization header. Twenty-three jobs drive that
  // surface and none of them shares an HTTP client, so one preload beats
  // twenty-three edits — and this job is the one place in the suite where
  // that convenience is the enemy: a request written to carry nothing came
  // out of this process carrying a token with admin:read and admin:write on
  // it, and the control reported the management API wide open to strangers.
  //
  // It cost a run to find, and the direction it failed in is the dangerous
  // one: the control PASSED by accident when run by hand (no token in the
  // environment, no preload) and FAILED under the launcher, which is the way
  // round that gets diagnosed. Reversed, it would have been a green control
  // asserting nothing in every stack that matters.
  //
  // `Authorization: none` is the shim's own documented way out — it never
  // replaces a header a job set, and this service reads that value as a
  // credential it cannot parse. So the caller is unauthenticated, which is
  // what this control is about, and `theSuitesTokenShimIsNarrow()` below
  // asserts that the shim is present and reaches THIS path and no other.
  // ---------------------------------------------------------------------
  { path: "/admin-api/status", expect: [401],
    headers: { Authorization: "none" },
    why: "the management API takes an OAuth access token audienced to itself " +
         "(2026-09-09), and this request deliberately carries something that " +
         "is not one" },
  { path: "/scim/v2/Users", expect: [401],
    why: "SCIM's data endpoints create and DELETE accounts, unlike the three " +
         "discovery endpoints above them" },
  { path: "/xacml/policies", expect: [403],
    why: "the XACML surface requires the built-in XACML_USER role, and the " +
         "refusal comes from the access policy rather than from a middleware " +
         "— which is why it is a 403 and not a 401" },
  { path: "/admin/sts-metadata", expect: [302, 303],
    why: "the console is an OIDC relying party and sends a stranger to " +
         "/oauth2/authorize. THIS is the one that catches a " +
         "redirect-following fetch: follow it and the sign-in screen answers " +
         "200" }
];

// ---------------------------------------------------------------------------
// The families that publish NOTHING a stranger can read, and why. Checked
// against `sts_metadata.ts`'s PROTOCOLS in section 6, so a new family
// arrives here as a failure rather than as silence. The NINETEENTH did
// exactly that on 2026-09-10 — PKI arrived with no row and this job went red
// naming it, which is the whole of what the check is for. PKI left this table
// on 2026-09-22 (#42): its crypto metadata document is the stranger's first
// read, and it is in DOCUMENTS.
// ---------------------------------------------------------------------------
const NO_PUBLIC_METADATA = {
  "Kerberos":
    "RFC 4120 has no metadata document. What a client needs — the realm, the " +
    "KDC's address — comes from its own krb5.conf, and the KDC is on raw " +
    "TCP/UDP 88 and MS-KKDCP where there is nothing to GET.",
  "SPNEGO":
    "RFC 4559 negotiates in the WWW-Authenticate header of the protected " +
    "resource itself. There is no document to fetch first, which is the " +
    "whole shape of the mechanism.",
  "XACML":
    "XACML 3.0 defines no discovery document, and since 2026-09-06 the whole " +
    "surface requires a role — GET /xacml/policies is a CONTROL in section 3 " +
    "for exactly that reason.",
  "LDAP":
    "the rootDSE (RFC 4512 section 5.1) IS this family's metadata and an " +
    "anonymous client reads it before it binds — but it is on the " +
    "directory's own socket, which no stack here publishes to this job. See " +
    "the header for what covering it would cost.",
  "WebAuthn / CTAP":
    "Level 3 has no relying-party metadata document; the creation and " +
    "request options are minted per ceremony at /authn/webauthn.",
  "One-time passwords (TOTP)":
    "RFC 6238 defines no discovery document and there is nothing a stranger " +
    "could usefully be told. The one thing this family publishes is an " +
    "otpauth:// URI carrying a SHARED SECRET, drawn once on /portal/mfa for " +
    "the signed-in person it belongs to — a family whose only artifact is a " +
    "credential is the opposite of one with a public document, and an " +
    "anonymous GET of anything here is meant to fail.",
  "Recovery codes":
    "not a protocol — there is no specification for a recovery code at all, " +
    "so there is nothing that could be discovered and no document any client " +
    "would look for. What this family publishes is a set of CODES, shown to " +
    "the person they belong to on /portal/mfa and to nobody else: its only " +
    "artifact is a credential, which is TOTP's position above read a second " +
    "time and with no document even in principle. An anonymous GET of " +
    "anything here is meant to fail.",
  "Federation":
    "there is no service-wide document — /federation/metadata/:id is one per " +
    "CONFIGURED relationship, and section 5 asserts the surface is ungated " +
    "by asking for a relationship that does not exist.",
  "User portal":
    "not a protocol. Its own card on /admin/sts-metadata says so in a field."
};

// ---------------------------------------------------------------------------
// Well-known paths this tree registers that are NOT one of the documents
// above, and what covers them instead. Section 7 is the drift check; this is
// its escape list, and every entry names a section rather than an excuse.
// ---------------------------------------------------------------------------
const WELL_KNOWN_ELSEWHERE = {
  "/.well-known/openid-configuration/*": "the inserted-path form, section 4",
  "/.well-known/oauth-authorization-server/*": "the inserted-path form, " +
                                               "section 4",
  "/*/.well-known/openid-configuration": "the issuer-path form, section 4",
  "/.well-known/openid-credential-issuer/*":
    "the inserted-path form, section 4",
  "/.well-known/jwt-vc-issuer/*": "the inserted-path form, section 4",
  "/.well-known/gnap-as-rs/:as":
    "the same handler as /.well-known/gnap-as-rs for a NAMED authorization " +
    "server profile, which only exists once somebody creates one; the " +
    "unnamed form is the row in DOCUMENTS.",
  "/.well-known/webfinger":
    "RFC 7033 WebFinger (#119): it answers only with a resource parameter, " +
    "and sts_discovery_realms.js fetches it anonymously for every form of " +
    "resource, with its JRD, its CORS header and its 400 and 404.",
  "/.well-known/hoba/register":
    "NOT a document — it is where a client REGISTERS a HOBA key, and it is a " +
    "POST that changes state. sts_admin_console.js and the SCIM jobs are " +
    "where that surface is driven."
};

// ---------------------------------------------------------------------------
// THE ONE VERB, and `redirect: "manual"` is not optional here — see the
// header's point 1 and the fourth control.
// ---------------------------------------------------------------------------
async function fetchDocument(target, headers) {
  log.debug("Entering fetchDocument(). target=" + target);
  const r = await fetch(base + target, {
    redirect: "manual",
    headers: headers || {}
  });
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchDocument(): " + ((e && e.message) || e));
    // Not JSON, which several of these documents legitimately are not. The
    // caller decides whether that matters; the raw text is what gets reported.
    body = null;
  }
  log.debug("Leaving fetchDocument(). status=" + r.status);
  return {
    status: r.status,
    text: text,
    body: body,
    type: r.headers.get("content-type") || "",
    cache: r.headers.get("cache-control") || "",
    cookie: r.headers.get("set-cookie") || "",
    location: r.headers.get("location") || ""
  };
}

// ===========================================================================
// 1. EVERY DOCUMENT, FETCHED BY SOMEBODY WITH NOTHING.
// ===========================================================================
async function everyDocumentAnswersAStranger() {
  log.debug("Entering everyDocumentAnswersAStranger().");
  log.info("=== every metadata document, fetched with no credential ===");

  for (const doc of DOCUMENTS) {
    const r = await fetchDocument(doc.path);
    const where = doc.path + " (" + doc.spec + ")";

    check(where + " answers 200", function () {
      assert.strictEqual(r.status, 200,
        where + " answered " + r.status +
        (r.location ? " -> " + r.location : "") + " to a caller with no " +
        "cookie, no Authorization header and no client certificate. This is " +
        "the document a client of this family reads BEFORE it can " +
        "authenticate, so a gate in front of it is a bootstrap deadlock: the " +
        "client has to know the answer to the question it is asking. If this " +
        "was deliberate, the setting that did it and the reason belong in " +
        "this file's table.\n  body: " + r.text.slice(0, 300));
    });

    check(where + " is served as " + doc.type, function () {
      assert.ok(doc.type.test(r.type),
        where + " came back as " + (r.type || "no content type at all") +
        " and this specification names " + doc.type + ". A discovery " +
        "document served as text/html is usually an error page answering 200.");
    });

    check(where + " is the document it claims to be", function () {
      const complaints = doc.json
        ? (r.body === null
            ? ["the body did not parse as JSON: " + r.text.slice(0, 200)]
            : doc.must(r.body))
        : doc.must(r.text);
      assert.deepStrictEqual(complaints, [],
        where + " answered 200 with something that is not that document:\n  " +
        complaints.join("\n  "));
    });

    check(where + " starts no session", function () {
      assert.strictEqual(applicationCookies(r.cookie), "",
        where + " set a cookie on a caller who sent none: " + r.cookie +
        ". Reading a public document must not begin a session — every other " +
        "surface here mints one deliberately and says so. (The request " +
        "pool's own routing pin, \"" + (POOL_COOKIE || "none found") + "\", " +
        "is exempt and is the only thing that is; see this file's " +
        "POOL_COOKIE block.)");
    });

    check(where + " is no-store", function () {
      assert.ok(/no-store/.test(r.cache),
        where + " was served with Cache-Control: " +
        (r.cache || "nothing at all") + ". Every document in this table " +
        "describes key material this service regenerates on every start, so " +
        "a cached copy outlives the key it names and the far end verifies " +
        "today's signatures against yesterday's certificate. CLAUDE.md " +
        "states the rule under *The signing key is regenerated on every " +
        "start*.");
    });
  }
  log.info("[anonymous] OK — " + DOCUMENTS.length + " documents, each " +
           "readable by a caller holding nothing.");
  log.debug("Leaving everyDocumentAnswersAStranger().");
}

// ===========================================================================
// 2. THE SAME DOCUMENTS, ASKED FOR WITH A CREDENTIAL THAT IS NO GOOD.
// ===========================================================================
async function aBadCredentialIsNotTheAbsenceOfOne() {
  log.debug("Entering aBadCredentialIsNotTheAbsenceOfOne().");
  log.info("=== the same documents, with a credential that does not verify " +
           "===");

  for (const doc of DOCUMENTS) {
    const r = await fetchDocument(doc.path,
      { Authorization: "Bearer not-a-real-token" });
    const where = doc.path;

    if (doc.badCredential === "refused") {
      check(where + " refuses a presented credential that failed", function () {
        assert.strictEqual(r.status, 401,
          where + " answered " + r.status + " to a caller presenting a token " +
          "that does not verify, and this row expects 401. That is SCIM's " +
          "documented order (scim/scim_auth.ts's authenticate()): a " +
          "credential which was presented and FAILED is always a refusal, " +
          "even on an endpoint that would have accepted nobody, so that a " +
          "client testing its expired-token path cannot get a 200 by " +
          "accident. If that rule changed, change this row and say why.");
      });
    } else {
      check(where + " ignores a credential it does not need", function () {
        assert.strictEqual(r.status, 200,
          where + " answered " + r.status + " to a caller presenting a token " +
          "that does not verify, having answered 200 to a caller presenting " +
          "nothing. A public document does not become private because the " +
          "caller mumbled — and a client that keeps a stale token around " +
          "would be unable to re-read the document that tells it how to get " +
          "a new one.");
      });
    }
  }
  log.info("[bad credential] OK — " + DOCUMENTS.length + " documents; the " +
           "three SCIM discovery endpoints refuse a failed credential and " +
           "the rest are unmoved by one.");
  log.debug("Leaving aBadCredentialIsNotTheAbsenceOfOne().");
}

// ===========================================================================
// 3. THE CONTROLS.
// ===========================================================================
async function theGatedSurfacesStillRefuse() {
  log.debug("Entering theGatedSurfacesStillRefuse().");
  log.info("=== four surfaces that must NOT answer a stranger ===");

  for (const control of CONTROLS) {
    const r = await fetchDocument(control.path, control.headers);
    check(control.path + " refuses", function () {
      assert.ok(control.expect.indexOf(r.status) >= 0,
        control.path + " answered " + r.status + " to a caller with nothing, " +
        "and it must answer one of " + control.expect.join(" or ") +
        " — " + control.why + ".\n\nTHIS IS A CONTROL, and it fails in two " +
        "very different situations. Either that surface has stopped " +
        "requiring a credential, which is a defect in the service; or this " +
        "file's notion of an anonymous read has gone soft — a fetch that " +
        "follows redirects, a status compared loosely — in which case " +
        "section 1 above is passing without checking anything.\n  body: " +
        r.text.slice(0, 200));
    });
  }
  log.info("[controls] OK — " + CONTROLS.length + " gated surfaces refused, " +
           "in " + CONTROLS.length + " different ways.");
  log.debug("Leaving theGatedSurfacesStillRefuse().");
}

// ===========================================================================
// 3a. THE SUITE'S OWN TOKEN SHIM IS PRESENT, AND IT IS NARROW.
//
// Every other section of this file rests on one unstated claim: that a request
// this file wrote with no Authorization header LEAVES THIS PROCESS with no
// Authorization header. Under `run-report.js` that is not free —
// `tests/tools/attach-admin-token.js` is preloaded into every job and rewrites
// requests on their way out — so the claim is asserted here rather than
// assumed, on the one path where the shim applies.
//
// Both branches are real states and each says something:
//
//   * a token in the environment is a LAUNCHER run. The shim must be reaching
//     /admin-api (the plain request is admitted) and the same path with
//     `Authorization: none` must still be refused. Together those say the
//     surface is gated AND that this file knows how to ask it anonymously.
//   * no token is a hand run of this job. Then nothing is patched, and the
//     plain request is refused exactly as the header-bearing one is.
//
// **WHAT NEITHER BRANCH CAN SHOW is a shim that widened to some other path** —
// there is no way to ask this service what headers it saw. What keeps that
// honest is that the shim's `WANTED` regex is one line in one file with this
// paragraph pointing at it: widen it and the documents above quietly stop
// being fetched anonymously. It would be a change to the suite's plumbing made
// for another job's convenience, which is exactly why it is written down here.
// ===========================================================================
async function theSuitesTokenShimIsNarrow() {
  log.debug("Entering theSuitesTokenShimIsNarrow().");
  const launcherRun = !!process.env.STS_ADMIN_API_TOKEN;
  log.info("=== the suite's own /admin-api token shim (" +
           (launcherRun ? "a launcher run: it is attached"
                        : "a hand run: nothing is attached") + ") ===");

  const plain = await fetchDocument("/admin-api/status");
  const refused = await fetchDocument("/admin-api/status",
                                      { Authorization: "none" });

  if (launcherRun) {
    check("the preload reaches /admin-api", function () {
      assert.strictEqual(plain.status, 200,
        "STS_ADMIN_API_TOKEN is in this job's environment, so " +
        "tests/tools/attach-admin-token.js should have attached it to a " +
        "request that carried no Authorization header — and " +
        "/admin-api/status " +
        "answered " + plain.status + " instead of 200. Either the preload is " +
        "no longer being applied, or that API's gate has changed. It matters " +
        "here because the control above sends `Authorization: none` " +
        "SPECIFICALLY to get past that shim, and if the shim is gone that " +
        "control is testing something other than what its comment says.");
    });
  } else {
    check("nothing is attached on a hand run", function () {
      assert.strictEqual(plain.status, 401,
        "no STS_ADMIN_API_TOKEN in this job's environment, so nothing should " +
        "be adding one — and /admin-api/status answered " + plain.status +
        " to a request carrying nothing.");
    });
  }

  check("`Authorization: none` reaches the API unauthenticated", function () {
    assert.strictEqual(refused.status, 401,
      "/admin-api/status answered " + refused.status + " to a caller " +
      "presenting `Authorization: none`, which this service cannot parse as " +
      "a credential. That is the shim's own documented way for a job to " +
      "drive this API as nobody, and the control above depends on it.");
  });

  log.info("[shim] OK — the one path the suite's preload touches, and it " +
           "still refuses a caller that presents nothing usable.");
  log.debug("Leaving theSuitesTokenShimIsNarrow().");
}

// ===========================================================================
// 4. THE ISSUER-PATH FORMS, which are the multi-authorization-server surface.
//
// RFC 8414 defines two ways to name a metadata document for an issuer with a
// path component, this service answers both, and in each the ISSUER inside the
// document must be the issuer the URL named — section 3.3 makes a conforming
// client reject anything else, so a copy-paste that returned the base issuer
// for every profile would be undetectable from the status code alone.
// ===========================================================================
async function theIssuerPathFormsAnswerToo() {
  log.debug("Entering theIssuerPathFormsAnswerToo().");
  log.info("=== the RFC 8414 path forms, anonymously ===");

  const expected = base + "/" + PROBE_PROFILE;
  const forms = [
    { path: "/" + PROBE_PROFILE + "/.well-known/openid-configuration",
      what: "the issuer-path form" },
    { path: "/.well-known/openid-configuration/" + PROBE_PROFILE,
      what: "the inserted-path form of the OIDC document" },
    { path: "/.well-known/oauth-authorization-server/" + PROBE_PROFILE,
      what: "the inserted-path form of the RFC 8414 document" }
  ];

  for (const form of forms) {
    const r = await fetchDocument(form.path);
    check(form.path + " answers a stranger", function () {
      assert.strictEqual(r.status, 200,
        form.what + " answered " + r.status + ". A named authorization " +
        "server is reached by clients that have been given nothing but its " +
        "issuer, exactly as the default one is.");
    });
    check(form.path + " names its own issuer", function () {
      assert.ok(r.body && r.body.issuer === expected,
        form.what + " claims issuer " + (r.body && r.body.issuer) + " and " +
        "was fetched from a URL " +
        "naming " + expected + ". RFC 8414 section 3.3 " +
        "makes a conforming client reject that document, which is a failure " +
        "no status code would show.");
    });
    check(form.path + " is no-store", function () {
      assert.ok(/no-store/.test(r.cache),
        form.what + " was served with Cache-Control: " +
        (r.cache || "nothing"));
    });
  }

  // The key set for a named authorization server, which is a separate route
  // (`/:as/oauth2/jwks`) and therefore a separate thing to leave gated.
  const jwks = await fetchDocument("/" + PROBE_PROFILE + "/oauth2/jwks");
  check("a named authorization server's JWKS answers a stranger", function () {
    assert.strictEqual(jwks.status, 200,
      "/" + PROBE_PROFILE + "/oauth2/jwks answered " + jwks.status +
      ". The document above points every client at it.");
  });
  check("a named authorization server's JWKS is public keys", function () {
    const complaints = publicKeySet(jwks.body && jwks.body.keys,
                                    "the named server's JWKS");
    assert.deepStrictEqual(complaints, [], complaints.join("\n  "));
  });

  log.info("[issuer paths] OK — both RFC 8414 forms and the named JWKS.");
  log.debug("Leaving theIssuerPathFormsAnswerToo().");
}

// ===========================================================================
// 5. THE PER-APPLICATION DOCUMENTS.
//
// Three of these families mint a document PER PARTNER, and two of them do it
// — in development mode — for a partner that has never been registered, which
// is this service being a mock, and is what lets a service provider be
// pointed at /saml2/metadata/<anything> and get a working entityID. In
// product mode (#112) those two answer 404 for such a name. The third
// refuses to invent anything, and the shape of its refusal is the assertion: a 404 says
// the reader was let in and there was nothing there, where a 401 or a redirect
// would say the surface had been closed. federation/CLAUDE.md's gate is on the
// SIGNER of an incoming assertion, and it must never become a gate on the
// reader of a metadata document.
// ===========================================================================
async function thePerPartnerDocuments() {
  log.debug("Entering thePerPartnerDocuments().");
  log.info("=== the per-partner documents ===");

  const minted = [
    { path: "/saml2/metadata/anon-probe-sp", family: "SAML 2.0" },
    { path: "/saml11/metadata/anon-probe-rp", family: "SAML 1.1" }
  ];
  for (const one of minted) {
    const r = await fetchDocument(one.path);
    // IN PRODUCT MODE (#112) a name nobody registered is a 404 at these
    // paths, and that 404 is the same kind of answer the federation one
    // below is: the reader was let in and there is nothing there. This job
    // sends no credential, so it tells the modes apart by the answer — a
    // handler-sent text/plain 404 saying why — rather than by asking.
    if (r.status === 404) {
      check(one.path + " is, in product mode, an honest 404 for a name " +
            "nobody registered", function () {
        assert.ok(/text\/plain/.test(r.type), r.type);
        assert.ok(/no-store/.test(r.cache), r.cache);
        assert.ok(/registered/.test(r.text) && /product mode/.test(r.text),
                  r.text.slice(0, 200));
      });
      continue;
    }
    check(one.path + " answers a stranger", function () {
      assert.strictEqual(r.status, 200,
        one.family + "'s per-partner metadata answered " + r.status +
        ". A service provider fetches this before it has any relationship " +
        "with this service at all.");
    });
    check(one.path + " is signed metadata for that partner", function () {
      const bad = [];
      if (!/<md:EntityDescriptor[\s>]/.test(r.text)) {
        bad.push("no EntityDescriptor");
      }
      if (!/<ds:Signature[\s>]/.test(r.text)) { bad.push("UNSIGNED"); }
      if (r.text.indexOf("anon-probe-") < 0) {
        bad.push("the document does not name the partner it was asked for, " +
                 "so every service provider would be handed the same entityID");
      }
      assert.deepStrictEqual(bad, [], one.path + ":\n  " + bad.join("\n  "));
    });
  }

  const fed = await fetchDocument("/federation/metadata/no-such-relationship");
  check("federation metadata for an unknown relationship is 404", function () {
    assert.strictEqual(fed.status, 404,
      "/federation/metadata/<unknown> answered " + fed.status +
      (fed.location ? " -> " + fed.location : "") + ", and it must answer " +
      "404. The difference matters: 404 means the reader was admitted and " +
      "the relationship does not exist, while 401 or a redirect would mean " +
      "this service had put a gate on READING metadata. Federation's gate is " +
      "on the SIGNER of an incoming assertion and is the one refusal here " +
      "that cannot be made permissive — which is exactly why it must not " +
      "spread to the document a partner reads while being configured.");
  });

  log.info("[per partner] OK — two minted documents and one honest 404.");
  log.debug("Leaving thePerPartnerDocuments().");
}

// ===========================================================================
// 6. EVERY PROTOCOL FAMILY IS ACCOUNTED FOR.
//
// Read off THIS WORKING TREE — `sts_metadata.ts`'s PROTOCOLS, the table that
// draws the cards on /admin/sts-metadata and is handed to the crypto report
// when its instance is wired. The SOURCE is read, not the `.js` an image build
// compiles beside it (#50), and the declaration may carry a type annotation.
// A family is either covered by a row in DOCUMENTS or named in
// NO_PUBLIC_METADATA with a reason. Both directions: a row here naming a
// family this service does not claim fails too, which is what a rename
// produces.
// ===========================================================================
function everyFamilyIsAccountedFor() {
  log.debug("Entering everyFamilyIsAccountedFor().");
  log.info("=== every protocol family this service advertises ===");

  const source = fs.readFileSync(path.join(ROOT, "sts_metadata.ts"), "utf8");
  const block = source.split(/const PROTOCOLS(?:: [A-Za-z]+\[\])? = \[/)[1];
  assert.ok(block,
    "sts_metadata.ts no longer contains `const PROTOCOLS = [`. That table is " +
    "where this service says which protocol families it offers, and this " +
    "section is the drift check between it and the documents above. If it " +
    "moved, follow it — do not delete this section.");
  const families = [];
  const re = /^ {2}\{ name: '([^']+)'/gm;
  let m = re.exec(block);
  while (m) {
    families.push(m[1]);
    m = re.exec(block);
  }

  // A FLOOR, on sts_roles.js's convention: an extractor that quietly stops
  // matching finds SOME families and reports everything covered.
  assert.ok(families.length >= 15,
    "only " + families.length + " protocol families were read out of " +
    "sts_metadata.ts and this service advertises nineteen. That is an " +
    "extractor that broke rather than a service that shrank — the table's " +
    "rows are `  { name: '...'` and something has changed their shape.");

  const uncovered = [];
  families.forEach(function (family) {
    const covered =
        DOCUMENTS.some(function (d) { return d.family === family; });
    if (covered) { return; }
    if (Object.prototype.hasOwnProperty.call(NO_PUBLIC_METADATA, family)) {
      return;
    }
    uncovered.push(family);
  });

  check("every family is covered or excused", function () {
    assert.deepStrictEqual(uncovered, [],
      "these protocol families are advertised on /admin/sts-metadata and " +
      "this job says nothing about " +
      "them: " + uncovered.join(", ") + ".\n\nEvery " +
      "family either publishes a document a stranger reads first — add it to " +
      "DOCUMENTS — or it does not, in which case say so in " +
      "NO_PUBLIC_METADATA with the reason. There is no third answer, and a " +
      "family that arrives here without one is a family whose discovery " +
      "surface nothing in either suite has ever fetched.");
  });

  const invented = [];
  DOCUMENTS.forEach(function (d) {
    if (d.family === null) { return; }
    if (families.indexOf(d.family) < 0) {
      invented.push(d.path + " -> " + d.family);
    }
  });
  Object.keys(NO_PUBLIC_METADATA).forEach(function (family) {
    if (families.indexOf(family) < 0) {
      invented.push("NO_PUBLIC_METADATA -> " + family);
    }
  });
  check("no row names a family this service does not claim", function () {
    assert.deepStrictEqual(invented, [],
      "these name a protocol family that is not in sts_metadata.ts's " +
      "PROTOCOLS: " + invented.join(", ") + ". That is what a rename " +
      "produces — the family is still there under another name and this file " +
      "goes on reporting it covered.");
  });

  log.info("[families] OK — " + families.length + " families; " +
           (families.length - Object.keys(NO_PUBLIC_METADATA).length) +
           " publish a document and " +
           Object.keys(NO_PUBLIC_METADATA).length + " say why they do not.");
  log.debug("Leaving everyFamilyIsAccountedFor().");
}

// ===========================================================================
// 7. EVERY WELL-KNOWN PATH THIS TREE REGISTERS IS IN THE TABLE.
//
// The other half of the drift check, one level down: a family that already has
// a card can grow a SECOND document, and nothing above would notice. This
// reads the registrations rather than the prose — the literal in `app.get()`,
// and the constant where the path is one (ssf.ts's WELL_KNOWN and scim.js's
// HOBA_REGISTER_PATH today; a scan of string literals would have matched
// sentences of documentation instead).
// ===========================================================================
function everyWellKnownPathIsAccountedFor() {
  log.debug("Entering everyWellKnownPathIsAccountedFor().");
  log.info("=== every /.well-known path this tree registers ===");

  const found = new Set();
  const dirs = fs.readdirSync(ROOT, { withFileTypes: true })
    .filter(function (e) {
      return e.isDirectory() && ["node_modules", "tests", "node-ldapjs",
                                 "xacml-pep", "docs", ".git", "coverage"]
        .indexOf(e.name) < 0;
    })
    .map(function (e) { return path.join(ROOT, e.name); });
  dirs.push(ROOT);

  dirs.forEach(function (dir) {
    let entries = [];
    try {
      entries = fs.readdirSync(dir)
                  .filter(function (f) { return /\.js$/.test(f); });
    } catch (e) {
      log.debug("Caught in a callback in everyWellKnownPathIsAccountedFor(): " +
                ((e && e.message) || e));
      // Not a readable directory, so not a route module. The floor below is
      // what catches a systematic loss rather than this one.
      return;
    }
    entries.forEach(function (file) {
      let text = "";
      try {
        text = fs.readFileSync(path.join(dir, file), "utf8");
      } catch (e) {
        log.debug("Caught in a callback in everyWellKnownPathIsAccountedFor(): " + ((e && e.message) || e));
        // Same as above: unreadable is not a route module.
        return;
      }
      // The literal form.
      let m;
      const literal =
          /app\.(?:get|all)\(\s*['"]([^'"]*\/\.well-known\/[^'"]*)['"]/g;
      m = literal.exec(text);
      while (m) {
        found.add(m[1]);
        m = literal.exec(text);
      }
      // The constant form: app.get(NAME, ... where `const NAME = '/...'`.
      const viaConst = /app\.(?:get|all)\(\s*([A-Z][A-Z0-9_]*)\b/g;
      m = viaConst.exec(text);
      while (m) {
        const decl = new RegExp("const\\s+" + m[1] +
                                "\\s*=\\s*['\"]([^'\"]+)['\"]");
        const hit = decl.exec(text);
        if (hit && hit[1].indexOf("/.well-known/") >= 0) {
          found.add(hit[1]);
        }
        m = viaConst.exec(text);
      }
    });
  });

  const paths = Array.from(found);
  assert.ok(paths.length >= 8,
    "only " + paths.length + " /.well-known registrations were found in this " +
    "tree and there are a dozen. The extractor broke rather than the service " +
    "shrinking — a new registration idiom, or a path built rather than " +
    "written.");

  const unaccounted = paths.filter(function (p) {
    if (DOCUMENTS.some(function (d) { return d.path === p; })) { return false; }
    return !Object.prototype.hasOwnProperty.call(WELL_KNOWN_ELSEWHERE, p);
  });

  check("every registered /.well-known path is accounted for", function () {
    assert.deepStrictEqual(unaccounted, [],
      "this tree registers " + unaccounted.join(", ") + " and nothing in " +
      "this file mentions it. A /.well-known path is by definition a " +
      "document somebody fetches without being invited — add it to " +
      "DOCUMENTS, or to WELL_KNOWN_ELSEWHERE naming the section that covers " +
      "it.");
  });

  log.info("[well-known] OK — " + paths.length + " registrations, all " +
           "accounted for.");
  log.debug("Leaving everyWellKnownPathIsAccountedFor().");
}

// ===========================================================================
// 8. WHAT THE DOCUMENTS POINT A STRANGER AT IS ITSELF READABLE.
//
// Three documents carry a `jwks_uri` and a client follows it with exactly the
// same nothing it used to fetch the document. A discovery document that is
// open and points at a key set that is not is the same deadlock one link
// further out — and it would be invisible to every check above, each of which
// only ever fetches a path this file wrote down.
// ===========================================================================
async function whatTheyPointAtIsReadableToo() {
  log.debug("Entering whatTheyPointAtIsReadableToo().");
  log.info("=== the URLs those documents send a client to ===");

  const sources = ["/.well-known/openid-configuration",
                   "/.well-known/jwt-vc-issuer",
                   "/.well-known/ssf-configuration"];
  const seen = new Set();
  for (const source of sources) {
    const r = await fetchDocument(source);
    const uri = r.body && r.body.jwks_uri;
    check(source + " advertises a jwks_uri", function () {
      assert.ok(uri, source + " carries no jwks_uri.");
    });
    if (!uri || seen.has(uri)) { continue; }
    seen.add(uri);
    const key = await fetch(uri, { redirect: "manual", headers: {} });
    const body = await key.json().catch(function (e) {
      // Not JSON; the check below reports the body as missing.
      log.debug("Caught parsing " + uri + ": " + ((e && e.message) || e));
      return null;
    });
    check(uri + " answers a stranger", function () {
      assert.strictEqual(key.status, 200,
        source + " points every client at " + uri + ", which answered " +
        key.status + " to the same caller that read the document naming it.");
    });
    check(uri + " is public keys", function () {
      const complaints = publicKeySet(body && body.keys, uri);
      assert.deepStrictEqual(complaints, [], complaints.join("\n  "));
    });
  }

  log.info("[references] OK — every advertised jwks_uri is readable by the " +
           "caller that was told about it.");
  log.debug("Leaving whatTheyPointAtIsReadableToo().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Fetching every metadata document " + base + " publishes, as a " +
           "caller holding nothing.");

  await everyDocumentAnswersAStranger();
  await aBadCredentialIsNotTheAbsenceOfOne();
  await theGatedSurfacesStillRefuse();
  await theSuitesTokenShimIsNarrow();
  await theIssuerPathFormsAnswerToo();
  await thePerPartnerDocuments();
  everyFamilyIsAccountedFor();
  everyWellKnownPathIsAccountedFor();
  await whatTheyPointAtIsReadableToo();

  // A FLOOR ON THE COUNT, for the reason sts_route_inputs.js gives: a section
  // that stops being called takes its assertions with it and the run still
  // says "passed", which is the one failure a suite cannot report about
  // itself. Twenty-three documents at five checks each is most of it.
  assert.ok(checks >= 110,
    "only " + checks + " checks ran, and this file makes well over a hundred " +
    "against a healthy service. A count this low means a SECTION STOPPED " +
    "BEING CALLED rather than that this service publishes less.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_metadata_anonymous")
  .description("Fetch every metadata document this service publishes — one " +
      "or more per protocol family — with no credential of any kind, and " +
      "require that each answers, says what it is, starts no session and is " +
      "not cached. Four gated surfaces are driven as controls.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
