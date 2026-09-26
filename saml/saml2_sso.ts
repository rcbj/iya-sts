'use strict';
//
// File: saml2_sso.ts
//
// ===========================================================================
// SAML 2.0 — the Web Browser SSO profile, all three bindings, and Single
// Logout.
//
// **THIS FILE REVERSES A DOCUMENTED NON-GOAL.** Until 2026-08-24 the sentence
// "there is no SAML 2.0 Web SSO profile" appeared in README.md, in the root
// `CLAUDE.md`, in `saml/CLAUDE.md`, in `ws-federation/wsfed.ts` (which is why
// its federation metadata publishes no IDPSSODescriptor), and in
// `sts_metadata.js` twice — once in the `saml2` coverage note and once on the
// SAML 2.0 protocol card, which said NO ROUTE OF ITS OWN. Every one of those
// had to be qualified rather than deleted, because the reason each of them
// EXISTED is still worth a reader's attention: this service was an assertion
// issuer with no browser-facing profile for a long time, deliberately, and the
// absence was documented so that nobody would take it for an oversight. What
// follows is the profile.
//
//   GET|POST /saml2/sso[/{sp}]      the Single Sign-On service. HTTP Redirect
//                                   (section 3.4) and HTTP POST (3.5) alike —
//                                   the binding is how the request ARRIVED, and
//                                   the AuthnRequest's own ProtocolBinding says
//                                   how the response goes back.
//   POST     /saml2/ars[/{sp}]      the Artifact Resolution Service, SOAP over
//                                   HTTP (3.2.3). This is the back channel the
//                                   Browser/Artifact profile rests on.
//   GET|POST /saml2/slo[/{sp}]      Single Logout (saml-profiles §4.4), both
//                                   directions: a LogoutRequest arriving from a
//                                   service provider, and this identity
//                                   provider starting one itself.
//   GET      /saml2/metadata[/{sp}] the SIGNED IdP metadata, and the
//            interesting
//                                   half of this feature — see below.
//   GET      /saml2/autopost.js     the one script an HTTP POST response runs.
//   GET|POST /saml2/sp              a mock SERVICE PROVIDER. NON-SPEC, the
//                                   default assertion consumer service, and
//                                   where a response can be verified check by
//                                   check without a second service.
//   GET      /saml2                 what all of that is, for somebody who
//                                   clicked the link.
//
// ---------------------------------------------------------------------------
// SIX DECISIONS HERE ARE NOT OBVIOUS FROM THE SPECIFICATIONS.
//
// 1. **THE METADATA IS UNIQUE PER SERVICE PROVIDER, and in DEVELOPMENT it is
//    minted for any entityID that is asked for.** `/saml2/metadata/{sp}` names
//    an identity provider of its own — `urn:sts:idp:{sp}` — with its own SSO,
//    SLO and artifact endpoints under that same `{sp}` segment, which is what
//    Okta and Ping do and what a service provider integrating with one of them
//    expects. In development it 404s for nothing: an entityID nobody has
//    registered is registered BY THE ASK, so a service provider can be pointed
//    at this service before anything at all has been provisioned. **IN
//    PRODUCT (#112, 2026-09-23) EVERY `{sp}` PATH IS A 404 FOR A NAME THAT IS
//    NOT A REGISTERED SAML 2.0 SERVICE PROVIDER** — the metadata, the SSO, the
//    SLO and the artifact resolution service alike (`STS-SAML-0082`,
//    `mode.publishesMetadataForUnregisteredProviders()`), because a signed
//    document naming an identity provider for a party nobody agreed to serve
//    is this service vouching for something an operator never decided. A
//    per-SP document is this service's own extension (SAML Metadata 2.0
//    section 4.1 defines one document per entity), so the 404 breaks no
//    specification. `saml2.perApplicationEntityId` turns
//    the per-application entityID off for a service provider library that keys
//    its trust store off the entityID and is surprised to find a new one per
//    application; the ENDPOINTS stay per-application either way, because that
//    is what makes the documents worth having separately.
//
// 2. **THERE IS NO SIGN-IN SCREEN IN THIS FILE, and that was once the
//    deliberate difference from `ws-federation/wsfed.ts`.** That module had
//    one, because section 13.2.1 lets a WS-Federation sign-in request arrive
//    as a cross-site form POST, which `SameSite=Lax` keeps the session cookie
//    off, so it could not read the session it would need to skip the screen.
//    The HTTP POST binding has exactly the same problem — and the answer here
//    is to STASH the request and 303 the browser to a GET on this same
//    endpoint, which is a top-level GET navigation and therefore DOES carry a
//    Lax cookie. So this profile reaches `authn.js`'s screen through
//    `beginAuthentication()` like the authorization endpoint does, and gets
//    single sign-on with OAuth in one session, a WebAuthn ceremony at the
//    screen, and one fewer place asking for a username. (WS-Federation gave
//    up its own screen for the same funnel on 2026-08-26 — `wsfed.ts` says
//    why.) A screen of this profile's own would have been a second
//    authentication service for no reason at all.
//
// 3. **EVERY ENTITYID IS ACCEPTED — AND SINCE 2026-09-17 (#37) A SIGNATURE IS
//    VERIFIED.** This decision used to read "nothing is verified, including a
//    signature the service provider went to the trouble of making": a signed
//    AuthnRequest's certificate was written onto the entry off its own
//    `ds:KeyInfo` and nothing checked it. Now a signature that is present —
//    the Redirect binding's query-string signature or the POST binding's
//    enveloped one, on an AuthnRequest, a LogoutRequest or a LogoutResponse —
//    is verified in every mode against the service provider's REGISTERED
//    certificates (`samlSigningCertificate`, from consumed metadata or an
//    operator) and refused when it does not verify; the certificate a request
//    carries is recorded as OBSERVED and verifies nothing; and an unsigned
//    request is refused where `saml2.requireSignedAuthnRequests` (on in
//    product by default) or the service provider's own metadata requires a
//    signature. `saml/request_signature.ts` is the policy and argues it. An
//    entityID nobody registered is still accepted in development — that half
//    of this decision stands.
//
// 4. **THE ASSERTION IS BUILT BY `saml2.ts` AND NOT BY THIS FILE.** That module
//    gained five options for this profile (a NameID format, a
//    SubjectConfirmationData, a session index, an authentication instant and an
//    issuer) rather than a second builder, for the reason its own header gives:
//    one assertion writer means one place where the element order, the
//    namespace and the signature location are decided, and those are exactly
//    what a service provider's parser is strict about. It also means the custom
//    SAML 2.0 attributes configured on `/admin/saml-attributes` reach an
//    assertion issued HERE with no wiring at all — the same line that puts them
//    in a WS-Trust or WS-Federation assertion puts them in this one, which is
//    the property that would have been lost by writing a second builder.
//
// 5. **THE RESPONSE IS SIGNED AS WELL AS THE ASSERTION, and both are
//    settings.** `saml2.signAssertion` and `saml2.signResponse` are ON by
//    default because that is what AD FS and Keycloak do and it is what a strict
//    service provider checks. Turning either off is a test case rather than a
//    mistake: a service provider that accepts an unsigned assertion has a hole
//    in it, and this is how somebody finds that out. On the HTTP Redirect
//    binding `signResponse` means the QUERY STRING signature of section
//    3.4.4.1, which is what a redirect response is really verified by — an XML
//    signature is there too and is not what that binding's verifier reads.
//
// 6. **THE ARTIFACT IS ONE-SHOT AND SAYS SO.** Section 3.6.4.1 requires that an
//    artifact be resolvable exactly once, and no lifetime setting can express
//    that — so resolving one DESTROYS it, and a second ArtifactResolve for the
//    same artifact is refused with a status naming the reason rather than
//    answering with the message again. It is the single easiest thing to get
//    wrong in this profile and the hardest to notice, because the happy path
//    passes either way.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `Saml2Sso` takes every module this file used to require (node's
// `zlib` and `crypto`, the XML parser, the realm and application registries,
// helpers, the SAML 2.0 builders, the SP-metadata reader, the session
// functions of `authn.js`, the issuance gate, `mode`, this directory's four
// libraries and the two cluster libraries) through its constructor, typed as
// `typeof` each module. Its routes are registered by `registerRoutes(app)`, in
// the order they always were. Loading the module does not call it (#50, R1):
// the module exports it, and `common/protocol_stack.ts` calls it at the point
// in the route order where requiring this module used to register the routes
// (rule 1). Since #50's R2 that root also BUILDS the instance; the module's
// old names are FACADES forwarding to it, for `admin-ui/admin.ts`,
// `saml11_sso.ts`, `logout/logout.ts` and the others, and a process without
// the root builds a default at load. The three stores stay module-level
// `realms.map()` declarations, which is where a store becomes per realm.
// ---------------------------------------------------------------------------

import zlib = require('zlib');
// TRUST REALMS: the stores below are partitioned by realm. It requires only
// config.js and error_codes.js here, so it cannot join a cycle and it
// registers no route, so its position is not a position at all.
import realms = require('../common/realms');
import crypto = require('crypto');
import xmldom = require('@xmldom/xmldom');
// Every signature and every cipher in this service is in one module since
// 2026-08-27. This file signs four documents and verifies two, and xml-crypto
// is no longer required here: `common/crypto.js` sits over the parent
// project's own signer, so a Response minted here canonicalizes with the same
// code the debugger uses to check it.
import stsCrypto = require('../common/crypto');
import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// The input validator. A LEAF (rule 3): it registers no route and closes no
// cycle.
import validation = require('../common/validation');
// Read per request rather than captured at require time, so that /admin/config
// and /admin-api can change what the next response says and how it is signed.
import config = require('../common/config');
// The error-code registry, a leaf: every refusal below is marked with its code
// on the response object, never in anything the service provider is sent.
import errorCodes = require('../common/error_codes');
// The one assertion writer. See decision 4.
import saml2 = require('./saml2');
import spMetadata = require('./sp_metadata');
// The TLS client certificate a SOAP caller presented (#37 follow-up), read the
// one way the service reads it. A library of `helpers`, `config` and
// `crypto`, so this require closes no cycle.
import mtls = require('../oauth-oidc/mtls');
// Whether a service provider's request is signed by it (#37). A library that
// registers nothing and requires only leaves.
import requestSignature = require('./request_signature');
// The audit log, for the one row per checked request signature (#37). A leaf
// that requires nothing that reaches back here.
import audit = require('../common/audit');
// The session, from the service that owns it. This profile starts none of its
// own: `beginAuthentication()` sends the browser to authn.js's screen and back.
import authn = require('../authn/authn');
// THE ROLE GATE. A LEAF (rule 3) requiring only `helpers`, `config` and
// `error_codes`, so it can be required from 10a without moving a route or
// closing a cycle — which is the whole reason `common/issuance_gate.js` exists
// rather than this module reaching into `xacml/` at 23c. An unfilled decider
// answers "allowed".
import gate = require('../common/issuance_gate');
// The application registry, which lives under ou=applications in the embedded
// directory. A library that registers no route, so requiring it here changes
// nothing about the route order this module's position in
// `common/protocol_stack.ts` fixes.
import applications = require('../common/applications');
// THE MODE, and four libraries beside this file (2026-09-12), each a leaf that
// registers nothing: the one reading of how a session authenticated, the
// configured signature algorithms and metadata organisation, the rule for
// where a response may be delivered, and the persona facts an assertion
// carries in each mode. Their headers argue them; none can move a route.
import mode = require('../common/mode');
import authnContext = require('./authn_context');
import documentSettings = require('./document_settings');
import returnAddress = require('./return_address');
import personAttributes = require('./person_attributes');
// THE CLUSTER CLAIM (2026-09-14, #46): the atomic "once" an artifact is spent
// through, so that two nodes against one store cannot both resolve it. A
// LIBRARY that registers no route and requires persistence lazily, so it
// neither moves a route nor closes a cycle. See resolveArtifact(), and the
// capability this file provides below for both profiles.
import clusterClaims = require('../cluster/cluster_claims');
import capabilities = require('../cluster/cluster_capabilities');

// --- the vocabulary --------------------------------------------------------
const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';

const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';

const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';

const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';

const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

const BINDING_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact';

// THE HTTP-POST-SimpleSign BINDING (#37 follow-up; OASIS "SAML V2.0 HTTP POST
// 'SimpleSign' Binding"): the POST binding's form, with the message NOT
// enveloped-signed and a detached `Signature`/`SigAlg` pair over the form
// values instead — the Redirect binding's signature without its length limit.
// Accepted for AuthnRequest, LogoutRequest and LogoutResponse, answered on
// when a request or a consumed endpoint asks for it, and published.
const BINDING_SIMPLESIGN =
  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign';

const BINDING_SOAP = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP';

const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

const STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

const STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

const STATUS_NO_PASSIVE = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';

const STATUS_PARTIAL_LOGOUT =
    'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';

const STATUS_UNKNOWN_PRINCIPAL =
    'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';

// `SigAlg` is a QUERY PARAMETER of the HTTP Redirect binding
// (saml-bindings-2.0-os section 3.4.4.1), sent so the far end knows what to
// verify with. It was the constant SIG_RSA_SHA256 here until 2026-09-12 and is
// now read, per message, from `saml.signatureAlgorithm` through
// `document_settings.ts` — the SAME call that decides what the query string is
// signed with, so the string a verifier is told to use and the algorithm this
// service actually signs with still cannot drift apart. See redirectUrlFor().

// The NameID formats this identity provider ADVERTISES. It is not a list of
// what it will accept: a NameIDPolicy naming something outside this list is
// answered with the format it asked for (see nameIdFormatFor), because a
// service provider being handed back its own format is the behaviour worth
// exercising — unless that service provider's CONSUMED METADATA declares its
// formats and the one asked for is not among them, which is
// InvalidNameIDPolicy (#37, `nameIdPolicyProblem()`). The list is what goes in
// the metadata, and a service provider's configuration UI is usually built
// from exactly this.
const NAMEID_FORMATS = [
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
];

// How the End-User authenticated, in SAML 2.0's vocabulary. **SINCE 2026-09-12
// THIS IS `saml/authn_context.ts` AND NOT A COPY HERE.** This file used to say
// it would not share the answer with `wsfed.ts` because a require from `saml/`
// into `ws-federation/` points the wrong way — which stays true, and is why the
// shared reading lives in THIS directory and `wsfed.ts` requires it. What the
// three copies had in common was a defect: every session that was not two
// factors or a key alone was called PasswordProtectedTransport, including a TLS
// client certificate, a Kerberos ticket, a federated sign-in and the
// unauthenticated session. See that file's header.
const AC_MULTIFACTOR = authnContext.AC_MULTIFACTOR;

// A RequestedAuthnContext naming one of these is read as "a second factor is
// required", and the sign-in screen is asked for one rather than the request
// being refused. WS-Federation's `wauth` does the same with the same demand
// since 2026-09-17 (#36) — it used to refuse, on the argument that its own
// screen could not run the ceremony, which stopped being true when that
// profile moved onto this screen.
const AC_MFA_DEMANDS = [
  AC_MULTIFACTOR,
  'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken',
  'urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI',
  'http://schemas.microsoft.com/claims/multipleauthn'
];

const BASE_PATH = '/saml2';

const SSO_PATH = BASE_PATH + '/sso';

const SLO_PATH = BASE_PATH + '/slo';

const ARS_PATH = BASE_PATH + '/ars';

const METADATA_PATH = BASE_PATH + '/metadata';

const SP_PATH = BASE_PATH + '/sp';

// Identity-provider-initiated SSO (#189): an unsolicited Response,
// saml-profiles-2.0-os section 4.1.5.
const UNSOLICITED_PATH = BASE_PATH + '/unsolicited';

// The attribute authority (#189): the Assertion Query and Request profile's
// AttributeQuery, over SOAP (saml-profiles-2.0-os section 6).
const AA_PATH = BASE_PATH + '/aa';

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const pendingRequests = realms.map({ persist: 'saml2_sso.pendingRequests',
                                     retain: 'age' });

// Artifact -> the message it stands for. See decision 6: resolving one deletes
// it, so this map is also the record of what has NOT been resolved yet.
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const artifacts = realms.map({ persist: 'saml2_sso.artifacts', retain: 'age' });

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
const spContexts = realms.map({ persist: 'saml2_sso.spContexts' });

// ---------------------------------------------------------------------------
// WHICH SERVICE PROVIDER A PATH NAMES.
//
// `{sp}` is a URL PATH SEGMENT, and an entityID is usually a URL — so it cannot
// simply be the entityID. Two spellings are accepted and they cover between
// them everything anybody types:
//
//   * the entityID itself, percent-encoded, which is what a machine generates
//     and what `/admin/saml2` links to;
//   * a SLUG, which is the entityID when it is already safe in a path segment
//     and `app-<12 hex of its sha256>` when it is not — the same device
//     `applications.js`'s shortName() uses on an RDN, and for the same reason:
//     the short form is not the identity, it is a handle for it.
//
// The consequence to keep in mind is that a slug is NOT reversible, so
// resolving one means asking the registry which of the applications it holds
// has that slug. That is a scan, and it is a scan of a mock's in-memory
// directory rather than of anything expensive.
// ---------------------------------------------------------------------------
const SAFE_SEGMENT = /^[A-Za-z0-9._~-]{1,64}$/;

// The attributes. Written from the one user object, in the shape a SAML 2.0
// service provider reads: a full URI in `Name` with the NameFormat that says
// so, plus the short unqualified spellings that a great many service providers
// (Keycloak's own default mappers among them) are configured with instead.
//
// **The custom SAML 2.0 attributes from /admin/saml-attributes are NOT added
// here**, and that is the point: `buildSamlAssertion()` appends them to
// whatever this returns, filtered by name so that a configured attribute cannot
// displace one of these — see decision 4 and the note in saml2.ts. Adding them
// here as well would put every one of them in twice.
const CLAIM_NS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

const ATTRNAME_FORMAT_URI = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

const ATTRNAME_FORMAT_BASIC =
    'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

// --- delivering it ----------------------------------------------------------
// Written with no regular expressions and nothing to escape, for the reason
// oauth2.js's ceremony script records: a backslash in a script that passes
// through a JavaScript string literal on its way out does not survive the trip.
const AUTOPOST_SCRIPT = [
  '(function () {',
  '  var f = document.getElementById("saml2-form");',
  '  if (f) { f.submit(); }',
  '})();',
  ''
].join('\n');

// ---------------------------------------------------------------------------
// SPENDING AN ARTIFACT ACROSS THE CLUSTER (2026-09-14, #46).
//
// The delete above is atomic in ONE process and nowhere else: `artifacts` is a
// `realms.map({ persist })`, so the delete reaches another node through the
// change log a moment later, and a service provider that retries its
// ArtifactResolve against a load balancer — or an attacker who read the
// artifact out of a browser history and races the service provider — can land
// both requests inside that moment on two nodes, and both would answer with the
// assertion. Section 3.6.4.1 allows one.
//
// So the in-memory check stays FIRST (the fast refusal for the common replay,
// and exactly the behaviour a single process always had), and an artifact this
// process still holds is then SPENT THROUGH `cluster_claims.claim()` before it
// is answered. On a postgres store that is one INSERT under the primary key, so
// exactly one node wins; on any other store it is this process's memory, which
// is as atomic as the delete it follows and changes nothing a single process
// did.
//
// The claim lives as long as the artifact could still be found by a node whose
// map has not caught up — its own remaining lifetime — plus CLAIM_SKEW_MS for
// two nodes' clocks disagreeing about when it expired. A store that cannot be
// asked REFUSES (fail closed, cluster_claims.js's rule): an artifact this
// service cannot prove unresolved is not one it may resolve. Nothing releases
// the claim: the delete above has already spent the artifact in this process
// whatever the answer, and a claim released where the map is not restored
// would only be a second node's licence to resolve it again.
// ---------------------------------------------------------------------------
const CLAIM_SKEW_MS = 60 * 1000;


interface Saml2SsoDeps {
  zlib: typeof zlib;
  realms: typeof realms;
  crypto: typeof crypto;
  xmldom: typeof xmldom;
  stsCrypto: typeof stsCrypto;
  app: typeof app;
  helpers: typeof helpers;
  validation: typeof validation;
  config: typeof config;
  errorCodes: typeof errorCodes;
  saml2: typeof saml2;
  spMetadata: typeof spMetadata;
  mtls: typeof mtls;
  requestSignature: typeof requestSignature;
  audit: typeof audit;
  authn: typeof authn;
  gate: typeof gate;
  applications: typeof applications;
  mode: typeof mode;
  authnContext: typeof authnContext;
  documentSettings: typeof documentSettings;
  returnAddress: typeof returnAddress;
  personAttributes: typeof personAttributes;
  clusterClaims: typeof clusterClaims;
  capabilities: typeof capabilities;
}

class Saml2Sso {
  constructor(private readonly deps: Saml2SsoDeps) {
    deps.helpers.log.debug("Entering Saml2Sso.constructor().");
    deps.helpers.log.debug("Leaving Saml2Sso.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): Saml2SsoDeps {
    helpers.log.debug("Entering Saml2Sso.defaultDeps().");
    helpers.log.debug("Leaving Saml2Sso.defaultDeps().");
    return {
      zlib: zlib,
      realms: realms,
      crypto: crypto,
      xmldom: xmldom,
      stsCrypto: stsCrypto,
      app: app,
      helpers: helpers,
      validation: validation,
      config: config,
      errorCodes: errorCodes,
      saml2: saml2,
      spMetadata: spMetadata,
      mtls: mtls,
      requestSignature: requestSignature,
      audit: audit,
      authn: authn,
      gate: gate,
      applications: applications,
      mode: mode,
      authnContext: authnContext,
      documentSettings: documentSettings,
      returnAddress: returnAddress,
      personAttributes: personAttributes,
      clusterClaims: clusterClaims,
      capabilities: capabilities
    };
  }

  // How many artifacts are waiting to be resolved, for the console.
  artifactCount(): number {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.artifactCount().");
    log.debug("Leaving Saml2Sso.artifactCount().");
    return artifacts.size;
  }

  // How many AuthnRequests are held for a sign-in, for the console.
  pendingRequestCount(): number {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.pendingRequestCount().");
    log.debug("Leaving Saml2Sso.pendingRequestCount().");
    return pendingRequests.size;
  }

  // Every route this profile answers, in the order the file always registered
  // them. The four handlers mounted twice are bound once.
  registerRoutes(app: typeof import('../common/app')): void {
    const { baseUrlOf, iso, log, randomId, xmlEscape } = this.deps.helpers;
    const self = this;
    const serveMetadata = this.serveMetadata.bind(this);
    const singleSignOn = this.singleSignOn.bind(this);
    const resolveArtifact = this.resolveArtifact.bind(this);
    const singleLogout = this.singleLogout.bind(this);
    log.debug("Entering Saml2Sso.registerRoutes().");
    // **THIS IS THE FIFTH SCRIPTED PAGE IN THIS SERVICE AND THE ARGUMENT IS
    // MADE AGAIN RATHER THAN BY ANALOGY**, which is what the root CLAUDE.md
    // asks for. `app.js` sets `script-src 'none'` on every response, and the
    // reason is in its own comment: it makes the family of reflected-content
    // problems moot rather than merely unlikely. The HTTP POST binding (section
    // 3.5) IS a self-submitting form — the message travels in the body of a
    // form POST, which is what keeps a response that can be several kilobytes
    // of signed XML out of a URL, a log and a Referer header — so there is no
    // version of this binding without one. The exception is the same shape as
    // the other four and no wider: `script-src 'self'` naming ONE resource,
    // never `'unsafe-inline'`. And the submit button is not a fallback nobody
    // sees — with scripting off the button IS the mechanism, so it is labelled
    // for a person rather than hidden.
    //
    // `form-action` is deliberately absent from the policy, here as everywhere:
    // the form posts to the assertion consumer service, which is by definition
    // another origin, and `form-action 'self'` would block the response from
    // ever reaching the service provider. The symptom is a sign-in that appears
    // to succeed while the service provider never hears anything.
    app.get(BASE_PATH + '/autopost.js', function (req, res) {
      log.debug("Serving the SAML 2.0 HTTP POST binding auto-post script.");
      res.set('Content-Security-Policy',
              app.contentSecurityPolicy({ 'style-src': null,
                                                                     'img-src':
                                                                       null }));
      res.type('application/javascript')
         .set('Cache-Control', 'no-store')
         .send(AUTOPOST_SCRIPT);
    });

    app.get(BASE_PATH, function (req, res) {
      log.debug("Entering the SAML 2.0 description page.");
      const base = baseUrlOf(req);
      const where = self.endpointsFor(base, '');
      self.sendPage(res, 200, 'SAML 2.0 — Web Browser SSO',
             '<h1>SAML 2.0 — Web Browser SSO, all three bindings</h1>' +
             '<p class="sub">Identity provider <code>' +
               xmlEscape(self.idpEntityIdFor('')) +
             '</code> ' +
             'at <code>' + xmlEscape(base) + '</code></p><p>A full SAML 2.0 ' +
             'identity provider: HTTP Redirect and HTTP POST for the ' +
             'request, and HTTP POST, HTTP Redirect or HTTP Artifact for the ' +
             'response, with a SOAP artifact resolution service behind the ' +
             'third. It accepts ANY entityID — a service provider does not ' +
             'have to be provisioned here before it can be pointed at this ' +
             'service, and the first valid AuthnRequest from an entityID ' +
             'creates its application entry in the embedded ' +
             'directory.</p><h2>The ' +
             'endpoints</h2><table><thead><tr><th>Endpoint</th><th>What it ' +
             'is</th></tr></thead><tbody><tr><td><a href="' + SSO_PATH + '">' +
               SSO_PATH + '</a></td><td>Single ' +
               'Sign-On. ' +
               '<code>' + SSO_PATH + '/{sp}</code> is the same service ' +
               'scoped to one service ' +
               'provider.</td></tr><tr><td><code>' + ARS_PATH +
             '</code></td><td>Artifact ' +
               'Resolution, SOAP over HTTP. A browser never touches it — the ' +
               'service provider calls it directly, which is the whole point ' +
               'of the artifact profile.</td></tr><tr><td><a ' +
               'href="' + SLO_PATH + '">' + SLO_PATH + '</a></td><td>Single ' +
               'Logout, both directions.</td></tr><tr><td><a ' +
               'href="' + METADATA_PATH + '">' + METADATA_PATH +
                 '</a></td><td>The ' +
               'signed identity provider metadata. ' +
               '<code>' + METADATA_PATH + '/{sp}</code> ' +
               'is a document of its OWN for that service provider — a ' +
               'different entityID and different endpoints — and it is ' +
               'minted for any {sp} asked for.</td></tr><tr><td><a ' +
               'href="' + SP_PATH + '">' + SP_PATH + '</a></td><td>A mock ' +
               'service provider. NON-SPEC, the default assertion consumer ' +
               'service, and where a response can be verified check by check ' +
               'without a second ' +
               'service.</td></tr></tbody></table><h2>Per-service-provider ' +
               'metadata</h2><p>Every service provider gets its own identity ' +
               'provider, the way Okta and Ping do it. Ask for <code>' +
                 METADATA_PATH + '/{anything}</code> and ' +
             'it is minted — the entityID may be a percent-encoded URL or a ' +
             'plain name:</p><ul><li><a ' +
             'href="' + METADATA_PATH + '/example-sp">' + METADATA_PATH +
             '/example-sp</a></li><li><code>' + METADATA_PATH + '/' +
             encodeURIComponent('https://sp.example.com/saml') +
             '</code></li></ul><p><code>saml2.perApplicationEntityId</code> ' +
             'turns the per-application entityID off; the endpoints stay ' +
             'per-application either way, which is what makes the documents ' +
             'worth having separately.</p><div class="meta"><div>The generic ' +
             'endpoints are <code>' + xmlEscape(where.sso) +
             '</code>, <code>' + xmlEscape(where.slo) + '</code> and <code>' +
             xmlEscape(where.ars) +
             '</code>. They behave identically — the scope in the path ' +
             'decides which identity provider names itself in the answer, ' +
             'and the AuthnRequest\'s own Issuer decides who the assertion ' +
             'is for either way.</div></div>');
      log.debug("Leaving the SAML 2.0 description page.");
    });

    app.get(METADATA_PATH, serveMetadata);
    app.get(METADATA_PATH + '/:sp', serveMetadata);

    app.get(SSO_PATH, singleSignOn);
    app.get(SSO_PATH + '/:sp', singleSignOn);
    // The HTTP POST binding (section 3.5). The one thing to know about it is
    // decision 2: this handler holds the request and turns it into a GET,
    // because the session cookie is SameSite=Lax and does not arrive on a
    // cross-site POST.
    app.post(SSO_PATH, singleSignOn);
    app.post(SSO_PATH + '/:sp', singleSignOn);

    // IDENTITY-PROVIDER-INITIATED SSO (#189): a GET a link on this service,
    // or a portal, sends a browser to; see unsolicitedSignOn().
    const unsolicitedSignOn = this.unsolicitedSignOn.bind(this);
    app.get(UNSOLICITED_PATH, unsolicitedSignOn);
    app.get(UNSOLICITED_PATH + '/:sp', unsolicitedSignOn);

    // THE ATTRIBUTE AUTHORITY (#189), SOAP like the resolver below.
    const attributeQuery = this.attributeQuery.bind(this);
    app.post(AA_PATH, attributeQuery);
    app.post(AA_PATH + '/:sp', attributeQuery);

    app.post(ARS_PATH, resolveArtifact);
    app.post(ARS_PATH + '/:sp', resolveArtifact);
    // A GET on the artifact resolution service is a person who clicked it, and
    // answering "Cannot POST" would send them looking for a typo.
    app.get(ARS_PATH, function (req, res) {
      log.debug("Entering the artifact resolution service description page.");
      // The base this request reached — global.publicBaseUrl when that is set —
      // rather than the literal http://localhost:8081 this example carried
      // until 2026-09-12, which was wrong for every deployment but one.
      const base = baseUrlOf(req);
      self.sendPage(res, 200, 'Artifact Resolution Service — SAML 2.0',
             '<h1>Artifact Resolution Service</h1><p class="sub">SOAP over ' +
             'HTTP (saml-bindings-2.0-os section 3.2.3), at <code>' +
             ARS_PATH + '</code></p><p>This endpoint takes a POST whose body ' +
             'is a SOAP 1.1 envelope carrying a ' +
             '<code>&lt;samlp:ArtifactResolve&gt;</code>, and answers with ' +
             'one carrying a <code>&lt;samlp:ArtifactResponse&gt;</code> ' +
             'with the message inside it. It is a BACK CHANNEL: the browser ' +
             'never touches it, which is the whole point of the artifact ' +
             'profile — the assertion never passes through the user agent at ' +
             'all.</p><h2>By hand</h2><pre>' + xmlEscape(
               'curl -s -X POST ' + base + ARS_PATH + " \\\n  -H " +
               "'Content-Type: text/xml; charset=utf-8' -H 'SOAPAction: " +
               "\"\"' \\\n  -d '<soap:Envelope xmlns:soap=\"" + NS_SOAP +
                 "\"><soap:Body>" +
               '<samlp:ArtifactResolve xmlns:samlp="' + NS_SAMLP +
                 '" xmlns:saml="' +
               NS_SAML + '" ' +
               'ID="_1" Version="2.0" IssueInstant="' + iso(0) + '">' +
               '<saml:Issuer>https://sp.example.com/saml</saml:Issuer>' +
               '<samlp:Artifact>THE-SAMLart-VALUE</samlp:Artifact>' +
               "</samlp:ArtifactResolve></soap:Body></soap:Envelope>'") +
                 '</pre><div ' +
             'class="meta"><div>An artifact resolves EXACTLY ONCE — section ' +
             '3.6.4.1 — so running that command twice with the same artifact ' +
             'is refused the second time, by design. It also expires: ' +
             '<code>saml2.artifactTtlS</code>.</div></div>');
      log.debug("Leaving the artifact resolution service description page.");
    });

    app.get(SLO_PATH, singleLogout);
    app.get(SLO_PATH + '/:sp', singleLogout);
    app.post(SLO_PATH, singleLogout);
    app.post(SLO_PATH + '/:sp', singleLogout);

    app.get(SP_PATH, function (req, res) {
      log.debug("Entering the mock service provider (GET).");
      const base = baseUrlOf(req);
      const spEntityId = base + SP_PATH;
      const acsUrl = base + SP_PATH;
      const destination = base + SSO_PATH;

      // A response can also arrive HERE by GET — the HTTP Redirect binding for
      // a response, and the artifact binding's SAMLart. Both are answered by
      // the same verification the POST below runs, because what arrived is the
      // same document.
      const params: any = self.paramsOf(req);
      if (params.SAMLResponse || params.SAMLart) {
        log.debug("Leaving the mock service provider (GET). A response " +
                  "arrived on a GET binding.");
        return self.receiveAtMockSp(req, res, params, base, spEntityId, acsUrl);
      }

      // THE REQUESTS ARE SIGNED (#37), on the Redirect binding's query
      // string, with THIS SERVICE'S key — which the SSO service trusts for
      // this one entityID and no other (implicitCertificatesFor()). The last
      // link is deliberately UNSIGNED, which is accepted or refused depending
      // on saml2.requireSignedAuthnRequests: both answers are worth seeing.
      const kinds = [
        { binding: BINDING_POST, sign: true },
        { binding: BINDING_REDIRECT, sign: true },
        { binding: BINDING_ARTIFACT, sign: true },
        { binding: BINDING_POST, sign: false }
      ];
      const links = kinds.map(function (kind) {
        const binding = kind.binding;
        const built = self.spAuthnRequest(base, spEntityId, acsUrl, binding,
                                          destination);
        // 128 bits (#65), section 13's floor for a value that looks up state.
        const relayState = 'sp-' + randomId(16);
        spContexts.set(relayState, { requestId: built.id, binding: binding,
                                     expires: Date.now() +
                                       self.spContextTtlMs() });
        spContexts.forEach(function (v, k) {
          if (v.expires < Date.now()) spContexts.delete(k);
        });
        let query = 'SAMLRequest=' +
          encodeURIComponent(self.encodeRedirect(built.xml)) +
          '&RelayState=' + encodeURIComponent(relayState);
        if (kind.sign) {
          const sigAlg = self.deps.documentSettings.signatureOptions().sigAlg;
          query += '&SigAlg=' + encodeURIComponent(sigAlg);
          query += '&Signature=' +
            encodeURIComponent(self.signQueryString(query, sigAlg));
        }
        const url = destination + '?' + query;
        const label = binding === BINDING_POST ? 'HTTP POST' :
          (binding === BINDING_REDIRECT ? 'HTTP Redirect' : 'HTTP Artifact');
        return '<li><a href="' + xmlEscape(url) + '">Response over ' + label +
          (kind.sign ? '' : ', from an UNSIGNED request') + '</a> ' +
          '— the request goes on the Redirect binding' +
          (kind.sign ? ', signed' : ' with no signature') + ', and ' +
          '<code>ProtocolBinding</code> asks for the answer on ' +
          label + '.' + (binding === BINDING_ARTIFACT
            ? ' The browser will carry a <code>SAMLart</code> back here and ' +
              'this page resolves it.' : '') +
          (kind.sign ? '' : ' ' + (self.deps.requestSignature
            .wantsSignedRequests({})
            ? 'This realm requires signed requests, so it is REFUSED.'
            : 'This realm accepts unsigned requests, so it is answered.')) +
          '</li>';
      }).join('');

      const inner = '<h1>Mock service provider</h1><p class="sub">NON-SPEC. ' +
        'A service provider is not part of an identity provider — this one ' +
        'exists so the Web Browser SSO profile can be exercised, and ' +
        'verified, without a second service.</p><p>Its entityID is ' +
        '<code>' + xmlEscape(spEntityId) + '</code>, and it ' +
        'is also the default <code>AssertionConsumerServiceURL</code>: an ' +
        'AuthnRequest that names none is answered here.</p><h2>Start a ' +
        'sign-in</h2><ul>' + links + '</ul>' +
        '<h2>Then</h2><ul>' +
        '<li><a href="' + SLO_PATH + '">Single Logout</a> — ends the session ' +
        'and names every service provider it signed into.</li><li><a ' +
        'href="' + METADATA_PATH + '/' +
          encodeURIComponent(self.slugOf(spEntityId)) +
        '">This ' +
        'service provider\'s own identity provider metadata</a> — a distinct ' +
        'entityID and its own endpoints, which is what makes the metadata ' +
        'unique per application.</li></ul><div class="meta"><div>The first ' +
        'three AuthnRequests are SIGNED on the Redirect binding\'s query ' +
        'string (section 3.4.4.1) with this service\'s own key, and the ' +
        'Single Sign-On service VERIFIES them — the one entityID it trusts ' +
        'that key for is this page\'s. The fourth is unsigned, and whether ' +
        'it is answered is saml2.requireSignedAuthnRequests: off in ' +
        'development, on in product.</div></div>';
      self.sendPage(res, 200, 'Mock service provider — SAML 2.0', inner);
      log.debug("Leaving the mock service provider (GET).");
    });

    app.post(SP_PATH, function (req, res) {
      log.debug("Entering the mock service provider (POST).");
      const base = baseUrlOf(req);
      self.receiveAtMockSp(req, res, self.paramsOf(req), base, base + SP_PATH,
                           base + SP_PATH);
      log.debug("Leaving the mock service provider (POST).");
    });
    log.debug("Leaving Saml2Sso.registerRoutes().");
  }

  // The AuthnRequest interrupted by the sign-in screen, and the AuthnRequest
  // that arrived by POST and has to become a GET before the session cookie is
  // visible. One map for both, because they are the same thing: a request this
  // service is holding while the browser goes somewhere and comes back.
  //
  // `saml2.requestTtlMin` since 2026-09-12 (it was the constant REQUEST_TTL_MS,
  // ten minutes, and the refusal said "ten minutes" in words). Read per use so
  // the console can change it, and the refusal is built from the value.
  private requestTtlMs() {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.requestTtlMs().");
    log.debug("Leaving Saml2Sso.requestTtlMs().");
    return Number(config.value('saml2.requestTtlMin')) * 60 * 1000;
  }

  // The RelayState values the mock service provider below has minted, so it can
  // check the round trip. Its own state and nobody else's, exactly as
  // /wsfed/rp's rpContexts is. `saml2.mockSpContextTtlMin` since 2026-09-12; it
  // was a thirty-minute constant.
  private spContextTtlMs() {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.spContextTtlMs().");
    log.debug("Leaving Saml2Sso.spContextTtlMs().");
    return Number(config.value('saml2.mockSpContextTtlMin')) * 60 * 1000;
  }

  slugOf(identifier) {
    const { crypto } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.slugOf().");
    const text = String(identifier == null ? '' : identifier);
    if (SAFE_SEGMENT.test(text)) {
      log.debug("Leaving Saml2Sso.slugOf().");
      return text;
    }
    log.debug("Leaving Saml2Sso.slugOf().");
    return 'app-' + crypto.createHash('sha256').update(text, 'utf8')
      .digest('hex').slice(0, 12);
  }

  // The entityID a path segment names, and whether this service had heard of
  // it. It never answers "no such service provider" itself: a segment that
  // matches nothing is taken to BE an entityID, which is what makes the
  // metadata endpoint answer for anything asked of it in development — and
  // what `refusedUnregistered()` turns into a 404 in product (decision 1).
  private entityIdFromSegment(segment) {
    const { applications } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering Saml2Sso.entityIdFromSegment(). segment=" +
              (segment || '(none)'));
    const text = String(segment == null ? '' : segment).trim();
    if (!text) {
      log.debug("Leaving Saml2Sso.entityIdFromSegment(). The unscoped " +
                "endpoint.");
      return { entityId: '', known: false, unscoped: true };
    }
    // Express has already percent-decoded the parameter, so an entityID that
    // was encoded into the path arrives whole here.
    const direct = applications.get(text);
    if (direct) {
      log.debug("Leaving Saml2Sso.entityIdFromSegment(). It is a known " +
                "identifier.");
      return { entityId: text, known: true, unscoped: false };
    }
    // A slug, then — which has to be looked for, because it cannot be reversed.
    const match = applications.list().filter(function (row) {
      return self.slugOf(row.identifier) === text;
    })[0];
    if (match) {
      log.debug("Leaving Saml2Sso.entityIdFromSegment(). A slug for " +
                match.identifier +
                ".");
      return { entityId: match.identifier, known: true, unscoped: false };
    }
    log.debug("Leaving Saml2Sso.entityIdFromSegment(). Nothing here knows " +
              "it; it IS the entityID.");
    return { entityId: text, known: false, unscoped: false };
  }

  // IS THE SEGMENT A REGISTERED SAML 2.0 SERVICE PROVIDER (#112)? An entry
  // of the kind, or one DECLARED for the SAML 2.0 family
  // (`appAllowedProtocol`) — not merely any application whose slug matches,
  // because an OAuth client's name is not a service provider this identity
  // provider has agreed to publish itself to.
  private isRegisteredServiceProvider(entityId): boolean {
    const { applications } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.isRegisteredServiceProvider().");
    const record: any = entityId ? applications.get(entityId) : null;
    const answer = !!record &&
      ((record.kinds || []).indexOf('saml2-service-provider') >= 0 ||
       applications.declaredFamiliesOf(record).indexOf('saml2') >= 0);
    log.debug("Leaving Saml2Sso.isRegisteredServiceProvider(). " + answer);
    return answer;
  }

  // THE PER-SERVICE-PROVIDER PATHS ANSWER ONLY FOR A REGISTERED ONE, IN
  // PRODUCT (#112, `mode.publishesMetadataForUnregisteredProviders()`):
  // `/saml2/metadata/{sp}`, `/saml2/sso/{sp}`, `/saml2/slo/{sp}` and
  // `/saml2/ars/{sp}`. A 404 sent HERE, text/plain and `no-store`, with
  // `STS-SAML-0082` — not Express's own 404 body, which is what tells an
  // unrouted path apart (the root CLAUDE.md), and this path IS routed.
  // Development answers for anything, decision 1. True when it answered.
  private refusedUnregistered(res, scoped, path): boolean {
    const { errorCodes, mode } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.refusedUnregistered(). " + path);
    if (!scoped.entityId || mode.publishesMetadataForUnregisteredProviders() ||
        this.isRegisteredServiceProvider(scoped.entityId)) {
      log.debug("Leaving Saml2Sso.refusedUnregistered(). Answered for.");
      return false;
    }
    errorCodes.mark(res, 'STS-SAML-0082');
    res.status(404)
       .type('text/plain')
       .set('Cache-Control', 'no-store')
       .send('There is no SAML 2.0 service provider registered here as "' +
             scoped.entityId + '", so ' + path + ' has nothing to answer ' +
             'for it. This identity provider publishes itself only to a ' +
             'service provider an operator registered (product mode).\n');
    log.debug("Leaving Saml2Sso.refusedUnregistered(). 404.");
    return true;
  }

  // This identity provider's own entityID, for a given service provider. See
  // decision 1 for why there is more than one of them, and
  // `saml2.perApplicationEntityId` for turning that off.
  //
  // **AN EMPTY `saml2.entityId` IS NOT FILLED IN WITH AN INVENTED NAME IN
  // PRODUCT MODE (2026-09-12).** Development still falls back to `urn:sts:idp`,
  // as it always did. A product realm answers '' instead, and
  // `idpEntityIdProblem()` is what the SSO service and the metadata endpoint
  // ask before issuing anything — an identity provider signing assertions under
  // a name nobody configured is publishing an identity nobody can check it
  // against, and `urn:sts:idp` is a development placeholder in a product's
  // signed documents. The predicate is `inventsClaimValues()` because that is
  // the question: may a value be invented where the configuration holds none.
  idpEntityIdFor(spEntityId) {
    const { config, mode } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.idpEntityIdFor().");
    const configured = String(config.value('saml2.entityId') || '').trim();
    const base = configured || (mode.inventsClaimValues() ? 'urn:sts:idp' : '');
    if (!base) {
      log.debug("Leaving Saml2Sso.idpEntityIdFor().");
      return '';
    }
    if (!spEntityId || !config.value('saml2.perApplicationEntityId')) {
      log.debug("Leaving Saml2Sso.idpEntityIdFor().");
      return base;
    }
    log.debug("Leaving Saml2Sso.idpEntityIdFor().");
    return base + ':' + this.slugOf(spEntityId);
  }

  // The sentence a refusal carries when there is no entityID to issue under, or
  // '' when there is one. See idpEntityIdFor().
  private idpEntityIdProblem() {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.idpEntityIdProblem().");
    if (this.idpEntityIdFor('')) {
      log.debug("Leaving Saml2Sso.idpEntityIdProblem().");
      return '';
    }
    log.debug("Leaving Saml2Sso.idpEntityIdProblem().");
    return 'saml2.entityId is empty, and this realm is in PRODUCT mode, ' +
           'where this identity provider does not invent a name to sign ' +
           'assertions under. Set saml2.entityId (the SAML 2.0 console page, ' +
           'POST /admin-api/config/set, or the appconfig file) to the ' +
           'entityID service providers are configured with.';
  }

  // Where this service provider's endpoints live. One function so that the
  // metadata document and the handlers cannot disagree about a URL — the
  // failure that produces is a service provider configured from a document,
  // posting to a path nothing serves, and a 404 that looks like the identity
  // provider is down.
  endpointsFor(base, spEntityId) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.endpointsFor().");
    const suffix = spEntityId ? '/' +
                   encodeURIComponent(this.slugOf(spEntityId)) : '';
    log.debug("Leaving Saml2Sso.endpointsFor().");
    return {
      sso: base + SSO_PATH + suffix,
      slo: base + SLO_PATH + suffix,
      ars: base + ARS_PATH + suffix,
      aa: base + AA_PATH + suffix,
      metadata: base + METADATA_PATH + suffix
    };
  }

  // ---------------------------------------------------------------------------
  // THE REGISTRY.
  //
  // Every entityID this profile answers for gets an application entry, and this
  // is the one place that happens. `counts` is the argument that matters:
  // `applications.seen()` counts an AUTHENTICATION unless told otherwise, and
  // an AuthnRequest arriving is not one — the person may never sign in. So the
  // request records the sighting with `counts: false` and the RESPONSE, which
  // is the moment this service has decided to tell that service provider who
  // somebody is, records the authentication.
  // ---------------------------------------------------------------------------
  private recordServiceProvider(detail) {
    const { applications, config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.recordServiceProvider(). identifier=" +
              (detail.identifier || '(none)'));
    if (!config.value('saml2.autocreateApplications')) {
      log.debug("Leaving Saml2Sso.recordServiceProvider(). " +
                "saml2.autocreateApplications is off.");
      return null;
    }
    const record = applications.seen(detail);
    log.debug("Leaving Saml2Sso.recordServiceProvider().");
    return record;
  }

  // What the registry already knows about this service provider, as plain
  // fields. Absent everywhere the directory is (see applications.js's header —
  // without ldap_server.js there is no registry at all), so every caller has to
  // cope with an empty object rather than with null.
  private fieldsOf(spEntityId) {
    const { applications } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.fieldsOf().");
    const row = spEntityId ? applications.get(spEntityId) : null;
    log.debug("Leaving Saml2Sso.fieldsOf().");
    return (row && row.fields) || {};
  }

  // ---------------------------------------------------------------------------
  // A SERVICE PROVIDER'S SIGNATURE (#37). Decision 3, and
  // `saml/request_signature.ts` for the policy; what is here is the plumbing
  // this file owns — the raw query string, the one implicit anchor, and the
  // audit row.
  // ---------------------------------------------------------------------------

  // The query string EXACTLY AS IT ARRIVED, without the '?'. `req.query` is
  // decoded, and a Redirect-binding signature is over the encoded octets.
  private rawQueryOf(req): string {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.rawQueryOf().");
    const url = String(req.originalUrl || req.url || '');
    const at = url.indexOf('?');
    log.debug("Leaving Saml2Sso.rawQueryOf().");
    return at < 0 ? '' : url.slice(at + 1);
  }

  // THE ONE IMPLICIT TRUST ANCHOR: this service's own certificate, for its own
  // mock service provider, which signs its AuthnRequests with this service's
  // key. Only this process holds that key, so trusting it for that entityID —
  // and no other — lets nothing in that this process did not sign; and it is
  // not written onto the entry, because the key changes on every start in
  // development and a stored copy would go stale.
  private implicitCertificatesFor(base, spEntityId): string[] {
    const { STS, log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.implicitCertificatesFor().");
    const mine = String(spEntityId) === base + SP_PATH;
    log.debug("Leaving Saml2Sso.implicitCertificatesFor(). mock SP=" + mine);
    // The XML key's certificate, in EVERY live generation (#42): the mock
    // SP signs with the current one, and a request signed a moment before a
    // rotation still verifies.
    return mine ? this.deps.helpers.ownRsaCertificates('xml')
      .map(function (one: any): string {
        return stsCrypto.stripPem(one.certPem);
      }) : [];
  }

  // Assess one message's signature, write the audit row, and say whether to
  // refuse. `what` is the root element's local name.
  private checkSignature(req, base, opts): any {
    const { audit, requestSignature, spMetadata } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.checkSignature(). " + opts.what);
    const fields = this.fieldsOf(opts.spEntityId);
    // EXPIRED METADATA FIRST (#37 follow-up): a service provider whose
    // consumed metadata is past its effective validUntil is not believed
    // about anything — its keys and endpoints are the expired document's —
    // so its messages are refused, in every mode, before the signature is
    // looked at. A stale document still works; the refresher replaces it.
    // A service provider with NO consumed metadata starts an MDQ lookup the
    // request never waits on (`sp_metadata.ts`) — which, for an entityID
    // nobody registered, in product is made only with a realm trust anchor
    // and registers only an answer that verifies against one (#112).
    const fresh = spMetadata.freshness(fields);
    if (fresh.state === 'none' && opts.spEntityId &&
        !fields.samlSpMetadataUrl &&
        !this.implicitCertificatesFor(base, opts.spEntityId).length) {
      spMetadata.queueMdqLookup(opts.spEntityId);
    }
    if (fresh.state === 'expired') {
      const expired = {
        signed: false, outcome: 'metadata-expired', binding: '',
        sigAlg: '', weak: false, why: fresh.why, errorCode: 'STS-SAML-0074',
        keyInfoCertificate: '', registered: 0
      };
      audit.audit({
        action: 'saml2.request.signature', outcome: 'refused',
        errorCode: 'STS-SAML-0074', protocol: 'SAML 2.0', channel: 'http',
        target: String(opts.spEntityId || ''),
        summary: 'The ' + opts.what + ' from "' + opts.spEntityId + '" was ' +
                 'refused: ' + fresh.why,
        detail: { message: opts.what, outcome: expired.outcome,
                  expiresAt: fresh.expiresAt }
      });
      log.warn('saml2: refused the ' + opts.what + ' from "' +
               opts.spEntityId + '": ' + fresh.why + '.');
      log.debug("Leaving Saml2Sso.checkSignature(). Metadata expired.");
      return { assessment: expired, observed: '',
               summary: 'metadata-expired - -',
               refusal: { refuse: true, errorCode: 'STS-SAML-0074',
                          title: 'This service provider\'s metadata has ' +
                                 'expired',
                          why: 'The metadata registered for "' +
                               opts.spEntityId + '" expired at ' +
                               fresh.expiresAt + ' (its validUntil), so ' +
                               'nothing it sends is accepted until it is ' +
                               'refreshed — press Refresh or upload a newer ' +
                               'document on the SAML 2.0 page.' } };
    }
    const assessment = requestSignature.assess({
      binding: req.method === 'POST' ? 'post' : 'redirect',
      rawQuery: this.rawQueryOf(req),
      params: opts.params,
      xml: opts.xml,
      rootLocalName: opts.what,
      messageField: opts.field,
      fields: fields,
      implicitCertificates: this.implicitCertificatesFor(base,
                                                         opts.spEntityId)
    });
    const refusal = requestSignature.refusal(assessment, fields);
    const registered = requestSignature.registeredCertificates(fields);
    // THE OBSERVED CERTIFICATE: what this request carried, when it is not
    // already trusted. Written onto the entry by the sighting at step 3, never
    // onto samlSigningCertificate.
    const observed = assessment.keyInfoCertificate &&
      registered.indexOf(assessment.keyInfoCertificate) < 0 &&
      this.implicitCertificatesFor(base, opts.spEntityId)
        .indexOf(assessment.keyInfoCertificate) < 0
      ? assessment.keyInfoCertificate : '';
    audit.audit({
      action: 'saml2.request.signature',
      outcome: refusal.refuse ? 'refused' : 'success',
      errorCode: refusal.refuse ? refusal.errorCode : '',
      protocol: 'SAML 2.0', channel: 'http',
      target: String(opts.spEntityId || ''),
      summary: 'The ' + opts.what + ' from "' +
               (opts.spEntityId || '(unnamed)') + '": signature ' +
               assessment.outcome +
               (assessment.binding ? ' (' + assessment.binding + ' binding, ' +
                                     (assessment.sigAlg || 'no SigAlg') + ')'
                                   : '') +
               (refusal.refuse ? ' — refused' : ''),
      detail: { message: opts.what, outcome: assessment.outcome,
                binding: assessment.binding, sigAlg: assessment.sigAlg,
                weak: assessment.weak, registered: registered.length,
                observedCertificate: !!observed, why: assessment.why }
    });
    if (refusal.refuse) {
      log.warn('saml2: refused the ' + opts.what + ' from "' +
               (opts.spEntityId || '(unnamed)') + '": ' + refusal.why);
    } else if (assessment.outcome !== 'unsigned') {
      log.info('saml2: the ' + opts.what + ' from "' +
               (opts.spEntityId || '(unnamed)') + '" is signed — ' +
               assessment.why + '.');
    }
    log.debug("Leaving Saml2Sso.checkSignature(). " + assessment.outcome +
              (refusal.refuse ? ', refused' : ''));
    return { assessment: assessment, refusal: refusal, observed: observed,
             summary: requestSignature.summary(assessment) };
  }

  // ---------------------------------------------------------------------------
  // THE CONSUMED ENDPOINTS (#37). `samlAcsEndpoint` and `samlSloEndpoint` hold
  // one endpoint per value with the URL last; see their schema rows.
  // ---------------------------------------------------------------------------
  private acsEndpointsOf(fields): any[] {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.acsEndpointsOf().");
    const values = Array.isArray(fields.samlAcsEndpoint)
      ? fields.samlAcsEndpoint
      : (fields.samlAcsEndpoint ? [fields.samlAcsEndpoint] : []);
    const out = values.map(function (value) {
      const parts = String(value).trim().split(/\s+/);
      return parts.length < 4 ? null : {
        index: parts[0] === '-' ? '' : parts[0],
        isDefault: parts[1],
        binding: parts[2],
        location: parts.slice(3).join(' ')
      };
    }).filter(function (one) { return !!one; });
    log.debug("Leaving Saml2Sso.acsEndpointsOf(). " + out.length);
    return out;
  }

  private sloEndpointsOf(fields): any[] {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.sloEndpointsOf().");
    const values = Array.isArray(fields.samlSloEndpoint)
      ? fields.samlSloEndpoint
      : (fields.samlSloEndpoint ? [fields.samlSloEndpoint] : []);
    const out = values.map(function (value) {
      const parts = String(value).trim().split(/\s+/);
      return parts.length < 2 ? null : {
        binding: parts[0], location: parts[1],
        responseLocation: parts[2] || ''
      };
    }).filter(function (one) { return !!one; });
    log.debug("Leaving Saml2Sso.sloEndpointsOf(). " + out.length);
    return out;
  }

  // Can this identity provider deliver on that binding?
  private deliverable(binding): boolean {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.deliverable().");
    log.debug("Leaving Saml2Sso.deliverable().");
    return binding === BINDING_POST || binding === BINDING_REDIRECT ||
           binding === BINDING_ARTIFACT || binding === BINDING_SIMPLESIGN;
  }

  // ---------------------------------------------------------------------------
  // WHICH REGISTERED ASSERTION CONSUMER SERVICE ANSWERS THIS REQUEST, when the
  // service provider's metadata has been consumed (#37). saml-core-2.0-os
  // section 3.4.1 and saml-metadata-2.0-os section 2.2.3, in that order:
  //
  //   * AssertionConsumerServiceIndex names an endpoint: that endpoint, on its
  //     own binding. An index nothing registered is refused (STS-SAML-0069).
  //   * AssertionConsumerServiceURL: it must be one of the registered
  //     locations — IN EVERY MODE, because consuming the metadata was an
  //     operator's registration and a request naming another address is
  //     asking for a response somewhere that registration does not cover
  //     (STS-SAML-0070). The endpoint on the requested ProtocolBinding is
  //     preferred; a URL registered only on another binding is answered on
  //     the binding the request asked for.
  //   * neither: the DEFAULT endpoint — isDefault="true", else the first not
  //     marked false, else the first — among those on the requested
  //     ProtocolBinding if it named one, and among those this identity
  //     provider can deliver on.
  //
  // `{ consumed: false }` when there is nothing consumed, and the caller goes
  // on exactly as it always did.
  // ---------------------------------------------------------------------------
  private registeredAcsFor(request, fields): any {
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering Saml2Sso.registeredAcsFor().");
    const endpoints = this.acsEndpointsOf(fields);
    if (!endpoints.length) {
      log.debug("Leaving Saml2Sso.registeredAcsFor(). Nothing consumed.");
      return { consumed: false };
    }
    if (request.acsIndex !== '') {
      const byIndex = endpoints.filter(function (one) {
        return one.index === String(request.acsIndex);
      })[0];
      if (!byIndex || !this.deliverable(byIndex.binding)) {
        log.debug("Leaving Saml2Sso.registeredAcsFor(). Unknown index.");
        return { consumed: true, ok: false, errorCode: 'STS-SAML-0069',
                 why: 'The AuthnRequest names AssertionConsumerServiceIndex ' +
                      '"' + request.acsIndex + '", and ' +
                      (byIndex
                        ? 'that endpoint\'s binding (' + byIndex.binding +
                          ') is not one this identity provider delivers on.'
                        : 'no AssertionConsumerService in this service ' +
                          'provider\'s consumed metadata has that index. The ' +
                          'registered indexes are: ' +
                          endpoints.map(function (one) {
                            return one.index || '(none)';
                          }).join(', ') + '.') };
      }
      log.debug("Leaving Saml2Sso.registeredAcsFor(). By index.");
      return { consumed: true, ok: true, url: byIndex.location,
               binding: byIndex.binding,
               from: 'AssertionConsumerServiceIndex ' + request.acsIndex +
                     ' in the consumed metadata' };
    }
    const asked = String(request.protocolBinding || '');
    if (request.acsUrl) {
      const same = endpoints.filter(function (one) {
        return one.location === request.acsUrl;
      });
      if (!same.length) {
        log.debug("Leaving Saml2Sso.registeredAcsFor(). URL not registered.");
        return { consumed: true, ok: false, errorCode: 'STS-SAML-0070',
                 why: 'The AssertionConsumerServiceURL "' + request.acsUrl +
                      '" is not one of the ' + endpoints.length +
                      ' assertion consumer service(s) in this service ' +
                      'provider\'s consumed metadata, and a response goes ' +
                      'only where that registration says (compared exactly, ' +
                      'in every mode). Refresh or re-upload the metadata if ' +
                      'the service provider has a new endpoint.' };
      }
      const exact = same.filter(function (one) {
        return !asked || one.binding === asked;
      })[0];
      log.debug("Leaving Saml2Sso.registeredAcsFor(). By URL.");
      return { consumed: true, ok: true, url: request.acsUrl,
               binding: exact ? exact.binding : (asked || same[0].binding),
               from: 'the request, and it is registered in the consumed ' +
                     'metadata' };
    }
    const candidates = endpoints.filter(function (one) {
      return self.deliverable(one.binding) &&
             (!asked || one.binding === asked);
    });
    const chosen = candidates.filter(function (one) {
      return one.isDefault === 'true';
    })[0] || candidates.filter(function (one) {
      return one.isDefault !== 'false';
    })[0] || candidates[0];
    if (!chosen) {
      log.debug("Leaving Saml2Sso.registeredAcsFor(). No usable default.");
      return { consumed: true, ok: false, errorCode: 'STS-SAML-0072',
               why: 'The AuthnRequest names no assertion consumer service, ' +
                    'and none of the ' + endpoints.length + ' in this ' +
                    'service provider\'s consumed metadata is on a binding ' +
                    'this identity provider delivers on' +
                    (asked ? ' that is also the ProtocolBinding asked for (' +
                             asked + ')' : '') + '.' };
    }
    log.debug("Leaving Saml2Sso.registeredAcsFor(). The default.");
    return { consumed: true, ok: true, url: chosen.location,
             binding: chosen.binding,
             from: 'the default assertion consumer service in the consumed ' +
                   'metadata' };
  }

  // The NameIDFormats a service provider's consumed metadata declares.
  private declaredNameIdFormats(fields): string[] {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.declaredNameIdFormats().");
    const raw = fields.samlSpNameIdFormat;
    const list = Array.isArray(raw) ? raw : (raw ? [raw] : []);
    log.debug("Leaving Saml2Sso.declaredNameIdFormats().");
    return list.map(function (one) {
      return String(one).trim();
    }).filter(function (one) {
      return one !== '';
    });
  }

  // saml-core-2.0-os section 3.4.1.1: a NameIDPolicy the identity provider
  // cannot satisfy is answered InvalidNameIDPolicy. That is decided here ONLY
  // for a service provider whose consumed metadata declares its formats — for
  // everybody else a format asked for is a format answered, which is the
  // behaviour this profile exists to exercise. `unspecified` is always
  // acceptable: it asks for nothing in particular.
  private nameIdPolicyProblem(request, fields): string {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.nameIdPolicyProblem().");
    const asked = String(request.nameIdFormat || '');
    const declared = this.declaredNameIdFormats(fields);
    if (!asked || !declared.length || declared.indexOf(asked) >= 0 ||
        asked === 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified') {
      log.debug("Leaving Saml2Sso.nameIdPolicyProblem(). Acceptable.");
      return '';
    }
    log.debug("Leaving Saml2Sso.nameIdPolicyProblem(). Not declared.");
    return 'The NameIDPolicy asks for Format "' + asked + '", and this ' +
           'service provider\'s consumed metadata declares only ' +
           declared.join(', ') + '.';
  }

  // --- reading a message off the wire ----------------------------------------
  // Both bindings, one function. The difference between them is entirely in the
  // ENCODING and in where the signature lives:
  //
  //   HTTP Redirect (3.4)  SAMLRequest is DEFLATE (raw, no zlib header) then
  //                        base64 then URL-encoded, and the signature is a
  //                        DETACHED one over the query string in `Signature`,
  //                        with `SigAlg` naming the algorithm.
  //   HTTP POST (3.5)      SAMLRequest is base64 of the XML with no
  //                        compression, and the signature is an enveloped
  //                        ds:Signature INSIDE the document.
  //
  // The decode accepts either shape whichever binding it arrived on, and that
  // is deliberate: a service provider that DEFLATEs a POST-binding message is
  // out of profile and is also common, and refusing it would produce "invalid
  // request" where the useful answer is the assertion it was asking for. What
  // is NOT guessed at is which binding it was — that comes from the HTTP
  // method.
  // ---------------------------------------------------------------------------
  // **THE INFLATE IS BOUNDED, AND WITHOUT THE BOUND THIS WAS A DECOMPRESSION
  // BOMB (2026-09-06).**
  //
  // The HTTP-Redirect binding carries a DEFLATEd, base64'd message in a query
  // parameter, so this function inflates bytes a caller chose. `inflateRawSync`
  // with no `maxOutputLength` inflates as far as the data says — node's default
  // ceiling is `buffer.kMaxLength`, about two gigabytes.
  //
  // Measured on 2026-09-06: **a 163 KB query string inflates to 120 MB in 100
  // ms at a ratio of 1029:1**, and the ratio is a property of the attacker's
  // input rather than of anything here. A few hundred kilobytes reaches
  // gigabytes.
  //
  // **AND IT IS SYNCHRONOUS ON THE THREAD THAT OWNS EVERY SOCKET.** That is the
  // argument `common/CLAUDE.md` makes about post-quantum signing and the whole
  // reason `common/worker_pool.js` exists: this process runs every listener
  // family on one thread, so a computation like this does not slow the service
  // down, it STOPS it — the KDC stops answering, the directory stops answering,
  // and from the outside that is indistinguishable from a service that is not
  // running.
  //
  // `maxOutputLength` refuses in about a millisecond instead. The ceiling is
  // `CAP.LARGE`, which is the same one `validation.parseXml()` applies to the
  // XML that comes out of here — a SAML message that inflates past a megabyte
  // is not a message this service was going to be able to read anyway.
  //
  // **THE REFUSAL FALLS THROUGH TO THE EXISTING catch**, which reads the bytes
  // as plain XML and hands them on; `parseXml()` then refuses them properly. So
  // a bomb is answered by the same 400 a malformed message gets, and no caller
  // of this function had to change.
  // ---------------------------------------------------------------------------
  private decodeMessage(encoded) {
    const { validation } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.decodeMessage().");
    const buf = Buffer.from(String(encoded || ''), 'base64');
    if (buf.length && buf[0] === 0x3c) {
      log.debug("Leaving Saml2Sso.decodeMessage(). Plain base64 XML.");
      return buf.toString('utf8');
    }
    try {
      const inflated = validation.inflate(buf, 'SAML message');
      if (!inflated.ok) {
        // Not DEFLATEd, or a bomb. Either way the bytes are handed on as plain
        // XML below and `parseXml()` refuses them properly — so a bomb is
        // answered by the same 400 a malformed message gets, and no caller of
        // this function had to change.
        log.debug("Leaving Saml2Sso.decodeMessage(). " + inflated.code + ".");
        return buf.toString('utf8');
      }
      log.debug("Leaving Saml2Sso.decodeMessage(). DEFLATEd.");
      return inflated.value.toString('utf8');
    } catch (e) {
      log.debug("Caught in Saml2Sso.decodeMessage(): " +
                ((e && e.message) || e));
      // Not DEFLATEd after all — a POST-binding message with leading
      // whitespace, most often. Read as plain XML, which is what it then is.
      log.debug("Leaving Saml2Sso.decodeMessage(). Not DEFLATEd: " + e.message);
      return buf.toString('utf8');
    }
  }

  private encodeRedirect(xml) {
    const { zlib } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.encodeRedirect().");
    log.debug("Leaving Saml2Sso.encodeRedirect().");
    return zlib.deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
  }

  private encodePost(xml) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.encodePost().");
    log.debug("Leaving Saml2Sso.encodePost().");
    return Buffer.from(xml, 'utf8').toString('base64');
  }

  // The parameters of a SAML message, from a GET query or a form POST. The body
  // wins on a collision for the reason `wsfed.ts`'s paramsOf() gives: a POST
  // that also carried query parameters said the same thing twice and the body
  // is the half it meant.
  private paramsOf(req): any {
    const { log, parseBody } = this.deps.helpers;
    log.debug("Entering Saml2Sso.paramsOf(). method=" + req.method);
    const out = {};
    Object.keys(req.query ||
                {}).forEach(function (k) { out[k] = req.query[k]; });
    if (req.method === 'POST') {
      const body = parseBody(req);
      Object.keys(body).forEach(function (k) { out[k] = body[k]; });
    }
    log.debug("Leaving Saml2Sso.paramsOf(). " + Object.keys(out).length +
              " parameter(s).");
    return out;
  }

  // --- the pages -------------------------------------------------------------
  // One shell, and it is `wsfed.ts`'s: the CSS is inline because app.js sets
  // `default-src 'none'` with `style-src 'unsafe-inline'`, so a stylesheet as a
  // separate resource would need its own exception to buy nothing.
  private page(title, inner) {
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.page().");
    log.debug("Leaving Saml2Sso.page().");
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width, initial-scale=1">' +
      '<title>' + xmlEscape(title) +
      '</title><style>body{font-family:system-ui,-apple-system,"Segoe UI",' +
      'Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem;color:#222;' +
      'line-height:1.45}.card{background:#fff;border:1px solid ' +
      '#d5d5dd;border-radius:10px;padding:24px 28px;max-width:56rem;margin:0 ' +
      'auto;box-shadow:0 6px 24px ' +
      'rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 ' +
      '4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 ' +
      '.4em}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
      '18px}.row{display:flex;gap:10px;margin-top:20px}button{padding:9px ' +
      '14px;border-radius:5px;border:1px solid ' +
      '#12107c;background:#12107c;color:#fff;font-size:.95em;cursor:pointer}' +
      'button.secondary{background:#fff;color:#12107c}' +
      '.err{background:#fdecea;' +
      'border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;' +
      'border-radius:5px;font-size:.9em;margin-bottom:12px}' +
      '.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px 10px;' +
      'border-radius:5px;font-size:.9em;margin-bottom:12px}' +
      'table{border-collapse:collapse;width:100%;margin:.5rem 0 ' +
      '1rem;font-size:.85em}th,td{border:1px solid #ddd;padding:.35rem ' +
      '.55rem;text-align:left;vertical-align:top}th{background:#f0f0f5}' +
      '.pass{color:#0b6b4f;font-weight:600;white-space:nowrap}' +
      '.fail{color:#b00020;font-weight:600;white-space:nowrap}' +
      '.meta{margin-top:18px;padding-top:12px;border-top:1px solid ' +
      '#eee;font-size:.78em;color:#666;word-break:break-all}.meta ' +
      'div{margin:3px 0}pre{background:#f4f4f8;border:1px solid #e2e2ea;' +
      'border-radius:5px;padding:.6rem;font-size:.75rem;overflow-x:auto;' +
      'white-space:pre-wrap;word-break:break-all}' +
      'code{font-family:ui-monospace,' +
      'SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
      'padding:.1rem .25rem;border-radius:3px;word-break:break-all}' +
      'a{color:#12107c}ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em ' +
      '0}</style></head><body><div ' +
      'class="card">' + inner + '</div></body></html>\n';
  }

  private sendPage(res, status, title, inner) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.sendPage().");
    res.status(status)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .send(this.page(title, inner));
    log.debug("Leaving Saml2Sso.sendPage().");
  }

  // A sentence naming what was wrong, and a status. It is a PAGE and not a SAML
  // error response, and which of the two a failure gets is a real distinction
  // this profile makes: once the assertion consumer service URL is known, an
  // error goes BACK TO THE SERVICE PROVIDER as a <samlp:Response> with a status
  // code, because that is what section 3.2.2 says and because a service
  // provider's error handling is the half of it least likely to have been
  // tested. Before that point there is nowhere to send anything, and the page
  // is the only honest answer — the same position `wsfed.ts` is in for its
  // whole profile.
  // error-code: none — the helper's definition, not a call to it
  private samlError(res, status, title, detail, extra?) {
    const { log, xmlEscape } = this.deps.helpers;
    // error-code: none — the helper's own debug line; each caller marks its
    // code
    log.debug("Entering Saml2Sso.samlError(). status=" + status + ", title=" +
              title);
    const inner = '<h1>' + xmlEscape(title) + '</h1>' +
      '<p class="sub">SAML 2.0 Web Browser SSO at <code>' + SSO_PATH +
      '</code></p><div ' +
      'class="err">' + xmlEscape(detail) + '</div>' + (extra || '') +
      '<div class="meta"><div>This is a page rather than a ' +
      '<code>&lt;samlp:Response&gt;</code> because the request never got as ' +
      'far as naming somewhere to send one. Once an assertion consumer ' +
      'service URL is known, a failure is delivered there as a Response ' +
      'carrying a status code — which is what section 3.2.2 requires and is ' +
      'the error path a service provider is least likely to have exercised. ' +
      'The request is logged in full at debug level.</div></div>';
    res.status(status)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .send(this.page(title, inner));
    // error-code: none — the helper's own debug line; each caller marks its
    // code
    log.debug("Leaving Saml2Sso.samlError().");
  }

  // --- signing ---------------------------------------------------------------
  // The enveloped XML signature this service puts on a Response, an
  // ArtifactResponse and its own metadata. The DIFFERENCE between the three is
  // the reference and where the signature goes, and both are schema-mandated
  // rather than a matter of taste: a protocol message puts ds:Signature after
  // Issuer, and a metadata EntityDescriptor puts it FIRST. Getting either wrong
  // produces a document that verifies and that a strict parser rejects, which
  // is the worst of both.
  private signDocument(xml, rootLocalName, id, placement) {
    const { documentSettings, stsCrypto } = this.deps;
    const { STS, log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.signDocument(). root=" + rootLocalName +
              ", placement=" +
              placement);
    // `after-issuer` for a protocol message, `prepend` for metadata — the two
    // spellings this file has always used, mapped onto the shared signer's
    // names. Kept as two locations rather than two functions because everything
    // else about the signature is identical, and a second function is where the
    // two drift.
    //
    // THE ALGORITHMS ARE THE CONFIGURED ONES since 2026-09-12 —
    // `saml.signatureAlgorithm` and `saml.canonicalizationAlgorithm`, through
    // `document_settings.ts` so every signer in this directory reads one
    // answer.
    const how = documentSettings.signatureOptions();
    const signed = stsCrypto.signXml(xml, {
      // The XML signing key (#42, D2): `STS.xml`, not the JOSE key.
      privateKeyPem: STS.xml.privateKeyPem,
      certPem: STS.xml.certPem,
      sigAlg: how.sigAlg,
      c14nAlg: how.c14nAlg,
      placement: placement === 'prepend'
        ? stsCrypto.PLACEMENT.FIRST : stsCrypto.PLACEMENT.AFTER_ISSUER,
      // The id is passed explicitly rather than left to the signer to find,
      // because this function is given one and the caller's is authoritative:
      // three of the four documents here are built by a template that put it
      // there, and re-deriving it would be a second opinion about the same
      // value.
      refUri: id ? ('#' + id) : '',
      what: 'SAML 2.0 ' + rootLocalName
    });
    log.debug("Leaving Saml2Sso.signDocument(). " + signed.length +
              " characters.");
    return signed;
  }

  // The HTTP Redirect binding's DETACHED signature (section 3.4.4.1). It is a
  // signature over the QUERY STRING and not over the document, and the order of
  // the parameters in the signed octet string is part of the specification:
  // SAMLRequest or SAMLResponse, then RelayState if there is one, then SigAlg.
  // A verifier rebuilds that string from the parameters as they arrived, so a
  // signer that used a different order produces a signature that verifies
  // nowhere and whose only symptom at the far end is "invalid signature".
  //
  // `sigAlg` is passed in by the caller, which has already written that SAME
  // value into the query string as `SigAlg` — see redirectUrlFor(). Reading the
  // setting a second time here could straddle a console change and sign with
  // one algorithm while telling the verifier another.
  private signQueryString(queryString, sigAlg) {
    const { stsCrypto } = this.deps;
    const { STS, log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.signQueryString().");
    // The XML signing key (#42, D2), which the metadata publishes for it.
    const signature = stsCrypto.signQueryString(queryString,
                                                STS.xml.privateKeyPem, sigAlg);
    log.debug("Leaving Saml2Sso.signQueryString().");
    return signature;
  }

  // --- what a session says ---------------------------------------------------
  // The shape this file has always used — `{ classRef, multiFactor, hardwareKey
  // }` — over the one shared reading in `saml/authn_context.ts`. See the note
  // above AC_MULTIFACTOR for why the reading moved and what it fixed.
  private authnContextFor(session) {
    const { authnContext } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.authnContextFor().");
    const read = authnContext.forSession(session);
    log.debug("Leaving Saml2Sso.authnContextFor(). " + read.kind + ".");
    return { classRef: read.saml2, multiFactor: read.multiFactor,
             hardwareKey: read.hardwareKey, kind: read.kind };
  }

  // --- reading an AuthnRequest
  // ------------------------------------------------ Everything section 3.4.1
  // of saml-core puts on one, plus the two things the bindings put beside it.
  // Nothing here REFUSES anything: an attribute this service does not act on is
  // recorded so that the log and the console can show what the service provider
  // actually sent, which for a debugging service is the whole point.
  private readAuthnRequest(xml): any {
    const { validation } = this.deps;
    const { firstByLocal, log, textByLocal } = this.deps.helpers;
    log.debug("Entering Saml2Sso.readAuthnRequest().");
    // **THIS PARSE ANSWERED 500 TO A MALFORMED `SAMLRequest` UNTIL
    // 2026-09-06.** `@xmldom/xmldom` 0.9.10 THROWS a ParseError from its
    // default handler where older versions carried on with a partial tree, and
    // this call sat outside any try/catch — so a malformed message was an
    // uncaught exception rather than the refusal three lines below, which this
    // function already knew how to give. `validation.parseXml()` never throws.
    const read = validation.parseXml(xml, 'AuthnRequest');
    if (!read.ok) {
      log.debug("Leaving Saml2Sso.readAuthnRequest(). " + read.detail);
      return { ok: false, why: read.detail };
    }
    const doc = read.value;
    const root = doc.documentElement;
    if (!root || root.localName !== 'AuthnRequest') {
      log.debug("Leaving Saml2Sso.readAuthnRequest(). It is not an " +
                "AuthnRequest.");
      return { ok: false,
               why: 'the message is <' + (root ? root.localName : 'nothing') +
                               '> and this endpoint reads ' +
                               '<samlp:AuthnRequest>' };
    }
    const policy = firstByLocal(root, 'NameIDPolicy');
    const requested = firstByLocal(root, 'RequestedAuthnContext');
    const out = {
      ok: true,
      xml: xml,
      id: root.getAttribute('ID') || '',
      version: root.getAttribute('Version') || '',
      issueInstant: root.getAttribute('IssueInstant') || '',
      destination: root.getAttribute('Destination') || '',
      protocolBinding: root.getAttribute('ProtocolBinding') || '',
      acsUrl: root.getAttribute('AssertionConsumerServiceURL') || '',
      acsIndex: root.getAttribute('AssertionConsumerServiceIndex') || '',
      forceAuthn: String(root.getAttribute('ForceAuthn') || '') === 'true',
      isPassive: String(root.getAttribute('IsPassive') || '') === 'true',
      issuer: textByLocal(root, 'Issuer'),
      nameIdFormat: policy ? (policy.getAttribute('Format') || '') : '',
      allowCreate: policy ?
                   String(policy.getAttribute('AllowCreate') || '') === 'true' :
                   false,
      subjectHint: '',
      requestedAuthnContexts: [],
      signed: !!firstByLocal(root, 'Signature'),
      signingCertificate: ''
    };
    // A <saml:Subject> on an AuthnRequest is the service provider saying WHO it
    // expects — section 3.4.1 allows it and most identity providers ignore it.
    // This one reads it as a hint to pre-fill the sign-in screen with, which is
    // exactly what OIDC's `login_hint` gets, and never as an assertion about
    // who is at the browser.
    const subject = firstByLocal(root, 'Subject');
    if (subject) {
      const nameId = firstByLocal(subject, 'NameID');
      out.subjectHint = nameId ? (nameId.textContent || '').trim() : '';
    }
    if (requested) {
      const refs = requested.getElementsByTagNameNS('*',
                                                    'AuthnContextClassRef');
      for (let i = 0; i < refs.length; i++) {
        out.requestedAuthnContexts.push((refs[i].textContent || '').trim());
      }
    }
    // `signed` and `signingCertificate` above are provisional: whether the
    // request is signed, and which certificate its OWN signature carries, are
    // `saml/request_signature.ts`'s to say (decision 3), and singleSignOn()
    // replaces both with its assessment. A `ds:X509Certificate` anywhere in
    // the document is not evidence of anything — it could sit in a Subject
    // or an Extensions element — so this no longer reads one.
    log.debug("Leaving Saml2Sso.readAuthnRequest(). id=" + out.id +
              ", issuer=" +
              out.issuer +
              ", binding=" + (out.protocolBinding || '(unstated)'));
    return out;
  }

  // Which binding the RESPONSE goes back on. The request's ProtocolBinding
  // says, and HTTP POST is the default when it says nothing — which is section
  // 4.1.2's own default and is what every service provider that omits it
  // expects. A binding this service does not implement is named in the refusal
  // rather than silently downgraded to POST: a service provider that asked for
  // PAOS and received a form post would conclude that PAOS worked.
  private responseBindingFor(request) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.responseBindingFor(). asked=" +
              (request.protocolBinding || '(none)'));
    const asked = String(request.protocolBinding || '');
    if (!asked) {
      log.debug("Leaving Saml2Sso.responseBindingFor(). HTTP POST, the " +
                "default.");
      return { binding: BINDING_POST, stated: false };
    }
    if (asked === BINDING_POST || asked === BINDING_REDIRECT ||
        asked === BINDING_ARTIFACT || asked === BINDING_SIMPLESIGN) {
      log.debug("Leaving Saml2Sso.responseBindingFor(). " + asked);
      return { binding: asked, stated: true };
    }
    log.debug("Leaving Saml2Sso.responseBindingFor(). It is not one this " +
              "service has.");
    return { error: asked };
  }

  // ---------------------------------------------------------------------------
  // THE FIVE SETTINGS ON THIS PAGE ARE PER SERVICE PROVIDER, AND THIS IS THE
  // ONE PLACE THAT IS DECIDED.
  //
  // `settingFor(sp, 'saml2.signAssertion')` is the value for THAT service
  // provider: what its application entry says if it carries the matching
  // attribute, and `saml2.signAssertion` itself if it does not. The five are
  // the assertion lifetime, the two signature switches, the default NameID
  // format and the artifact lifetime; `/admin/saml-assertions` draws the
  // defaults and names the attribute beside each one.
  //
  // EVERY CALLER PASSES AN ENTITYID AND SOME OF THEM HAVE TO BE HANDED ONE.
  // That is the whole cost of this feature in this file: `buildResponse()`,
  // `deliver()` and `stashArtifact()` are reached from paths that knew the
  // service provider and were not carrying it, so they now take it. A caller
  // with nothing to pass passes '' and gets the service-wide value, which is
  // what this service did everywhere before 2026-08-27.
  //
  // IT IS NOT CACHED, deliberately. The lookup is a read of an in-memory
  // directory, and a cache would be a second place the value lived — the thing
  // `applications.js`'s header spends three paragraphs refusing.
  private settingFor(spEntityId, key) {
    const { applications, config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.settingFor().");
    log.debug("Leaving Saml2Sso.settingFor().");
    return applications.settingFor(spEntityId, key, config);
  }

  // ---------------------------------------------------------------------------
  // ENCRYPTION: WHOSE KEY, WHICH ALGORITHMS, AND WHAT HAPPENS WHEN THERE IS NO
  // KEY AT ALL.
  //
  // THE CERTIFICATE IS LOOKED FOR IN THREE PLACES, most specific first:
  //
  //   1. `samlEncryptionCertificate` on the entry — which the metadata refresh
  //      writes from a <md:KeyDescriptor use="encryption">, and which can also
  //      be typed for a service provider whose metadata this service cannot
  //      reach.
  //   2. a REGISTERED `samlSigningCertificate` — from consumed metadata or an
  //      operator. Using a signing key to encrypt to is not what a careful
  //      deployment does; it is the right default for a mock.
  //   3. the OBSERVED `samlObservedSigningCertificate` off a signed
  //      AuthnRequest's ds:KeyInfo — IN DEVELOPMENT ONLY since 2026-09-17
  //      (#37), `mode.encryptsToObservedCertificates()`. It is what lets a
  //      service provider that signs its requests receive an encrypted
  //      assertion with no configuration at all; product does not encrypt to a
  //      key anybody could have put in a request, until an operator confirms
  //      it. Until #37 this step was the second, and the certificate it read
  //      was written straight onto `samlSigningCertificate`.
  //   4. Nothing, and this is the case the whole design turns on.
  //
  // WITH NO CERTIFICATE THE DOCUMENT GOES OUT IN CLEAR AND SAYS SO LOUDLY. It
  // is not refused: a mock that stopped issuing because a key was missing would
  // be useless exactly when somebody is setting this up. It is not silent
  // either — silently sending plaintext while a console page says "encrypted"
  // is the worst of the three, because the person testing their client would
  // believe the wrong thing about what their client accepted. So it is logged
  // at WARN, every time, naming the application and what to do about it.
  private encryptionCertificateFor(spEntityId): any {
    const { applications, mode, spMetadata } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.encryptionCertificateFor(). sp=" +
              (spEntityId || '(none)'));
    const record = spEntityId ? applications.get(spEntityId) : null;
    const fields = (record && record.fields) || {};
    const first = function (value) {
      log.debug("Entering first().");
      const one = Array.isArray(value) ? value[0] : value;
      log.debug("Leaving first().");
      return String(one == null ? '' : one).trim();
    };
    const configured = first(fields.samlEncryptionCertificate);
    if (configured) {
      log.debug("Leaving Saml2Sso.encryptionCertificateFor(). Its own " +
                "encryption certificate.");
      return { pem: spMetadata.toPem(configured),
               source: 'samlEncryptionCertificate' };
    }
    // THE FIRST REGISTERED SIGNING CERTIFICATE THAT CAN BE ENCRYPTED TO:
    // since the #37 follow-up a service provider may sign with EC, EdDSA or a
    // post-quantum key, and key transport here wraps to RSA.
    const rsaOnly = function (value) {
      log.debug("Entering rsaOnly().");
      const list = Array.isArray(value) ? value : (value ? [value] : []);
      log.debug("Leaving rsaOnly().");
      return list.map(function (one) {
        return String(one).trim();
      }).filter(function (one) {
        return one && !spMetadata.certificateProblem(one);
      })[0] || '';
    };
    const signing = rsaOnly(fields.samlSigningCertificate);
    if (signing) {
      log.debug("Leaving Saml2Sso.encryptionCertificateFor(). Its signing " +
                "certificate.");
      return { pem: spMetadata.toPem(signing),
               source: 'samlSigningCertificate' };
    }
    const observed = rsaOnly(fields.samlObservedSigningCertificate);
    if (observed && mode.encryptsToObservedCertificates()) {
      log.debug("Leaving Saml2Sso.encryptionCertificateFor(). The observed " +
                "certificate, in development.");
      return { pem: spMetadata.toPem(observed),
               source: 'samlObservedSigningCertificate (observed, not ' +
                       'confirmed — development mode only)' };
    }
    log.debug("Leaving Saml2Sso.encryptionCertificateFor(). There is none.");
    return { pem: '', source: '',
             observedWithheld: !!observed };
  }

  // The two algorithm choices for one service provider, each falling back to
  // the setting. A value the enum does not know is IGNORED with a warning
  // rather than used — `applications.settingFor()` already refuses one that
  // fails the setting's own check, and this second guard catches the case where
  // the SETTING itself was widened and an entry still names something retired.
  private encryptionAlgorithmsFor(spEntityId) {
    const { log } = this.deps.helpers;
    const { BLOCK_CIPHERS, KEY_TRANSPORTS } = this.deps.saml2;
    log.debug("Entering Saml2Sso.encryptionAlgorithmsFor().");
    const algorithm = String(this.settingFor(spEntityId,
                                             'saml2.encryptionAlgorithm') ||
                                               '');
    const keyTransport = String(
      this.settingFor(spEntityId, 'saml2.keyTransportAlgorithm') || '');
    log.debug("Leaving Saml2Sso.encryptionAlgorithmsFor().");
    return {
      algorithm: BLOCK_CIPHERS[algorithm] ? algorithm : 'aes256-gcm',
      keyTransport: KEY_TRANSPORTS[keyTransport] ?
        keyTransport : 'rsa-oaep-mgf1p'
    };
  }

  // Encrypt `xml` for this service provider, or hand back the plaintext and say
  // why. ONE function for the assertion and the logout NameID, differing only
  // in the wrapper element — the same argument encryptElement() itself makes.
  private encryptFor(spEntityId, xml, wrapper, what) {
    const { errorCodes } = this.deps;
    const { log } = this.deps.helpers;
    const { encryptElement } = this.deps.saml2;
    log.debug("Entering Saml2Sso.encryptFor(). sp=" + (spEntityId || '(none)') +
              ", as=" +
              wrapper);
    const cert = this.encryptionCertificateFor(spEntityId);
    if (!cert.pem) {
      log.warn('saml2: ' + (spEntityId || 'this service provider') + ' is ' +
               'configured to have ' +
               'its ' + what + ' ENCRYPTED and this service holds no ' +
               'certificate to encrypt to, so it is going out IN CLEAR. Set ' +
               'samlSpMetadataUrl and refresh the metadata, upload its ' +
               'metadata, or set samlEncryptionCertificate by hand' +
               (cert.observedWithheld
                 ? '. A signed request\'s certificate is on the entry as ' +
                   'OBSERVED and this realm does not encrypt to it until it ' +
                   'is confirmed on the SAML 2.0 page.'
                 : ' — in development mode a signed request\'s certificate ' +
                   'is used as a fallback.'));
      log.debug("Leaving Saml2Sso.encryptFor(). No certificate; plaintext.");
      return { xml: xml, encrypted: false, why: 'no certificate' };
    }
    const how = this.encryptionAlgorithmsFor(spEntityId);
    try {
      const out = encryptElement(xml, cert.pem,
        { algorithm: how.algorithm, keyTransport: how.keyTransport,
          wrapper: wrapper });
      log.info('saml2: the ' + what + ' for ' + (spEntityId || '(unnamed)') +
               ' ' +
               'is encrypted ' +
               '(' + how.algorithm + ', key wrapped with ' + how.keyTransport +
               ', ' +
               'to the certificate on ' + cert.source + ').');
      log.debug("Leaving Saml2Sso.encryptFor(). Encrypted.");
      return { xml: out, encrypted: true, algorithm: how.algorithm,
               keyTransport: how.keyTransport, source: cert.source };
    } catch (e) {
      log.debug("Caught in Saml2Sso.encryptFor(): " +
                ((e && e.message) || e));
      // A certificate that parsed and will not encrypt — an EC key, most
      // likely, since XML Encryption key transport here wraps to RSA. Plaintext
      // and a warning, for the reason the missing-certificate case above gives.
      log.error(errorCodes.tag('STS-SAML-0012') + 'saml2: the ' + what +
                ' for ' +
                (spEntityId || '(unnamed)') + ' ' +
                'could not be encrypted ' +
                '(' + e.message + '), so it is going out IN CLEAR. ' +
                'The certificate ' +
                'on ' + cert.source + ' is readable but cannot be encrypted ' +
                'to — an EC key is the usual cause, since key transport here ' +
                'wraps to RSA.');
      log.debug("Leaving Saml2Sso.encryptFor(). Failed; plaintext.");
      return { xml: xml, encrypted: false, why: e.message };
    }
  }

  // The NameID Format to answer with. See `saml2.nameIdFormat`: a request
  // naming a format gets that format back, whatever it is — and where it does
  // not, the service provider's own `saml2NameIdFormat` decides before the
  // setting does.
  private nameIdFormatFor(request, spEntityId?) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.nameIdFormatFor().");
    const asked = String(request.nameIdFormat || '');
    if (asked) {
      log.debug("Leaving Saml2Sso.nameIdFormatFor().");
      return asked;
    }
    const configured = String(
      this.settingFor(spEntityId, 'saml2.nameIdFormat') ||
      'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
    // A SERVICE PROVIDER THAT DECLARED ITS FORMATS (#37) is answered in one
    // of them: the configured default where it is declared, otherwise the
    // first declared format this identity provider publishes, otherwise the
    // first declared.
    const declared = spEntityId
      ? this.declaredNameIdFormats(this.fieldsOf(spEntityId)) : [];
    if (!declared.length || declared.indexOf(configured) >= 0) {
      log.debug("Leaving Saml2Sso.nameIdFormatFor().");
      return configured;
    }
    const published = declared.filter(function (one) {
      return NAMEID_FORMATS.indexOf(one) >= 0;
    });
    log.debug("Leaving Saml2Sso.nameIdFormatFor(). From the metadata.");
    return published[0] || declared[0];
  }

  // The NameID VALUE. Every format but one is answered with the username,
  // because this service invents no second identifier for somebody and a
  // `persistent` value that was really the username is at least honest about
  // being the username. `transient` is the exception and has to be: the
  // format's whole meaning is that the value is per-session and opaque, so
  // answering it with a stable username would be a lie a service provider
  // cannot detect.
  private nameIdValueFor(format, session) {
    const { crypto, personAttributes } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.nameIdValueFor(). format=" + format);
    const username = (session.user && session.user.username) || '';
    if (format === 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') {
      // Derived from the session so that two requests inside one browser
      // session get the SAME transient id, which is what a service provider
      // correlating two logins in one session expects, and a new one after
      // signing out.
      const handle = crypto.createHash('sha256')
        .update(String(session.id || '') + '|' + username, 'utf8')
                           .digest('hex')
                           .slice(0, 32);
      log.debug("Leaving Saml2Sso.nameIdValueFor(). A transient identifier.");
      return '_' + handle;
    }
    if (format === 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress') {
      // The PERSON's mail address — invented in development, off the directory
      // entry in product (see person_attributes.ts). With neither, the
      // username, which is what this always fell back to.
      log.debug("Leaving Saml2Sso.nameIdValueFor(). The mail address.");
      return personAttributes.personFor(session.user).email || username;
    }
    log.debug("Leaving Saml2Sso.nameIdValueFor(). The username.");
    return username;
  }

  private attributesFor(sessionUser) {
    const { personAttributes } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.attributesFor(). user=" +
              sessionUser.username);
    // THE PERSON, and the rows with nothing in them left OUT (2026-09-12). In
    // development `userFor()` invents all four persona facts and this is
    // exactly the list it always was. In product it invents none, so the facts
    // come off the directory entry or are omitted — see person_attributes.ts —
    // rather than being signed as <AttributeValue>undefined</AttributeValue>.
    const user = personAttributes.personFor(sessionUser);
    const attributes = personAttributes.withoutAbsent([
      { name: CLAIM_NS + '/name', nameFormat: ATTRNAME_FORMAT_URI,
        value: user.username },
      { name: CLAIM_NS + '/givenname', nameFormat: ATTRNAME_FORMAT_URI,
        value: user.given_name },
      { name: CLAIM_NS + '/surname', nameFormat: ATTRNAME_FORMAT_URI,
        value: user.family_name },
      { name: CLAIM_NS + '/emailaddress', nameFormat: ATTRNAME_FORMAT_URI,
        value: user.email },
      { name: CLAIM_NS + '/nameidentifier', nameFormat: ATTRNAME_FORMAT_URI,
        value: user.sub },
      // The unqualified four. A service provider configured against Keycloak or
      // Shibboleth keys off these, and one configured against AD FS keys off
      // the URIs above; sending both is what makes this mock usable against
      // either without a mapper being written first. They are distinct Name
      // values, so this is not one attribute said twice — it is the same fact
      // under the two names the ecosystem actually uses.
      { name: 'uid', nameFormat: ATTRNAME_FORMAT_BASIC, value: user.username },
      { name: 'mail', nameFormat: ATTRNAME_FORMAT_BASIC, value: user.email },
      { name: 'givenName', nameFormat: ATTRNAME_FORMAT_BASIC,
        value: user.given_name },
      { name: 'sn', nameFormat: ATTRNAME_FORMAT_BASIC,
        value: user.family_name },
      { name: 'displayName', nameFormat: ATTRNAME_FORMAT_BASIC,
        value: user.name },
      // AND THE SAML V2.0 X.500/LDAP ATTRIBUTE PROFILE'S NAMES (#189): the
      // LDAP attribute's OID as a `urn:oid:` URN in the `uri` name format,
      // with its LDAP name as FriendlyName. They are what a Shibboleth or
      // SimpleSAMLphp service provider's stock attribute map reads — the two
      // spellings above are Keycloak's and AD FS's — and without them the
      // Shibboleth SP 3 skipped every attribute this service sent.
      { name: 'urn:oid:0.9.2342.19200300.100.1.1', friendlyName: 'uid',
        nameFormat: ATTRNAME_FORMAT_URI, value: user.username },
      { name: 'urn:oid:0.9.2342.19200300.100.1.3', friendlyName: 'mail',
        nameFormat: ATTRNAME_FORMAT_URI, value: user.email },
      { name: 'urn:oid:2.5.4.42', friendlyName: 'givenName',
        nameFormat: ATTRNAME_FORMAT_URI, value: user.given_name },
      { name: 'urn:oid:2.5.4.4', friendlyName: 'sn',
        nameFormat: ATTRNAME_FORMAT_URI, value: user.family_name },
      { name: 'urn:oid:2.16.840.1.113730.3.1.241',
        friendlyName: 'displayName', nameFormat: ATTRNAME_FORMAT_URI,
        value: user.name }
    ]);
    log.debug("Leaving Saml2Sso.attributesFor(). " + attributes.length +
              " attribute(s).");
    return attributes;
  }

  // --- building the response
  // --------------------------------------------------
  private statusElement(code, subCode, message) {
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.statusElement().");
    log.debug("Leaving Saml2Sso.statusElement().");
    return '<samlp:Status><samlp:StatusCode Value="' + xmlEscape(code) + '">' +
      (subCode ? '<samlp:StatusCode Value="' + xmlEscape(subCode) +
       '"/>' : '') +
      '</samlp:StatusCode>' +
      (message ?
       '<samlp:StatusMessage>' + xmlEscape(message) + '</samlp:StatusMessage>' :
       '') +
      '</samlp:Status>';
  }

  // A <samlp:Response>, with or without an assertion in it. One builder for the
  // success and the failure alike, because the two differ by exactly one child
  // element and a status code — and because an error response that took a
  // different code path is an error response nobody ever looks at. `opts.sp` is
  // the SERVICE PROVIDER'S entityID and is what makes the signature switch per
  // application — NOT `opts.issuer`, which is this identity provider's own
  // entityID and is a DIFFERENT string per service provider when
  // `saml2.perApplicationEntityId` is on. Passing the issuer here would have
  // looked right, found no application entry under it, and silently used the
  // service-wide default every time.
  private buildResponse(opts) {
    const { errorCodes } = this.deps;
    const { genId, iso, log, logArtifact, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.buildResponse(). status=" + opts.status);
    const id = genId();
    const xml =
      '<samlp:Response xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' + NS_SAML +
        '" ' +
        'ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
        (opts.destination ? ' Destination="' + xmlEscape(opts.destination) +
         '"' :
         '') +
        (opts.inResponseTo ?
         ' InResponseTo="' + xmlEscape(opts.inResponseTo) + '"' : '') +
        '><saml:Issuer>' + xmlEscape(opts.issuer) + '</saml:Issuer>' +
        this.statusElement(opts.status, opts.subStatus, opts.statusMessage) +
        (opts.assertion || '') +
      '</samlp:Response>';
    logArtifact('SAML 2.0 Response', 'before signing', xml);
    if (!this.settingFor(opts.sp || '', 'saml2.signResponse')) {
      log.debug("Leaving Saml2Sso.buildResponse(). Unsigned: " +
                "saml2.signResponse is off.");
      return { xml: xml, id: id, signed: false };
    }
    try {
      const signed = this.signDocument(xml, 'Response', id, 'after-issuer');
      logArtifact('SAML 2.0 Response', 'after signing', signed);
      log.debug("Leaving Saml2Sso.buildResponse(). Signed.");
      return { xml: signed, id: id, signed: true };
    } catch (e) {
      log.debug("Caught in Saml2Sso.buildResponse(): " +
                ((e && e.message) || e));
      // Reported and returned unsigned rather than thrown, exactly as
      // buildSamlAssertion() does: an unsigned response that a service provider
      // rejects is a diagnosable failure, and an exception here is a 500 that
      // says nothing about SAML at all.
      log.error(errorCodes.tag('STS-SAML-0013') + 'the SAML 2.0 Response ' +
                                                  'could not be signed, ' +
                                                  'sending it unsigned: ' +
                                                    e.message);
      log.debug("Leaving Saml2Sso.buildResponse(). Unsigned after a signing " +
                "failure.");
      return { xml: xml, id: id, signed: false };
    }
  }

  // The assertion, from the one builder. Everything the Web Browser SSO profile
  // requires of it and nothing this file decided for itself — see decision 4.
  private buildAssertionFor(request, session, spEntityId, idpEntityId, acsUrl) {
    const { config } = this.deps;
    const { iso, log } = this.deps.helpers;
    const { buildSamlAssertion } = this.deps.saml2;
    log.debug("Entering Saml2Sso.buildAssertionFor(). sp=" + spEntityId);
    const user = session.user;
    const context = this.authnContextFor(session);
    const lifetimeMin = Number(this.settingFor(spEntityId,
                                               'saml2.assertionLifetimeMin')) ||
                                                 60;
    const format = this.nameIdFormatFor(request, spEntityId);
    const assertion = buildSamlAssertion(user.username, spEntityId, lifetimeMin,
                                         {
      issuer: idpEntityId,
      authnContextClassRef: context.classRef,
      nameIdFormat: format,
      nameIdValue: this.nameIdValueFor(format, session),
      // saml-profiles-2.0-os section 4.1.4.2: the bearer assertion MUST carry a
      // Recipient that matches the assertion consumer service URL it was
      // delivered to, and an InResponseTo that matches the request. A service
      // provider that checks either — and most do — refuses an assertion
      // without them, with a message that reads like a signature problem.
      subjectConfirmation: {
        recipient: acsUrl,
        inResponseTo: request.id,
        // The SAME instant as the Conditions/NotOnOrAfter the builder computes,
        // saml.clockSkewS included. Two expiries inside one assertion that
        // disagree by the skew is the kind of defect a service provider reports
        // as "assertion expired" while the console shows a window that has not
        // closed, so this reads the setting the builder reads rather than
        // re-deriving the lifetime on its own.
        notOnOrAfter: iso(lifetimeMin +
          Math.max(0, Number(config.value('saml.clockSkewS')) || 0) / 60)
      },
      // The SESSION, not the assertion, is what a LogoutRequest names later.
      // This is the line that makes Single Logout able to find anything.
      sessionIndex: session.id,
      authnInstant: new Date((session.authTime || 0) * 1000).toISOString(),
      attributes: this.attributesFor(user),
      sign: this.signsAssertionFor(spEntityId)
    });
    log.debug("Leaving Saml2Sso.buildAssertionFor(). " + assertion.length +
              " characters.");
    return assertion;
  }

  // ---------------------------------------------------------------------------
  // WHETHER THE ASSERTION IS SIGNED (#37). `saml2.signAssertion` for this
  // service provider — unless its consumed metadata says
  // WantAssertionsSigned="true", which a PRODUCT realm honours whatever the
  // setting says: an unsigned assertion to a service provider that asked for a
  // signed one is a response weaker than the registration asked for, which is
  // `mode.sendsWeakerThanAsked()`'s question. Development honours the setting,
  // because turning it off is the test case that setting exists for, and says
  // that the service provider asked otherwise.
  // ---------------------------------------------------------------------------
  private signsAssertionFor(spEntityId): boolean {
    const { mode } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.signsAssertionFor().");
    const configured = !!this.settingFor(spEntityId, 'saml2.signAssertion');
    const wanted = String(this.fieldsOf(spEntityId)
                            .samlSpWantAssertionsSigned || '') === 'TRUE';
    if (configured || !wanted) {
      log.debug("Leaving Saml2Sso.signsAssertionFor(). " + configured);
      return configured;
    }
    if (!mode.sendsWeakerThanAsked()) {
      log.info('saml2: saml2.signAssertion is off for "' + spEntityId +
               '", and its metadata says WantAssertionsSigned="true"; this ' +
               'realm is in PRODUCT mode, so the assertion is signed.');
      log.debug("Leaving Saml2Sso.signsAssertionFor(). Signed anyway.");
      return true;
    }
    log.warn('saml2: saml2.signAssertion is off for "' + spEntityId + '", ' +
             'whose metadata says WantAssertionsSigned="true". Development ' +
             'mode sends the assertion UNSIGNED as configured; product would ' +
             'sign it.');
    log.debug("Leaving Saml2Sso.signsAssertionFor(). Unsigned, as set.");
    return false;
  }

  private postBindingPage(destination, field, message, relayState, note,
                          extra?) {
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.postBindingPage(). destination=" +
              destination);
    const inner = '<h1>' + xmlEscape(note.title) + '</h1>' +
      '<p class="sub">' + note.sub + '</p>' +
      '<form method="post" action="' + xmlEscape(destination) + '" ' +
        'id="saml2-form"><input type="hidden" ' +
        'name="' + field + '" value="' + xmlEscape(message) + '">' +
        (relayState !== undefined && relayState !== null && relayState !== ''
          ? '<input type="hidden" name="RelayState" value="' +
            xmlEscape(relayState) + '">' : '') +
        (extra || []).map(function (pair) {
          return '<input type="hidden" name="' + pair[0] + '" value="' +
                 xmlEscape(pair[1]) + '">';
        }).join('') +
        '<div class="row"><button type="submit">Continue to ' +
      xmlEscape(note.who) +
        '</button></div>' +
      '</form>' +
      '<div class="meta">' +
      '<div>posting to: <code>' + xmlEscape(destination) + '</code></div>' +
      '<div>field: <code>' + field + '</code>, ' + message.length + ' base64 ' +
      'characters</div><div>RelayState: ' +
      (relayState ? '<code>' + xmlEscape(relayState) +
        '</code>, echoed byte for byte' : 'the request carried none, so none ' +
                                          'is returned') + '</div><div>The ' +
      'form submits itself from ' +
      '<code>' + BASE_PATH + '/autopost.js</code>. ' +
      'It is a separate resource because this service sets <code>script-src ' +
      '\'none\'</code> on every response and this page relaxes it to ' +
      '<code>\'self\'</code> — an inline script would not run, and the ' +
      'button would be the only thing that worked. With scripting off, the ' +
      'button IS the mechanism.</div></div><script ' +
      'src="' + BASE_PATH + '/autopost.js"></script>';
    log.debug("Leaving Saml2Sso.postBindingPage().");
    return inner;
  }

  private sendPostBinding(res, title, inner) {
    const { app } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.sendPostBinding().");
    res.set('Content-Security-Policy',
            app.contentSecurityPolicy({ 'script-src': "'self'" }));
    res.status(200)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .send(this.page(title, inner));
    log.debug("Leaving Saml2Sso.sendPostBinding().");
  }

  // A message on the HTTP Redirect binding: DEFLATE, base64, URL-encode, and —
  // when this service signs its responses — the detached signature of section
  // 3.4.4.1 over the octet string in the order that section fixes.
  private redirectUrlFor(destination, field, xml, relayState, spEntityId) {
    const { documentSettings } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.redirectUrlFor(). field=" + field);
    // THE ENVELOPED SIGNATURE COMES OFF (saml-bindings-2.0-os section
    // 3.4.4.1): on this binding the query string is what is signed, below. It
    // was left on until #192, and a LogoutRequest from here then reached
    // Keycloak with an XML signature it does not read on this binding and no
    // SigAlg, which it refuses.
    let qs = field + '=' + encodeURIComponent(this.encodeRedirect(
      this.withoutEnvelopedSignature(xml)));
    if (relayState) {
      qs += '&RelayState=' + encodeURIComponent(relayState);
    }
    if (this.settingFor(spEntityId || '', 'saml2.signResponse')) {
      // ONE read of the algorithm for both halves: the SigAlg the verifier is
      // told and the algorithm the octets are signed with. See
      // signQueryString().
      const sigAlg = documentSettings.signatureOptions().sigAlg;
      qs += '&SigAlg=' + encodeURIComponent(sigAlg);
      qs += '&Signature=' + encodeURIComponent(this.signQueryString(qs,
                                                                    sigAlg));
    }
    const url = destination + (destination.indexOf('?') >= 0 ? '&' : '?') + qs;
    log.debug("Leaving Saml2Sso.redirectUrlFor(). " + url.length +
              " characters.");
    return url;
  }

  // THE SimpleSign FORM (#37 follow-up): the message base64'd as the POST
  // binding does it, with its enveloped signature taken OFF — the binding
  // signs the form values, and says the XML signature is to be removed — and,
  // where `saml2.signResponse` holds for this service provider, `SigAlg` and
  // `Signature` over `SAMLResponse=<b64>[&RelayState=<rs>]&SigAlg=<alg>`, the
  // octets `request_signature.ts`'s `simpleSignOctets()` checks.
  // THE MESSAGE WITHOUT ITS OWN ENVELOPED SIGNATURE: the one after the
  // root's Issuer (or first in the root). Both detached bindings sign the
  // octets instead and say the XML signature is to be removed —
  // saml-bindings-2.0-os section 3.4.4.1 for HTTP-Redirect, and the
  // SimpleSign binding's section 2.5 — and a signature inside the assertion
  // is not touched.
  private withoutEnvelopedSignature(xml) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.withoutEnvelopedSignature().");
    log.debug("Leaving Saml2Sso.withoutEnvelopedSignature().");
    return String(xml).replace(
      /^(<[^>]*>(?:\s*<(?:[A-Za-z_][\w.-]*:)?Issuer\b[\s\S]*?<\/(?:[A-Za-z_][\w.-]*:)?Issuer>)?)\s*<(?:[A-Za-z_][\w.-]*:)?Signature\b[\s\S]*?<\/(?:[A-Za-z_][\w.-]*:)?Signature>/,
      '$1');
  }

  private simpleSignFields(field, xml, relayState, spEntityId) {
    const { documentSettings } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.simpleSignFields().");
    const bare = this.withoutEnvelopedSignature(xml);
    const message = this.encodePost(bare);
    const extra = [];
    if (this.settingFor(spEntityId || '', 'saml2.signResponse')) {
      const sigAlg = documentSettings.signatureOptions().sigAlg;
      // THE RAW XML, NOT ITS BASE64 (the SimpleSign binding, section 2.5;
      // `request_signature.ts`'s `simpleSignOctets()` says what this got
      // wrong until #189).
      const octets = field + '=' + bare +
        (relayState ? '&RelayState=' + relayState : '') +
        '&SigAlg=' + sigAlg;
      extra.push(['SigAlg', sigAlg]);
      extra.push(['Signature', this.signQueryString(octets, sigAlg)]);
    }
    log.debug("Leaving Saml2Sso.simpleSignFields(). signed=" +
              (extra.length > 0));
    return { message: message, extra: extra };
  }

  // The artifact of section 3.6.4: a four-byte header and two twenty-byte
  // halves.
  //
  //   TypeCode        0x0004, which is the only artifact type SAML 2.0 defines
  //   EndpointIndex   which ArtifactResolutionService to come back to; this
  //                   service publishes one, at index 0
  //   SourceID        SHA-1 of the ISSUER's entityID — not a hash for security,
  //                   an INDEX, so that a service provider talking to several
  //                   identity providers can tell whose artifact it is holding
  //                   without asking anybody
  //   MessageHandle   twenty random bytes, and the only part that is a secret
  //
  // The whole 44 bytes are base64, which is what travels in `SAMLart`.
  private mintArtifact(idpEntityId, endpointIndex) {
    const { crypto } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.mintArtifact(). idp=" + idpEntityId);
    const header = Buffer.alloc(4);
    header.writeUInt16BE(0x0004, 0);
    header.writeUInt16BE(endpointIndex || 0, 2);
    const sourceId = crypto.createHash('sha1')
                           .update(String(idpEntityId), 'utf8')
                           .digest();
    const handle = crypto.randomBytes(20);
    const artifact = Buffer.concat([header, sourceId,
                                    handle]).toString('base64');
    log.debug("Leaving Saml2Sso.mintArtifact(). " + artifact.length +
              " base64 characters.");
    return artifact;
  }

  private stashArtifact(artifact, detail) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.stashArtifact().");
    // Off the service provider this artifact was minted FOR, which `detail`
    // already carried before this was per application.
    const ttlS = Number(this.settingFor(detail.spEntityId || '',
                                        'saml2.artifactTtlS'));
    // `|| 300` used to follow the read, which turned a configured 0 — an
    // artifact that expires the moment it is minted, a legitimate negative test
    // — into five minutes (2026-09-12). Only a value that is not a number at
    // all falls back.
    const ttlSUsable = isFinite(ttlS) && ttlS >= 0 ? ttlS : 300;
    artifacts.set(artifact,
                  Object.assign({ expires: Date.now() + ttlSUsable * 1000 },
                                detail));
    artifacts.forEach(function (v, k) {
      if (v.expires < Date.now()) artifacts.delete(k);
    });
    log.debug("Leaving Saml2Sso.stashArtifact().");
  }

  // Deliver a built message to a service provider, on whichever binding was
  // asked for. One function for the sign-in response and the logout response
  // alike, because the three bindings are a property of SAML and not of the
  // message.
  private deliver(res, opts) {
    const { config } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.deliver(). binding=" + opts.binding);
    if (opts.binding === BINDING_ARTIFACT) {
      const artifact = this.mintArtifact(opts.issuer, 0);
      this.stashArtifact(artifact, {
             xml: opts.xml, spEntityId: opts.spEntityId, issuer: opts.issuer,
             inResponseTo: opts.inResponseTo, createdAt: Date.now()
      });
      let url = opts.destination +
        (opts.destination.indexOf('?') >= 0 ? '&' : '?') +
        'SAMLart=' + encodeURIComponent(artifact);
      if (opts.relayState) {
        url += '&RelayState=' + encodeURIComponent(opts.relayState);
      }
      log.info('saml2: artifact ' + artifact.slice(0, 12) + '… stands for a ' +
               opts.field +
               ' for ' + (opts.spEntityId || '(unnamed)') + '; it is ' +
                   'resolvable once, at ' +
               ARS_PATH + '.');
      // 303, not 302: this may follow the POST that carried the AuthnRequest,
      // and a 307 would repeat that body at the service provider. The same
      // reasoning authn.js's returnToCaller() writes down at length.
      res.set('Cache-Control', 'no-store').redirect(303, url);
      log.debug("Leaving Saml2Sso.deliver(). By artifact.");
      return;
    }
    if (opts.binding === BINDING_REDIRECT) {
      const url = this.redirectUrlFor(opts.destination, opts.field, opts.xml,
                                      opts.relayState,
                                      opts.spEntityId);
      const warnAt = Number(config.value('saml2.redirectWarnLength'));
      if (url.length > warnAt) {
        // Not refused — reported. Section 4.1.2 says the Redirect binding MUST
        // NOT be used for a response because it will typically exceed what a
        // user agent permits, and this service lets it happen anyway because a
        // service provider with no server behind its ACS has no other way to
        // receive one. What it will not do is let the truncation be discovered
        // as a mystery.
        log.warn('saml2: this redirect-binding response is ' + url.length +
                 ' ' +
                 'characters, which is past saml2.redirectWarnLength ' +
                 '(' + warnAt + ') and past what ' +
                 'several browsers and most CDNs carry. Section 4.1.2 says ' +
                 'the Redirect binding MUST NOT be used for a response for ' +
                 'exactly this reason. It is being sent anyway; ask for ' +
                 'ProtocolBinding=HTTP-POST or HTTP-Artifact instead.');
      }
      res.set('Cache-Control', 'no-store').redirect(303, url);
      log.debug("Leaving Saml2Sso.deliver(). By redirect.");
      return;
    }
    if (opts.binding === BINDING_SIMPLESIGN) {
      const form = this.simpleSignFields(opts.field, opts.xml,
                                         opts.relayState, opts.spEntityId);
      this.sendPostBinding(res, opts.note.title,
                           this.postBindingPage(opts.destination, opts.field,
                                                form.message, opts.relayState,
                                                opts.note, form.extra));
      log.debug("Leaving Saml2Sso.deliver(). By SimpleSign.");
      return;
    }
    this.sendPostBinding(res, opts.note.title,
                         this.postBindingPage(opts.destination, opts.field,
                                              this.encodePost(opts.xml),
                                              opts.relayState, opts.note));
    log.debug("Leaving Saml2Sso.deliver(). By form POST.");
  }

  // ---------------------------------------------------------------------------
  // THE SINGLE SIGN-ON SERVICE.
  //
  // The whole of the profile's front half is here, and it runs in five steps
  // that are worth naming because each one can end the request:
  //
  //   1. read the message off whichever binding it arrived on
  //   2. hold it and become a GET, if it arrived by POST — see decision 2
  //   3. work out where the response goes, because after this point a failure
  //      can be REPORTED to the service provider instead of shown on a page
  //   4. get a session, which may mean going to the sign-in screen and back
  //   5. build the response and deliver it on the binding that was asked for
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // ONE AuthnRequest ID IS ANSWERED ONCE (#190).
  //
  // saml-core-2.0-os section 3.2.1 makes the ID unique per message, and a
  // request replayed at this service — out of a proxy log, or a browser's
  // history — would otherwise start a new sign-in and deliver a fresh
  // assertion in answer to a request its service provider sent long ago. So
  // the first arrival of a request CLAIMS its issuer and ID for as long as a
  // request can be fresh (`requestWindowMs()`), through the cluster's claim
  // store, before anything else reads it; a second arrival is refused with
  // STS-SAML-0088 once the rest of the request has been checked (below, in
  // singleSignOnChecked()). A store that cannot be asked refuses too
  // (STS-SAML-0089): fail closed, as the artifact's claim does.
  //
  // The claim is answered in this process, synchronously, where this process
  // holds no shared claims table (`claimInProcess()`), and awaited where it
  // does. A held request coming back (`rid`) was claimed on its first arrival.
  // ---------------------------------------------------------------------------
  private singleSignOn(req, res) {
    const { clusterClaims } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.singleSignOn().");
    const params: any = this.paramsOf(req);
    if (params.rid || !params.SAMLRequest) {
      log.debug("Leaving Saml2Sso.singleSignOn(). Nothing to claim.");
      return this.singleSignOnChecked(req, res, null);
    }
    const request: any = this.readAuthnRequest(
      this.decodeMessage(params.SAMLRequest));
    const issuer = request.ok
      ? (request.issuer || this.entityIdFromSegment(req.params.sp).entityId)
      : '';
    if (!request.ok || !request.id || !issuer) {
      // Unreadable, or naming no issuer or no ID: refused by the checks the
      // claim would only have run ahead of.
      log.debug("Leaving Saml2Sso.singleSignOn(). Nothing claimable.");
      return this.singleSignOnChecked(req, res, null);
    }
    const spec = { scope: 'saml2.authnrequest',
                   value: issuer + '\n' + request.id,
                   ttlMs: this.requestWindowMs() + CLAIM_SKEW_MS };
    const now = clusterClaims.claimInProcess(spec);
    if (now) {
      log.debug("Leaving Saml2Sso.singleSignOn(). Claimed in process.");
      return this.singleSignOnChecked(req, res, now);
    }
    log.debug("Leaving Saml2Sso.singleSignOn(). Asking the claim store.");
    return clusterClaims.claim(spec).then((claimed) => {
      return this.singleSignOnChecked(req, res, claimed);
    });
  }

  // How long a request is FRESH (#190): as long as one may be held at the
  // sign-in screen (`saml2.requestTtlMin`). Older, and its IssueInstant is
  // refused; the ID claim above lives as long.
  private requestWindowMs() {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.requestWindowMs().");
    log.debug("Leaving Saml2Sso.requestWindowMs().");
    return this.requestTtlMs();
  }

  // ---------------------------------------------------------------------------
  // THE MESSAGE'S OWN ENVELOPE (#190): what the service provider said about
  // the message itself, checked after its signature and before anything is
  // acted on. pysaml2, scripted to send each of these wrong, found every one
  // of them ANSWERED until #190.
  //
  //   Version       "2.0" (saml-core-2.0-os section 3.2.2.1: anything else is
  //                 a version this service does not speak) — STS-SAML-0087
  //   IssueInstant  present, an xs:dateTime, no later than now plus a minute
  //                 of clock disagreement (CLAIM_SKEW_MS) and no earlier than
  //                 the freshness window before it — STS-SAML-0086
  //   Destination   where present, the URL the message ARRIVED at: section
  //                 3.2.1 requires the recipient to check it and to discard a
  //                 message addressed elsewhere, and saml-bindings-2.0-os
  //                 sections 3.4.5.2 and 3.5.5.2 require it on a signed
  //                 message — whose signature is then about THIS endpoint —
  //                 so it is REQUIRED when the message is signed.
  //                 STS-SAML-0085
  //
  // `null` when it is in order; otherwise { errorCode, title, why }.
  // ---------------------------------------------------------------------------
  private envelopeProblem(req, base, spec): any {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.envelopeProblem(). " + spec.what);
    if (spec.version !== '2.0') {
      log.debug("Leaving Saml2Sso.envelopeProblem(). Version.");
      return { errorCode: 'STS-SAML-0087',
               title: 'That ' + spec.what + ' is not SAML 2.0',
               why: 'Its Version is "' + spec.version + '"; this endpoint ' +
                    'speaks SAML 2.0 (saml-core-2.0-os section 3.2.2.1).' };
    }
    const issued = Date.parse(String(spec.issueInstant || ''));
    const now = Date.now();
    if (!spec.issueInstant || isNaN(issued) ||
        issued > now + CLAIM_SKEW_MS ||
        issued < now - this.requestWindowMs() - CLAIM_SKEW_MS) {
      log.debug("Leaving Saml2Sso.envelopeProblem(). IssueInstant.");
      return { errorCode: 'STS-SAML-0086',
               title: 'That ' + spec.what + ' is not fresh',
               why: 'Its IssueInstant is "' + (spec.issueInstant || '') +
                    '". A request is accepted from a minute in the future ' +
                    'to ' + Math.round(this.requestWindowMs() / 60000) +
                    ' minute(s) in the past (saml2.requestTtlMin, plus a ' +
                    'minute of clock disagreement); an older one is a ' +
                    'replay or a stale page, and a missing one is not a ' +
                    'SAML message.' };
    }
    const arrivedAt = base + req.path;
    const destination = String(spec.destination || '');
    if (destination ? destination !== arrivedAt : spec.signed) {
      log.debug("Leaving Saml2Sso.envelopeProblem(). Destination.");
      return { errorCode: 'STS-SAML-0085',
               title: 'That ' + spec.what + ' was addressed elsewhere',
               why: destination
                 ? 'Its Destination is "' + destination + '", and it ' +
                   'arrived at "' + arrivedAt + '". saml-core-2.0-os ' +
                   'section 3.2.1 has the recipient discard a message whose ' +
                   'Destination is not the location it was received at — ' +
                   'a signature over a message sent to another endpoint is ' +
                   'not a signature about this one.'
                 : 'It is signed and carries no Destination, which ' +
                   'saml-bindings-2.0-os sections 3.4.5.2 and 3.5.5.2 ' +
                   'require of a signed message, so what it was signed for ' +
                   'cannot be told.' };
    }
    log.debug("Leaving Saml2Sso.envelopeProblem(). In order.");
    return null;
  }

  private singleSignOnChecked(req, res, claimed) {
    const { applications, audit, config, errorCodes, gate, mode,
            returnAddress } = this.deps;
    const { beginAuthentication, notePresented, sessionOf } = this.deps.authn;
    const { baseUrlOf, log, logArtifact, nowSec, randomId } = this.deps.helpers;
    log.debug("Entering Saml2Sso.singleSignOnChecked(). method=" + req.method);
    const base = baseUrlOf(req);
    const params: any = this.paramsOf(req);
    const scoped = this.entityIdFromSegment(req.params.sp);
    if (this.refusedUnregistered(res, scoped, SSO_PATH + '/{sp}')) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). Not registered.");
      return;
    }

    // --- step 2, first, because it decides whether there is anything to read
    // --- A held request being resumed: either the browser has come back from
    // the sign-in screen, or a POST-binding request has just been turned into a
    // GET.
    const held = params.rid ? pendingRequests.get(String(params.rid)) : null;
    if (params.rid && !held) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "The held request had " +
                "expired.");
      errorCodes.mark(res, 'STS-SAML-0001');
      log.debug("Leaving Saml2Sso.singleSignOnChecked().");
      return this.samlError(res, 400, 'This sign-in request has expired',
        'A request is held for ' + config.value('saml2.requestTtlMin') + ' ' +
        'minute(s) (saml2.requestTtlMin) while the browser is at the sign-in ' +
        'screen. Start the AuthnRequest again from the service provider.');
    }

    const encoded = held ? held.samlRequest : params.SAMLRequest;
    if (!encoded) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "No SAMLRequest, so it " +
                "describes itself.");
      return this.sendPage(res, 200, 'SAML 2.0 Single Sign-On service',
                           this.describeSsoPage(base, scoped));
    }

    const relayState = held ? held.relayState : (params.RelayState || '');
    const arrivedBy = held ? held.arrivedBy :
                      (req.method !== 'POST' ? BINDING_REDIRECT
                        : (params.Signature ? BINDING_SIMPLESIGN
                                            : BINDING_POST));
    const xml = this.decodeMessage(encoded);
    logArtifact('SAML 2.0 AuthnRequest', 'as received on the ' +
                (arrivedBy === BINDING_REDIRECT ? 'HTTP Redirect'
                  : (arrivedBy === BINDING_SIMPLESIGN ? 'HTTP POST SimpleSign'
                                                      : 'HTTP POST')) +
                    ' ' +
                    'binding', xml);
    const request: any = this.readAuthnRequest(xml);
    if (!request.ok) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "The message could not be " +
                "read.");
      errorCodes.mark(res, 'STS-SAML-0002');
      log.debug("Leaving Saml2Sso.singleSignOnChecked().");
      return this.samlError(res, 400, 'That is not an AuthnRequest',
        request.why + '. The Single Sign-On service reads ' +
        '<samlp:AuthnRequest> (saml-core-2.0-os section 3.4.1); a ' +
        '<samlp:LogoutRequest> goes to ' +
        SLO_PATH + '.');
    }
    // --- THE SIGNATURE (#37, decision 3) ------------------------------------
    // Checked ONCE, on the request's first arrival, because that is the only
    // moment the Redirect binding's raw query string exists — the return trip
    // is a GET carrying `rid` and nothing else. The outcome rides on the held
    // record, which is this service's own copy and not something a browser
    // can edit. A signature that fails is refused in every mode; an unsigned
    // request only where one is required. Refused on a PAGE, for the reason an
    // unregistered address is: the AssertionConsumerServiceURL a Response
    // would go to is part of what the signature was meant to protect.
    let verification = held ? held.verification : null;
    if (!verification) {
      const claimed = request.issuer || scoped.entityId;
      const checked = this.checkSignature(req, base, {
        what: 'AuthnRequest', field: 'SAMLRequest', xml: xml,
        params: params, spEntityId: claimed
      });
      if (checked.refusal.refuse) {
        if (claimed && applications.get(claimed)) {
          this.recordServiceProvider({
            identifier: claimed, kind: 'saml2-service-provider',
            protocol: 'SAML 2.0', counts: false,
            note: 'sent an AuthnRequest to the Web Browser SSO profile',
            fields: {
              samlAuthnRequestSigned: checked.assessment.signed ? 'TRUE' :
                                                                  'FALSE',
              samlAuthnRequestVerification: checked.summary
            }
          });
        }
        errorCodes.mark(res, checked.refusal.errorCode || 'STS-SAML-0061');
        log.debug("Leaving Saml2Sso.singleSignOnChecked(). The signature was " +
                  "refused.");
        return this.samlError(res, 403, checked.refusal.title ||
                              'That AuthnRequest\'s signature is not accepted',
                              checked.refusal.why);
      }
      verification = {
        signed: checked.assessment.signed,
        outcome: checked.assessment.outcome,
        binding: checked.assessment.binding,
        sigAlg: checked.assessment.sigAlg,
        weak: checked.assessment.weak,
        why: checked.assessment.why,
        summary: checked.summary,
        observed: checked.observed
      };
    }
    request.signed = !!verification.signed;
    request.sigAlg = String(verification.sigAlg || '');
    request.signingCertificate = String(verification.observed || '');
    request.verification = verification;

    // --- THE ENVELOPE AND THE ID (#190), on the FIRST arrival only: a held
    // request coming back is this service's own copy, already checked and
    // already claimed. Refused on a PAGE, for the signature's reason above.
    if (!held) {
      const problem = this.envelopeProblem(req, base, {
        what: 'AuthnRequest', version: request.version,
        issueInstant: request.issueInstant,
        destination: request.destination, signed: request.signed
      });
      const replay = claimed && !claimed.ok
        ? (claimed.reason === 'used'
          ? { errorCode: 'STS-SAML-0088',
              title: 'That AuthnRequest has already been answered',
              why: 'Its ID "' + request.id + '" from "' +
                   (request.issuer || scoped.entityId) + '" arrived ' +
                   'before. saml-core-2.0-os section 3.2.1 makes a request ' +
                   'ID unique, and one arriving twice is a replay — of a ' +
                   'page from a browser\'s history, or of a message ' +
                   'captured on its way here. Start again from the service ' +
                   'provider.' }
          : { errorCode: 'STS-SAML-0089',
              title: 'That AuthnRequest could not be checked for a replay',
              why: 'The store that remembers which requests were answered ' +
                   'could not be asked (' + String(claimed.why || '') +
                   '), and a request that cannot be shown to be new is ' +
                   'refused rather than answered.' })
        : null;
      const refusal = problem || replay;
      if (refusal) {
        audit.audit({
          action: 'saml2.authnrequest', outcome: 'refused',
          errorCode: refusal.errorCode, protocol: 'SAML 2.0',
          channel: 'http',
          target: String(request.issuer || scoped.entityId || ''),
          summary: 'An AuthnRequest was refused: ' + refusal.title,
          detail: { id: request.id, issueInstant: request.issueInstant,
                    destination: request.destination }
        });
        log.warn('saml2: refused an AuthnRequest from "' +
                 (request.issuer || scoped.entityId || '(unnamed)') + '": ' +
                 refusal.why);
        errorCodes.mark(res, refusal.errorCode);
        log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                  refusal.errorCode);
        // error-code: none — marked above: refusal.errorCode is 0085–0089.
        return this.samlError(res, 400, refusal.title, refusal.why);
      }
    }

    // --- step 2 proper -------------------------------------------------------
    // A POST-binding request has to become a GET before this service can see
    // its own session cookie: the cookie is SameSite=Lax, the POST is
    // cross-site, and the cookie is therefore NOT sent — so a signed-in person
    // would be shown the sign-in screen every time. Holding the request and
    // 303ing to a GET on this same endpoint is a top-level GET navigation,
    // which Lax does carry. This is the difference from ws-federation/wsfed.ts,
    // which answers the same problem with a sign-in screen of its own; see
    // decision 2.
    if (!held && (arrivedBy === BINDING_POST ||
                  arrivedBy === BINDING_SIMPLESIGN)) {
      const record = {
        id: randomId(18), samlRequest: String(encoded),
        relayState: String(relayState || ''),
        arrivedBy: arrivedBy, signature: String(params.Signature || ''),
        sigAlg: String(params.SigAlg || ''), expires: Date.now() +
          this.requestTtlMs(),
        verification: verification
      };
      pendingRequests.set(record.id, record);
      pendingRequests.forEach(function (v, k) {
        if (v.expires < Date.now()) pendingRequests.delete(k);
      });
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "Held and redirected so the " +
                "session cookie is visible.");
      return res.set('Cache-Control', 'no-store')
                .redirect(303,
                          req.path + '?rid=' + encodeURIComponent(record.id));
    }

    // --- step 3: where does the answer go ------------------------------------
    const spEntityId = request.issuer || scoped.entityId;
    if (!spEntityId) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "The request names no " +
                "issuer.");
      errorCodes.mark(res, 'STS-SAML-0003');
      log.debug("Leaving Saml2Sso.singleSignOnChecked().");
      return this.samlError(res, 400, 'The AuthnRequest names no issuer',
        'A <saml:Issuer> is what says which service provider this request is ' +
        'from, and it becomes the assertion\'s audience restriction. An ' +
        'assertion with no audience is one any service provider would be ' +
        'entitled to accept.',
        '<p>There is a mock service provider here that sends a complete ' +
        'request: <a href="' + SP_PATH + '">' + SP_PATH + '</a>.</p>');
    }
    const issuerProblem = this.idpEntityIdProblem();
    if (issuerProblem) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "There is no entityID to " +
                "issue under.");
      errorCodes.mark(res, 'STS-SAML-0004');
      log.debug("Leaving Saml2Sso.singleSignOnChecked().");
      return this.samlError(res, 503, 'This identity provider has no entityID',
                            issuerProblem);
    }
    const idpEntityId = this.idpEntityIdFor(spEntityId);
    const known = this.fieldsOf(spEntityId);
    // The assertion consumer service URL, in the order a real identity provider
    // would take it — except that the middle step, SP metadata, is one this
    // service does not have.
    //
    // **WHETHER IT IS VALIDATED DEPENDS ON THE MODE (2026-09-12).** In
    // development it is not, exactly as WS-Federation's wreply is not and for
    // the same stated reason: that mode accepts arbitrary return URLs on
    // purpose, and a request naming none goes to the registered value or to
    // this service's own mock service provider. In PRODUCT
    // (`mode.acceptsUnregisteredAddresses()` false) the URL must be one of the
    // `samlAssertionConsumerService` values on this service provider's entry, a
    // request naming another is REFUSED on a page — not delivered a failure
    // Response, because the address that Response would go to is the one in
    // question — and there is no mock fallback. `saml/return_address.ts` is the
    // rule, shared with the other two profiles.
    //
    // Either way it must be an absolute http(s) URL, because a form action that
    // is not one posts back to this origin and the failure reads as a service
    // provider that ignored the response.
    //
    // WHICH OF THE ENTRY'S ADDRESSES COUNT is
    // `applications.returnAddressesOf()`'s to say (2026-09-12): in product an
    // ACS URL a development-mode request recorded is still marked OBSERVED and
    // is withheld until an operator confirms it. In development it answers
    // every value, as this line always read.
    //
    // **AND A SERVICE PROVIDER WHOSE METADATA WAS CONSUMED (#37)** is answered
    // at one of the endpoints that metadata registered — by index, by URL or
    // by default — in every mode; see registeredAcsFor(). What it chooses is
    // then held to the same rule as any other address, so an endpoint an
    // operator has since removed from samlAssertionConsumerService is refused
    // in product like any unregistered one.
    const consumedAcs = this.registeredAcsFor(request, known);
    if (consumedAcs.consumed && !consumedAcs.ok) {
      log.info('saml2: refused an AuthnRequest from "' + spEntityId + '": ' +
               consumedAcs.why);
      errorCodes.mark(res, consumedAcs.errorCode || 'STS-SAML-0070');
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). Not a registered " +
                "assertion consumer service.");
      return this.samlError(res, 400, 'That assertion consumer service is ' +
                                      'not registered', consumedAcs.why);
    }
    const acsKnown =
      applications.returnAddressesOf(known,
                                     'samlAssertionConsumerService');
    const acsWhere = returnAddress.resolve({
      requested: consumedAcs.consumed ? consumedAcs.url : request.acsUrl,
      registered: acsKnown.registered,
      unconfirmed: acsKnown.unconfirmed,
      fallback: base + SP_PATH,
      attribute: 'samlAssertionConsumerService',
      parameter: 'AssertionConsumerServiceURL',
      application: spEntityId
    });
    if (!acsWhere.ok) {
      log.info('saml2: refused an AuthnRequest from "' + spEntityId + '": ' +
               acsWhere.why);
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "The assertion consumer " +
                "service is not registered.");
      errorCodes.mark(res, errorCodes.codeOf(acsWhere) || 'STS-SAML-0005');
      log.debug("Leaving Saml2Sso.singleSignOnChecked().");
      return this.samlError(res, 400, 'That assertion consumer service is ' +
                                      'not registered', acsWhere.why);
    }
    const acsUrl = String(acsWhere.url);
    if (!/^https?:\/\//i.test(acsUrl)) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). The ACS URL is not " +
                "absolute.");
      errorCodes.mark(res, 'STS-SAML-0006');
      log.debug("Leaving Saml2Sso.singleSignOnChecked().");
      return this.samlError(res, 400, 'The assertion consumer service URL ' +
                                      'must be absolute',
        'It is "' + acsUrl + '". The response is delivered to that address ' +
        'by form POST, by redirect or as an artifact, and a relative value ' +
        'addresses this service instead — which looks exactly like a service ' +
        'provider that ignored the response.');
    }
    let wanted = this.responseBindingFor(request);
    if (wanted.error) {
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). An unimplemented " +
                "ProtocolBinding was asked for.");
      errorCodes.mark(res, 'STS-SAML-0007');
      log.debug("Leaving Saml2Sso.singleSignOnChecked().");
      return this.samlError(res, 400,
                            'That response binding is not implemented',
        'This request asked for ProtocolBinding="' + wanted.error + '". This ' +
        'identity provider delivers a response over HTTP POST, HTTP Redirect ' +
        'and HTTP Artifact, which are the three its metadata advertises.',
        '<p>It is refused rather than quietly answered over HTTP POST, ' +
        'because a service provider that asked for PAOS and received a form ' +
        'post would conclude that PAOS worked.</p>');
    }
    // The registered endpoint's own binding, where the metadata chose it.
    if (consumedAcs.consumed && this.deliverable(consumedAcs.binding)) {
      wanted = { binding: consumedAcs.binding, stated: true };
    }
    const acsFrom = consumedAcs.consumed ? consumedAcs.from : acsWhere.from;

    // THE SERVICE PROVIDER, recorded now that the request has been understood
    // and before anything can go wrong at the sign-in screen. `counts: false`
    // because an AuthnRequest is not an authentication — the person may never
    // sign in — and counting one here would double every successful flow.
    this.recordServiceProvider({
           identifier: spEntityId,
           kind: 'saml2-service-provider',
           protocol: 'SAML 2.0',
           note: 'sent an AuthnRequest to the Web Browser SSO profile',
           counts: false,
           fields: {
             samlEntityId: spEntityId,
             samlAssertionConsumerService: acsUrl,
             samlNameIdFormat: request.nameIdFormat || '',
             samlResponseBinding: wanted.binding,
             samlAuthnRequestSigned: request.signed ? 'TRUE' : 'FALSE',
             samlAuthnRequestVerification: String(
               request.verification.summary || ''),
             // OBSERVED, never registered — decision 3. Empty when the request
             // carried no certificate or one already trusted.
             samlObservedSigningCertificate: request.signingCertificate || ''
           }
    });

    // THE NAMEIDPOLICY, against a service provider that DECLARED its formats
    // (#37). A Response carrying InvalidNameIDPolicy, which is what section
    // 3.4.1.1 says and what a service provider's error handling should meet.
    const policyProblem = this.nameIdPolicyProblem(request, known);
    if (policyProblem) {
      log.info('saml2: ' + policyProblem + ' Answering "' + spEntityId +
               '" with InvalidNameIDPolicy.');
      pendingRequests.delete(String(params.rid || ''));
      errorCodes.mark(res, 'STS-SAML-0071');
      const refusal = this.buildResponse({
        issuer: idpEntityId, sp: spEntityId,
        destination: acsUrl, inResponseTo: request.id,
        status: STATUS_REQUESTER,
        subStatus: 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
        statusMessage: policyProblem
      });
      this.deliver(res, {
             binding: wanted.binding, destination: acsUrl,
             field: 'SAMLResponse', xml: refusal.xml,
             relayState: relayState, issuer: idpEntityId,
             spEntityId: spEntityId, inResponseTo: request.id,
             note: { title: 'Refused — SAML 2.0', who: 'the service provider',
                     sub: 'A <samlp:Response> carrying InvalidNameIDPolicy. ' +
                          policyProblem }
      });
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). InvalidNameIDPolicy.");
      return;
    }

    // The person cancelled at the screen, or it failed. authn.js reports back
    // on the query string and leaves it to the CALLER to decide what its
    // protocol does — and what this one does is send a Response carrying a
    // status, because section 3.2.2 has one for exactly this and a service
    // provider's handling of it is worth exercising.
    //
    // **BEFORE THE SESSION IS LOOKED AT, AND IT WAS AFTER UNTIL 2026-09-14.** A
    // person who cancels has, by definition, no session — so step 4 found none,
    // sent them straight back to the sign-in screen, and Cancel never reached
    // this block at all: a loop between the screen and this endpoint. The
    // authorization endpoint has always checked `authn_error` before the
    // session for exactly this reason (`authn/CLAUDE.md`).
    if (params.authn_error) {
      log.debug("The sign-in did not complete: " + params.authn_error);
      pendingRequests.delete(String(params.rid || ''));
      errorCodes.mark(res, 'STS-SAML-0009');
      const refusal = this.buildResponse({
        issuer: idpEntityId, sp: spEntityId,
        destination: acsUrl, inResponseTo: request.id,
        status: STATUS_RESPONDER,
        subStatus: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
        statusMessage: String(params.authn_error_description ||
                                   params.authn_error)
      });
      this.deliver(res, {
             binding: wanted.binding, destination: acsUrl,
               field: 'SAMLResponse',
             xml: refusal.xml,
             relayState: relayState, issuer: idpEntityId,
               spEntityId: spEntityId,
             inResponseTo: request.id,
             note: { title: 'Sign-in failed — SAML 2.0',
                     who: 'the service provider',
                     sub: 'A <samlp:Response> carrying AuthnFailed. Unlike ' +
                          'WS-Federation\'s passive profile, this one has ' +
                          'somewhere to report a cancellation to.' }
      });
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). AuthnFailed.");
      return;
    }

    // --- step 4: a session
    // ----------------------------------------------------
    const session = sessionOf(req);
    const wantsMfa = request.requestedAuthnContexts.some(function (ref) {
      return AC_MFA_DEMANDS.indexOf(ref) >= 0;
    });
    const stale = session && wantsMfa &&
                  !this.authnContextFor(session).multiFactor;
    // ---------------------------------------------------------------------
    // ONE TRIP TO THE SIGN-IN SCREEN PER REQUEST, AND NEVER A SECOND
    // (2026-09-14).
    //
    // The request is HELD while the person is at the screen, and the return
    // address reads it again from its XML — so `ForceAuthn="true"` was just as
    // true on the way back, the session the person had just made did not
    // change that, and they were sent to the screen again, for ever. The same
    // loop waited for a RequestedAuthnContext the sign-in could not meet (a
    // federated partner that authenticated with one factor, say).
    //
    // So the trip is RECORDED on the held request (`forcedAt`), and a request
    // that has made it is never redirected again: it is answered from a session
    // authenticated at or after that instant — which is what ForceAuthn asks
    // for, saml-core-2.0-os section 3.4.1 — and otherwise a Response with a
    // status goes back to the service provider: NoAuthnContext where the
    // authentication context is still not met, AuthnFailed where no fresh
    // authentication happened. RFC 9470's step-up takes the same shape at the
    // authorization endpoint (`step_up_honoured`), for the same reason.
    //
    // **FRESH IS COMPARED IN WHOLE SECONDS**, because `authTime` is one: a
    // session authenticated earlier in the same second as the trip counts as
    // fresh. The marker is on the SERVER's copy of the request, so a browser
    // cannot claim to have made the trip.
    // ---------------------------------------------------------------------
    const returned = !!(held && held.forcedAt);
    if (!returned && (!session || request.forceAuthn || stale)) {
      if (request.isPassive) {
        // IsPassive says the identity provider MUST NOT take control of the
        // user interface — so the answer is a Response carrying NoPassive,
        // delivered to the service provider, and not a sign-in screen. It is
        // one of the two status codes a service provider is most likely never
        // to have handled, which is exactly why it is implemented rather than
        // ignored.
        log.debug("IsPassive is set and there is no usable session, so " +
                  "NoPassive goes back.");
        errorCodes.mark(res, 'STS-SAML-0008');
        const refusal = this.buildResponse({
          issuer: idpEntityId, sp: spEntityId,
          destination: acsUrl, inResponseTo: request.id,
          status: STATUS_RESPONDER, subStatus: STATUS_NO_PASSIVE,
          statusMessage: session
            ? 'The session here has one factor and this request asked for ' +
              'more, and IsPassive forbids asking for it.'
            : 'There is no browser session here, and IsPassive forbids ' +
              'asking for one.'
        });
        this.deliver(res, {
               binding: wanted.binding, destination: acsUrl,
                 field: 'SAMLResponse',
               xml: refusal.xml,
               relayState: relayState, issuer: idpEntityId,
                 spEntityId: spEntityId,
               inResponseTo: request.id,
               note: { title: 'Refused — SAML 2.0', who: 'the service provider',
                       sub: 'A <samlp:Response> carrying NoPassive. ' +
                            'IsPassive="true" forbids this identity provider ' +
                            'from taking control of the user interface, so ' +
                            'it reports rather than asks.' }
        });
        log.debug("Leaving Saml2Sso.singleSignOnChecked(). NoPassive.");
        return;
      }
      // Hold the request and go to authn.js's screen. The return address is a
      // GET on this endpoint carrying the held id, so coming back runs this
      // function again from the top with a session in place.
      const record = held || {
        id: randomId(18), samlRequest: String(encoded),
        relayState: String(relayState || ''),
        arrivedBy: arrivedBy, signature: String(params.Signature || ''),
        sigAlg: String(params.SigAlg || ''),
        verification: verification
      };
      record.expires = Date.now() + this.requestTtlMs();
      // The trip, recorded before it is made. See `returned` above.
      record.forcedAt = nowSec();
      pendingRequests.set(record.id, record);
      pendingRequests.forEach(function (v, k) {
        if (v.expires < Date.now()) pendingRequests.delete(k);
      });
      const returnTo = req.path + '?rid=' + encodeURIComponent(record.id);
      const where = beginAuthentication({
        returnTo: returnTo,
        hint: request.subjectHint,
        // The service provider's entityID is its identifier in the application
        // registry, so an entry naming a federation relationship federates a
        // SAML 2.0 sign-in exactly as it federates an OAuth one. Nothing in
        // this module knows that happened: what comes back is a session.
        application: spEntityId,
        // A RequestedAuthnContext demanding more than one factor takes the
        // opt-out away rather than being refused — what WS-Federation's wauth
        // does with the same demand too. See the note on AC_MFA_DEMANDS.
        forceMfa: wantsMfa,
        protocol: 'SAML 2.0',
        details: [
          { label: 'Service provider', value: spEntityId,
            note: 'the <saml:Issuer> of the AuthnRequest, and the audience ' +
                  'of the assertion.' },
          { label: 'Assertion consumer service', value: acsUrl,
            note: 'where the response is delivered — ' + acsFrom +
                  (mode.acceptsUnregisteredAddresses()
                    ? '. Not checked against any registration in this mode.'
                    : '. Checked against the registration, which this mode ' +
                      'requires.') },
          { label: 'Response binding', value: wanted.binding,
            note: wanted.stated ? 'asked for by ProtocolBinding.'
                                : 'the default, because the request named ' +
                                  'none.' },
          { label: 'Request signature',
            value: String(request.verification.outcome || 'unsigned'),
            note: String(request.verification.why || '') + '.' },
          { label: 'NameID format',
            value: this.nameIdFormatFor(request, spEntityId),
            note: request.nameIdFormat ? 'asked for by NameIDPolicy.'
                                       : 'this service\'s default: the ' +
                                         'request asked for none.' }
        ].concat(request.forceAuthn
          ? [{ label: 'ForceAuthn', value: 'true',
               note: 'why this screen appeared even though a session already ' +
                     'existed.' }]
          : []).concat(stale
          ? [{ label: 'RequestedAuthnContext',
               value: request.requestedAuthnContexts.join(' '),
               note: 'more than one factor was asked for and this session ' +
                     'has one.' }]
          : [])
      });
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                "To the sign-in screen, " +
                "returning to " +
                returnTo + ".");
      return res.set('Cache-Control', 'no-store').redirect(303, where);
    }

    // BACK FROM THE ONE TRIP, and what it did not achieve is REPORTED rather
    // than asked for again.
    if (returned) {
      const fresh = !!session &&
                    Number(session.authTime || 0) >= Number(held.forcedAt);
      const contextUnmet = !!session && wantsMfa &&
                           !this.authnContextFor(session).multiFactor;
      const unmet = !session || (request.forceAuthn && !fresh)
        ? 'authn' : (contextUnmet ? 'context' : '');
      if (unmet) {
        const why = unmet === 'context'
          ? 'The person signed in, and the session still does not meet the ' +
            'RequestedAuthnContext (' +
              request.requestedAuthnContexts.join(' ') +
            ').'
          : (!session
            ? 'The person came back from the sign-in screen with no session.'
            : 'ForceAuthn asked for a fresh authentication and the person ' +
              'came back from the sign-in screen without authenticating ' +
              'again.');
        log.info('saml2: ' + why + ' Answering "' + spEntityId + '" with a ' +
                 'status rather than sending the person to the sign-in ' +
                 'screen a second time.');
        pendingRequests.delete(String(params.rid || ''));
        const subStatus = unmet === 'context'
          ? 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext'
          : 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed';
        errorCodes.mark(res, unmet === 'context' ? 'STS-SAML-0056'
                                                 : 'STS-SAML-0055');
        const refusal = this.buildResponse({
          issuer: idpEntityId, sp: spEntityId,
          destination: acsUrl, inResponseTo: request.id,
          status: STATUS_RESPONDER, subStatus: subStatus, statusMessage: why
        });
        this.deliver(res, {
               binding: wanted.binding, destination: acsUrl,
                 field: 'SAMLResponse',
               xml: refusal.xml,
               relayState: relayState, issuer: idpEntityId,
                 spEntityId: spEntityId,
               inResponseTo: request.id,
               note: { title: 'Refused — SAML 2.0', who: 'the service provider',
                       sub: 'A <samlp:Response> carrying ' +
                            subStatus.split(':').pop() + '. ' + why }
        });
        log.debug("Leaving Saml2Sso.singleSignOnChecked(). " +
                  subStatus.split(':').pop() + ".");
        return;
      }
    }

    // --- step 5: the answer
    // ---------------------------------------------------
    //
    // SINGLE SIGN-ON JUST HAPPENED, IF THE SESSION WAS NOT MADE FOR THIS
    // REQUEST. CAEP is a vocabulary about SESSIONS and not about the protocol
    // that minted one, so a `session-presented` is as due here as it is at the
    // authorization endpoint — and until this call existed a receiver watching
    // a stream saw a SAML 2.0 session start and end while every single sign-on
    // between the two was silent. `authn.notePresented()` drops the FIRST
    // presentation of a brand-new session, because that one is the sign-in's
    // own return trip through this endpoint and not single sign-on; its header
    // argues it, and the flag it spends is set by `startSession()` whichever
    // protocol called it, so a sign-in HERE and a later OIDC authorization
    // request report exactly one presentation between them.
    //
    // Here rather than beside `sessionOf()` at step 4, for the reason that call
    // site gives: this is the branch that HONOURS the session, and the two
    // above it — IsPassive with nothing usable, and a sign-in that came back
    // carrying `authn_error` — end in a Response carrying a status instead. THE
    // ROLE GATE, asked once the session is known to be the one that will answer
    // this request and before anything is minted. A refusal is a
    // <samlp:Response> carrying a status and NOT a page on this service, for
    // the reason the AuthnFailed branch above gives: section 3.2.2 has a status
    // for this and a service provider's handling of it is worth exercising — a
    // person who is refused should land back at the application that sent them,
    // with the application knowing why.
    //
    // `Responder` with a second-level `RequestDenied`: the failure is at THIS
    // end (the request was well formed and the identity provider declined it),
    // which is what Responder means, and RequestDenied is the second-level code
    // the specification gives for a request the responder refused to act on.
    // AuthnFailed would be the wrong word — the person authenticated perfectly
    // well and is not permitted to have an assertion for this service provider.
    const roleAnswer = gate.check({
      application: spEntityId,
      kind: gate.ISSUANCE.SAML_ASSERTION,
      // WHETHER ANYBODY AUTHENTICATED, READ OFF THE SESSION (2026-09-05).
      //
      // This was the constant `true` until unauthenticated sessions existed,
      // and a constant is what it looked like: every session this service held
      // had somebody behind it. `authenticated !== false` rather than a plain
      // read, because a session object made before this field existed has no
      // such property and must go on meaning what it always meant.
      subject: { kind: 'user', name: String((session.user || {}).username ||
                                            ''),
                 authenticated: session.authenticated !== false },
      claims: null,
      // The session the assertion rests on, whose risk the issuance policy
      // reads (#62 P3).
      session: session
    });
    if (!roleAnswer.allowed) {
      log.info('saml2: the issuance policy refused an assertion for "' +
               String((session.user || {}).username) + '" to "' + spEntityId +
               '". ' + roleAnswer.why);
      pendingRequests.delete(String(params.rid || ''));
      errorCodes.mark(res, 'STS-SAML-0010');
      const denied = this.buildResponse({
        issuer: idpEntityId, sp: spEntityId,
        destination: acsUrl, inResponseTo: request.id,
        status: STATUS_RESPONDER,
        subStatus: 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
        statusMessage: roleAnswer.why
      });
      this.deliver(res, {
             binding: wanted.binding, destination: acsUrl,
               field: 'SAMLResponse',
             xml: denied.xml, relayState: relayState, issuer: idpEntityId,
             spEntityId: spEntityId, inResponseTo: request.id,
             note: { title: 'Refused by policy — SAML 2.0',
                     who: 'the service provider',
                     sub: 'A <samlp:Response> carrying RequestDenied. The ' +
                          'person signed in; the XACML issuance policy would ' +
                          'not let this service provider have an assertion ' +
                          'for them.' }
      });
      log.debug("Leaving Saml2Sso.singleSignOnChecked(). RequestDenied.");
      return;
    }

    pendingRequests.delete(String(params.rid || ''));
    notePresented(session, 'SAML 2.0', req);
    this.issueSignInResponse(res, {
           request: request, session: session, spEntityId: spEntityId,
           idpEntityId: idpEntityId,
           acsUrl: acsUrl, binding: wanted.binding, relayState: relayState
    });
    log.debug("Leaving Saml2Sso.singleSignOnChecked(). A response went to " +
              spEntityId + ".");
  }

  // ---------------------------------------------------------------------------
  // IDENTITY-PROVIDER-INITIATED SSO (#189): an UNSOLICITED Response
  // (saml-profiles-2.0-os section 4.1.5), for a service provider that did not
  // ask — the sign-in starts HERE, at a link, and the service provider
  // receives an assertion carrying no InResponseTo. This was listed under
  // *What is still absent* in saml/CLAUDE.md until #189; the Shibboleth SP,
  // SimpleSAMLphp and pysaml2 all accept one, and a deployable identity
  // provider is expected to send one.
  //
  //   GET /saml2/unsolicited[/{sp}]?providerId=<entityID>
  //       [&shire=<ACS URL>][&target=<RelayState>][&binding=post|artifact]
  //
  // The parameter names are the Shibboleth identity provider's for the same
  // thing (its /profile/SAML2/Unsolicited/SSO), which is what a deployer's
  // links already say. `providerId` may be the path segment instead.
  //
  // WHAT IS HELD TO WHAT a solicited request is held to, since nothing here
  // is the service provider's word: the service provider must be one this
  // realm registered in product (a 404, STS-SAML-0082, as every per-SP path);
  // the assertion consumer service is one its CONSUMED metadata registered —
  // `shire` choosing among them, the default otherwise, in every mode — or,
  // with no metadata, an address on its entry, which product requires; the
  // Response goes on that endpoint's binding (never HTTP-Redirect, which
  // section 4.1.2 forbids for a Response); and the issuance policy is asked
  // as for any sign-in. `saml2.unsolicitedSso` turns the whole of it off for
  // a realm (STS-SAML-0091). The Response and its assertion carry no
  // InResponseTo, and the target travels as RelayState, byte for byte.
  // ---------------------------------------------------------------------------
  private unsolicitedSignOn(req, res) {
    const { applications, config, errorCodes, gate, mode,
            returnAddress } = this.deps;
    const { beginAuthentication, notePresented, sessionOf } = this.deps.authn;
    const { baseUrlOf, log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.unsolicitedSignOn().");
    const base = baseUrlOf(req);
    const params: any = this.paramsOf(req);
    const scoped = this.entityIdFromSegment(req.params.sp);
    if (this.refusedUnregistered(res, scoped, UNSOLICITED_PATH + '/{sp}')) {
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). Not registered.");
      return;
    }
    if (!config.value('saml2.unsolicitedSso')) {
      errorCodes.mark(res, 'STS-SAML-0091');
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). Turned off.");
      return this.samlError(res, 403, 'Identity-provider-initiated sign-in ' +
                                      'is turned off here',
        'saml2.unsolicitedSso is off in this realm, so this identity ' +
        'provider sends a Response only in answer to an AuthnRequest. Start ' +
        'the sign-in from the service provider.');
    }
    const spEntityId = String(params.providerId || '') || scoped.entityId;
    if (!spEntityId) {
      errorCodes.mark(res, 'STS-SAML-0092');
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). No service provider.");
      return this.samlError(res, 400, 'Which service provider?',
        'An unsolicited sign-in names the service provider it is for, as ' +
        'providerId or as the path segment, because that entityID is the ' +
        'assertion\'s audience.');
    }
    if (!mode.publishesMetadataForUnregisteredProviders() &&
        !this.isRegisteredServiceProvider(spEntityId)) {
      this.refusedUnregistered(res, { entityId: spEntityId },
                               UNSOLICITED_PATH);
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). Unregistered.");
      return;
    }
    const issuerProblem = this.idpEntityIdProblem();
    if (issuerProblem) {
      errorCodes.mark(res, 'STS-SAML-0004');
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). No entityID.");
      return this.samlError(res, 503, 'This identity provider has no ' +
                                      'entityID', issuerProblem);
    }
    const askedFor = String(params.binding || '').toLowerCase();
    const asked = askedFor === 'artifact' || askedFor === BINDING_ARTIFACT
      ? BINDING_ARTIFACT
      : (askedFor === 'post' || askedFor === BINDING_POST ? BINDING_POST
        : (askedFor === 'simplesign' || askedFor === BINDING_SIMPLESIGN
          ? BINDING_SIMPLESIGN : ''));
    if (askedFor && !asked) {
      errorCodes.mark(res, 'STS-SAML-0093');
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). Unknown binding.");
      return this.samlError(res, 400, 'That binding is not one a Response ' +
                                      'goes on',
        'binding="' + askedFor + '": an unsolicited Response goes on ' +
        'HTTP-POST, HTTP-POST-SimpleSign or HTTP-Artifact — never ' +
        'HTTP-Redirect, which saml-profiles-2.0-os section 4.1.2 forbids ' +
        'for a Response.');
    }
    const idpEntityId = this.idpEntityIdFor(spEntityId);
    const known = this.fieldsOf(spEntityId);
    const shire = String(params.shire || '');
    const consumed = this.registeredAcsFor({ acsIndex: '', acsUrl: shire,
                                             protocolBinding: asked }, known);
    if (consumed.consumed && !consumed.ok) {
      errorCodes.mark(res, consumed.errorCode || 'STS-SAML-0070');
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). Not registered ACS.");
      return this.samlError(res, 400, 'That assertion consumer service is ' +
                                      'not registered', consumed.why);
    }
    const acsKnown = applications.returnAddressesOf(
      known, 'samlAssertionConsumerService');
    const where = returnAddress.resolve({
      requested: consumed.consumed ? consumed.url : shire,
      registered: acsKnown.registered,
      unconfirmed: acsKnown.unconfirmed,
      fallback: '',
      attribute: 'samlAssertionConsumerService',
      parameter: 'shire',
      application: spEntityId
    });
    const acsUrl = where.ok ? String(where.url || '') : '';
    if (!acsUrl || !/^https?:\/\//i.test(acsUrl)) {
      errorCodes.mark(res, errorCodes.codeOf(where) || 'STS-SAML-0005');
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). No ACS.");
      return this.samlError(res, 400, 'There is nowhere to send it',
        where.ok ? 'This service provider has no registered assertion ' +
                   'consumer service and the link named no shire.'
                 : String(where.why || ''));
    }
    const binding = consumed.consumed &&
                    consumed.binding !== BINDING_REDIRECT &&
                    this.deliverable(consumed.binding)
      ? consumed.binding : (asked || BINDING_POST);
    const relayState = String(params.target || params.RelayState || '');

    const session = sessionOf(req);
    if (!session) {
      const query = this.rawQueryOf(req);
      const where2 = beginAuthentication({
        returnTo: req.path + (query ? '?' + query : ''),
        application: spEntityId,
        protocol: 'SAML 2.0',
        details: [
          { label: 'Service provider', value: spEntityId,
            note: 'named by the link — an identity-provider-initiated ' +
                  'sign-in (saml-profiles-2.0-os section 4.1.5); the ' +
                  'service provider did not ask.' },
          { label: 'Assertion consumer service', value: acsUrl,
            note: consumed.consumed ? consumed.from
                                    : String(where.from || '') },
          { label: 'Response binding', value: binding, note: '' }
        ]
      });
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). To the sign-in " +
                "screen.");
      return res.set('Cache-Control', 'no-store').redirect(303, where2);
    }
    this.recordServiceProvider({
      identifier: spEntityId, kind: 'saml2-service-provider',
      protocol: 'SAML 2.0', counts: false,
      note: 'was sent an unsolicited Response (identity-provider-initiated)',
      fields: { samlEntityId: spEntityId }
    });
    const roleAnswer = gate.check({
      application: spEntityId,
      kind: gate.ISSUANCE.SAML_ASSERTION,
      subject: { kind: 'user', name: String((session.user || {}).username ||
                                            ''),
                 authenticated: session.authenticated !== false },
      claims: null,
      session: session
    });
    if (!roleAnswer.allowed) {
      errorCodes.mark(res, 'STS-SAML-0010');
      const denied = this.buildResponse({
        issuer: idpEntityId, sp: spEntityId, destination: acsUrl,
        inResponseTo: '', status: STATUS_RESPONDER,
        subStatus: 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
        statusMessage: roleAnswer.why
      });
      this.deliver(res, {
        binding: binding, destination: acsUrl, field: 'SAMLResponse',
        xml: denied.xml, relayState: relayState, issuer: idpEntityId,
        spEntityId: spEntityId, inResponseTo: '',
        note: { title: 'Refused by policy — SAML 2.0',
                who: 'the service provider',
                sub: 'A <samlp:Response> carrying RequestDenied.' }
      });
      log.debug("Leaving Saml2Sso.unsolicitedSignOn(). RequestDenied.");
      return;
    }
    notePresented(session, 'SAML 2.0', req);
    this.issueSignInResponse(res, {
      request: { id: '', nameIdFormat: '', requestedAuthnContexts: [] },
      session: session, spEntityId: spEntityId, idpEntityId: idpEntityId,
      acsUrl: acsUrl, binding: binding, relayState: relayState
    });
    log.debug("Leaving Saml2Sso.unsolicitedSignOn(). An unsolicited " +
              "Response went to " + spEntityId + ".");
  }

  // ---------------------------------------------------------------------------
  // THE ATTRIBUTE AUTHORITY (#189): the Assertion Query and Request profile's
  // <samlp:AttributeQuery> over the SOAP binding (saml-profiles-2.0-os section
  // 6, saml-bindings-2.0-os section 3.2), published as an
  // AttributeAuthorityDescriptor in the per-SP metadata. It was listed under
  // *What is still absent* until #189; the Shibboleth SP's Query resolver
  // asks one after every SAML 2.0 sign-in that carried no attributes, and its
  // AttributeResolver handler on demand.
  //
  // WHO MAY ASK, AND ABOUT WHOM — the release policy SAML 1.1's responder
  // never had, and the reason this one is not refused in product:
  //
  //   * the caller is the service provider its <Issuer> names, AUTHENTICATED
  //     as the artifact resolver's caller is (`authenticateSoapCaller()`: a
  //     signature on the query or its registered certificate at the TLS
  //     handshake, required where signed requests are — product by default;
  //     a signature present and wrong refused in every mode);
  //   * the SUBJECT is a person that service provider holds a live session
  //     for FROM THIS SERVICE: the NameID in the query must be the one a
  //     session here gave it (`saml2ServiceProviders[sp].nameId`) — which is
  //     what makes a transient NameID answerable at all, and what keeps a
  //     service provider from asking about anybody it names. Otherwise
  //     Requester / UnknownPrincipal (STS-SAML-0094);
  //   * the issuance policy is asked with that session, as a sign-in is;
  //   * what is released is what that sign-in released (`attributesFor()`),
  //     narrowed to the <saml:Attribute>s the query names when it names any.
  //
  // The assertion is signed as the service provider's sign-in assertions are,
  // and encrypted to it where they are. It carries no SubjectConfirmation and
  // no AuthnStatement (`attributeQuery` in saml2.ts).
  // ---------------------------------------------------------------------------
  private attributeQuery(req, res) {
    const { audit, errorCodes, gate, mode, validation } = this.deps;
    const { firstByLocal, log, logArtifact, textByLocal } = this.deps.helpers;
    const { buildSamlAssertion } = this.deps.saml2;
    const self = this;
    log.debug("Entering Saml2Sso.attributeQuery().");
    const scoped = this.entityIdFromSegment(req.params.sp);
    if (this.refusedUnregistered(res, scoped, AA_PATH + '/{sp}')) {
      log.debug("Leaving Saml2Sso.attributeQuery(). Not registered.");
      return;
    }
    const raw = typeof req.body === 'string' ? req.body : '';
    logArtifact('SAML 2.0 AttributeQuery', 'as received over SOAP', raw);
    let inResponseTo = '';
    let spEntityId = '';
    const answer = function (code, status, subStatus, message, assertion) {
      log.debug("Entering answer().");
      if (code) {
        errorCodes.mark(res, code);
      }
      audit.audit({
        action: 'saml2.attribute-query', outcome: code ? 'refused' : 'success',
        errorCode: code || '', protocol: 'SAML 2.0', channel: 'http',
        target: spEntityId,
        summary: 'An AttributeQuery from "' + (spEntityId || '(unnamed)') +
                 '": ' + (code ? 'refused — ' + message : 'answered')
      });
      const response = self.buildResponse({
        issuer: self.idpEntityIdFor(spEntityId || scoped.entityId),
        sp: spEntityId, destination: '', inResponseTo: inResponseTo,
        status: status,
        subStatus: subStatus, statusMessage: message, assertion: assertion
      });
      const envelope = self.soapEnvelope(response.xml);
      logArtifact('SAML 2.0 attribute query Response', 'as returned over ' +
                  'SOAP', envelope);
      res.status(200)
         .type('text/xml; charset=utf-8')
         .set('Cache-Control', 'no-store')
         .send(envelope);
      log.debug("Leaving answer().");
    };
    const read = validation.parseXml(raw, 'AttributeQuery');
    const query = read.ok ? firstByLocal(read.value, 'AttributeQuery') : null;
    if (!query) {
      log.debug("Leaving Saml2Sso.attributeQuery(). No AttributeQuery.");
      return answer('STS-SAML-0095', STATUS_REQUESTER, '',
                    'there is no <samlp:AttributeQuery> in the SOAP body: ' +
                    'this endpoint answers the Assertion Query and Request ' +
                    'profile\'s attribute query, over SOAP, and nothing ' +
                    'else.', '');
    }
    inResponseTo = query.getAttribute('ID') || '';
    spEntityId = textByLocal(query, 'Issuer') || '';
    if (!spEntityId) {
      log.debug("Leaving Saml2Sso.attributeQuery(). No issuer.");
      return answer('STS-SAML-0095', STATUS_REQUESTER, '',
                    'the AttributeQuery names no <Issuer>, and the Issuer is ' +
                    'who the answer is for.', '');
    }
    if (!mode.publishesMetadataForUnregisteredProviders() &&
        !this.isRegisteredServiceProvider(spEntityId)) {
      log.debug("Leaving Saml2Sso.attributeQuery(). Unregistered.");
      return answer('STS-SAML-0082', STATUS_REQUESTER,
                    'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
                    'no SAML 2.0 service provider is registered here as "' +
                    spEntityId + '".', '');
    }
    const envelopeProblem = this.envelopeProblem(req, this.deps.helpers
      .baseUrlOf(req), {
      what: 'AttributeQuery', version: query.getAttribute('Version') || '',
      issueInstant: query.getAttribute('IssueInstant') || '',
      destination: query.getAttribute('Destination') || '', signed: false
    });
    if (envelopeProblem) {
      log.debug("Leaving Saml2Sso.attributeQuery(). Its envelope.");
      return answer(envelopeProblem.errorCode, STATUS_REQUESTER, '',
                    envelopeProblem.why, '');
    }
    const caller = this.authenticateQueryCaller(req, query, spEntityId);
    if (caller.refuse) {
      log.debug("Leaving Saml2Sso.attributeQuery(). The caller.");
      return answer(caller.errorCode || 'STS-SAML-0077', STATUS_REQUESTER,
                    'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
                    caller.why, '');
    }
    const nameIdEl = firstByLocal(query, 'NameID');
    const nameId = nameIdEl ? String(nameIdEl.textContent || '').trim() : '';
    const nameIdFormat = nameIdEl
      ? (nameIdEl.getAttribute('Format') ||
         'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified') : '';
    const authnApi = this.deps.authn;
    const live = nameId ? authnApi.sessionsMatching(function (session) {
      const there = (session.saml2ServiceProviders || {})[spEntityId];
      return !!there && there.nameId === nameId &&
             !authnApi.sessionEnded(session);
    }) : [];
    const session = live[0];
    if (!session) {
      log.info('saml2: an AttributeQuery from "' + spEntityId + '" named "' +
               nameId + '", which no live session here gave it; ' +
               'UnknownPrincipal.');
      log.debug("Leaving Saml2Sso.attributeQuery(). Unknown principal.");
      return answer('STS-SAML-0094', STATUS_REQUESTER,
                    STATUS_UNKNOWN_PRINCIPAL,
                    'no session here gave this service provider that NameID ' +
                    '(or it has ended); an attribute query is answered only ' +
                    'about a subject the asking service provider was signed ' +
                    'in for by this identity provider.', '');
    }
    const roleAnswer = gate.check({
      application: spEntityId,
      kind: gate.ISSUANCE.SAML_ASSERTION,
      subject: { kind: 'user',
                 name: String((session.user || {}).username || ''),
                 authenticated: session.authenticated !== false },
      claims: null,
      session: session
    });
    if (!roleAnswer.allowed) {
      log.debug("Leaving Saml2Sso.attributeQuery(). The issuance policy.");
      return answer('STS-SAML-0010', STATUS_RESPONDER,
                    'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
                    roleAnswer.why, '');
    }
    // NARROWED TO WHAT WAS ASKED FOR (saml-core-2.0-os section 3.3.2.3): an
    // attribute the query names, by Name and — where it gives one — by
    // NameFormat; everything the sign-in released when it names none.
    const asked = [];
    const askedEls = query.getElementsByTagNameNS('*', 'Attribute');
    for (let i = 0; i < askedEls.length; i++) {
      asked.push({ name: askedEls[i].getAttribute('Name') || '',
                   nameFormat: askedEls[i].getAttribute('NameFormat') || '' });
    }
    const released = this.attributesFor(session.user).filter(function (a) {
      return !asked.length || asked.some(function (one) {
        return one.name === a.name &&
               (!one.nameFormat || one.nameFormat === a.nameFormat);
      });
    });
    const idpEntityId = this.idpEntityIdFor(spEntityId);
    const lifetimeMin = Number(this.settingFor(spEntityId,
                                               'saml2.assertionLifetimeMin')) ||
                                                 60;
    const built = buildSamlAssertion(
      String((session.user || {}).username || ''), spEntityId, lifetimeMin, {
        issuer: idpEntityId, nameIdFormat: nameIdFormat, nameIdValue: nameId,
        // The query's qualifiers, repeated: the answer's Subject must STRONGLY
        // match the query's (saml-core-2.0-os section 3.3.4), and the
        // Shibboleth SP ignores an assertion whose NameID drops them.
        nameQualifier: nameIdEl ? nameIdEl.getAttribute('NameQualifier') || ''
                                : '',
        spNameQualifier: nameIdEl
          ? nameIdEl.getAttribute('SPNameQualifier') || '' : '',
        attributes: released, attributeQuery: true,
        sign: this.signsAssertionFor(spEntityId)
      });
    const wantsEncryption = !!this.settingFor(spEntityId,
                                              'saml2.encryptAssertion') ||
      String(this.fieldsOf(spEntityId).samlSpWantAssertionsEncrypted ||
             '') === 'TRUE';
    const sealed: any = wantsEncryption
      ? this.encryptFor(spEntityId, built, 'saml:EncryptedAssertion',
                        'assertion')
      : { xml: built, encrypted: false };
    if (wantsEncryption && !sealed.encrypted && !mode.sendsWeakerThanAsked()) {
      log.debug("Leaving Saml2Sso.attributeQuery(). Encryption impossible.");
      return answer('STS-SAML-0011', STATUS_RESPONDER, '',
                    'the assertion for this service provider is to be ' +
                    'encrypted and could not be (' + (sealed.why ||
                    'unknown') + ').', '');
    }
    log.info('saml2: answered an AttributeQuery from "' + spEntityId +
             '" about ' + nameId + ' with ' + released.length +
             ' attribute(s).');
    log.debug("Leaving Saml2Sso.attributeQuery(). Answered.");
    return answer('', STATUS_SUCCESS, '', '', sealed.xml);
  }

  // The attribute authority's caller: the artifact resolver's rule, without
  // an artifact (see authenticateArtifactCaller()).
  private authenticateQueryCaller(req, query, spEntityId): any {
    const { mtls, requestSignature, spMetadata } = this.deps;
    const { baseUrlOf, log } = this.deps.helpers;
    const { XMLSerializer } = this.deps.xmldom;
    log.debug("Entering Saml2Sso.authenticateQueryCaller().");
    const fields = this.fieldsOf(spEntityId);
    const fresh = spMetadata.freshness(fields);
    if (fresh.state === 'expired') {
      log.debug("Leaving Saml2Sso.authenticateQueryCaller(). Expired.");
      return { refuse: true, errorCode: 'STS-SAML-0074', why: fresh.why };
    }
    const peer = mtls.peerCertificate(req);
    const revoked = req.certificateRevocation &&
                    req.certificateRevocation.refused;
    const caller = requestSignature.authenticateSoapCaller({
      xml: new XMLSerializer().serializeToString(query),
      rootLocalName: 'AttributeQuery', fields: fields,
      tlsCertificate: peer && !revoked
        ? Buffer.from(peer.raw).toString('base64') : '',
      implicitCertificates: this.implicitCertificatesFor(baseUrlOf(req),
                                                         spEntityId)
    });
    log.debug("Leaving Saml2Sso.authenticateQueryCaller(). " +
              (caller.refuse ? caller.errorCode : 'via ' + caller.via));
    return caller;
  }

  private issueSignInResponse(res, ctx) {
    const { errorCodes, mode } = this.deps;
    const { noteSessionChanged } = this.deps.authn;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.issueSignInResponse(). sp=" + ctx.spEntityId);
    const session = ctx.session;
    const built = this.buildAssertionFor(ctx.request, session, ctx.spEntityId,
                                        ctx.idpEntityId, ctx.acsUrl);
    // SIGNED FIRST, THEN ENCRYPTED, and that order is the specification's
    // rather than a preference: the signature lives INSIDE the ciphertext, so
    // what a service provider verifies is what it decrypted. Encrypting first
    // and signing the ciphertext would produce a document that verifies without
    // anybody being able to say what was signed. buildAssertionFor() has
    // already signed it by the time it gets here.
    // WANTED by the setting, or by the service provider itself: consumed
    // metadata that publishes a use="encryption" key (#37 follow-up) is
    // encrypted to in every mode, which is the one reading of that key the
    // interoperability profiles give.
    const wantsEncryption = !!this.settingFor(ctx.spEntityId,
                                              'saml2.encryptAssertion') ||
      String(this.fieldsOf(ctx.spEntityId).samlSpWantAssertionsEncrypted ||
             '') === 'TRUE';
    const sealed: any = wantsEncryption
      ? this.encryptFor(ctx.spEntityId, built, 'saml:EncryptedAssertion',
                        'assertion')
      : { xml: built, encrypted: false };
    // -------------------------------------------------------------------------
    // ENCRYPTION WAS ASKED FOR AND DID NOT HAPPEN (2026-09-12).
    //
    // Development sends the assertion IN CLEAR and says so loudly — the
    // argument at encryptionCertificateFor(): a mock that stopped issuing
    // because a key was missing is useless exactly when somebody is setting
    // this up. That argument is about a MOCK. In product the same fallback
    // means an assertion a deployment configured to be confidential crossing
    // the browser readable, and the WARN line is the only evidence. So a
    // product realm REFUSES: the service provider is sent a Response carrying
    // Responder, which is the status for "the identity provider could not do
    // this", and no assertion at all.
    //
    // `sendsWeakerThanAsked()` is the predicate — the question is what a
    // response may lose on the way out, which is not the same question as who
    // may drive a test control (`opensTestControls()`, which this used for an
    // hour for want of a predicate that named it).
    // -------------------------------------------------------------------------
    if (wantsEncryption && !sealed.encrypted && !mode.sendsWeakerThanAsked()) {
      log.warn('saml2: refused to send an assertion for ' + ctx.spEntityId +
               ' ' +
               'in clear: saml2.encryptAssertion is on for it and the ' +
               'encryption did not happen (' +
               (sealed.why || 'unknown') + '). Development mode would have ' +
                                           'sent it anyway.');
      errorCodes.mark(res, 'STS-SAML-0011');
      const refusal = this.buildResponse({
        issuer: ctx.idpEntityId, sp: ctx.spEntityId,
        destination: ctx.acsUrl, inResponseTo: ctx.request.id,
        status: STATUS_RESPONDER,
        statusMessage: 'The assertion for this service provider is ' +
                            'configured to be ENCRYPTED and could not be ' +
                            '(' + (sealed.why || 'unknown') + '), ' +
                            'so none was sent. Register an encryption ' +
                            'certificate for it (samlEncryptionCertificate, ' +
                            'or its metadata).'
      });
      this.deliver(res, {
             binding: ctx.binding, destination: ctx.acsUrl,
               field: 'SAMLResponse',
             xml: refusal.xml, relayState: ctx.relayState,
               issuer: ctx.idpEntityId,
             spEntityId: ctx.spEntityId, inResponseTo: ctx.request.id,
             note: { title: 'Refused — SAML 2.0', who: 'the service provider',
                     sub: 'A <samlp:Response> carrying Responder and no ' +
                          'assertion: encryption was required and could not ' +
                          'be performed.' }
      });
      log.debug("Leaving Saml2Sso.issueSignInResponse(). Encryption required " +
                "and not possible.");
      return;
    }
    const assertion = sealed.xml;
    const response = this.buildResponse({
      issuer: ctx.idpEntityId, sp: ctx.spEntityId,
      destination: ctx.acsUrl, inResponseTo: ctx.request.id,
      status: STATUS_SUCCESS, assertion: assertion
    });

    // THE AUTHENTICATION, recorded here rather than when the request arrived:
    // this is the moment this service has decided to tell that service provider
    // who somebody is. The sighting was recorded at step 3 with `counts: false`
    // for exactly this reason.
    this.recordServiceProvider({
           identifier: ctx.spEntityId,
           kind: 'saml2-service-provider',
           protocol: 'SAML 2.0',
           sessionId: session.id || '',
           user: (session.user && session.user.username) || '',
           note: 'was issued a Web Browser SSO assertion',
           fields: {
             samlEntityId: ctx.spEntityId,
             samlAssertionConsumerService: ctx.acsUrl,
             samlResponseBinding: ctx.binding
           }
    });

    // Which service providers this session has signed into, so that Single
    // Logout has somewhere to fan out to. It lives ON the session rather than
    // in a map of its own because that is exactly the lifetime it should have:
    // when the session goes, so does the list, and nothing has to be swept. The
    // same decision `wsfed.ts` makes about `session.wsfedRealms`.
    session.saml2ServiceProviders = session.saml2ServiceProviders || {};
    // AND THE NameID IT WAS GIVEN THERE (#192): what a LogoutRequest from
    // that service provider names, and what one from here must name — a
    // transient or an emailAddress NameID is not the username.
    const issuedFormat = this.nameIdFormatFor(ctx.request || {},
                                              ctx.spEntityId);
    session.saml2ServiceProviders[ctx.spEntityId] = {
      acs: ctx.acsUrl, idpEntityId: ctx.idpEntityId, at: Date.now(),
      nameId: this.nameIdValueFor(issuedFormat, session),
      nameIdFormat: issuedFormat
    };
    // AND THE STORE IS TOLD (2026-09-14, #46): the line above edits an object
    // the session store holds, which it does not journal, so without this the
    // list never reached another node and its `/saml2/slo` offered nothing.
    // `authn.noteSessionChanged()` carries the argument.
    noteSessionChanged(session);

    this.deliver(res, {
           binding: ctx.binding, destination: ctx.acsUrl, field: 'SAMLResponse',
           xml: response.xml,
           relayState: ctx.relayState, issuer: ctx.idpEntityId,
           spEntityId: ctx.spEntityId,
           inResponseTo: ctx.request.id,
           note: { title: 'Signing in — SAML 2.0', who: 'the service provider',
                   sub: 'saml-profiles-2.0-os section 4.1.4 — the response ' +
                        'travels in the body of a form POST, so it is not ' +
                        'length-limited and never appears in a URL, a log or ' +
                        'a Referer header.' }
    });
    log.debug("Leaving Saml2Sso.issueSignInResponse(). " +
              ((session.user && session.user.username) || '?') +
              " signed in to " + ctx.spEntityId + ".");
  }

  // ---------------------------------------------------------------------------
  // THE ARTIFACT RESOLUTION SERVICE (section 3.6.3, over the SOAP binding
  // 3.2.3).
  //
  // This is the back channel the Browser/Artifact profile rests on, and it is
  // the one endpoint in this profile a BROWSER never touches: the service
  // provider calls it directly, server to server, with the artifact its user
  // agent carried. That is the whole reason the profile exists — the assertion
  // never passes through the browser at all.
  //
  // IT AUTHENTICATES ITS CALLER since the #37 follow-up — a signature on the
  // ArtifactResolve, or the service provider's registered certificate as the
  // TLS client certificate, required where signed requests are — and answers
  // only the service provider the artifact was minted for; see
  // `authenticateArtifactCaller()`. The MessageHandle's twenty random bytes
  // and the one-shot rule of decision 6 still stand behind that.
  // ---------------------------------------------------------------------------
  private soapEnvelope(inner) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.soapEnvelope().");
    log.debug("Leaving Saml2Sso.soapEnvelope().");
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' + inner +
      '</soap:Body></soap:Envelope>';
  }

  private buildArtifactResponse(idpEntityId, inResponseTo, status,
                                statusMessage,
                                 payload) {
    const { genId, iso, log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.buildArtifactResponse(). status=" + status);
    const xml =
      '<samlp:ArtifactResponse xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' +
        NS_SAML + '" ' +
        'ID="' + genId() + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
        (inResponseTo ? ' InResponseTo="' + xmlEscape(inResponseTo) + '"' :
         '') + '><saml:Issuer>' + xmlEscape(idpEntityId) + '</saml:Issuer>' +
        this.statusElement(status, '', statusMessage) +
        (payload || '') +
      '</samlp:ArtifactResponse>';
    log.debug("Leaving Saml2Sso.buildArtifactResponse().");
    return xml;
  }

  // The ArtifactResponse is DELIBERATELY NOT SIGNED, and it is worth saying why
  // rather than leaving it to look like an omission: what a service provider
  // verifies is the <samlp:Response> INSIDE it, which carries its own signature
  // and its own assertion signature, and which is the document its whole
  // security model is written about. A signature on the envelope would be a
  // second thing to check that no service provider library checks. The back
  // channel's own integrity is TLS's job, which is what the SOAP binding says.
  private resolveArtifact(req, res) {
    const { errorCodes } = this.deps;
    const { firstByLocal, log, logArtifact, textByLocal } = this.deps.helpers;
    const { DOMParser } = this.deps.xmldom;
    const self = this;
    log.debug("Entering Saml2Sso.resolveArtifact().");
    const scoped = this.entityIdFromSegment(req.params.sp);
    if (this.refusedUnregistered(res, scoped, ARS_PATH + '/{sp}')) {
      log.debug("Leaving Saml2Sso.resolveArtifact(). Not registered.");
      return;
    }
    const raw = typeof req.body === 'string' ? req.body : '';
    logArtifact('SAML 2.0 ArtifactResolve', 'as received over SOAP', raw);
    const answer = function (status, message, payload, inResponseTo) {
      log.debug("Entering answer().");
      const envelope = self.soapEnvelope(self.buildArtifactResponse(
        self.idpEntityIdFor(scoped.entityId), inResponseTo, status, message,
          payload));
      logArtifact('SAML 2.0 ArtifactResponse', 'as returned over SOAP',
                  envelope);
      // 200 whatever the status: a SOAP fault is an HTTP-layer failure and this
      // is a SAML-layer refusal, and collapsing the two makes a service
      // provider's client throw a transport error where it should be reading a
      // status code.
      res.status(200)
         .type('text/xml; charset=utf-8')
         .set('Cache-Control', 'no-store')
         .send(envelope);
      log.debug("Leaving answer().");
    };

    let doc = null;
    try {
      doc = new DOMParser().parseFromString(raw, 'text/xml');
    } catch (e) {
      log.debug("Caught in Saml2Sso.resolveArtifact(): " +
                ((e && e.message) || e));
      // Kept as a SAML status rather than thrown, for the reason above.
      log.error(errorCodes.tag('STS-SAML-0015') + 'saml2: the ' +
                                                  'ArtifactResolve body is ' +
                                                  'not XML: ' + e.message);
      log.debug("Leaving Saml2Sso.resolveArtifact(). Unparseable.");
      errorCodes.mark(res, 'STS-SAML-0015');
      log.debug("Leaving Saml2Sso.resolveArtifact().");
      return answer(STATUS_REQUESTER, 'the request body is not XML: ' +
                    e.message,
                    '', '');
    }
    const resolve = firstByLocal(doc, 'ArtifactResolve');
    if (!resolve) {
      log.debug("Leaving Saml2Sso.resolveArtifact(). No ArtifactResolve.");
      errorCodes.mark(res, 'STS-SAML-0016');
      log.debug("Leaving Saml2Sso.resolveArtifact().");
      return answer(STATUS_REQUESTER, 'there is no <samlp:ArtifactResolve> ' +
                    'in the SOAP body. This endpoint speaks the SOAP binding ' +
                    '(saml-bindings-2.0-os section 3.2.3) and nothing ' +
                    'else.', '', '');
    }
    const inResponseTo = resolve.getAttribute('ID') || '';
    const spEntityId = textByLocal(resolve, 'Issuer');
    const artifact = textByLocal(resolve, 'Artifact');
    if (!artifact) {
      log.debug("Leaving Saml2Sso.resolveArtifact(). No artifact in the " +
                "request.");
      errorCodes.mark(res, 'STS-SAML-0017');
      log.debug("Leaving Saml2Sso.resolveArtifact().");
      return answer(STATUS_REQUESTER, 'the ArtifactResolve carries no ' +
                                      '<samlp:Artifact>.',
                    '', inResponseTo);
    }
    const held = artifacts.get(artifact);
    if (held) {
      // WHO IS ASKING, BEFORE ANYTHING IS SPENT (#37 follow-up): a caller that
      // is not the service provider the artifact was minted for — or cannot
      // show that it is — is refused, and the artifact stays resolvable by
      // the one it was issued to.
      const caller = this.authenticateArtifactCaller(req, resolve,
                                                     spEntityId, held);
      if (caller.refuse) {
        log.debug("Leaving Saml2Sso.resolveArtifact(). The caller was " +
                  "refused: " + caller.errorCode);
        errorCodes.mark(res, caller.errorCode || 'STS-SAML-0077');
        return answer(STATUS_REQUESTER, caller.why, '', inResponseTo);
      }
    }
    if (!held) {
      // The one refusal in this file that is worth making loudly, because it is
      // the same answer for three different mistakes and a service provider
      // cannot tell them apart from the status code alone: an artifact that was
      // never minted here, one that has expired, and — the interesting one —
      // one that has ALREADY BEEN RESOLVED. Decision 6.
      log.warn('saml2: artifact ' + String(artifact).slice(0, 12) + '… does ' +
               'not resolve. It was never minted here, or it has expired ' +
               '(saml2.artifactTtlS), or it has already been resolved once — ' +
               'which destroys it, because section 3.6.4.1 says an artifact ' +
               'is resolvable exactly once.');
      log.debug("Leaving Saml2Sso.resolveArtifact(). Unknown artifact.");
      errorCodes.mark(res, 'STS-SAML-0018');
      log.debug("Leaving Saml2Sso.resolveArtifact().");
      return answer(STATUS_REQUESTER,
                    'that artifact does not resolve: it was never issued ' +
                    'here, it has expired, or it has already been resolved — ' +
                    'an artifact is one-shot (section 3.6.4.1).',
                    '', inResponseTo);
    }
    // ONE-SHOT. Deleted BEFORE the answer is built rather than after it is
    // sent, so that two ArtifactResolve calls arriving together cannot both
    // find it.
    artifacts.delete(artifact);
    log.debug("Leaving Saml2Sso.resolveArtifact(). Claiming the artifact.");
    return this.spendArtifact(artifact, held).then(function (spent) {
      log.debug("Entering Saml2Sso.resolveArtifact()'s claim answer.");
      if (!spent.ok) {
        errorCodes.mark(res, spent.errorCode);
        log.debug("Leaving Saml2Sso.resolveArtifact()'s claim answer. " +
                  "Refused.");
        return answer(spent.reason === 'used' ? STATUS_REQUESTER :
                      STATUS_RESPONDER, spent.message, '', inResponseTo);
      }
      log.debug("Leaving Saml2Sso.resolveArtifact()'s claim answer. Spent.");
      return self.answerResolved(held, spEntityId, artifact, inResponseTo,
                                 answer);
    }).catch(function (e) {
      // `claim()` never rejects, so what lands here is the answer failing to be
      // built or sent — which is also what a synchronous throw from this
      // handler used to be, and Express's own handler answered that 500.
      log.error(errorCodes.tag('STS-SAML-0060') + 'saml2: the ' +
                'ArtifactResolve could not be answered after its claim: ' +
                ((e && e.message) || e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-SAML-0060');
        answer(STATUS_RESPONDER, 'the artifact could not be resolved.', '',
               inResponseTo);
      }
    });
  }

  // ---------------------------------------------------------------------------
  // THE ARTIFACT RESOLUTION SERVICE'S CALLER (#37 follow-up). Three checks, in
  // every mode, and each refuses WITHOUT spending the artifact:
  //
  //   1. the ArtifactResolve's <Issuer> must be the service provider the
  //      artifact was minted for (`STS-SAML-0078`) — saml-bindings-2.0-os
  //      section 3.6.4.1: the artifact is to be given only to its intended
  //      recipient. Until this follow-up that was logged and answered anyway;
  //   2. that service provider's consumed metadata must not have expired
  //      (`STS-SAML-0074`);
  //   3. the caller must be AUTHENTICATED as it — a signature on the
  //      ArtifactResolve or its registered certificate as the TLS client
  //      certificate — under the request policy
  //      (`request_signature.ts`'s `authenticateSoapCaller()`).
  //
  // This service's own mock service provider resolves in process
  // (`resolveForMockSp()`) and never reaches here.
  // ---------------------------------------------------------------------------
  private authenticateArtifactCaller(req, resolve, spEntityId, held): any {
    const { audit, mtls, requestSignature, spMetadata } = this.deps;
    const { baseUrlOf, log } = this.deps.helpers;
    const { XMLSerializer } = this.deps.xmldom;
    log.debug("Entering Saml2Sso.authenticateArtifactCaller().");
    const intended = String(held.spEntityId || '');
    const refuse = function (code, why, via) {
      log.debug("Entering refuse().");
      audit.audit({
        action: 'saml2.artifact.resolve', outcome: 'refused',
        errorCode: code, protocol: 'SAML 2.0', channel: 'http',
        target: String(spEntityId || ''),
        summary: 'An ArtifactResolve from "' + (spEntityId || '(unnamed)') +
                 '" was refused: ' + why,
        detail: { intended: intended, via: via || '' }
      });
      log.warn('saml2: refused an ArtifactResolve from "' +
               (spEntityId || '(unnamed)') + '": ' + why + '.');
      log.debug("Leaving refuse().");
      return { refuse: true, errorCode: code, why: why };
    };
    if (intended && String(spEntityId || '') !== intended) {
      log.debug("Leaving Saml2Sso.authenticateArtifactCaller(). Wrong SP.");
      return refuse('STS-SAML-0078', 'that artifact was issued to another ' +
                    'service provider, and an artifact is resolved only by ' +
                    'the one it was issued to (section 3.6.4.1)' +
                    (spEntityId ? '' : ' — this ArtifactResolve names no ' +
                                       '<Issuer>'), '');
    }
    const fields = this.fieldsOf(spEntityId);
    const fresh = spMetadata.freshness(fields);
    if (fresh.state === 'expired') {
      log.debug("Leaving Saml2Sso.authenticateArtifactCaller(). Expired.");
      return refuse('STS-SAML-0074', fresh.why, '');
    }
    const peer = mtls.peerCertificate(req);
    const revoked = req.certificateRevocation &&
                    req.certificateRevocation.refused;
    const caller = requestSignature.authenticateSoapCaller({
      xml: new XMLSerializer().serializeToString(resolve),
      rootLocalName: 'ArtifactResolve', fields: fields,
      tlsCertificate: peer && !revoked
        ? Buffer.from(peer.raw).toString('base64') : '',
      implicitCertificates: this.implicitCertificatesFor(baseUrlOf(req),
                                                         spEntityId)
    });
    if (caller.refuse) {
      log.debug("Leaving Saml2Sso.authenticateArtifactCaller(). " +
                caller.errorCode);
      return refuse(caller.errorCode, caller.why, caller.via);
    }
    audit.audit({
      action: 'saml2.artifact.resolve', outcome: 'success',
      protocol: 'SAML 2.0', channel: 'http', target: String(spEntityId || ''),
      summary: 'An ArtifactResolve from "' + (spEntityId || '(unnamed)') +
               '": caller ' + (caller.via === 'none'
                 ? 'NOT authenticated, which the policy allows'
                 : 'authenticated by ' + caller.via),
      detail: { via: caller.via, why: caller.why }
    });
    log.debug("Leaving Saml2Sso.authenticateArtifactCaller(). via=" +
              caller.via);
    return { refuse: false, via: caller.via };
  }

  private spendArtifact(artifact, held) {
    const { clusterClaims, errorCodes } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.spendArtifact().");
    const remaining = Math.max(0, Number(held && held.expires) - Date.now()) ||
                      0;
    log.debug("Leaving Saml2Sso.spendArtifact(). Asking the claim store.");
    return clusterClaims.claim({ scope: 'saml2.artifact', value: artifact,
                                 ttlMs: remaining + CLAIM_SKEW_MS })
      .then(function (claimed) {
        log.debug("Entering Saml2Sso.spendArtifact()'s answer.");
        if (claimed.ok) {
          log.debug("Leaving Saml2Sso.spendArtifact()'s answer. Spent here.");
          return { ok: true };
        }
        if (claimed.reason === 'used') {
          log.warn(errorCodes.tag('STS-SAML-0057') + 'saml2: artifact ' +
                   String(artifact).slice(0, 12) + '… was still held here ' +
                   'but has ALREADY BEEN RESOLVED by another node against ' +
                   'the same store. Refused: section 3.6.4.1 allows one ' +
                   'resolution.');
          log.debug("Leaving Saml2Sso.spendArtifact()'s answer. Used " +
                    "elsewhere.");
          return { ok: false, reason: 'used', errorCode: 'STS-SAML-0057',
                   message: 'that artifact does not resolve: it has already ' +
                            'been resolved — an artifact is one-shot ' +
                            '(section 3.6.4.1).' };
        }
        log.error(errorCodes.tag('STS-SAML-0059') + 'saml2: whether artifact ' +
                  String(artifact).slice(0, 12) + '… was already resolved ' +
                  'could not be asked of the claim store (' +
                  (claimed.why || 'no reason given') + '). It is refused.');
        log.debug("Leaving Saml2Sso.spendArtifact()'s answer. Store " +
                  "unavailable.");
        return { ok: false, reason: 'store', errorCode: 'STS-SAML-0059',
                 message: 'the identity provider could not confirm that ' +
                          'artifact is unresolved, so it is not resolved.' };
      });
  }

  // The success half of resolveArtifact(), after the artifact is spent.
  private answerResolved(held, spEntityId, artifact, inResponseTo, answer) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.answerResolved().");
    // A resolver that is not the artifact's service provider was refused
    // before the artifact was spent — `authenticateArtifactCaller()`.
    log.debug("Leaving Saml2Sso.answerResolved(). Resolved and destroyed.");
    return answer(STATUS_SUCCESS, '', held.xml, inResponseTo);
  }

  // ---------------------------------------------------------------------------
  // SINGLE LOGOUT (saml-profiles-2.0-os section 4.4).
  //
  // Both directions arrive here, and they are told apart by which message the
  // binding carried: a <samlp:LogoutRequest> is a service provider asking this
  // identity provider to end the session, and a bare GET is somebody asking
  // this identity provider to start one.
  //
  // **WHERE THE LogoutResponse GOES.** A LogoutRequest carries no return
  // address — only SP METADATA has one, in a SingleLogoutService element. So
  // the address is looked for in four places in order: the SingleLogoutService
  // endpoints of the service provider's CONSUMED metadata (#37) — the
  // ResponseLocation for a response, on the binding the request arrived on
  // where the service provider publishes one; the application entry's
  // `samlSingleLogoutService`, which is what an operator sets and what an
  // `ldapmodify` reaches; `saml2.defaultSingleLogoutService`; and finally the
  // assertion consumer service URL that service provider last used, which is
  // a GUESS and is logged as one. It is a guess that works — a service
  // provider's ACS and its SLO endpoint are commonly the same handler — and it
  // is the difference between Single Logout being testable here and not for a
  // service provider nobody registered.
  //
  // `want.response` asks for a LogoutResponse's address; `want.binding` is the
  // binding it would go back on. The answer's `binding` is the one to use.
  // ---------------------------------------------------------------------------
  private logoutReturnAddressFor(spEntityId, want?): any {
    const { applications, config } = this.deps;
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering Saml2Sso.logoutReturnAddressFor(). sp=" + spEntityId);
    const asked = want || {};
    const known = this.fieldsOf(spEntityId);
    const endpoints = this.sloEndpointsOf(known).filter(function (one) {
      return self.deliverable(one.binding) && one.binding !== BINDING_ARTIFACT;
    });
    // A LogoutRequest this service STARTS is sent as a link on the Redirect
    // binding (logoutTargetsFor()), so that is the endpoint it wants.
    const preferred = asked.response ? asked.binding : BINDING_REDIRECT;
    const endpoint = endpoints.filter(function (one) {
      return one.binding === preferred;
    })[0] || endpoints[0];
    if (endpoint) {
      const url = asked.response && endpoint.responseLocation
        ? endpoint.responseLocation : endpoint.location;
      log.debug("Leaving Saml2Sso.logoutReturnAddressFor(). From the " +
                "consumed metadata.");
      return { url: url, binding: endpoint.binding,
               from: 'the SingleLogoutService ' +
                     (asked.response && endpoint.responseLocation
                       ? 'ResponseLocation ' : '') +
                     'in its consumed metadata' };
    }
    const declared = known.samlSingleLogoutService;
    const first = Array.isArray(declared) ? declared[0] : declared;
    if (first) {
      log.debug("Leaving Saml2Sso.logoutReturnAddressFor(). From the " +
                "application entry.");
      return { url: String(first), from: 'the samlSingleLogoutService on its ' +
                                         'application entry' };
    }
    const configured =
      String(config.value('saml2.defaultSingleLogoutService') || '');
    if (configured) {
      log.debug("Leaving Saml2Sso.logoutReturnAddressFor(). From the " +
                "configuration.");
      return { url: configured, from: 'saml2.defaultSingleLogoutService' };
    }
    // The GUESS reads only what `applications.returnAddressesOf()` believes
    // (2026-09-12), for the reason the sign-in path does: in product an ACS URL
    // a development-mode request recorded and nobody confirmed is not somewhere
    // a signed LogoutResponse goes either. Development believes every value, so
    // this is the last one exactly as it was.
    const acsBelieved =
      applications.returnAddressesOf(known,
                                     'samlAssertionConsumerService')
        .registered;
    const acs = acsBelieved[acsBelieved.length - 1];
    if (acs) {
      log.warn('saml2: "' + spEntityId + '" has no SingleLogoutService ' +
               'recorded, so its LogoutResponse is going to the assertion ' +
               'consumer service URL it last used (' +
               acs + '). That is a GUESS — a LogoutRequest carries no return ' +
               'address, and this service provider has no consumed metadata ' +
               'saying where one goes. Consume its metadata, set ' +
               'samlSingleLogoutService on its application entry, or set ' +
               'saml2.defaultSingleLogoutService, to remove it.');
      log.debug("Leaving Saml2Sso.logoutReturnAddressFor(). Guessed from the " +
                "ACS URL.");
      return { url: String(acs), from: 'the assertion consumer service URL ' +
                                       'it last used — A GUESS' };
    }
    log.debug("Leaving Saml2Sso.logoutReturnAddressFor(). There is nowhere " +
              "to send it.");
    return { url: '', from: '' };
  }

  private buildLogoutResponse(idpEntityId, destination, inResponseTo, status,
                               message, sp, subStatus?) {
    const { errorCodes } = this.deps;
    const { genId, iso, log, logArtifact, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.buildLogoutResponse(). status=" + status);
    const id = genId();
    const xml =
      '<samlp:LogoutResponse xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' +
        NS_SAML + '" ' +
        'ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
        (destination ? ' Destination="' + xmlEscape(destination) + '"' : '') +
        (inResponseTo ? ' InResponseTo="' + xmlEscape(inResponseTo) + '"' :
         '') + '><saml:Issuer>' + xmlEscape(idpEntityId) + '</saml:Issuer>' +
        // THE SECOND-LEVEL CODE (#192): PartialLogout, or UnknownPrincipal.
        // It was computed by singleLogout() and never passed here, so every
        // LogoutResponse said a bare Success whatever it had meant to say.
        this.statusElement(status, subStatus || '', message) +
      '</samlp:LogoutResponse>';
    logArtifact('SAML 2.0 LogoutResponse', 'before signing', xml);
    if (!this.settingFor(sp || '', 'saml2.signResponse')) {
      log.debug("Leaving Saml2Sso.buildLogoutResponse(). Unsigned.");
      return xml;
    }
    try {
      const signed = this.signDocument(xml, 'LogoutResponse', id,
                                       'after-issuer');
      logArtifact('SAML 2.0 LogoutResponse', 'after signing', signed);
      log.debug("Leaving Saml2Sso.buildLogoutResponse(). Signed.");
      return signed;
    } catch (e) {
      log.debug("Caught in Saml2Sso.buildLogoutResponse(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SAML-0013') + 'the LogoutResponse could ' +
                                                  'not be signed, sending it ' +
                                                  'unsigned: ' + e.message);
      log.debug("Leaving Saml2Sso.buildLogoutResponse(). Unsigned after a " +
                "signing failure.");
      return xml;
    }
  }

  // The <saml:NameID> of a LogoutRequest, or the <saml:EncryptedID> that stands
  // in for it. Separate from buildLogoutRequest() so the decision is one
  // expression rather than a branch around eight lines of markup, and so the
  // plaintext element is built exactly once whether or not it is then sealed —
  // two spellings of a NameID is how the encrypted and clear paths come to
  // disagree about a Format attribute.
  private subjectFor(sp, nameId, nameIdFormat) {
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.subjectFor().");
    const attributes = (nameIdFormat ?
                        ' Format="' + xmlEscape(nameIdFormat) + '"' : '');
    if (!this.settingFor(sp || '', 'saml2.encryptLogoutNameId')) {
      log.debug("Leaving Saml2Sso.subjectFor().");
      // In the document, so the prefix is declared on the LogoutRequest above
      // it.
      return '<saml:NameID' + attributes + '>' + xmlEscape(nameId) +
             '</saml:NameID>';
    }
    // ENCRYPTED, SO IT DECLARES ITS OWN NAMESPACE. Once this element is
    // ciphertext it has no parent to inherit `saml:` from — the service
    // provider decrypts it as a standalone fragment, and one that relies on a
    // declaration three levels up in a document it has not reassembled yet is a
    // NamespaceError on the other side. Found by decrypting our own output,
    // which is the only way this class of bug is ever found.
    const plain = '<saml:NameID xmlns:saml="' + NS_SAML + '"' + attributes +
                  '>' +
      xmlEscape(nameId) + '</saml:NameID>';
    log.debug("Leaving Saml2Sso.subjectFor().");
    return this.encryptFor(sp, plain, 'saml:EncryptedID', 'logout NameID').xml;
  }

  private buildLogoutRequest(idpEntityId, destination, nameId, nameIdFormat,
                              sessionIndex, sp) {
    const { errorCodes } = this.deps;
    const { genId, iso, log, logArtifact, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.buildLogoutRequest(). to=" + destination);
    const id = genId();
    const xml =
      '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' +
        NS_SAML + '" ' +
        'ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
        (destination ? ' Destination="' + xmlEscape(destination) + '"' :
         '') + '><saml:Issuer>' + xmlEscape(idpEntityId) + '</saml:Issuer>' +
        // THE ONLY THING IN A SAML 2.0 REQUEST THAT CAN BE ENCRYPTED. There is
        // no EncryptedAuthnRequest in the specification — a request is signed,
        // not sealed — so <saml:EncryptedID> in a LogoutRequest is the whole of
        // what "request encryption" means in this protocol. saml-core-2.0-os
        // section 3.7.1 allows it exactly where the NameID would be.
        this.subjectFor(sp, nameId, nameIdFormat) +
        (sessionIndex ?
         '<samlp:SessionIndex>' + xmlEscape(sessionIndex) +
         '</samlp:SessionIndex>' : '') +
      '</samlp:LogoutRequest>';
    logArtifact('SAML 2.0 LogoutRequest', 'before signing', xml);
    if (!this.settingFor(sp || '', 'saml2.signResponse')) {
      log.debug("Leaving Saml2Sso.buildLogoutRequest(). Unsigned.");
      return xml;
    }
    try {
      const signed = this.signDocument(xml, 'LogoutRequest', id,
                                       'after-issuer');
      log.debug("Leaving Saml2Sso.buildLogoutRequest(). Signed.");
      return signed;
    } catch (e) {
      log.debug("Caught in Saml2Sso.buildLogoutRequest(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SAML-0013') + 'the LogoutRequest could ' +
                                                  'not be signed, sending it ' +
                                                  'unsigned: ' + e.message);
      log.debug("Leaving Saml2Sso.buildLogoutRequest(). Unsigned after a " +
                "signing failure.");
      return xml;
    }
  }

  private singleLogout(req, res) {
    const { errorCodes, validation } = this.deps;
    const { endSession } = this.deps.authn;
    const { STS, baseUrlOf, firstByLocal, log, logArtifact, textByLocal,
            xmlEscape } = this.deps.helpers;
    const { decryptElement } = this.deps.saml2;
    const { DOMParser, XMLSerializer } = this.deps.xmldom;
    log.debug("Entering Saml2Sso.singleLogout(). method=" + req.method);
    const base = baseUrlOf(req);
    const params: any = this.paramsOf(req);
    const scoped = this.entityIdFromSegment(req.params.sp);
    if (this.refusedUnregistered(res, scoped, SLO_PATH + '/{sp}')) {
      log.debug("Leaving Saml2Sso.singleLogout(). Not registered.");
      return;
    }

    // A LogoutResponse arriving HERE is another identity provider's answer to a
    // LogoutRequest this one sent, and this service is not a federation gateway
    // — it is reported and dropped rather than acted on, which is the same
    // decision wsfed.ts makes about a cleanup request arriving at the identity
    // provider.
    if (params.SAMLResponse) {
      const answered = this.decodeMessage(params.SAMLResponse);
      logArtifact('SAML 2.0 LogoutResponse', 'as received at the identity ' +
                                             'provider', answered);
      // ITS SIGNATURE IS CHECKED (#37) under the same policy as a request's,
      // although nothing is acted on: a LogoutResponse that does not verify is
      // a forged or altered message, and a page saying "received" about one
      // would tell the person testing their service provider that its signing
      // works.
      const readAnswer = validation.parseXml(answered, 'LogoutResponse');
      const answerRoot = readAnswer.ok ? readAnswer.value.documentElement
                                       : null;
      const answerFrom = (answerRoot && textByLocal(answerRoot, 'Issuer')) ||
                         scoped.entityId;
      let checkedAnswer = null;
      if (answerRoot && answerRoot.localName === 'LogoutResponse') {
        checkedAnswer = this.checkSignature(req, base, {
          what: 'LogoutResponse', field: 'SAMLResponse', xml: answered,
          params: params, spEntityId: answerFrom
        });
        if (checkedAnswer.refusal.refuse) {
          errorCodes.mark(res, checkedAnswer.refusal.errorCode ||
                               'STS-SAML-0061');
          log.debug("Leaving Saml2Sso.singleLogout(). A LogoutResponse's " +
                    "signature was refused.");
          return this.samlError(res, 403, checkedAnswer.refusal.title ||
                                'That LogoutResponse\'s signature is not ' +
                                'accepted',
                                checkedAnswer.refusal.why);
        }
      }
      log.debug("Leaving Saml2Sso.singleLogout(). A LogoutResponse was " +
                "received and dropped.");
      return this.sendPage(res, 200, 'Logout response received — SAML 2.0',
        '<h1>A LogoutResponse arrived here</h1><div class="ok">It has been ' +
        'logged and dropped.</div><p>A LogoutResponse is an answer to a ' +
        'LogoutRequest, and this identity provider does not wait for one: ' +
        'its logout page fans out and reports, rather than driving a chain ' +
        'of redirects through every service provider in turn. Acting on this ' +
        'would make this service a federation gateway, which it is ' +
        'not.</p>' +
        (checkedAnswer
          ? '<p>Its signature: <strong>' +
            xmlEscape(checkedAnswer.assessment.outcome) + '</strong> — ' +
            xmlEscape(checkedAnswer.assessment.why) + '.</p>'
          : '') +
        '<pre>' + xmlEscape(answered) + '</pre>');
    }

    if (!params.SAMLRequest) {
      // IdP-initiated: somebody asked this identity provider to end the
      // session.
      log.debug("Leaving Saml2Sso.singleLogout(). " +
                "Identity-provider-initiated.");
      return this.identityProviderInitiatedLogout(req, res, base, params);
    }

    const xml = this.decodeMessage(params.SAMLRequest);
    logArtifact('SAML 2.0 LogoutRequest', 'as received from a service provider',
                xml);
    // Unguarded until 2026-09-06, for readAuthnRequest()'s reason exactly: a
    // malformed LogoutRequest was an uncaught ParseError rather than the
    // refusal below it.
    const readLogout = validation.parseXml(xml, 'LogoutRequest');
    if (!readLogout.ok) {
      log.debug("Leaving Saml2Sso.singleLogout(). " + readLogout.detail);
      errorCodes.mark(res, 'STS-SAML-0019');
      log.debug("Leaving Saml2Sso.singleLogout().");
      return this.samlError(res, 400, 'That is not a LogoutRequest',
                            readLogout.detail);
    }
    const doc = readLogout.value;
    const root = doc.documentElement;
    if (!root || root.localName !== 'LogoutRequest') {
      log.debug("Leaving Saml2Sso.singleLogout(). It is not a LogoutRequest.");
      errorCodes.mark(res, 'STS-SAML-0019');
      log.debug("Leaving Saml2Sso.singleLogout().");
      return this.samlError(res, 400, 'That is not a LogoutRequest',
        'This endpoint reads <samlp:LogoutRequest> (saml-core-2.0-os section ' +
        '3.7.1). An <samlp:AuthnRequest> goes to ' + SSO_PATH + '.');
    }
    const requestId = root.getAttribute('ID') || '';
    const spEntityId = textByLocal(root, 'Issuer') || scoped.entityId;
    // THE SIGNATURE (#37), before anything is decrypted or ended: a
    // LogoutRequest whose signature fails, or an unsigned one where signed
    // requests are required, ends NO session. saml-profiles-2.0-os section
    // 4.4.3.1 asks for a logout message to be authenticated, and ending
    // somebody's session on the strength of a forged one is the attack.
    const checkedLogout = this.checkSignature(req, base, {
      what: 'LogoutRequest', field: 'SAMLRequest', xml: xml,
      params: params, spEntityId: spEntityId
    });
    if (checkedLogout.refusal.refuse) {
      errorCodes.mark(res, checkedLogout.refusal.errorCode || 'STS-SAML-0061');
      log.debug("Leaving Saml2Sso.singleLogout(). The signature was " +
                "refused.");
      return this.samlError(res, 403, checkedLogout.refusal.title ||
                            'That LogoutRequest\'s signature is not accepted',
                            checkedLogout.refusal.why + ' The session was ' +
                            'NOT ended.');
    }
    // ITS ENVELOPE (#190): Version, IssueInstant and Destination, as an
    // AuthnRequest's — a LogoutRequest ending somebody's session is at least
    // as worth being sure of.
    const logoutEnvelope = this.envelopeProblem(req, base, {
      what: 'LogoutRequest', version: root.getAttribute('Version') || '',
      issueInstant: root.getAttribute('IssueInstant') || '',
      destination: root.getAttribute('Destination') || '',
      signed: !!checkedLogout.assessment.signed
    });
    if (logoutEnvelope) {
      errorCodes.mark(res, logoutEnvelope.errorCode);
      log.warn('saml2: refused a LogoutRequest from "' +
               (spEntityId || '(unnamed)') + '": ' + logoutEnvelope.why);
      log.debug("Leaving Saml2Sso.singleLogout(). Its envelope was " +
                "refused.");
      // error-code: none — marked above: STS-SAML-0085, 0086 or 0087.
      return this.samlError(res, 400, logoutEnvelope.title,
                            logoutEnvelope.why + ' The session was NOT ' +
                            'ended.');
    }
    // THE SUBJECT, WHICH MAY BE ENCRYPTED. A service provider that has this
    // service's metadata has an encryption key to use, and section 3.7.1 lets
    // it send <saml:EncryptedID> in place of <saml:NameID>.
    //
    // IT IS ALWAYS DECRYPTED AND THERE IS NO SETTING FOR IT. Every other
    // encryption switch here governs what this service SENDS; refusing to
    // understand a message somebody encrypted to a key this service published
    // would make that key a lie. The outbound switches exist because a service
    // provider may not be able to READ what we send; nothing equivalent applies
    // in this direction.
    //
    // A FAILURE IS A REFUSAL WITH A SENTENCE, not a silent fall-through to an
    // empty NameID. An empty one would end the session anyway — endSession()
    // reads the cookie, not this value — and the LogoutResponse would say
    // Success, so the service provider would be told its logout worked while
    // this service had no idea who it was about.
    const encryptedIdEl = firstByLocal(root, 'EncryptedID');
    let nameIdEl = firstByLocal(root, 'NameID');
    let decrypted = null;
    if (encryptedIdEl && !nameIdEl) {
      // Any of this realm's RSA keys, every live generation (#42).
      decrypted = this.deps.helpers.decryptOwnElement(
        new XMLSerializer().serializeToString(encryptedIdEl),
        { logArtifact: this.deps.helpers.logArtifact });
      if (!decrypted.ok) {
        log.warn('saml2: a LogoutRequest from ' + (spEntityId || '(unnamed)') +
                 ' ' +
                 'carried an <saml:EncryptedID> that could not be read ' +
                 '— ' + decrypted.why + '.');
        // An rsa-1_5 key transport refused in product (#181) is recorded as
        // itself, because the operator's fix is the service provider's
        // algorithm rather than its certificate; every other failure is 0020.
        errorCodes.mark(res, errorCodes.codeOf(decrypted) === 'STS-KEYS-0070'
          ? 'STS-KEYS-0070' : 'STS-SAML-0020');
        log.debug("Leaving Saml2Sso.singleLogout().");
        return this.samlError(res, 400,
                              'That EncryptedID could not be decrypted',
          'This LogoutRequest carries a &lt;saml:EncryptedID&gt; rather than ' +
          'a &lt;saml:NameID&gt;, and ' + xmlEscape(decrypted.why) + '. The ' +
          'session was NOT ended, because a logout this service cannot ' +
          'attribute to anybody is one it cannot honestly report as done. ' +
          'This service\'s current encryption certificate is in its ' +
          'metadata, which is regenerated on every start.');
      }
      const reparsed = new DOMParser().parseFromString(decrypted.xml,
                                                       'text/xml');
      nameIdEl = reparsed && reparsed.documentElement ?
                 reparsed.documentElement :
                 null;
      log.info('saml2: the LogoutRequest from ' + (spEntityId || '(unnamed)') +
               ' ' +
               'carried an encrypted NameID ' +
               '(' + decrypted.algorithm + ', key unwrapped ' +
                   'with ' +
               decrypted.keyTransport + '); it decrypted to ' +
               ((nameIdEl && nameIdEl.textContent) || '(nothing)') + '.');
    }
    const nameId = nameIdEl ? (nameIdEl.textContent || '').trim() : '';
    const nameIdFormat = nameIdEl ?
                         (nameIdEl.getAttribute('Format') || '') : '';
    const sessionIndex = textByLocal(root, 'SessionIndex');
    const idpEntityId = this.idpEntityIdFor(spEntityId);
    const arrivedBy = req.method !== 'POST' ? BINDING_REDIRECT
      : (params.Signature ? BINDING_SIMPLESIGN : BINDING_POST);

    // The session ends here. `endSession()` returns what it dropped, which is
    // how the page below can name the other service providers that were signed
    // in — and which is why the list has to be read BEFORE the answer is built.
    let session = endSession(req, res);
    // THE BACK CHANNEL (#192). A LogoutRequest a service provider sends
    // SERVER TO SERVER — Keycloak's broker does, and saml-profiles-2.0-os
    // section 4.4 allows every binding for it — arrives with no browser and
    // so no cookie, and until #192 it ended NOTHING while the LogoutResponse
    // said Success. The request names the session itself: its SessionIndex is
    // the session id this service put in the assertion. That session is ended
    // when it signed into this service provider and was issued THIS NameID
    // there; a SessionIndex naming anybody else's session ends nothing and is
    // answered UnknownPrincipal (STS-SAML-0090).
    let principalRefused = false;
    if (!session && sessionIndex) {
      const back = this.sessionNamedBy(spEntityId, sessionIndex, nameId);
      if (back.session) {
        session = this.deps.authn.endSessionById(
          back.session.id, 'saml2-slo ' + spEntityId);
        log.info('saml2: the back-channel LogoutRequest from "' +
                 spEntityId + '" ended the session it named (' +
                 sessionIndex + ').');
      } else if (back.mismatch) {
        principalRefused = true;
        errorCodes.mark(res, 'STS-SAML-0090');
        log.warn(errorCodes.tag('STS-SAML-0090') + 'saml2: a LogoutRequest ' +
                 'from "' + spEntityId + '" named session ' + sessionIndex +
                 ' and the NameID "' + nameId + '", which is not the ' +
                 'NameID that session was issued there; nothing was ended.');
      }
    }
    const others = (session && session.saml2ServiceProviders) || {};
    const otherNames = Object.keys(others)
                             .filter(function (name) {
                               return name !== spEntityId;
                             });

    this.recordServiceProvider({
           identifier: spEntityId,
           kind: 'saml2-service-provider',
           protocol: 'SAML 2.0',
           counts: false,
           note: 'sent a LogoutRequest',
           fields: { samlEntityId: spEntityId }
    });

    const back = this.logoutReturnAddressFor(spEntityId,
                                             { response: true,
                                               binding: arrivedBy });
    // PartialLogout rather than Success when this session had OTHER service
    // providers in it, because that is what happened: section 3.7.3.2 has a
    // status code for exactly this, and reporting Success would tell the
    // service provider that a federation-wide logout it never got was complete.
    // Every real identity provider that does not implement front-channel
    // fan-out gets this wrong.
    const partial = otherNames.length > 0;
    const status = principalRefused ? STATUS_REQUESTER : STATUS_SUCCESS;
    const subStatus = principalRefused ? STATUS_UNKNOWN_PRINCIPAL
      : (partial ? STATUS_PARTIAL_LOGOUT : '');
    const message = partial
      ? 'The browser session ended. ' + otherNames.length + ' other service ' +
        'provider(s) were signed in on it and were NOT sent a LogoutRequest ' +
        'from here — see ' + base + SLO_PATH + '.'
      : '';
    if (!back.url) {
      log.debug("Leaving Saml2Sso.singleLogout(). Nowhere to send the " +
                "LogoutResponse.");
      return this.sendPage(res, 200, 'Signed out — SAML 2.0',
        '<h1>Signed out</h1>' +
        '<div class="ok">' + (session
          ? 'The session for ' +
            xmlEscape((session.user && session.user.username) || '') +
            ' has ended. It is the session the OAuth 2.0 / OIDC and ' +
            'WS-Federation sides share, so they are signed out too.'
          : 'There was no session to end. The cookie has been cleared ' +
            'anyway.') +
        '</div><p>There ' +
        'is nowhere to send the <code>&lt;samlp:LogoutResponse&gt;</code>: ' +
        '<code>' +
        xmlEscape(spEntityId) + '</code> has no ' +
        '<code>samlSingleLogoutService</code> on its application entry, ' +
        '<code>saml2.defaultSingleLogoutService</code> is empty, no ' +
        'metadata has been consumed for it, and this service has never seen ' +
        'an assertion consumer service URL for it either. A LogoutRequest ' +
        'carries no return address of its own — only SP metadata ' +
        'does.</p><p>Consume its metadata, or set an address on <a ' +
        'href="/admin/saml2">the SAML 2.0 console page</a>, through ' +
        '<code>POST /admin-api/saml2/set-logout-service</code>, or with an ' +
        '<code>ldapmodify</code>.</p>');
    }

    const response = this.buildLogoutResponse(idpEntityId, back.url, requestId,
                                              status, message, spEntityId,
                                              subStatus);
    log.info('saml2: ' + spEntityId + ' logged out' +
             (nameId ? ' ' + nameId : '') +
             (sessionIndex ? ' (session index ' + sessionIndex + ')' : '') +
             '; the LogoutResponse goes to ' + back.url + ', from ' +
               back.from +
             '.');
    this.deliver(res, {
           binding: back.binding || arrivedBy, destination: back.url,
           field: 'SAMLResponse',
           xml: response,
           relayState: params.RelayState ||
                       '', issuer: idpEntityId, spEntityId: spEntityId,
           inResponseTo: requestId,
           note: { title: 'Signed out — SAML 2.0', who: 'the service provider',
                   sub: 'A <samlp:LogoutResponse>, going to ' +
                          xmlEscape(back.from) + '.' }
    });
    log.debug("Leaving Saml2Sso.singleLogout(). A LogoutResponse went to " +
              spEntityId +
              ".");
    return undefined;
  }

  // The session a back-channel LogoutRequest names (#192): the one whose id is
  // its SessionIndex, when that session signed into this service provider and
  // was given this NameID there. `{ session }`, `{ mismatch: true }` when the
  // session exists and the rest does not hold, or `{}` when there is no such
  // session — already ended, which a logout may answer Success to.
  private sessionNamedBy(spEntityId, sessionIndex, nameId): any {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.sessionNamedBy().");
    const named = this.deps.authn.sessionById(sessionIndex);
    if (!named) {
      log.debug("Leaving Saml2Sso.sessionNamedBy(). No such session.");
      return {};
    }
    const there = (named.saml2ServiceProviders || {})[spEntityId];
    const given = there && there.nameId !== undefined ? there.nameId
      : ((named.user && named.user.username) || '');
    if (!there || given !== nameId) {
      log.debug("Leaving Saml2Sso.sessionNamedBy(). Not this principal's.");
      return { mismatch: true };
    }
    log.debug("Leaving Saml2Sso.sessionNamedBy(). Found.");
    return { session: named };
  }

  // ---------------------------------------------------------------------------
  // THE LOGOUT REQUESTS ONE SESSION IS OWED, as data rather than as HTML.
  //
  // `session.saml2ServiceProviders` is written when a sign-in response goes
  // out. This turns it into the list Single Logout has to address, with the
  // LogoutRequest already built and encoded for the HTTP Redirect binding.
  //
  // It is a function of its own for ONE reason: the protocol-independent
  // `/logout` at the root of this service has to name exactly these, and a
  // second builder over there would be a second answer to what a LogoutRequest
  // for this session looks like — a message this service SIGNS, so two builders
  // would be two signed documents that could differ.
  //
  // A service provider with no logout return address is REPORTED with an empty
  // url rather than dropped, for the same reason the table below prints
  // "nowhere to send one": that is the interesting row.
  // ---------------------------------------------------------------------------
  logoutTargetsFor(session) {
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering Saml2Sso.logoutTargetsFor().");
    const signedInto = (session && session.saml2ServiceProviders) || {};
    const username = (session && session.user && session.user.username) || '';
    const out = Object.keys(signedInto).map(function (name) {
      const back = self.logoutReturnAddressFor(name);
      const idpEntityId = signedInto[name].idpEntityId ||
                          self.idpEntityIdFor(name);
      // The NameID that service provider was GIVEN (#192), where the
      // session recorded one; the username in the configured format for a
      // session from before that was recorded.
      const given = signedInto[name] || {};
      const request = self.buildLogoutRequest(idpEntityId, back.url,
        given.nameId !== undefined ? given.nameId : username,
        String(given.nameIdFormat ||
               self.settingFor(name, 'saml2.nameIdFormat')),
        (session && session.id) || '', name);
      // THROUGH redirectUrlFor() (#192), so it is signed on the query
      // string as the binding requires, rather than carrying only the
      // enveloped signature the Redirect binding removes.
      return {
        entityId: name,
        from: back.from,
        destination: back.url,
        url: back.url
          ? self.redirectUrlFor(back.url, 'SAMLRequest', request, '', name)
          : ''
      };
    });
    log.debug("Leaving Saml2Sso.logoutTargetsFor(). " + out.length +
              " service " +
        "provider(s).");
    return out;
  }

  // Identity-provider-initiated logout. The session ends and every service
  // provider it signed into is NAMED, with a LogoutRequest built for each.
  //
  // It is a page of links and not an automatic fan-out, and that is the same
  // decision wsfed.ts makes about its cleanup pings for a different reason: a
  // WS-Federation cleanup is an idempotent GET that works as a one-pixel image,
  // and a SAML LogoutRequest is a signed message that most service providers
  // expect over POST and that they ANSWER. Firing those into hidden frames
  // would produce a page that claims a federation-wide logout it cannot
  // observe. Naming them, with the message ready to send, is what this service
  // can honestly do.
  private identityProviderInitiatedLogout(req, res, base, params) {
    const { endSession } = this.deps.authn;
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.identityProviderInitiatedLogout().");
    const session = endSession(req, res);
    const targets = this.logoutTargetsFor(session);
    const names = targets.map(function (t) { return t.entityId; });
    const username = (session && session.user && session.user.username) || '';
    const rows = targets.map(function (target) {
      return '<tr><td><code>' + xmlEscape(target.entityId) + '</code></td>' +
        '<td>' + (target.url
          ? '<a href="' + xmlEscape(target.url) + '">send a ' +
            'LogoutRequest</a><br><span ' +
            'class="sub">' + xmlEscape(target.from) + '</span>'
          : '<span class="fail">nowhere to send one</span>') + '</td></tr>';
    }).join('');
    const inner = '<h1>Signed out</h1>' +
      '<p class="sub">SAML 2.0 Single Logout, identity-provider-initiated ' +
      '(saml-profiles-2.0-os section 4.4)</p>' +
      '<div class="ok">' + (session
        ? 'The session for ' + xmlEscape(username) + ' has ended. It is the ' +
          'session the OAuth 2.0 / OIDC and WS-Federation sides share, so ' +
          'they are signed out too.'
        : 'There was no session to end. The cookie has been cleared anyway.') +
      '</div>' +
      (names.length
        ? '<h2>' + names.length + ' service provider' +
          (names.length === 1 ? '' : 's') +
          ' was signed in on it</h2><table><thead><tr><th>Service ' +
          'provider</th><th>LogoutRequest</th></tr></thead><tbody>' + rows +
          '</tbody></table><p ' +
          'class="sub">These are LINKS rather than an automatic fan-out, and ' +
          'that is deliberate. WS-Federation\'s ' +
          '<code>wsignoutcleanup1.0</code> is an idempotent GET that works ' +
          'as a one-pixel image; a SAML LogoutRequest is a signed message ' +
          'that a service provider ANSWERS, and firing those into hidden ' +
          'frames would produce a page claiming a federation-wide logout it ' +
          'cannot observe.</p>'
        : '<p>This session had signed into no service provider through this ' +
          'profile, so there is nothing to log out of.</p>') +
      (params.RelayState ? '<div class="meta"><div>RelayState: <code>' +
        xmlEscape(String(params.RelayState)) + '</code></div></div>' : '');
    this.sendPage(res, 200, 'Signed out — SAML 2.0', inner);
    log.debug("Leaving Saml2Sso.identityProviderInitiatedLogout(). " +
              names.length + " " +
        "named.");
  }

  // ---------------------------------------------------------------------------
  // THE METADATA (saml-metadata-2.0-os).
  //
  // SIGNED, with ds:Signature FIRST inside EntityDescriptor — the metadata
  // schema puts it at the head of the sequence, where a protocol message puts
  // it after Issuer and a SAML 1.1 assertion puts it last. Four documents in
  // this service, three positions, all schema-mandated; see wsfed.ts's
  // federation metadata, which is the same argument for the same reason.
  //
  // It answers for ANY {sp}. See decision 1 — the ask is what registers it.
  // ---------------------------------------------------------------------------
  metadataFor(base, spEntityId) {
    const { documentSettings, errorCodes, requestSignature } = this.deps;
    const { STS, genId, log, logArtifact, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.metadataFor(). sp=" +
              (spEntityId || '(unscoped)'));
    const id = genId();
    const idpEntityId = this.idpEntityIdFor(spEntityId);
    const where = this.endpointsFor(base, spEntityId);
    const keyDescriptor = function (use) {
      log.debug("Entering keyDescriptor().");
      log.debug("Leaving keyDescriptor().");
      // SIGNING: one KeyDescriptor per live generation of the XML key (#42)
      // — the `next` key published ahead of its promotion, and a retired key
      // still verifying. ENCRYPTION: the current key alone, so new encryption
      // goes to it while something encrypted to a retired one still opens.
      if (use === 'signing') {
        return helpers.ownRsaCertificates('xml').map(function (one: any) {
          return '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="' +
            NS_DS + '"><ds:X509Data><ds:X509Certificate>' +
            stsCrypto.stripPem(one.certPem) + '</ds:X509Certificate>' +
            '</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
        }).join('');
      }
      return '<md:KeyDescriptor use="' + use + '"><ds:KeyInfo xmlns:ds="' +
        NS_DS + '"><ds:X509Data><ds:X509Certificate>' + STS.xml.certB64 +
        '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';
    };

    const service = function (element, binding, location, extra?) {
      log.debug("Entering service().");
      log.debug("Leaving service().");
      return '<md:' + element + ' Binding="' + binding + '" Location="' +
             xmlEscape(location) + '"' +
        (extra || '') + '/>';
    };
    const xml =
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ID="' + id + '"' +
        ' entityID="' + xmlEscape(idpEntityId) + '">' +
        // WHERE EVERY SIGNER GENERATION IS DESCRIBED (#42, D8), in an
        // md:Extensions of this document's own namespace, which SAML
        // metadata section 2.3.1 lets any consumer ignore. After the
        // prepended ds:Signature and before the role, as the schema orders.
        '<md:Extensions><cm:CryptoMetadataLocation xmlns:cm="' +
          'urn:iya:sts:crypto-metadata:1">' +
          xmlEscape(base + '/crypto/metadata.xml') +
          '</cm:CryptoMetadataLocation></md:Extensions>' +
        '<md:IDPSSODescriptor' +
          // WantAuthnRequestsSigned FOLLOWS WHAT IS ENFORCED (#37). It was the
          // literal "false" while nothing verified a request signature, and
          // that was the honest value then. Now it is true exactly when an
          // unsigned request would be refused: saml2.requireSignedAuthnRequests
          // (on in product by default), or — in a document minted for one
          // service provider — that service provider's own metadata saying
          // AuthnRequestsSigned="true".
          ' WantAuthnRequestsSigned="' +
            (requestSignature.wantsSignedRequests(
              spEntityId ? this.fieldsOf(spEntityId) : {}) ? 'true'
                                                          : 'false') + '"' +
          ' protocolSupportEnumeration="' + NS_SAMLP + '">' +
          keyDescriptor('signing') +
          // AN ENCRYPTION KEY, published since 2026-08-27, and it is the SAME
          // certificate as the signing one because this service has one key. A
          // real deployment separates them; a mock that minted a second key
          // pair per start to look tidy would give a reader two certificates to
          // keep straight for no behaviour. What matters is that the descriptor
          // is HERE at all: without it a service provider has nowhere to learn
          // the key it must encrypt an <saml:EncryptedID> to, and the inbound
          // half of this feature would be unreachable.
          //
          // IT CHANGES ON EVERY START, like everything else this key signs, so
          // a service provider that cached this document encrypts to a key that
          // no longer exists — which decryptElement() names as the usual cause
          // when an unwrap fails.
          keyDescriptor('encryption') +
          // The artifact resolution service comes FIRST inside the descriptor,
          // because the metadata schema's sequence puts
          // ArtifactResolutionService before SingleLogoutService before
          // NameIDFormat before SingleSignOnService. A document in any other
          // order is one a generated parser rejects, and hand-written parsers
          // were written against this.
          service('ArtifactResolutionService', BINDING_SOAP, where.ars, ' ' +
              'index="0" isDefault="true"') +
          service('SingleLogoutService', BINDING_REDIRECT, where.slo) +
          service('SingleLogoutService', BINDING_POST, where.slo) +
          service('SingleLogoutService', BINDING_SIMPLESIGN, where.slo) +
          NAMEID_FORMATS.map(function (format) {
            return '<md:NameIDFormat>' + format + '</md:NameIDFormat>';
          }).join('') +
          service('SingleSignOnService', BINDING_REDIRECT, where.sso) +
          service('SingleSignOnService', BINDING_POST, where.sso) +
          service('SingleSignOnService', BINDING_SIMPLESIGN, where.sso) +
          // NO HTTP-Artifact SingleSignOnService (#191). A SingleSignOnService
          // names a binding an AuthnRequest may ARRIVE on, and HTTP-Artifact
          // as a request binding means an artifact this service would resolve
          // at the service provider's own ArtifactResolutionService — which
          // it does not do. The ARTIFACT PROFILE everybody means is a request
          // over Redirect or POST carrying ProtocolBinding=HTTP-Artifact, and
          // that needs no endpoint here. It was advertised anyway until #191,
          // so a service provider building a binding menu from this document
          // offered the artifact choice — and SimpleSAMLphp, which reads it
          // literally, sent its AuthnRequest AS an artifact nothing resolved.
        '</md:IDPSSODescriptor>' +
        // THE ATTRIBUTE AUTHORITY (#189): its own role, after the IdP's, as
        // saml-metadata-2.0-os section 2.4.7 has it — a service provider
        // looks for an AttributeService here and nowhere else. The signing
        // keys are the same generations; the NameID formats the ones it can
        // be asked about (whatever a sign-in here gave).
        '<md:AttributeAuthorityDescriptor protocolSupportEnumeration="' +
          NS_SAMLP + '">' +
          keyDescriptor('signing') +
          service('AttributeService', BINDING_SOAP, where.aa) +
          NAMEID_FORMATS.map(function (format) {
            return '<md:NameIDFormat>' + format + '</md:NameIDFormat>';
          }).join('') +
        '</md:AttributeAuthorityDescriptor>' +
        // `saml.organizationName` and its two siblings since 2026-09-12 — the
        // literal "mock-sts" / "Mock security token service" until then — and
        // omitted entirely when the name is emptied. See document_settings.ts.
        documentSettings.organizationElement(base) +
      '</md:EntityDescriptor>';
    logArtifact('SAML 2.0 IdP metadata', 'before signing', xml);
    try {
      const signed = this.signDocument(xml, 'EntityDescriptor', id, 'prepend');
      logArtifact('SAML 2.0 IdP metadata', 'after signing', signed);
      log.debug("Leaving Saml2Sso.metadataFor(). Signed.");
      return signed;
    } catch (e) {
      log.debug("Caught in Saml2Sso.metadataFor(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-SAML-0014') + 'the SAML 2.0 metadata ' +
                                                  'could not be signed, ' +
                                                  'serving it unsigned: ' +
                                                    e.message);
      log.debug("Leaving Saml2Sso.metadataFor(). Unsigned.");
      return xml;
    }
  }

  private serveMetadata(req, res) {
    const { errorCodes } = this.deps;
    const { baseUrlOf, log } = this.deps.helpers;
    log.debug("Entering the SAML 2.0 metadata endpoint.");
    const base = baseUrlOf(req);
    const scoped = this.entityIdFromSegment(req.params.sp);
    if (this.refusedUnregistered(res, scoped, METADATA_PATH + '/{sp}')) {
      log.debug("Leaving the SAML 2.0 metadata endpoint. Not registered.");
      return;
    }
    // A document with entityID="" is one no service provider can be configured
    // from; say why instead. See idpEntityIdFor().
    const issuerProblem = this.idpEntityIdProblem();
    if (issuerProblem) {
      errorCodes.mark(res, 'STS-SAML-0004');
      res.status(503)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(issuerProblem + '\n');
      log.debug("Leaving the SAML 2.0 metadata endpoint. There is no " +
                "entityID.");
      return;
    }
    if (scoped.entityId) {
      // THE ASK IS WHAT REGISTERS IT. `counts: false` because fetching a
      // metadata document is not an authentication and is not even a request
      // from that service provider — it is somebody configuring one.
      this.recordServiceProvider({
             identifier: scoped.entityId,
             kind: 'saml2-service-provider',
             protocol: 'SAML 2.0',
             counts: false,
             note: scoped.known
               ? 'its identity provider metadata was fetched'
               : 'first seen when its identity provider metadata was asked for',
             fields: { samlEntityId: scoped.entityId }
      });
    }
    // no-store like every other document here that carries the signing key: the
    // key is regenerated on every start, so a cached copy describes a key that
    // is gone and the failure looks like a broken signature rather than a stale
    // document.
    res.status(200)
       .type('application/samlmetadata+xml')
       .set('Cache-Control', 'no-store')
       .send(this.metadataFor(base, scoped.entityId));
    log.debug("Leaving the SAML 2.0 metadata endpoint. sp=" +
              (scoped.entityId || '(unscoped)'));
  }

  // ---------------------------------------------------------------------------
  // THE PAGES A PERSON REACHES BY CLICKING.
  // ---------------------------------------------------------------------------
  private describeSsoPage(base, scoped) {
    const { mode, requestSignature } = this.deps;
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.describeSsoPage().");
    const where = this.endpointsFor(base, scoped.entityId);
    log.debug("Leaving Saml2Sso.describeSsoPage().");
    return '<h1>SAML 2.0 — Single Sign-On service</h1>' +
      '<p class="sub">Identity provider <code>' +
      xmlEscape(this.idpEntityIdFor(scoped.entityId)) +
      '</code> at <code>' + xmlEscape(where.sso) + '</code></p><p>This ' +
      'endpoint takes a <code>SAMLRequest</code> carrying a ' +
      '<code>&lt;samlp:AuthnRequest&gt;</code>, on the HTTP Redirect binding ' +
      '(a GET) or the HTTP POST binding (a form POST), and answers with a ' +
      '<code>&lt;samlp:Response&gt;</code> on whichever binding the ' +
      'request\'s <code>ProtocolBinding</code> asked for. It authenticates ' +
      'nobody: the username typed at the sign-in screen becomes the subject ' +
      'of the assertion.</p><h2>Try it</h2><ul><li><a ' +
      'href="' + SP_PATH + '">' + SP_PATH + '</a> — a mock service ' +
      'provider here that sends a complete AuthnRequest over each of the ' +
      'three bindings and then verifies the response check by ' +
      'check.</li><li><a href="' + xmlEscape(where.metadata) + '">' +
        xmlEscape(where.metadata) +
      '</a> ' +
      '— the signed identity provider metadata, which is what a service ' +
      'provider should be configured from.</li></ul><h2>What it ' +
      'reads</h2><table><thead><tr><th>Where</th><th>What this service does ' +
      'with it</th></tr></thead><tbody>' +
      [['SAMLRequest', 'Required. DEFLATE + base64 on the Redirect binding, ' +
                       'plain base64 on POST — and either is accepted on ' +
                       'either, because a service provider that compresses a ' +
                       'POST message is out of profile and common.'],
       ['RelayState', 'Echoed back byte for byte and never interpreted. It ' +
                      'is the service provider\'s own state, and an identity ' +
                      'provider that decoded and re-encoded it produces the ' +
                      'same symptom as a lost session.'],
       ['SigAlg, Signature', 'The Redirect binding\'s detached signature ' +
                             '(section 3.4.4.1) — or, on POST, the enveloped ' +
                             'ds:Signature. VERIFIED against the service ' +
                             'provider\'s REGISTERED signing certificates ' +
                             '(from its consumed metadata or the console), ' +
                             'never the one in the request, and refused when ' +
                             'it does not verify. An unsigned request is ' +
                             (requestSignature.wantsSignedRequests({})
                               ? 'REFUSED in this realm ' +
                                 '(saml2.requireSignedAuthnRequests).'
                               : 'accepted in this realm unless the service ' +
                                 'provider\'s metadata says ' +
                                 'AuthnRequestsSigned.')],
       ['ProtocolBinding', 'Which binding the RESPONSE comes back on: ' +
                           'HTTP-POST (the default), HTTP-Redirect or ' +
                           'HTTP-Artifact. Anything else is refused by name.'],
       ['AssertionConsumerServiceURL', mode.acceptsUnregisteredAddresses()
         ? 'Where the response goes. In development mode — this realm\'s — ' +
           'it is not validated against any registration, like every other ' +
           'return URL here, UNLESS the service provider\'s metadata has ' +
           'been consumed, when it must be one of the endpoints that ' +
           'registered; with none the response goes to the registered ' +
           'default or this service\'s own mock service provider at ' +
           SP_PATH + '.'
         : 'Where the response goes. This realm is in PRODUCT mode, so it ' +
           'must be one of the samlAssertionConsumerService values ' +
           'registered on the service provider\'s entry, compared exactly; ' +
           'with none, the registered one is used; and there is no mock ' +
           'fallback.'],
       ['NameIDPolicy/@Format', 'Answered with the format it asks for, ' +
                                'whatever it is — unless the service ' +
                                'provider\'s consumed metadata declares its ' +
                                'formats and this is not one, which is ' +
                                'InvalidNameIDPolicy. With none, the ' +
                                'saml2.nameIdFormat setting.'],
       ['AssertionConsumerServiceIndex', 'Chooses a registered endpoint from ' +
                                         'the service provider\'s consumed ' +
                                         'metadata, and its binding; an ' +
                                         'index nothing registered is ' +
                                         'refused.'],
       ['ForceAuthn', 'Shows the sign-in screen even when a session already ' +
                      'exists.'],
       ['IsPassive', 'Never shows it: with no usable session the answer is a ' +
                     'Response carrying NoPassive, which is the status code ' +
                     'a service provider is least likely to have handled.'],
       ['RequestedAuthnContext', 'A class asking for more than one factor ' +
                                 'takes the opt-out away at the sign-in ' +
                                 'screen, as WS-Federation\'s wauth does ' +
                                 'with the same demand.'],
       ['Subject/NameID', 'Read as a hint to pre-fill the sign-in screen, ' +
                          'exactly as OIDC\'s login_hint is, and never as a ' +
                          'claim about who is at the browser.'],
       ['Destination, IssueInstant', 'Recorded in the log. Neither is ' +
                                     'enforced: there is no clock skew ' +
                                     'setting for this profile to reject a ' +
                                     'request under.']
      ].map(function (r) {
        return '<tr><td><code>' + r[0] + '</code></td><td>' + r[1] +
               '</td></tr>';
      }).join('') + '</tbody></table><div class="meta"><div>Not implemented, ' +
      'and stated rather than left to be discovered: the ECP profile and its ' +
      'PAOS binding, identity-provider-initiated SSO with an unsolicited ' +
      'Response, Name Identifier Management, and the Assertion Query and ' +
      'Request profile.</div></div>';
  }

  // ===========================================================================
  // THE MOCK SERVICE PROVIDER. NON-SPEC, and it earns its place the same two
  // ways /wsfed/rp does:
  //
  //   * it is the default AssertionConsumerServiceURL, so an AuthnRequest that
  //     names no return address has somewhere real to go instead of nowhere;
  //   * it makes the profile testable from one service. Everything else here is
  //     verified by the client under test; a Response POSTed into the void
  //     could not be checked at all without standing up a second service, and
  //     the checks below are the ones that catch the mistakes this profile
  //     makes — an unresolvable signature reference, a mangled RelayState, an
  //     audience naming the wrong service provider, a SubjectConfirmationData
  //     whose InResponseTo does not match the request.
  // ===========================================================================
  private verifyResponseSignature(xml, wanted) {
    const { stsCrypto } = this.deps;
    const { STS, log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.verifyResponseSignature(). wanted=" + wanted);
    // **THE `element` ARGUMENT IS THE WHOLE POINT AND IT IS NOT A
    // CONVENIENCE.** A Response carrying a signed assertion has TWO signatures,
    // and asking a verifier "is this signed by us" without saying WHICH element
    // gets an answer about whichever it found first. The shared verifier
    // selects the element by name, takes the signature that is its own DIRECT
    // CHILD, and additionally refuses a signature whose reference names
    // something else — the last of which none of the four implementations this
    // replaced ever checked.
    //
    // The `idAttribute` dance is gone with them: the shared signer resolves
    // `ID`, `AssertionID`, `ResponseID` and `RequestID` natively, so there is
    // no list to add a name to and no duplicate to unshift onto it. That is
    // what removed the hazard this function used to carry a paragraph about.
    // Any generation of this realm's XML key (#42): helpers.verifyOwnXml().
    const result = this.deps.helpers.verifyOwnXml(xml, { element: wanted });
    log.debug("Leaving Saml2Sso.verifyResponseSignature(). ok=" + result.ok);
    return result;
  }

  // Every check, in the order a service provider would apply them, each with
  // its own verdict. One boolean for the whole response would say "it failed"
  // and nothing anybody could act on — the same argument /wsfed/rp and the
  // OID4VP verifier both make.
  verifyResponse(xml, spEntityId, acsUrl, relayState): any {
    const { firstByLocal, log, textByLocal } = this.deps.helpers;
    const { DOMParser } = this.deps.xmldom;
    log.debug("Entering Saml2Sso.verifyResponse().");
    const checks = [];
    const add = function (name, ok, detail) {
      log.debug("Entering add().");
      checks.push({ name: name, ok: !!ok, detail: detail });
      log.debug("Leaving add().");
    };
    const result: any = { checks: checks, subject: '', attributes: [],
                     sessionIndex: '', status: '' };

    let doc = null;
    try {
      doc = new DOMParser().parseFromString(xml, 'text/xml');
    } catch (e) {
      log.debug("Caught in Saml2Sso.verifyResponse(): " +
                ((e && e.message) || e));
      add('the response parses as XML', false, e.message);
      log.debug("Leaving Saml2Sso.verifyResponse(). Not XML.");
      return result;
    }
    const root = doc.documentElement;
    add('it is a samlp:Response', !!root && root.localName === 'Response',
        root ? '<' + root.localName + '> in ' + (root.namespaceURI || '(no ' +
            'namespace)')
             : 'nothing parsed');
    if (!root || root.localName !== 'Response') {
      log.debug("Leaving Saml2Sso.verifyResponse(). Not a Response.");
      return result;
    }

    const statusEl = firstByLocal(root, 'StatusCode');
    const status = statusEl ? (statusEl.getAttribute('Value') || '') : '';
    result.status = status;
    const statusMessage = textByLocal(root, 'StatusMessage');
    add('the status is Success', status === STATUS_SUCCESS,
        (status || '(no StatusCode)') + (statusMessage ? ' — ' + statusMessage :
                                         ''));

    const issuer = textByLocal(root, 'Issuer');
    add('the issuer is this identity provider',
        issuer === this.idpEntityIdFor(spEntityId),
        issuer + (issuer === this.idpEntityIdFor(spEntityId) ? ''
          : ', expected ' + this.idpEntityIdFor(spEntityId)));

    const destination = root.getAttribute('Destination') || '';
    add('Destination names this assertion consumer service',
        destination === acsUrl,
        destination || '(none)');

    const responseSig = this.verifyResponseSignature(xml, 'Response');
    add('the Response signature verifies', responseSig.ok,
        responseSig.present ?
        (responseSig.ok ? (responseSig.signatureMethod || 'signed') + ' ' +
            'over ' +
                                                (responseSig.canonicalization ||
                                                 'a ' +
                                                    'canonicalization')
                                              : responseSig.why)
          : 'unsigned — saml2.signResponse is off, which is a supported ' +
            'state and not a failure of the service provider');

    const assertion = firstByLocal(root, 'Assertion');
    add('it contains an assertion', !!assertion,
        assertion ? 'in ' + assertion.namespaceURI : 'no saml:Assertion — ' +
                                                     'see the status above');
    if (!assertion) {
      result.ok = checks.every(function (c) { return c.ok; });
      log.debug("Leaving Saml2Sso.verifyResponse(). No assertion.");
      return result;
    }

    const assertionSig = this.verifyResponseSignature(xml, 'Assertion');
    add('the assertion signature verifies', assertionSig.ok,
        assertionSig.present ? (assertionSig.ok ? 'resolved through the ID ' +
                                                  'attribute'
                                                : assertionSig.why)
          : 'unsigned — saml2.signAssertion is off');

    const conditions = firstByLocal(assertion, 'Conditions');
    const audience = conditions ? textByLocal(conditions, 'Audience') : '';
    add('the audience is this service provider', audience === spEntityId,
        'audience ' + (audience || '(none)') + ', expected ' + spEntityId);

    const notBefore = conditions ? conditions.getAttribute('NotBefore') : '';
    const notOnOrAfter = conditions ? conditions.getAttribute('NotOnOrAfter') :
                         '';
    const now = Date.now();
    add('it is inside its validity window',
        !!notBefore && !!notOnOrAfter && Date.parse(notBefore) <= now &&
        now < Date.parse(notOnOrAfter),
        (notBefore || '(no NotBefore)') + ' to ' + (notOnOrAfter || '(no ' +
            'NotOnOrAfter)'));

    // The four things saml-profiles section 4.1.4.2 requires of a BEARER
    // assertion, which is the half of the profile a service provider most often
    // skips and an identity provider most often omits.
    const scd = firstByLocal(assertion, 'SubjectConfirmationData');
    add('the bearer SubjectConfirmationData is there', !!scd,
        scd ? 'Recipient, NotOnOrAfter and InResponseTo' : 'missing — ' +
            'section 4.1.4.2 requires it');
    if (scd) {
      add('its Recipient is this assertion consumer service',
          (scd.getAttribute('Recipient') || '') === acsUrl,
          scd.getAttribute('Recipient') || '(none)');
      const known = spContexts.get(String(relayState || ''));
      add('its InResponseTo is the request this service provider sent',
          !!known && (scd.getAttribute('InResponseTo') ||
                      '') === known.requestId,
          known ?
          (scd.getAttribute('InResponseTo') ||
           '(none)') + ', expected ' + known.requestId
                : 'this service provider has no record of the request — the ' +
                  'RelayState was altered, or this response was not started ' +
                  'from ' + SP_PATH);
    }

    // The RelayState round trip. Its own state, so this service provider is the
    // only thing that can check it — and an identity provider that decoded and
    // re-encoded it, or dropped it for being long, produces exactly the same
    // symptom as a lost session.
    const known = spContexts.get(String(relayState || ''));
    add('RelayState came back unaltered', !!known,
        known ? 'the same value this service provider minted, byte for byte'
              : (relayState ?
                 'this service provider did not mint "' + relayState + '"'
                            : 'no RelayState came back'));

    const nameEl = firstByLocal(assertion, 'NameID');
    result.subject = nameEl ? (nameEl.textContent || '').trim() : '';
    result.nameIdFormat = nameEl ? (nameEl.getAttribute('Format') || '') : '';
    add('the assertion names a subject', !!result.subject,
        result.subject || '(none)');

    const authnStatement = firstByLocal(assertion, 'AuthnStatement');
    result.sessionIndex = authnStatement ?
                          (authnStatement.getAttribute('SessionIndex') || '') :
                          '';
    result.authnContext = textByLocal(assertion, 'AuthnContextClassRef');
    add('it carries an AuthnStatement with a SessionIndex',
        !!result.sessionIndex,
        result.sessionIndex ?
        result.sessionIndex + ' (' + (result.authnContext || 'no ' +
            'class ref') + ')'
                            : 'missing — Single Logout has nothing to name ' +
                              'the session by');

    const attributes = assertion.getElementsByTagNameNS('*', 'Attribute');
    for (let i = 0; i < attributes.length; i++) {
      const a = attributes[i];
      const values = a.getElementsByTagNameNS('*', 'AttributeValue');
      const list = [];
      for (let j = 0; j < values.length; j++) {
        list.push((values[j].textContent || '').trim());
      }
      result.attributes.push({ name: a.getAttribute('Name') || '',
                               nameFormat: a.getAttribute('NameFormat') || '',
                               values: list });
    }
    add('the attributes arrived', result.attributes.length > 0,
        result.attributes.length + ' attribute(s)');

    result.ok = checks.every(function (c) { return c.ok; });
    log.debug("Leaving Saml2Sso.verifyResponse(). ok=" + result.ok + ", " +
              checks.length +
        " " +
        "check(s).");
    return result;
  }

  // The mock service provider's own AuthnRequest. Unsigned, and that is not
  // laziness: this identity provider records a request signature and does not
  // check it (decision 3), so a signature here would be ceremony that proved
  // nothing — and the one thing worth demonstrating, that an unsigned request
  // is accepted, is exactly what the debugger's signed one cannot show.
  private spAuthnRequest(base, spEntityId, acsUrl, protocolBinding,
                          destination) {
    const { genId, iso, log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.spAuthnRequest(). binding=" + protocolBinding);
    const id = genId();
    const xml =
      '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' +
        NS_SAML + '" ' +
        'ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
        ' Destination="' + xmlEscape(destination) + '"' +
        ' ProtocolBinding="' + protocolBinding + '"' +
        ' AssertionConsumerServiceURL="' + xmlEscape(acsUrl) + '">' +
        '<saml:Issuer>' + xmlEscape(spEntityId) + '</saml:Issuer>' +
        '<samlp:NameIDPolicy AllowCreate="true"/>' +
      '</samlp:AuthnRequest>';
    log.debug("Leaving Saml2Sso.spAuthnRequest(). id=" + id);
    return { id: id, xml: xml };
  }

  // Resolving an artifact for the mock service provider. It calls the
  // resolution function IN PROCESS rather than making a SOAP call to this same
  // service over HTTP, and that is a deliberate refusal rather than a shortcut:
  // an outbound HTTP request this service makes to a URL it computed is the
  // shape of thing every other module here declines to do (wsfed's `wreqptr`,
  // the registry's `jwks_uri`), and there is nothing to learn from this process
  // talking to itself over a socket. What the page does instead is SHOW the
  // SOAP exchange that a real service provider would have made.
  private resolveForMockSp(artifact) {
    const { log } = this.deps.helpers;
    log.debug("Entering Saml2Sso.resolveForMockSp().");
    const held = artifacts.get(artifact);
    if (!held) {
      log.debug("Leaving Saml2Sso.resolveForMockSp(). It does not resolve.");
      return { ok: false, why: 'that artifact does not resolve: it was never ' +
                               'issued here, it has expired, or it has ' +
                               'already been resolved — an artifact is ' +
                               'one-shot.' };
    }
    artifacts.delete(artifact);
    log.debug("Leaving Saml2Sso.resolveForMockSp(). Resolved and destroyed.");
    return { ok: true, xml: held.xml };
  }

  private receiveAtMockSp(req, res, params, base, spEntityId, acsUrl) {
    const { errorCodes } = this.deps;
    const { log, logArtifact, xmlEscape } = this.deps.helpers;
    log.debug("Entering Saml2Sso.receiveAtMockSp().");
    const relayState = String(params.RelayState || '');
    let xml = '';
    let howItArrived = '';
    if (params.SAMLart) {
      const resolved = this.resolveForMockSp(String(params.SAMLart));
      if (!resolved.ok) {
        log.debug("Leaving Saml2Sso.receiveAtMockSp(). The artifact did not " +
                  "resolve.");
        errorCodes.mark(res, 'STS-SAML-0021');
        log.debug("Leaving Saml2Sso.receiveAtMockSp().");
        return this.sendPage(res, 200, 'Artifact did not resolve — mock ' +
                                       'service provider',
          '<h1>The artifact did not resolve</h1>' +
          '<div class="err">' + xmlEscape(resolved.why) + '</div><p>The ' +
          'commonest cause is the most interesting one: an artifact is ' +
          'resolvable EXACTLY ONCE (section 3.6.4.1), so reloading this page ' +
          'after a successful resolution lands here. That is the behaviour ' +
          'rather than a fault.</p><p><a ' +
          'href="' + SP_PATH + '">Start another sign-in</a></p>');
      }
      xml = resolved.xml;
      howItArrived = 'as a SAMLart the browser carried, resolved over the ' +
                     'back channel';
    } else {
      xml = this.decodeMessage(String(params.SAMLResponse || ''));
      howItArrived = req.method === 'POST'
        ? 'in the body of a form POST (the HTTP POST binding)'
        : 'on the query string (the HTTP Redirect binding)';
    }
    logArtifact('SAML 2.0 Response', 'as received by the mock service provider',
                xml);
    const verdict = this.verifyResponse(xml, spEntityId, acsUrl, relayState);
    if (relayState) spContexts.delete(relayState);

    const rows = verdict.checks.map(function (c) {
      return '<tr><td>' + xmlEscape(c.name) + '</td><td class="' +
        (c.ok ? 'pass">PASS' : 'fail">FAIL') +
        '</td><td>' + xmlEscape(c.detail) + '</td></tr>';
    }).join('');
    const attributeRows = verdict.attributes.map(function (a) {
      return '<tr><td><code>' + xmlEscape(a.name) + '</code></td><td>' +
        xmlEscape(a.values.join(', ')) + '</td><td>' +
        xmlEscape(a.nameFormat || '') + '</td></tr>';
    }).join('');
    const inner = '<h1>Response received</h1>' +
      '<p class="sub">Mock service provider at <code>' + xmlEscape(spEntityId) +
      '</code> ' +
          '— ' +
      xmlEscape(howItArrived) + '.</p>' +
      (verdict.ok
        ? '<div class="ok">Every check passed. An assertion for <code>' +
          xmlEscape(verdict.subject) + '</code>.</div>'
        : '<div class="err">Not every check passed. Each one below says ' +
          'which, and why — a single verdict for the whole response would ' +
          'say "it failed" and nothing anybody could act on.</div>') +
      '<h2>Checks</h2><table><thead><tr><th>Check</th><th>Verdict</th><th>' +
      'Detail</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      (attributeRows
        ?
          '<h2>Attributes</h2><table><thead><tr><th>Name</th>' +
          '<th>Value</th><th>NameFormat</th></tr></thead>' +
          '<tbody>' + attributeRows + '</tbody></table><p ' +
          'class="sub">Anything configured on <a ' +
          'href="/admin/saml-attributes">Custom SAML attributes</a> is in ' +
          'this table too: the SAML 2.0 set is appended by the same ' +
          'assertion builder that serves WS-Trust and WS-Federation, so it ' +
          'reaches this profile with no wiring of its own.</p>'
        : '') +
      '<h2>The response, as it arrived</h2><pre>' +
      xmlEscape(xml || '(nothing)') + '</pre><p><a ' +
      'href="' + SP_PATH + '">Start another sign-in</a> &middot; ' +
      '<a href="' + SLO_PATH + '">Sign out</a></p><div ' +
      'class="meta"><div>This service provider keeps no session. It verifies ' +
      'what it was sent and shows it, which is all a mock service provider ' +
      'can honestly claim to do.</div>' +
      (params.SAMLart
        ? '<div>The artifact was resolved IN PROCESS rather than by this ' +
          'service making a SOAP call to itself over HTTP — there is nothing ' +
          'to learn from that, and an outbound request to a URL this service ' +
          'computed is the shape of thing every other module here declines ' +
          'to make. A real service provider POSTs a signed ArtifactResolve ' +
          'to <code>' + ARS_PATH +
          '</code>; the curl for it is on <a href="' + ARS_PATH + '">that ' +
          'endpoint\'s own page</a>.</div>'
        : '') + '</div>';
    // 200 whatever the verdict: the request was answered, and the verdict is
    // the document. A 400 here would be this service provider reporting on the
    // identity provider's behaviour with a status code the browser attributes
    // to itself.
    if (!verdict.ok) {
      errorCodes.mark(res, 'STS-SAML-0022');
    }
    this.sendPage(res, 200, 'Response — mock service provider', inner);
    log.debug("Leaving Saml2Sso.receiveAtMockSp(). ok=" + verdict.ok);
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Saml2Sso>(
  'saml/saml2_sso',
  () => new Saml2Sso(Saml2Sso.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.
// #46: an artifact is resolved once across the cluster — here by
// spendArtifact(), and in saml11_sso.ts by respond()'s claim. Provided from
// THIS file for both profiles because the capability row names it, and
// saml11_sso.ts requires this module, so the 1.1 half is always loaded with
// it in the protocol stack.
capabilities.provide('saml.artifacts-once');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  Saml2Sso: Saml2Sso,
  installInstance: (instance: Saml2Sso): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BINDING_REDIRECT: BINDING_REDIRECT,
  BINDING_POST: BINDING_POST,
  BINDING_SIMPLESIGN: BINDING_SIMPLESIGN,
  BINDING_ARTIFACT: BINDING_ARTIFACT,
  BINDING_SOAP: BINDING_SOAP,
  NAMEID_FORMATS: NAMEID_FORMATS,
  // Read by admin-ui/admin.ts, which draws the console page for this profile
  // and must not reimplement any of it — the same division /admin/groups keeps
  // with ldap_server.js.
  slugOf: slot.forward('slugOf'),
  idpEntityIdFor: slot.forward('idpEntityIdFor'),
  endpointsFor: slot.forward('endpointsFor'),
  artifactCount: slot.forward('artifactCount'),
  pendingRequestCount: slot.forward('pendingRequestCount'),
  metadataFor: slot.forward('metadataFor'),
  verifyResponse: slot.forward('verifyResponse'),
  // The LogoutRequests one session is owed. Read by ../logout/logout.ts so that
  // a global sign-out names exactly what Single Logout names — see the block
  // above logoutTargetsFor().
  logoutTargetsFor: slot.forward('logoutTargetsFor')
};
