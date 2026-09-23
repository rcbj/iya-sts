'use strict';
//
// File: oauth2.ts
//
// ===========================================================================
// The endpoints the RFC 8414 metadata advertises.
//
// A dummy authorization server: every endpoint in the metadata document
// answers, and every token it issues is a real JWT signed with the STS key
// (RS256 unless a client registered another ID Token algorithm), so it
// verifies against the JWKS the same document points at (/oauth2/jwks). A
// refresh token is then encrypted to its realm as well.
//
//   GET  /oauth2/authorize   authorization endpoint (code / implicit / hybrid)
//   POST /oauth2/token       authorization_code, refresh_token, password,
//                            client_credentials, token-exchange
//   *    /oauth2/userinfo    OIDC Core 5.3, on GET and POST — the one protected
//                            endpoint here that verifies the token first
//   POST /oauth2/introspect  RFC 7662
//   POST /oauth2/revoke      RFC 7009
//   POST /oauth2/par         RFC 9126 pushed authorization requests
//   *    /oauth2/register    RFC 7591 registration + RFC 7592 management
//   GET  /oauth2/logout      end_session_endpoint (RP-Initiated Logout)
//   GET  /oauth2/check_session  the OP iframe, and its script beside it
//                            (Session Management, #121; off by default)
//   *    /oauth2/step-up/resource/:application
//                            NON-SPEC: RFC 9470's stand-in resource server
//   GET  /oauth2/rfc9700     NON-SPEC: whether the RFC 9700 Security BCP mode
//                            is on, and every requirement it does and does not
//                            enforce (oauth2_bcp.js)
//   GET  /oauth2/oauth21     NON-SPEC: the same for OAuth 2.1 mode (oauth21.js)
//   *    /dpop/nonce-mode    NON-SPEC: a development test control
//   *    /{id}/oauth2/...    every OAuth endpoint again, per named
//                            authorization server (authorization_servers.ts)
//   GET  /oauth2/jwks        the signing key (above, with the metadata)
//   GET  /docs /policy /tos  the documents the metadata links to
//
// In development mode it authenticates almost NOBODY: the person is signed in
// by `authn/authn.ts`, which checks no password there, and any client secret
// is accepted — with the exceptions `oauth2_bcp.js` (RFC 9700 mode, section
// 2.5), `oauth21.js` and `/oauth2/introspect` (RFC 9701) argue. No END USER's
// password is checked in development; product mode (`common/mode.js`) checks
// it at the sign-in screen and at the password grant. That is the point — it
// exists so the debugger's panes have something complete to talk to, not to
// enforce anything. What it does do
// properly is the mechanics a client can check: PKCE verification, single-use
// authorization codes, real signatures, honest introspection, and revocation
// that actually takes effect.
//
// **And, when it is asked to, the mechanics a client should FAIL.**
// `oauth2.rfc9700` puts this endpoint set into RFC 9700 mode — exact redirect
// URI matching, PKCE required of public clients, no implicit grant, no open
// redirect — which is the other half of exercising a client: one that has only
// ever met a permissive server has never run the paths it will need in
// production. The decisions are `oauth2_bcp.js`'s and the refusals are this
// module's; every call into it is a no-op while the flag is off, which is its
// default.
// ===========================================================================
//
// It also serves BOTH discovery documents — the RFC 8414 metadata and the
// OpenID Provider Configuration an OIDC client looks for — and the JWKS they
// advertise, because those describe THIS server: the endpoints below are the
// ones the metadata promises, and keeping the promise beside the thing that
// keeps it is what stops the two drifting. The OIDC document is the RFC 8414
// one extended, for the same reason at one remove: two documents describing one
// server must not be two hand-kept copies of the members they share.
//
// The one place it reaches outside itself is the OID4VCI pre-authorized code
// grant: the codes and the issuer_states are minted by the Credential Offer
// (vc_offers.js) and redeemed here, because redeeming a code is a token
// endpoint's job whatever minted it. That is a one-way dependency — the offer
// module knows nothing about this one.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for the largest module there is. `OAuth2Server` takes every module
// it reads through its constructor as `OAuth2ServerDeps`, whose names are the
// ones this file used at its top level before, so each method takes what it
// reads with one destructuring line and its body reads as it did. Every
// function of the old file is a method of the same name, and its
// `registerRoutes(app)` holds every route and middleware in the old order —
// `app.use(dpop.proofClaims())` first of all.
//
// The stores (`realms.map()`) and the tables are still declared at module
// scope, because a store becomes per realm at its declaration. The three
// refusal types are module-level classes that take the logger first.
//
// The code at the bottom declares `oauth.codes-once` at load, as the old last
// statement did, and exports the old names, for every module that requires
// this one by them. It registers NOTHING (#50, R1): it exports
// `registerRoutes(app)`, and `common/protocol_stack.ts` — the composition
// root — calls it at the point in the route order where requiring this module
// used to register the routes. Since R2 that root also builds the one
// `OAuth2Server` and installs it, and the exported functions are FACADES that
// forward to it; a process that loads this module without the root builds a
// default instance at load, as loading it always did.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
// TRUST REALMS: the stores below are partitioned by realm. It requires
// config.js and error_codes.js and nothing else here, so it cannot join a
// cycle, and it registers no route, so its position is not a position at all.
import realms = require('../common/realms');
import forge = require('node-forge');
import jwt = require('jsonwebtoken');
// One signer and one verifier for the whole service since 2026-08-27.
import stsCrypto = require('../common/crypto');
import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import dpop = require('./dpop');
// WHICH `kid` A JWK SET NAMES EACH SIGNING KEY UNDER (2026-09-13). A LEAF over
// `config`, `crypto` and `error_codes`; `sendJwks()` is the one reader here.
import joseKid = require('../common/jose_kid');
// RFC 8705 — certificate-bound access tokens, the other mechanism RFC 9700
// section 2.2 names. A library like dpop.ts, and read here for one thing: the
// confirmation claim that goes on a token issued over a connection that carried
// a client certificate. The RESOURCE server's half of it is in dpop.ts, at the
// single check the four protected endpoints share.
import mtls = require('./mtls');
// The six client authentication methods, and which of them this service can
// verify — read here for the metadata, which must not advertise one that would
// fall through unchecked.
import clientAuth = require('./client_auth');
// RFC 7521 / RFC 7523 SECTION 2.1 — the JWT bearer AUTHORIZATION GRANT. A
// LIBRARY (rule 3): it registers no route, so its position here is not a
// position. `client_auth.js` above already does section 2.2, which is the same
// document format used for a different purpose; that module requires this one
// and never the reverse.
import assertionGrant = require('./assertion_grant');
// RFC 7591 SECTION 2.3 (2026-09-13). A LIBRARY (rule 3) that registers no
// route: it decides whether a software statement is trusted and what it fixes,
// and the registration endpoint below answers.
import softwareStatement = require('./software_statement');
// RFC 7522 — the SAML 2.0 profile of the SAME framework, in a module of
// its own rather than a format flag on the one above. A LIBRARY (rule 3);
// it requires nothing that requires it back, and it deliberately does not
// require `assertion_grant.js` either. Its header argues both.
import samlAssertionGrant = require('./saml_assertion_grant');
// The mode. A LEAF (rule 3): registers nothing, requires only `config` (and
// bunyan).
import mode = require('../common/mode');
// MORE THAN ONE AUTHORIZATION SERVER out of one process: the path component the
// two discovery shapes already carry now selects a CONFIGURATION as well as an
// issuer identifier. A library that registers no route and requires only
// `common/` leaves (helpers, realms, mode, config), so it cannot create a
// cycle. A path nobody has configured
// publishes the document this service always published, which is what keeps
// every existing caller unaffected.
import authorizationServers = require('./authorization_servers');
// The service's statistics and its ONE set of revoked jtis. It is a library
// like dpop.ts — it registers nothing, and nothing it requires requires this
// module — so requiring it here cannot create a cycle. The revocation set used
// to be a Set in this file; see the comment where it was, below.
import stats = require('../common/admin_stats');
import vcConfigs = require('../oid4vc/vc_configs');
// For one thing: checking a wallet's requested claim paths against the ones
// this issuer's metadata advertises for that credential's format. A library
// that registers no route, so this adds nothing to the require order.
import vcClaims = require('../oid4vc/vc_claims');
import vcOffers = require('../oid4vc/vc_offers');
// The issuer identifier and everything else settable at runtime.
import config = require('../common/config');
// The authentication service. It requires nothing from this module, which is
// what makes this a one-way dependency: a protocol asks it to authenticate
// somebody and is handed them back with a session.
import authn = require('../authn/authn');
// RFC 9700, the OAuth 2.0 Security Best Current Practice, as a mode this
// service can be put into. A library like dpop.ts — it registers nothing and
// requires only libraries, none of which requires this module — so requiring
// it here cannot create a cycle and its position in the require order does
// not matter. It DECIDES; what
// a refusal looks like stays here, because that is protocol knowledge: a bad
// redirect_uri is answered on this server rather than redirected to, which is
// the difference between honouring section 2.1 and being the open redirector it
// forbids. Every call below is a no-op while `oauth2.rfc9700` is off.
import bcp = require('./oauth2_bcp');
// OAuth 2.1 (draft-ietf-oauth-v2-1-16) as a mode, which implies the one above —
// the difference between the two. A LEAF (rule 3, `oauth-oidc/CLAUDE.md` rule
// 3ah): it requires helpers.js and config.js, decides, and never touches `res`.
// Every call below is a no-op while `oauth2.oauth21` is off.
import oauth21 = require('./oauth21');
// The FAPI profiles (#138): a leaf like oauth21.js, whose enabled() also
// turns RFC 9700 mode on.
import fapi = require('./fapi');
// THE FIVE SETTINGS THAT ASK FOR MORE THAN EITHER OF THE TWO MODES ABOVE (#34,
// 2026-09-15): refresh token rotation on its own switch, and DPoP or mutual
// TLS REQUIRED at the token endpoint and at every resource. A leaf like
// `oauth21.js` — it decides and never touches `res` — and the same file
// `dpop.ts` asks the resource-side half of, so the console page, the two
// compliance reports and both doors cannot disagree about what is on.
import senderConstraints = require('./sender_constraints');
// OpenID Connect Front-Channel Logout 1.0 — the `sid` claim below, the two
// metadata members, the list of relying parties a session has signed into, and
// the iframe fan-out /oauth2/logout renders. A library (rule 3): it registers
// nothing, so its place in the require order does not matter, and it requires
// only helpers.js, config.js, app.js, applications.js, validation.js and
// error_codes.js — none of which requires it back, so it cannot join a cycle.
// It exists as a file of its own rather than as code in here for one reason:
// `/logout` and the console have to render the SAME fan-out, and reaching into
// this module for it would be a require in the wrong direction.
import frontchannel = require('./frontchannel_logout');
// OpenID Connect Back-Channel Logout 1.0 (2026-09-17, #36): the discovery
// members, the `sid` it needs, and the sign-out page's list of deliveries. A
// library of the same kind as the one above, and it does not require this
// module either.
import backchannel = require('./backchannel_logout');
// The application registry, which lives in the embedded LDAP directory. A
// library like the two above — it registers no route and requires only
// `common/` libraries, none of which requires this module — so requiring it
// here cannot create a cycle and cannot move a route. It is where the RFC 7591
// registrations are kept and where every client_id this endpoint accepts is
// recorded.
import applications = require('../common/applications');

// The input validator. A LEAF (rule 3) — registers no route, requires only
// `config`, `error_codes` and npm packages (bunyan, zod, xmldom), so it closes
// no cycle and moves nothing in the route order. `common/validation.js` argues
// the shape/existence line: what a value may BE is refused in both modes, and
// whether the client is KNOWN stays with `mode.js` and the application
// registry.
import validation = require('../common/validation');
// The registry of error codes, a leaf. Every refusal below is MARKED on the
// response before it is sent, and a code is never written into one.
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');
// EVERY REFRESH TOKEN IS ENCRYPTED TO ITS REALM (2026-09-12). A LIBRARY that
// registers no route — refreshToken() seals through it, and everything below
// that reads a refresh token opens through it first.
import refreshTokenCrypto = require('./refresh_token_crypto');
// RFC 9068, THE JWT ACCESS TOKEN PROFILE (2026-09-13). A LIBRARY that registers
// no route: accessToken() takes its header from it, tokenSet() and the
// authorization endpoint take the audience and scope decision from it, and
// issuerOf() is its issuerFor() — shared with the resource-server check in
// dpop.ts, which could not otherwise have asked the same question.
import jwtAccessToken = require('./jwt_access_token');
// RFC 9701, THE JWT RESPONSE FOR TOKEN INTROSPECTION (2026-09-13). A LIBRARY
// that registers no route: introspectEndpoint() asks it whether a request wants
// a JWT and has it build and protect one, the metadata publishes its algorithm
// lists, and the UserInfo response takes its recipient-key reading from it.
import introspectionJwt = require('./introspection_jwt');
// OPENID CONNECT CORE SECTION 10.2, THE ENCRYPTED ID TOKEN (2026-09-17, #36
// follow-up). A LIBRARY that registers no route: idToken() hands it the signed
// token, and the registration endpoint asks it whether a client that
// registered `id_token_encrypted_response_alg` gave a key to encrypt to.
import idTokenEncryption = require('./id_token_encryption');
// JARM (#139, #143): the JWT-secured authorization response.
import jarm = require('./jarm');
// OIDC Core section 8's pairwise subjects (#118). A LIBRARY that requires
// nothing here back.
import pairwiseSubjects = require('./pairwise_subjects');
// RFC 9470 (2026-09-13): step-up authentication. A library (rule 3) — what an
// authorization request's acr_values and max_age ask of a session, what meets
// them, and the refusal when nothing can. See `step_up.ts`.
import stepUp = require('./step_up');
// RFC 9101, THE JWT-SECURED AUTHORIZATION REQUEST (2026-09-13). A LIBRARY that
// registers no route: authorizeEndpoint() hands it the query before anything
// else is read, and runs on the parameters it answers. `requestObjectKeysFor()`
// is the realm's published request object encryption key pair.
import requestObject = require('./request_object');
// RFC 9396's types, checks, audience and consent — see its header.
import richAuthorization = require('./authorization_details');
// RFC 9126, PUSHED AUTHORIZATION REQUESTS (2026-09-13). Two LIBRARIES that
// register no route: `par.ts` holds a pushed request behind its request_uri,
// and `oauth2_monitor.ts` counts what happens to it for /admin/oauth2/monitor.
// The endpoint is `parEndpoint()` below; the validation of what is pushed is
// this module's own `vetAuthorizationRequest()`.
import par = require('./par');
import oauthMonitor = require('./oauth2_monitor');
// The delegation register (/admin/delegation). Exactly ONE thing this module
// does reaches it — the RFC 8693 token exchange, in both of its shapes — and no
// other grant here delegates anything. A library like the one above: it
// registers no route, so it can neither create a cycle nor move one.
import delegation = require('../common/delegation');
// CONSENT: the register, and the screen that fills it.
//
// `common/consent.ts` is a LIBRARY (rule 3) — it registers no route and
// requires helpers.js, config.js, applications.js, error_codes.js and
// admin_stats.js — so requiring it here can neither create a cycle nor move a
// route. `./consent_screen.ts` DOES have two routes, and this require cannot
// move them: since #50's R1 requiring it registers nothing, and
// `common/protocol_stack.ts` registers them BEFORE this module's, exactly as
// it registers `authn/authn.ts`'s before this module's, and for the identical
// reason — the authorization endpoint hands a browser to a screen somebody
// else owns and takes it back afterwards. It also requires it before this
// module, so this require is a cache hit.
import consent = require('../common/consent');
import consentScreen = require('./consent_screen');
// The LDAP-attribute half of a claim set, read here for ONE thing this module
// could not do without it: OpenID Connect Core section 5.5 lets a client name
// individual claims it wants back from the UserInfo endpoint, and answering
// that means finding the attribute on that person's entry under ou=users which
// produces the named claim. A library (rule 3) — it registers no route and
// requires helpers.js, realms.js, admin_stats.js, vc_claims.js, audit.js and
// error_codes.js, none of which requires it back — so it can neither create a
// cycle nor move a
// route. It is required here rather than reached through admin_stats.js's slot
// because the slot answers "what did an administrator TICK" and this is the
// other question: "what did the CLIENT ask for".
import claimAttributes = require('../common/claim_attributes');
// THE ROLE GATE. A LEAF (rule 3): it registers nothing, requires `helpers`,
// `config` and `error_codes` and nothing else here, and answers "allowed" in
// any process that never loaded the XACML family — so this require cannot move
// a route, cannot close a cycle and cannot change what this module does on its
// own. What fills its decider is `xacml/xacml_role_pep.ts` at 23c, far below
// this module in `common/protocol_stack.ts`, which is exactly why the gate
// exists rather than this file requiring the PEP. See
// `common/issuance_gate.js`.
import gate = require('../common/issuance_gate');
// WHO MAY BE GRANTED THE EMBEDDED DEBUGGER'S PERMISSION (2026-09-13). A
// library (rule 3) that registers nothing and requires only libraries —
// `admin-ui/admin_rbac.ts`, `common/access_gate.ts`, `common/audit.js`,
// `common/helpers.js`, `common/realms.js` — so it
// cannot move a route or close a cycle. See `debugger/debugger_access.ts`.
import debuggerAccess = require('../debugger/debugger_access');
// WHICH SCOPES A CLIENT MAY BE ISSUED (#110, 2026-09-22). A library (rule 3)
// requiring only libraries this module already requires. See
// `common/scope_policy.ts` and scopeRefusal() below.
import scopePolicy = require('../common/scope_policy');
// THE ONE PLACE A PRESENTED PASSWORD IS CHECKED, for the RFC 6749 section 4.3
// password grant (2026-09-12). A library (rule 3): it registers no route, and
// `authn/authn.ts` — required at 8, above this module — already requires it,
// so this is a cache hit that can neither move a route nor close a cycle.
// `websecurity.js` beside it is the rate limiter the sign-in screen already
// uses, required for the same grant and on the same argument.
import credentials = require('../common/credentials');
import websecurity = require('../common/websecurity');
// The audit log, for the one row the HTTP funnel's own cannot carry: WHICH
// client revoked WHOSE token at /oauth2/revoke (RFC 7009, #102). A library
// that requires nothing here, so it can neither close a cycle nor move a
// route.
import audit = require('../common/audit');
// SEVERAL NODES AGAINST ONE STORE (2026-09-14, #46). Two LIBRARIES: the
// atomic "once" an authorization code and a PAR request_uri are spent through,
// and the barrier a request that lost that race waits on to see what the
// winner wrote. Neither registers a route; `cluster_claims.js` requires
// `config`, `realms`, `error_codes` and the capability table, and requires
// `persistence.js` LAZILY; `cluster_barrier.js` requires `config`,
// `error_codes` and the table, and `persistence.js` and `cluster.js` lazily —
// so neither can move a route or close a cycle.
// `capabilities` is the table this module declares `oauth.codes-once` in.
import clusterClaims = require('../cluster/cluster_claims');
import clusterBarrier = require('../cluster/cluster_barrier');
import capabilities = require('../cluster/cluster_capabilities');
// A leaf: OpenID Connect Session Management 1.0 (#121).
import sessionManagement = require('./session_management');
// A leaf: a client's registered `jwks_uri`, fetched and cached (#120).
import clientJwks = require('./client_jwks');

// A loose JSON-shaped object: the tokens, records, requests and results this
// file builds and passes on. Their shapes are the libraries' own, and those
// libraries are being typed one at a time (#50), so this stays `any` rather
// than a shape that a newly typed library would then fail to match.
type Json = any;

// The express request and response, as far as this file reads them.
type Req = any;
type Res = any;

// What the authorization server needs from the rest of the service. The
// names are the ones this module used at its top level before #50, so each
// method takes what it reads with one destructuring line and its body reads
// as it did.
interface OAuth2ServerDeps {
  crypto: typeof crypto;
  realms: typeof realms;
  forge: typeof forge;
  jwt: typeof jwt;
  stsCrypto: typeof stsCrypto;
  app: typeof app;
  // `common/helpers.js`, member by member, as this module destructured it.
  log: typeof helpers.log;
  logArtifact: typeof helpers.logArtifact;
  STS: typeof helpers.STS;
  baseUrlOf: typeof helpers.baseUrlOf;
  b64u: typeof helpers.b64u;
  jsonFromB64u: typeof helpers.jsonFromB64u;
  nowSec: typeof helpers.nowSec;
  randomId: typeof helpers.randomId;
  xmlEscape: typeof helpers.xmlEscape;
  parseBody: typeof helpers.parseBody;
  bodyValues: typeof helpers.bodyValues;
  // helpers.oauthError, which `oauthError()` below wraps.
  plainOauthError: typeof helpers.oauthError;
  signJwt: typeof helpers.signJwt;
  signJwtAs: typeof helpers.signJwtAs;
  allSigningKeys: typeof helpers.allSigningKeys;
  allSigningKeysAsync: typeof helpers.allSigningKeysAsync;
  signJwtAsAsync: typeof helpers.signJwtAsAsync;
  userFor: typeof helpers.userFor;
  hasScope: typeof helpers.hasScope;
  signingKeyFor: typeof helpers.signingKeyFor;
  certificateHeaderFor: typeof helpers.certificateHeaderFor;
  publishedKidFor: typeof helpers.publishedKidFor;
  nameForSubject: typeof helpers.nameForSubject;
  hasSubjectResolver: typeof helpers.hasSubjectResolver;
  LEGACY_SUBJECT_PREFIX: typeof helpers.LEGACY_SUBJECT_PREFIX;
  requestObjectKeysFor: typeof helpers.requestObjectKeysFor;
  dpop: typeof dpop;
  joseKid: typeof joseKid;
  mtls: typeof mtls;
  clientAuth: typeof clientAuth;
  assertionGrant: typeof assertionGrant;
  softwareStatement: typeof softwareStatement;
  samlAssertionGrant: typeof samlAssertionGrant;
  mode: typeof mode;
  authorizationServers: typeof authorizationServers;
  stats: typeof stats;
  // `oid4vc/vc_configs`, member by member.
  VCI_CONFIGS: typeof vcConfigs.VCI_CONFIGS;
  VCI_CONFIG_ID: typeof vcConfigs.VCI_CONFIG_ID;
  VCI_SCOPE: typeof vcConfigs.VCI_SCOPE;
  vciFormatOf: typeof vcConfigs.vciFormatOf;
  vcClaims: typeof vcClaims;
  // `oid4vc/vc_offers`, member by member.
  deferredAccessTokens: typeof vcOffers.deferredAccessTokens;
  issuerStates: typeof vcOffers.issuerStates;
  preAuthorizedCodes: typeof vcOffers.preAuthorizedCodes;
  checkTxCode: typeof vcOffers.checkTxCode;
  spendPreAuthorizedCode: typeof vcOffers.spendPreAuthorizedCode;
  config: typeof config;
  authn: typeof authn;
  sessionOf: typeof authn.sessionOf;
  endSession: typeof authn.endSession;
  bcp: typeof bcp;
  oauth21: typeof oauth21;
  fapi: typeof fapi;
  senderConstraints: typeof senderConstraints;
  frontchannel: typeof frontchannel;
  backchannel: typeof backchannel;
  applications: typeof applications;
  validation: typeof validation;
  errorCodes: typeof errorCodes;
  refreshTokenCrypto: typeof refreshTokenCrypto;
  jwtAccessToken: typeof jwtAccessToken;
  introspectionJwt: typeof introspectionJwt;
  idTokenEncryption: typeof idTokenEncryption;
  jarm: typeof jarm;
  pairwiseSubjects: typeof pairwiseSubjects;
  stepUp: typeof stepUp;
  requestObject: typeof requestObject;
  richAuthorization: typeof richAuthorization;
  par: typeof par;
  oauthMonitor: typeof oauthMonitor;
  delegation: typeof delegation;
  consent: typeof consent;
  consentScreen: typeof consentScreen;
  claimAttributes: typeof claimAttributes;
  gate: typeof gate;
  debuggerAccess: typeof debuggerAccess;
  scopePolicy: typeof scopePolicy;
  credentials: typeof credentials;
  websecurity: typeof websecurity;
  audit: typeof audit;
  clusterClaims: typeof clusterClaims;
  clusterBarrier: typeof clusterBarrier;
  capabilities: typeof capabilities;
}

const vt = validation.types;
const vz = validation.z;

// The path parameter that names an authorization server — see
// `forProfile()`.
const AS_PROFILE_PARAMS = vz.object({
  as: vt.opt(vt.identifier)
});

// ---------------------------------------------------------------------------
// THE SIGNED COPY OF A DISCOVERY DOCUMENT, AND WHY IT IS CACHED.
//
// Discovery is the single most-fetched endpoint on this service — every client
// reads it before it does anything else — and signing this document was costing
// an RSA signature on EVERY fetch, which made /.well-known/oauth-authorization-
// server the slowest read-only endpoint here by a factor of five.
//
// It is also the one artifact on this service where re-signing per request buys
// nothing. RFC 8414 section 2.1 describes signed_metadata as something the
// issuer PUBLISHES: there is no nonce in it, no jti, and nothing bound to the
// caller, so two clients fetching a second apart are entitled to byte-identical
// documents and a real deployment would serve a pre-signed one. Everything that
// can vary — the base URL the request arrived on, which authorization-server
// profile it selected, any setting changed at runtime through /admin/config —
// varies the METADATA, and the metadata is the cache key. A document that
// differs by one member is a different key and is signed afresh, so runtime
// settability is untouched.
//
// **The entry is held for a minute and the token lives for an hour**, and that
// gap is the point rather than a rounding: a caller must never be handed a
// signature that is about to expire, so the TTL is a small slice of the
// lifetime and the worst case is a token with 59 minutes left instead of 60.
//
// It is capped for the reason every registry in this service is: the key
// includes the base URL, which comes off the Host header, so a caller that
// varies it could otherwise grow this map without limit.
// ---------------------------------------------------------------------------
//
// BOTH NUMBERS ARE SETTINGS SINCE 2026-09-12 — `oauth2.signedMetadataCacheS`
// and `oauth2.maxSignedMetadataEntries` — and the constants below are their
// defaults, kept under their old names. The ceiling on the first is half the
// signature's own hour, which is the "never hand out one about to expire"
// rule above written into the row.
const SIGNED_METADATA_TTL_MS = 60 * 1000;

const MAX_SIGNED_METADATA = 64;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// DELIBERATELY NOT PERSISTED, and it is the only store in this file that is
// not. A CACHE is not minted state: this holds a copy of a document that is
// re-derivable at any moment, keyed by the very claims it was derived from.
// Restoring one would save a signature and risk serving a document built
// under settings that have since changed — a bad trade in both directions.
// Said here rather than left silent, because "it has no handle" and
// "somebody forgot" look identical from persistence_minted.js.
// the claims, serialised -> { signed, until }
const signedMetadataCache = realms.map();

// Described to `/admin/caches` (#74, rule 3ap). The key shown is the
// algorithm, header choice, kid format and issuer — the claims half of the
// real key is a whole metadata document.
const signedMetadataCount = cacheRegistry.register({
  name: 'oauth2.signed-metadata',
  title: 'Signed authorization server metadata',
  description: 'RFC 8414 signed_metadata JWTs, reused while the metadata ' +
    'and signing settings they were built from are unchanged, so a busy ' +
    'discovery endpoint does not sign on every fetch.',
  owner: 'oauth-oidc/oauth2.ts',
  scope: 'realm',
  settings: ['oauth2.signedMetadataCacheS',
             'oauth2.maxSignedMetadataEntries'],
  maxEntries: function (): number {
    return Number(config.value('oauth2.maxSignedMetadataEntries')) ||
      MAX_SIGNED_METADATA;
  },
  bound: 'Enforced: oauth2.maxSignedMetadataEntries per realm, the oldest ' +
    'dropped and signed again when next asked for.',
  lifetime: function (): string {
    return 'oauth2.signedMetadataCacheS (' +
      config.value('oauth2.signedMetadataCacheS') + ' s) after signing, ' +
      'per realm; the oldest goes first when full.';
  },
  // A document past `until`, which `signedMetadata()` would sign again
  // (#49 P5).
  eject: cacheRegistry.realmMapEjector(realms, signedMetadataCache,
    function (held: Json, key: unknown, now: number): boolean {
      return !(held && Number(held.until) > now);
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmRows(
      realms.list().map(function (r: { id: string }): string {
        return r.id;
      }),
      function (id: string): Map<unknown, unknown> {
        return signedMetadataCache.realmMap(id);
      },
      function (held: Json, key: unknown): Json {
        const parts = String(key).split(' ');
        return { key: parts.slice(0, 3).join(' ') + ' ' +
                   String(held.issuer || ''),
                 validUntil: held.until };
      });
  }
});

// THE DEFAULT OF `oauth2.authorizationCodeTtlS` (2026-09-12), kept under its
// old name because four places below explain themselves in terms of it.
// `authCodeTtlMs()` is the live value and what every reader uses; a code
// carries the lifetime it was minted with (`ttlMs`), so a change reaches the
// next code and never one already issued. `oauth2_bcp.js` reads the SAME
// setting for its transaction window rather than a comment claiming a match.
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// code -> the authorization request it came from
// TOMBSTONED (2026-09-14, #46): a redeemed or expired code's delete leaves a
// tombstone in the store, so a node holding an older copy of the row cannot
// write it back. `persistence/persistence_minted.js` carries the mechanism.
const authzCodes = realms.map({ persist: 'oauth2.authzCodes', retain: 'age',
                                tombstone: true });

// ---------------------------------------------------------------------------
// NON-SPEC: what happens when the SAME authorization code arrives twice.
//
// RFC 6749 section 4.1.2 says a code is single use, and section 10.5 says a
// second presentation SHOULD invalidate what the first one issued. A real
// authorization server does exactly that, and so did this one: the record was
// deleted the moment it was looked up, so EVERY second Token Request carrying
// that code — a reloaded debugger2.html, a double-submitted form, a retry
// after a PKCE or redirect_uri check refused the first attempt — was answered
// with "Unknown or already-used authorization code". That sentence is equally
// true of a stolen code and of a browser that asked twice, and it says nothing
// about which one happened, which is the wrong trade for a service whose whole
// job is to show what occurred.
//
// So redemption here is IDEMPOTENT for as long as the code would have been
// valid anyway: the token set a code was redeemed for is kept for the rest of
// that code's own five-minute lifetime, and a repeat of the SAME request —
// same client, same redirect_uri, same PKCE verifier, same DPoP key — is
// answered with the tokens it already got. Nothing new is minted, so the
// second answer IS the first answer, down to the jti.
//
// It is not a way to redeem somebody else's code. Anything about the request
// that differs is refused and the difference is named; once the code's own
// lifetime is over, so is the replay; and both refusals now say when the code
// was redeemed and by which client, which is the fact the old message was
// missing. What is remembered is kept a further five minutes past the code's
// expiry PURELY so that those sentences can still be written.
//
// The pre-authorized code grant further down is deliberately NOT relaxed: its
// single use is a property of the Credential Offer under test, and
// tests/sd_jwt_vc_issuance.js asserts that a replayed offer is refused.
// ---------------------------------------------------------------------------
// PER TRUST REALM. `realms.map()` is a Map that holds a separate one for each
// realm and hands out the ambient realm's — so every reader below is
// unchanged and every one of them is now realm-correct. In the default realm,
// and in a service with no realms defined, there is exactly one partition and
// this behaves as the plain Map it replaced. See common/realms.js.
// code -> the token set it was redeemed for
const redeemedCodes = realms.map({ persist: 'oauth2.redeemedCodes',
                                   retain: 'age' });

// Described to `/admin/caches` (#74, rule 3ap). The key is an authorization
// code and the value holds the tokens it produced, so a row is the code's
// digest, the client and when the record is dropped — nothing else.
const redeemedCodesCount = cacheRegistry.register({
  name: 'oauth2.redeemed-codes',
  title: 'Redeemed authorization codes',
  description: 'Each authorization code already exchanged at the token ' +
    'endpoint, so a second exchange is recognised as a replay (RFC 9700 ' +
    'section 4.5, RFC 6749 section 4.1.2).',
  owner: 'oauth-oidc/oauth2.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a code already redeemed, presented again',
  settings: ['oauth2.authorizationCodeTtlS', 'oauth2.redeemedCodeCacheSize'],
  maxEntries: function (): number {
    return Number(config.value('oauth2.redeemedCodeCacheSize'));
  },
  bound: 'Enforced: oauth2.redeemedCodeCacheSize per realm; the oldest ' +
    'redemption is forgotten. The code itself went at redemption, so a ' +
    'repeat of a forgotten one is still refused, as an unknown code.',
  lifetime: function (): string {
    return 'One code lifetime after the code would have expired.';
  },
  // What `forgetStaleRedemptions()` drops, in every realm (#49 P5).
  eject: cacheRegistry.realmMapEjector(realms, redeemedCodes,
    function (done: Json, code: unknown, now: number): boolean {
      return Number(done && done.forget) < now;
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, redeemedCodes,
      function (done: Json, code: unknown): Json {
        return { key: cacheRegistry.digestKey(code) + ' for ' +
                   String((done && done.client_id) || '?'),
                 validUntil: Number(done && done.forget) || null };
      });
  }
});

// ---------------------------------------------------------------------------
// THE ROLE GATE, ASKED ONCE PER KIND OF THING A TOKEN RESPONSE CARRIES.
//
// `common/issuance_gate.js` names nine kinds of issuance and they are a
// VOCABULARY policies are written against — so a token response that mints an
// access token, an ID Token and a refresh token asks about all three rather
// than about "a token". A policy may then permit an access token to a client
// and refuse it a refresh token, which is a distinction somebody will want and
// which asking once could not express.
//
// THE FIRST REFUSAL WINS AND THE WHOLE REQUEST IS REFUSED. There is no partial
// answer: a token response missing its `id_token` because a policy refused
// that one alone would be an OIDC client with no way to discover why, and
// section 5.1's `id_token` is not optional in a response to an `openid`
// request. So the response is `access_denied` naming the kind that was
// refused.
//
// A THROW RATHER THAN A RETURN, and it is thrown from inside `issue()` on
// purpose. Six grants mint through that one closure precisely so that a
// seventh added later cannot forget something — the comment above it makes
// that argument about the client certificate — and a check that returned a
// value would have to be read at six call sites, which is five that would and
// a sixth that would not. `tokenEndpoint()` catches it below and turns it into
// an OAuth error; the wrapper at the route catches anything that gets past
// that.
// ---------------------------------------------------------------------------
class IssuanceRefused extends Error {
  [member: string]: any;

  constructor(log: { debug(message: string): void }, answer: Json,
              kind: string) {
    log.debug("Entering IssuanceRefused.constructor().");
    super(answer.why);
    this.name = 'IssuanceRefused';
    this.issuance = answer;
    this.kind = kind;
    this.message = answer.why;
    log.debug("Leaving IssuanceRefused.constructor().");
  }
}

// ---------------------------------------------------------------------------
// OpenID Connect Core 1.0 section 5.5 — THE `claims` REQUEST PARAMETER.
//
// A client sends a JSON object at the authorization endpoint naming the
// individual claims it wants, per artefact:
//
//   claims={"userinfo":{"birthdate":null,"address":null,
//                       "email":{"essential":true}},
//           "id_token":{"acr":{"values":["urn:mace:incommon:iap:silver"]}}}
//
// Two top-level members are defined and only two. Anything else is IGNORED
// rather than refused — section 5.5 says other members MAY be defined, so a
// request carrying one this service has never heard of is a request from a
// client that knows something this one does not, and refusing it would make
// this service the reason an extension cannot be tried against it. What is
// ignored is REPORTED, in the reply's log line and on /admin/userinfo-claims,
// because "ignored silently" and "not understood" look identical from a client.
//
// WHAT IS REFUSED IS THE SHAPE, and that is a deliberate asymmetry. A `claims`
// that is not JSON, or is not an object, or whose `userinfo` member is a
// string, or whose individual claim request is a number, is not an extension —
// it is a client that has misread the section, and answering `invalid_request`
// with the reason is the only thing that will ever tell them so. That refusal
// happens at the AUTHORIZATION endpoint, which is the last point at which the
// client is still being talked to: a token endpoint refusal for a parameter
// sent an interaction earlier is a message nobody is reading for. Same
// reasoning as RFC 8707's `resource`, which is refused further below for the
// same reason.
//
// **`essential`, `value` and `values` ARE CARRIED AND ARE NOT ENFORCED, and
// that is the honest reading of the section rather than a shortfall.**
// Section 5.5.1 says an essential claim is a hint about what the client will do
// without it, and that a server MUST NOT return an error because a requested
// claim is unavailable. `value` and `values` ask for a claim to be returned
// with a particular value — which this service could satisfy by echoing the
// value back, and deliberately does not: everything this mock says about a
// person comes from the directory or from the invented persona, and a UserInfo
// response that agreed with whatever the client asked it to say would be the
// one surface here that cannot be used to test anything. The MISMATCH is
// reported instead, in the log and in the response's artifact, which is the
// thing a client's error path is built for.
//
// THE PARSED REQUEST RIDES IN THE ACCESS TOKEN, as the `claims` claim. That is
// the same decision `authorization_details` records above it and for the same
// reason: the UserInfo endpoint sees the token and nothing else — no code, no
// session, no request record — so a side table keyed by jti would have to be
// swept, would not survive a refresh, and would make the token stop being the
// record of what was authorized. `claims` is on the reserved list in
// admin_stats.js so that no web form can decide what a request asked for.
// ---------------------------------------------------------------------------

// The two members section 5.5 defines. `userinfo` is the one this service acts
// on at the endpoint below; `id_token` is honoured where idToken() is built.
const CLAIMS_REQUEST_MEMBERS = ['userinfo', 'id_token'];

// A cap, for the reason every other cap in this file has one: the parsed object
// is copied into a signed token, and a request naming ten thousand claims would
// produce a token no HTTP header can carry — which fails somewhere unrelated,
// at a client, in a way nobody traces back to here.
//
// `oauth2.maxRequestedClaims` since 2026-09-12; the constant is its default
// and the export below reads the setting through a getter, so the console's
// "at most N" and this refusal cannot disagree.
const MAX_REQUESTED_CLAIMS = 64;

// The six claims this service invents from the username, in userFor(). They are
// the FALLBACK for a requested name the LDAP catalogue cannot produce, and the
// list is written out rather than derived from that object because `userFor()`
// also carries `sub` and `username`, neither of which a client may displace or
// ask for by name — `sub` is the subject identifier the whole response is about
// and `username` is not an OIDC claim at all.
const PERSONA_CLAIMS = ['name', 'given_name', 'family_name',
                        'preferred_username',
                        'email', 'email_verified'];

// ---------------------------------------------------------------------------
// THE PERSON, AS AN ID TOKEN AND A USERINFO RESPONSE DESCRIBE THEM — IN A REALM
// THAT INVENTS NOTHING (2026-09-12).
//
// `helpers.userFor()` stopped inventing `name`, `given_name`, `family_name`,
// `email` and `email_verified` when `mode.inventsClaimValues()` is false, and
// that left two readers here holding a person object with four holes in it:
// the ID Token, which names those claims in its payload whatever they hold,
// and the UserInfo endpoint's `profile` and `email` scopes. Neither may go back
// to inventing, and both would otherwise be answering `profile` with nothing
// while the person's own directory entry holds a real `cn` and `mail`.
//
// **SO THE DIRECTORY FILLS THEM, THROUGH THE CATALOGUE EVERY CLAIM SET ALREADY
// USES** — `cn` is `name`, `givenName` is `given_name`, `sn` is `family_name`
// and `mail` is `email`, which is the mapping `oid4vc/vc_claims.ts` states and
// `/admin/claims` draws. It is `claimAttributes.requestedClaimsFor()` rather
// than a read of the entry here, so there is ONE answer to "which attribute is
// a person's family name" and a directory that renamed one would change both
// readers together. That function reads the entry ONCE for all four.
//
// FOUR RULES, and each is a place this could have gone quietly wrong:
//
//   * A value the person object ALREADY carries is kept. A federated sign-in
//     or a certificate may have put a real `email` on the session's user, and
//     the directory lookup is a fallback beneath it rather than a second
//     opinion over it.
//   * A claim the entry does not hold is ABSENT — never an empty string and
//     never `undefined` on an object that a later `Object.assign` could use to
//     clobber a configured claim of the same name. `definedOnly()` below is
//     what the payloads go through.
//   * **`email_verified` IS NEVER SET HERE.** Nothing in a directory entry says
//     a mailbox was verified, and the invented `true` this replaced was the
//     single most harmful claim in the persona: relying parties link accounts
//     on a verified email. An absent claim is what OIDC Core 5.1 permits for a
//     value the provider cannot vouch for.
//   * DEVELOPMENT IS UNTOUCHED — `userFor()` filled all six there, so this
//     function finds nothing undefined and returns the object as it was given.
//
// `sub` is not touched here, and that is worth saying because it is the claim a
// reader might expect a directory-backed person to take from the entry — which
// is what it does, one layer down: since 2026-09-14 `userFor()` gives
// `urn:uuid:<entryUUID>`, so a person deleted and re-created under the same
// username is a DIFFERENT subject to every relying party (it was
// `urn:sts:user:<username>`, derived from the name, before that date).
// ---------------------------------------------------------------------------
const DIRECTORY_PERSONA_CLAIMS = ['name', 'given_name', 'family_name', 'email'];

// A refusal accessTokenPlan() made at the point a token was about to be
// minted, carried out of tokenSet() to the token endpoint the way
// IssuanceRefused carries the role gate's: every grant mints through issue(),
// and that is where one catch can answer all of them.
class AccessTokenRefused extends Error {
  declare refusal: Json;

  constructor(log: typeof helpers.log, refusal: Json) {
    super(refusal.description);
    log.debug("Entering AccessTokenRefused.constructor().");
    this.name = 'AccessTokenRefused';
    this.refusal = refusal;
    this.message = refusal.description;
    log.debug("Leaving AccessTokenRefused.constructor().");
  }
}

// A refusal by one of the two REFRESH TOKEN sender-constraint settings (#34,
// 2026-09-15), carried the same way and for the same reason. It is thrown from
// `issue()` rather than checked once at the top of the token endpoint because
// the question is "is a refresh token about to be minted", and the only honest
// answer to that is `withRefresh`, which the grant decides — a list of grants
// kept beside it would be the second list that eventually disagrees, which is
// the argument `issuanceKindsOf()` already makes.
//
// THE WHOLE REQUEST IS REFUSED, access token included. Minting the access
// token and dropping the refresh token silently would leave a client that
// believes it has a durable grant and discovers otherwise an hour later, which
// is a worse failure than the error it gets instead.
class SenderConstraintRefused extends Error {
  declare refusal: Json;

  constructor(log: typeof helpers.log, refusal: Json) {
    super(refusal.description);
    log.debug("Entering SenderConstraintRefused.constructor().");
    this.name = 'SenderConstraintRefused';
    this.refusal = refusal;
    this.message = refusal.description;
    log.debug("Leaving SenderConstraintRefused.constructor().");
  }
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION RESPONSE, in whichever of the three response modes was
// asked for.
//
// `query` and `fragment` are the two OAuth 2.0 and OpenID Connect define
// positionally: a bare code goes in the query, anything carrying a token goes
// in the fragment so that it is never sent to a server. FORM_POST is the third
// (OAuth 2.0 Form Post Response Mode), and until now this service advertised it
// and did not have it — every request was answered with a 302 whatever it
// asked for, so a client that requested form_post sat waiting for a POST that
// never came. That is the worst shape a metadata member can have and the
// document said so rather than pretending; this is the other way to fix it.
//
// **RFC 9700 section 4.3 is why it is worth having.** A redirect puts the
// response in a URL, and a URL goes into browser history, into the address bar,
// into any log the browser's own crash reporter keeps, and into the `Referer`
// of anything the landing page fetches. A form POST puts it in a request body,
// which does none of those. That is true of a bare authorization code as well
// as of a token — a code in history is a code somebody can read, which is why
// section 4.3 asks for it to be single-use and PKCE-bound as well.
//
// The page is the SAME SHAPE WS-Federation's has, deliberately: a real form
// with a real submit button, plus a separate script that submits it. The button
// is not a fallback nobody sees — this service sets `script-src 'none'` on
// every response, so with the script blocked the button is the whole mechanism.
// An inline script would need `'unsafe-inline'`, which is the clause that would
// make the relaxation matter; a named resource does not.
//
// `form-action` is deliberately absent from the policy, for the reason app.js
// records about the OAuth redirect: the form posts to the client's
// redirect_uri, which is by definition another origin, and `form-action 'self'`
// would stop the response ever reaching the client.
// ---------------------------------------------------------------------------
const AUTOPOST_SCRIPT = [
  '(function () {',
  '  var f = document.getElementById("oauth2-form");',
  '  if (f) { f.submit(); }',
  '})();',
  ''
].join('\n');

// ---------------------------------------------------------------------------
// THE AUTHORIZATION REQUEST, AND WHY THIS ONE SCHEMA PASSES UNKNOWNS THROUGH.
//
// **`z.looseObject` AND NOT `z.object`, WHICH IS THE OPPOSITE OF EVERY OTHER
// SCHEMA IN THIS SERVICE, AND IT IS A FACT ABOUT THIS HANDLER RATHER THAN A
// PREFERENCE.** `common/validation.js`'s header explains that stripping
// undeclared parameters is what RFC 6749 section 3.1 requires of an
// authorization server, and that is still true of what this endpoint ACTS on.
// It is not true of what it FORWARDS.
//
// Two things carry `q` onward whole:
//
//   * `bcp.checkAuthorizationRequest({ query: q, ... })`, which reads the
//     request for RFC 9700 and looks at parameters this handler never does;
//   * **`queryString(q, ['prompt'])`, which REBUILDS THE QUERY STRING** for the
//     round trip through the consent screen and back.
//
// So a stripped parameter is not merely unread — it is DELETED from the request
// the person resumes after consenting. A client that sent `ui_locales` or a
// vendor extension would have it silently vanish half way through a sign-in,
// which is the quietest possible way to break an authorization server.
//
// What passing through costs is that an undeclared parameter is not bounded or
// typed. What it keeps is that every declared one is, and that `flatten()` has
// still refused an array, a nested object and a control character on ALL of
// them, declared or not — which is the class this work exists to close.
//
// **`resource` AND `claim` ARE THE TWO THAT MAY REPEAT.** RFC 8707 section 2
// says so of the first; the second is this service's own spelling of an
// individual claims request (see `parseClaimsRequest()`). Everything else is
// single-valued and a repeat of it is refused, which is what makes
// `redirect_uri` given twice an error rather than a choice this handler makes
// silently on the caller's behalf.
// ---------------------------------------------------------------------------
const AUTHORIZE_QUERY = vz.looseObject({
  // RFC 6749 section 4.1.1.
  client_id: vt.opt(vt.identifier),
  response_type: vz.string().max(128).optional(),
  redirect_uri: vt.opt(vt.redirectUri),
  scope: vt.opt(vt.scope),
  state: vt.opt(vt.opaque),

  // OpenID Connect Core section 3.1.2.1.
  nonce: vt.opt(vt.opaque),
  response_mode: vz.string().max(64).optional(),
  prompt: vz.string().max(128).optional(),
  display: vz.string().max(64).optional(),
  max_age: vt.opt(vt.integer(0, 315360000)),
  ui_locales: vz.string().max(256).optional(),
  // Section 5.2 (#118): accepted and recorded; see claims_locales_supported.
  claims_locales: vz.string().max(256).optional(),
  id_token_hint: vz.string().max(validation.CAP.TOKEN).optional(),
  login_hint: vt.opt(vt.name),
  acr_values: vz.string().max(512).optional(),

  // RFC 7636 (PKCE). The verifier's length is section 4.1's, and the challenge
  // is its base64url digest — bounded here rather than at the token endpoint
  // too, because a challenge stored now is compared much later.
  code_challenge: vt.opt(vz.string().min(43).max(128)),
  code_challenge_method: vz.string().max(16).optional(),

  // OpenID Connect Core section 5.5, and this service's own per-claim spelling.
  claims: vz.string().max(validation.CAP.TEXT).optional(),
  claim: vt.repeatable(vz.string().max(256)).optional(),

  // RFC 8707 section 2 — MAY be repeated, and this is the parameter that whole
  // rule in `common/validation.js` exists for.
  resource: vt.repeatable(vt.uri).optional(),

  // RFC 9449 section 10, RFC 9396, and OpenID4VCI's issuer_state.
  dpop_jkt: vt.opt(vt.base64url),
  authorization_details: vz.string().max(validation.CAP.TEXT).optional(),
  issuer_state: vt.opt(vt.opaque),

  // This service's own round-trip fields, put in the URL by its OWN screens and
  // read back here. They are declared so that a hand-crafted one is bounded
  // like everything else — nothing here trusts them because it wrote them.
  authn_error: vz.string().max(256).optional(),
  authn_error_description: vz.string().max(1024).optional(),
  consent_error: vz.string().max(256).optional(),
  consent_error_description: vz.string().max(1024).optional(),
  // RFC 9101 (2026-09-13): the request object's `prompt` was honoured on the
  // first pass — see `authorizationReturnQuery()`.
  jar_prompt_honoured: vz.string().max(8).optional(),
  // RFC 9470 (2026-09-13): the sign-in this request was sent to for its
  // acr_values or max_age has happened — see `step_up.ts`'s header.
  step_up_honoured: vz.string().max(8).optional(),
  // And the two ways a request object arrives. Bounded here too, so a request
  // that is not resolved still has them held to a size.
  request: vz.string().max(validation.CAP.TEXT).optional(),
  request_uri: vz.string().max(2048).optional()
});

// ---------------------------------------------------------------------------
// OpenID Connect Core 1.0 section 5.3 — the UserInfo Endpoint.
//
// A protected resource: present the access token from an OIDC flow and get back
// the claims about the person it was issued for. GET and POST both, because
// section 5.3.1 requires both, and the token comes from the Authorization
// header only — RFC 6750 section 2.3's query-parameter form is NOT RECOMMENDED
// by its own specification, leaks the token into logs and referrers, and could
// not carry a DPoP-bound token in any case.
//
// **This is the one protected endpoint here that refuses a token it did not
// issue, and the exception is the point rather than an inconsistency.** The
// Credential, Deferred Credential and Notification endpoints accept a foreign
// token because OID4VCI lets the authorization server be somebody else, so
// refusing one would break the flow this mock exists to exercise. UserInfo is
// defined the other way round: it answers "who did YOU authenticate", and about
// the subject of a signature it cannot check this server knows nothing at all.
// A mock that made up a profile for an unverifiable token would be teaching the
// wrong lesson to the client reading its output — and it is also what makes
// `cnf.jkt` mean something here, since the binding is only real on a token
// whose signature was checked first.
//
// So four things are checked, and each has a distinct answer so a client can
// tell them apart:
//
//   * the signature, issuer and expiry (401 invalid_token, with the reason — an
//     expired token and a forged one are different problems and "invalid_token"
//     alone sends people looking in the wrong place)
//   * `typ`, so a refresh token or an id_token presented here is refused rather
//     than quietly answered. They are all JWTs this service signed, so nothing
//     but this claim — and RFC 9068's `at+jwt` header beside it since
//     2026-09-13 — distinguishes them
//   * revocation, because /oauth2/revoke has to mean the same thing at every
//     endpoint that reads a token — introspection reporting `active: false`
//     while UserInfo still answers would make revocation decorative
//   * the `openid` scope (403 insufficient_scope), which is what a token from
//     the client_credentials or token-exchange grant lacks: those have no
//     end-user, and there is no profile to return for a token that never
//     described one
//
// Scope gating, and why the id_token does NOT do the same. Section 5.4 makes
// `profile` and `email` requests for a named set of claims AT THIS ENDPOINT, so
// this is one place in this mock where a scope genuinely changes the answer,
// and that is worth being able to watch. The id_token still carries everything
// whatever was asked for, which the same section permits — the claims go in the
// id_token when there is no access token to fetch them with — and it is also
// the only behaviour that can serve the implicit flow this server offers.
//
// ---------------------------------------------------------------------------
// TWO THINGS ARRIVED HERE ON 2026-08-26 AND BOTH CHANGE WHAT THIS ENDPOINT
// ANSWERS. A reader who knows this endpoint as "sub plus whatever the scope
// asked for" has the picture it had before them.
//
// **A CUSTOM CLAIM SET OF ITS OWN — /admin/userinfo-claims.** The fifth set in
// admin_stats.js, configured like the four beside it: typed claims, ticked LDAP
// attribute types read off the person's entry under ou=users, and the groups
// claim. What makes it worth having SEPARATELY from the ID Token's set, rather
// than being the same list under two names, is the one property no issued
// artefact has — this response is BUILT ON EVERY CALL, so a claim added here
// reaches a client that is already holding its tokens and has not signed in
// since. That is a different thing to be able to test from anything the ID
// Token set can express, and it is the reason the page carries no "nothing
// already issued changes" warning while every other claims page does.
//
// **THE CLAIMS REQUEST — OIDC Core section 5.5.** A client may name individual
// claims in the `userinfo` member of the `claims` parameter, and this server
// now parses it, refuses a malformed one BY NAME at the authorization endpoint,
// carries it on the code and inside the access token, and answers it HERE by
// reading the named claims off that person's directory entry. It is the one
// path by which a client — rather than an administrator at a console — decides
// what this response carries, and `claims_parameter_supported` says so in the
// discovery document, where it said `false` until that day.
//
// The four layers and which of them wins are written out at the merge below,
// because that is where somebody debugging an unexpected member will be
// looking.
// ---------------------------------------------------------------------------

// Which claims each scope asks for — OIDC Core section 5.4, every one of them
// (#118, 2026-09-22). It named four `profile` claims and left `address` and
// `phone` out because `userFor()` mints neither; what is not on the person
// object is now answered from the directory entry through the one claim
// catalogue (`claimAttributes.requestedClaimsFor()`), so all four scopes are
// honoured and advertised. A claim nobody holds is absent, never invented
// beyond what that catalogue already does in development.
//
// **THEY ARE NO LONGER THE WHOLE ANSWER, AND HAVE NOT BEEN SINCE 2026-08-26.**
// Two things reach this response beside them, and both are argued at the merge
// in userinfoResponse() rather than here: the `userinfo` CUSTOM CLAIM SET
// configured on /admin/userinfo-claims, which is what everybody gets, and the
// claims a CLIENT named in section 5.5's request, which is what this client
// asked about this person this time. A reader who takes this table for the
// response has the picture this service had before either existed.
const USERINFO_SCOPE_CLAIMS = {
  profile: ['name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website', 'gender',
            'birthdate', 'zoneinfo', 'locale', 'updated_at'],
  email: ['email', 'email_verified'],
  address: ['address'],
  phone: ['phone_number', 'phone_number_verified']
};

// ---------------------------------------------------------------------------
// NON-SPEC: A CLAIMS REQUEST SENT TO THE USERINFO ENDPOINT ITSELF.
//
// OpenID Connect Core defines exactly one way to ask for individual claims —
// the `claims` parameter at the AUTHORIZATION endpoint, section 5.5 — and that
// is implemented above and is the one a real client uses. Section 5.3.1 defines
// no request parameters at all here: an access token and nothing else.
//
// This accepts one anyway, and it is labelled rather than quietly added,
// because the reason is about what this service is FOR. Exercising a claims
// request through the specified route means running a whole authorization flow
// per variation — a browser, a sign-in, a code, a redemption — to change one
// claim name. A person debugging what this endpoint does with `address` versus
// `address.locality` versus a name nothing can produce wants to send three
// requests, and a mock that made them sign in three times would not be used.
//
// TWO SPELLINGS, both of which the console's own links use:
//
//   ?claims={"userinfo":{"birthdate":null}}   the section 5.5 structure, whole
//   ?claim=birthdate&claim=address            the shorthand, one name each
//
// **IT IS A UNION WITH THE TOKEN'S OWN REQUEST AND NEVER A REPLACEMENT.** What
// the client asked for at the authorization endpoint is what it was authorized
// for, and a request parameter that could take a claim AWAY from that would
// make the two disagree about the same grant. What this can do is add to it —
// which changes nothing about what the grant permits, because every name it can
// answer is one the endpoint would already answer for this same subject.
//
// A MALFORMED ONE IS REFUSED, `invalid_request`, with the reason. The
// alternative was to ignore it, and ignoring a debugging parameter that was
// typed wrong is the worst possible answer: the response looks exactly like the
// one for a parameter that was never sent.
// ---------------------------------------------------------------------------
const USERINFO_CLAIMS_QUERY = vz.looseObject({
  claims: vz.string().max(validation.CAP.TEXT).optional(),
  claim: vt.repeatable(vz.string().max(256)).optional()
});

// ---------------------------------------------------------------------------
// SECTION 5.3.2's PROTECTED USERINFO RESPONSE — signed, encrypted, or both.
//
// What a client registers decides the shape of the answer:
//
//   neither                     application/json, the claims as they are
//   ..._signed_response_alg     application/jwt, a JWS over the claims
//   ..._encrypted_response_alg  application/jwt, a JWE
//   both                        application/jwt, a JWS INSIDE a JWE
//
// THE ORDER IS SIGN THEN ENCRYPT and it is not a preference. Encrypting first
// and signing the ciphertext would let anyone who can decrypt strip the
// signature and re-encrypt to somebody else, and the recipient would have no
// way to tell. Section 5.3.2 says signed then encrypted, JWT section 5.2 says
// the outer header carries `cty: "JWT"` to announce it, and both are done here.
//
// A SIGNED RESPONSE GAINS `iss` AND `aud`, which is the whole reason to want
// one. Without them a signed profile of Alice issued for client A is a signed
// profile of Alice that client B will also believe — the signature proves who
// wrote it and says nothing about who it was written for.
// ---------------------------------------------------------------------------

// What this service can sign a UserInfo response with. The RSA families use the
// RSA key in the JWKS; the HMAC family uses that client's own client_secret,
// which is why it needs no published key.
const USERINFO_RSA_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384',
                           'PS512'];
const USERINFO_HMAC_ALGS = ['HS256', 'HS384', 'HS512'];
// The curve algorithms, each with a key of its own in the JWKS. They were
// absent until 2026-08-28 and the reason was only ever that no EC key was
// generated — see makeStsKeys(). A capability withheld because of a missing key
// pair is the wrong kind of gap in a tool people point at real identity
// providers, since ES256 is what a great many of them use.
// ES256K is in here with the rest and is the one that needed an implementation
// rather than only a key: `jsonwebtoken` has no secp256k1, so stsCrypto signs
// and verifies it directly on node's OpenSSL, converting the DER signature
// OpenSSL returns into the R||S concatenation RFC 7518 section 3.4 requires.
const USERINFO_EC_ALGS = ['ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'];
// The post-quantum and composite signatures, taken from the shared table so
// this list cannot fall behind it. signJwtAs() already knows which key each
// one needs, so nothing else here had to change to gain them.
const USERINFO_PQ_ALGS = stsCrypto.JWS_SIGNING_ALGS.filter(function (alg) {
  return stsCrypto.JWS_ALGS[alg].family === 'pq';
});
const USERINFO_SIGNING_ALGS = USERINFO_RSA_ALGS
  .concat(USERINFO_EC_ALGS)
  .concat(USERINFO_PQ_ALGS)
  .concat(USERINFO_HMAC_ALGS)
  .concat(['none']);

// What an ID Token may be signed with. OIDC Core section 3.1.3.7 lets a client
// register `id_token_signed_response_alg`, and this service can sign with
// anything in the shared table — so the advertised list is that table rather
// than a subset, and `none` is absent because an unsigned ID Token is not
// something this service will produce: the ID Token is the one artifact whose
// whole purpose is to be verified.
const ID_TOKEN_SIGNING_ALGS = stsCrypto.JWS_SIGNING_ALGS;

// The algorithms `helpers.signJwt()` signs with this realm's own RSA or curve
// key in process (#139) — every other one is post-quantum (the pool) or HMAC
// (the client's secret) and goes through `signJwtAsAsync()`.
// OpenID Connect Discovery section 2's link relation (#119).
const WEBFINGER_ISSUER_REL = 'http://openid.net/specs/connect/1.0/issuer';

const OWN_SYNC_SIGNING = /^(RS|PS|ES)(256|384|512)$|^ES256K$|^EdDSA$/;

// ---------------------------------------------------------------------------
// TWO REDEMPTIONS OF ONE CODE AT ONCE (2026-09-14, #46).
//
// **WHAT WAS WRONG.** A code is looked up in `authzCodes`, every check runs,
// the tokens are minted — `await issue()`, which may take seconds for a
// post-quantum ID Token — and only then is the code deleted. Inside one
// process that await was already a window: two Token Requests for one code
// both found the record and both were issued tokens. Across nodes the window
// is the change log as well, because the delete reaches the other node a
// moment after it is written. And RFC 9700 section 4.5's "revoke what the code
// bought" never fired, because each redemption found a live code rather than
// a redemption record.
//
// **WHAT IT IS NOW.** The code is SPENT through `cluster_claims.claim()`
// immediately before the tokens are minted — below every check, so a request
// refused for its code_verifier or its redirect_uri spends nothing (the
// comment above the checks says why that matters) — and the claim is bound to
// the response: a mint that fails (the role gate, a signing error) gives the
// code back. On postgres the claim is one `INSERT … ON CONFLICT`, so exactly
// one node wins however many race.
//
// **THE LOSER IS A REPLAY, AND A REPLAY NEEDS THE WINNER'S RECORD.** The
// winner writes `redeemedCodes` when its tokens exist, and the barrier holds
// its response until that write has committed. So the loser waits — catching
// up with the change log between looks (`cluster_barrier.syncShared()`, the
// same pull the barrier makes at a request's arrival) — until the record is
// there, and then goes down `replayOrRefuseRedemption()` exactly as a
// sequential replay does: an identical request is answered with the same
// token set outside RFC 9700 mode, and inside it the repeat is refused and
// everything the first redemption bought is revoked.
//
// **BOUNDED, AND WHAT THE BOUND COSTS.** `CONCURRENT_REDEMPTION_WAIT_MS`. A
// winner whose mint FAILED writes no record and releases its claim, and a
// loser waiting on it would otherwise wait for ever; after the bound the loser
// is refused (`STS-OAUTH-0512`) and the code is left to whoever retries. The
// residue: a winner whose commit takes longer than the bound has bought tokens
// the loser could not find to revoke. The replication hole wait is four
// seconds for the same reason, and a commit slower than that is already a
// condition `STS-CLUSTER-0018` reports.
// ---------------------------------------------------------------------------
const CONCURRENT_REDEMPTION_WAIT_MS = 5000;
const CONCURRENT_REDEMPTION_POLL_MS = 50;

// ---------------------------------------------------------------------------
// THE BACK-CHANNEL ENDPOINTS.
//
// `z.looseObject` on the TOKEN REQUEST for AUTHORIZE_QUERY's reason one door
// along: `body` escapes `tokenGrant()` into `clientFrom()`,
// `redemptionFingerprint()`, `bcp.checkTokenRequest()` and the claims merge,
// each of which reads members this schema does not name. Stripping would make
// a parameter vanish between the parse and the check that exists to read it.
//
// **`resource` IS DELIBERATELY NOT `repeatable` HERE, WHICH IS THE OPPOSITE OF
// THE AUTHORIZATION ENDPOINT** — and it is not an inconsistency. A repeated
// form field never reaches this object at all: `parseBody()` builds a plain
// object with `out[k] = v`, so the last value wins, and the repeats are read
// separately off the RAW body by `bodyValues(req, body, 'resource')`. Declaring
// it repeatable here would hand `tokenGrant()` an ARRAY where sixty-odd call
// sites across fourteen modules expect `String(body.x)` — which is the exact
// change `helpers.js` refused to make when `bodyValues()` was written instead.
// ---------------------------------------------------------------------------
const TOKEN_FORM = vz.looseObject({
  grant_type: vz.string().max(128).optional(),
  client_id: vt.opt(vt.identifier),
  client_secret: vz.string().max(1024).optional(),
  code: vt.opt(vt.opaque),
  code_verifier: vt.opt(vz.string().min(43).max(128)),
  redirect_uri: vt.opt(vt.redirectUri),
  refresh_token: vt.opt(vt.opaque),
  scope: vt.opt(vt.scope),
  username: vt.opt(vt.name),
  password: vz.string().max(1024).optional(),

  // RFC 8693 token exchange.
  subject_token: vz.string().max(validation.CAP.TEXT).optional(),
  subject_token_type: vt.opt(vt.uri),
  actor_token: vz.string().max(validation.CAP.TEXT).optional(),
  actor_token_type: vt.opt(vt.uri),
  requested_token_type: vt.opt(vt.uri),
  audience: vz.string().max(validation.CAP.URI).optional(),

  // RFC 8707, and OpenID4VCI's pre-authorized code transaction code.
  resource: vz.string().max(validation.CAP.URI).optional(),
  tx_code: vz.string().max(64).optional(),
  authorization_details: vz.string().max(validation.CAP.TEXT).optional(),

  // RFC 7523 / OIDC private_key_jwt.
  client_assertion: vz.string().max(validation.CAP.TEXT).optional(),
  client_assertion_type: vt.opt(vt.uri),

  // RFC 7521 section 4.1 — the ASSERTION GRANT's own parameter, and it is a
  // different one from `client_assertion` above on purpose. That one says who
  // is CALLING; this says who the token is FOR. A request may legitimately
  // carry both: a client authenticating with its own assertion and presenting
  // somebody else's as the grant.
  assertion: vz.string().max(validation.CAP.TEXT).optional()
});

// RFC 7662 and RFC 7009. Both take one token and an optional hint about which
// kind it is, and this service reads only the first — the hint is advisory in
// both specifications and a wrong one must not change the answer.
const TOKEN_QUERY_FORM = vz.looseObject({
  token: vz.string().max(validation.CAP.TEXT).optional(),
  token_type_hint: vt.opt(vt.oneOf(['access_token', 'refresh_token'])),
  client_id: vt.opt(vt.identifier),
  client_secret: vz.string().max(1024).optional()
});

// RFC 7009 ALONE (#102, 2026-09-22), and it differs from the form above in
// exactly two places. `token_type_hint` is any short string: section 2.1 says
// a server that does not understand a hint MAY ignore it, and section 4.1.2 is
// a REGISTRY of hint values that grows — so an unknown one is ignored here
// rather than refused as a malformed request, which is what sharing
// introspection's form did. And `token` stays optional to the validator so
// that its absence is answered by name (`STS-OAUTH-0608`) rather than as a
// schema failure. Introspection keeps its own form, unchanged.
const REVOCATION_FORM = vz.looseObject({
  token: vz.string().max(validation.CAP.TEXT).optional(),
  token_type_hint: vz.string().max(256).optional(),
  client_id: vt.opt(vt.identifier),
  client_secret: vz.string().max(1024).optional()
});

// OpenID Connect RP-Initiated Logout 1.0 section 2.
//
// **`post_logout_redirect_uri` IS A `redirectUri` AND THAT IS THE POINT OF
// TYPING IT AT ALL**: it is an address this service sends a BROWSER to, so a
// `javascript:` scheme here is script execution on somebody's machine at the
// end of a sign-out. `vt.uri` refuses the executable schemes and the
// `redirectUri` refinement refuses a fragment besides.
const LOGOUT_QUERY = vz.looseObject({
  post_logout_redirect_uri: vt.opt(vt.redirectUri),
  client_id: vt.opt(vt.identifier),
  id_token_hint: vz.string().max(validation.CAP.TOKEN).optional(),
  state: vt.opt(vt.opaque),
  logout_hint: vz.string().max(256).optional(),
  ui_locales: vz.string().max(256).optional()
});

// ---------------------------------------------------------------------------
// POST /oauth2/par — RFC 9126, THE PUSHED AUTHORIZATION REQUEST ENDPOINT
// (2026-09-13).
//
// `oauth-oidc/par.ts` argues the design and holds the store; this is the
// response. The order below is the section's own, and each step says why it is
// where it is:
//
//   1. WHAT KIND OF REQUEST: switched off (404), too large (section 2.3's 413),
//      not a form, malformed — before anything in it is read;
//   2. WHOSE REQUEST: a client_id (section 2.1 "similarly required"), the
//      per-client push limit (section 2.3's 429) and the secret lockout;
//   3. A DPoP PROOF, where one is sent (RFC 9449 section 10.1): it binds the
//      authorization code to its key, and a `dpop_jkt` naming another key is
//      refused;
//   4. CLIENT AUTHENTICATION "in the same way as at the token endpoint"
//      (section 2.1 step 1) — the token endpoint's own sequence and its own
//      libraries: the advertised methods, RFC 9700 mode's policy, OAuth 2.1's
//      declaration and presented-credential rules, the observation every mode
//      makes, and product mode's refusal of a public client. rcbj chose this
//      reading over "every mode" (`par.ts`, decision 1);
//   5. `request_uri` REFUSED (step 2), and a `request` object verified by
//      `request_object.ts` with its client bound to the authenticated one
//      (section 3), or refused where a signed one is required and none came
//      (section 2.3);
//   6. VALIDATED AS AN AUTHORIZATION REQUEST (step 3) — by
//      `vetAuthorizationRequest()`, the authorization endpoint's own checks,
//      and the five parsers `issueAuthorizationResponse()` asks before it
//      mints, so a request that could never be answered is refused here, where
//      the client can still be told, rather than after a person has signed in;
//   7. KEPT, and answered 201 `{ request_uri, expires_in }` (section 2.2).
//
// EVERY REFUSAL IS SECTION 2.3's JSON — the token endpoint's error format —
// and none is redirected: there is no browser here. Each is counted on
// /admin/oauth2/monitor.
// ---------------------------------------------------------------------------
const PAR_FORM = vz.looseObject({
  client_id: vt.opt(vt.identifier),
  client_secret: vz.string().max(1024).optional(),
  client_assertion: vz.string().max(validation.CAP.TEXT).optional(),
  client_assertion_type: vt.opt(vt.uri),
  // Section 3: a request object pushed by value.
  request: vz.string().max(validation.CAP.TEXT).optional(),
  // Section 2.1: "MUST NOT be provided" — bounded so the refusal can quote it.
  request_uri: vz.string().max(validation.CAP.URI).optional()
});

// What a push carries that is NOT the authorization request: the client's
// credential, and this service's own round-trip markers, which only its sign-in
// and consent screens may put on a request and a client must not be able to
// pre-load into one.
const PAR_NOT_PARAMETERS = ['client_secret', 'client_assertion',
                            'client_assertion_type'];

const PAR_PRIVATE_FIELDS = ['authn_error', 'authn_error_description',
                            'consent_error', 'consent_error_description',
                            'jar_prompt_honoured', 'step_up_honoured'];

// The parameters that may repeat in a push: RFC 8707's `resource` and this
// service's own `claim`, exactly as at the authorization endpoint.
const PAR_REPEATABLE = ['resource', 'claim'];

// The management calls all authenticate with the registration access token the
// registration handed out.
const REGISTERED_CLIENT_PARAMS = vz.object({
  client_id: vt.identifier
});

class OAuth2Server {
  constructor(private readonly deps: OAuth2ServerDeps) {
    deps.log.debug("Entering OAuth2Server.constructor().");
    deps.log.debug("Leaving OAuth2Server.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): OAuth2ServerDeps {
    helpers.log.debug("Entering OAuth2Server.defaultDeps().");
    helpers.log.debug("Leaving OAuth2Server.defaultDeps().");
    return {
      crypto: crypto,
      realms: realms,
      forge: forge,
      jwt: jwt,
      stsCrypto: stsCrypto,
      app: app,
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      STS: helpers.STS,
      baseUrlOf: helpers.baseUrlOf,
      b64u: helpers.b64u,
      jsonFromB64u: helpers.jsonFromB64u,
      nowSec: helpers.nowSec,
      randomId: helpers.randomId,
      xmlEscape: helpers.xmlEscape,
      parseBody: helpers.parseBody,
      bodyValues: helpers.bodyValues,
      plainOauthError: helpers.oauthError,
      signJwt: helpers.signJwt,
      signJwtAs: helpers.signJwtAs,
      allSigningKeys: helpers.allSigningKeys,
      allSigningKeysAsync: helpers.allSigningKeysAsync,
      signJwtAsAsync: helpers.signJwtAsAsync,
      userFor: helpers.userFor,
      hasScope: helpers.hasScope,
      signingKeyFor: helpers.signingKeyFor,
      certificateHeaderFor: helpers.certificateHeaderFor,
      publishedKidFor: helpers.publishedKidFor,
      nameForSubject: helpers.nameForSubject,
      hasSubjectResolver: helpers.hasSubjectResolver,
      LEGACY_SUBJECT_PREFIX: helpers.LEGACY_SUBJECT_PREFIX,
      requestObjectKeysFor: helpers.requestObjectKeysFor,
      dpop: dpop,
      joseKid: joseKid,
      mtls: mtls,
      clientAuth: clientAuth,
      assertionGrant: assertionGrant,
      softwareStatement: softwareStatement,
      samlAssertionGrant: samlAssertionGrant,
      mode: mode,
      authorizationServers: authorizationServers,
      stats: stats,
      VCI_CONFIGS: vcConfigs.VCI_CONFIGS,
      VCI_CONFIG_ID: vcConfigs.VCI_CONFIG_ID,
      VCI_SCOPE: vcConfigs.VCI_SCOPE,
      vciFormatOf: vcConfigs.vciFormatOf,
      vcClaims: vcClaims,
      deferredAccessTokens: vcOffers.deferredAccessTokens,
      issuerStates: vcOffers.issuerStates,
      preAuthorizedCodes: vcOffers.preAuthorizedCodes,
      checkTxCode: vcOffers.checkTxCode,
      spendPreAuthorizedCode: vcOffers.spendPreAuthorizedCode,
      config: config,
      authn: authn,
      sessionOf: authn.sessionOf,
      endSession: authn.endSession,
      bcp: bcp,
      oauth21: oauth21,
      fapi: fapi,
      senderConstraints: senderConstraints,
      frontchannel: frontchannel,
      backchannel: backchannel,
      applications: applications,
      validation: validation,
      errorCodes: errorCodes,
      refreshTokenCrypto: refreshTokenCrypto,
      jwtAccessToken: jwtAccessToken,
      introspectionJwt: introspectionJwt,
      idTokenEncryption: idTokenEncryption,
      jarm: jarm,
      pairwiseSubjects: pairwiseSubjects,
      stepUp: stepUp,
      requestObject: requestObject,
      richAuthorization: richAuthorization,
      par: par,
      oauthMonitor: oauthMonitor,
      delegation: delegation,
      consent: consent,
      consentScreen: consentScreen,
      claimAttributes: claimAttributes,
      gate: gate,
      debuggerAccess: debuggerAccess,
      scopePolicy: scopePolicy,
      credentials: credentials,
      websecurity: websecurity,
      audit: audit,
      clusterClaims: clusterClaims,
      clusterBarrier: clusterBarrier,
      capabilities: capabilities
    };
  }

  // EVERY OAUTH ERROR BODY THIS MODULE WRITES GOES THROUGH HERE, so OAuth 2.1
  // mode's one rule about what an error SAYS — section 3.2.4's character set
  // for `error_description` — is applied in one place rather than at two
  // hundred. The helper's own behaviour is untouched and every other module
  // that uses it is unaffected; outside that mode the description is passed
  // as written.
  // error-code: none — the wrapper's definition, not a call to it.
  oauthError(res: Res, status: number, error: string,
             description?: string): unknown {
    const { log, plainOauthError, oauth21 } = this.deps;
    // error-code: none — the wrapper's trace line, not a call to it.
    log.debug("Entering OAuth2Server.oauthError(). (oauth2.ts)");
    // error-code: none — the wrapper's trace line, not a call to it.
    log.debug("Leaving OAuth2Server.oauthError(). (oauth2.ts)");
    // error-code: none — every caller marks its own condition first.
    return plainOauthError(res, status, error,
                           oauth21.sanitizeDescription(description));
  }

  // ---------------------------------------------------------------------------
  // RFC 8414 — OAuth 2.0 Authorization Server Metadata
  //
  // A dummy metadata document with EVERY member RFC 8414 section 2 defines
  // populated, so the debugger's Configuration Parameters pane can be filled
  // from a real endpoint. Served at the well-known path from section 3, and
  // also with an issuer path component appended (section 3.1) so both shapes
  // resolve.
  //
  // The issuer and every endpoint are derived from the URL the request arrived
  // on, so the document is self-consistent whether it is reached as
  // http://localhost:8081 (host) or http://sts:8081 (compose network).
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE ISSUER IDENTIFIER, which is not the same thing as the base URL even
  // though it is derived from it by default.
  //
  // Everything this module serves is addressed from the URL the request arrived
  // on, so one process answers correctly as http://localhost:8081 from a host
  // run and as http://sts:8081 from a compose network without being told which.
  // The issuer came from the same place, and for the same good reason: a
  // conforming client MUST reject a discovery document whose `issuer` is not
  // the identifier it fetched from, so a pinned value would break one of those
  // two callers.
  //
  // `oauth2.issuer` in config.js lets it be pinned anyway, and is EMPTY by
  // default so that nothing changes unless somebody means it to. Pinning it is
  // how the mismatch above is produced on purpose — which is a case worth being
  // able to reach, since the failure it causes in a real client is reported as
  // something else entirely.
  //
  // Only the IDENTIFIER moves. Every endpoint in the document stays on the
  // request's base URL, because an endpoint has to be reachable and a pinned
  // issuer may not be.
  //
  // ---------------------------------------------------------------------------
  // THE ONE THING DONE TO A PINNED VALUE: its SCHEME is upgraded to https when
  // this port is an HTTPS listener (`global.https`, which RFC 9700 mode brings
  // with it).
  //
  // The unpinned case needs nothing — the base URL comes from `req.protocol`,
  // so it is already https and so is every `iss` this module signs, since this
  // function is the single funnel all four of them pass through (the access
  // token, the refresh token, the ID Token and the UserInfo JWT). A PINNED
  // value is a string somebody wrote once, and `http://localhost:8081` written
  // before the mode was turned on is now an identifier for a URL that no longer
  // exists on this machine.
  //
  // It is an upgrade rather than a refusal because of what a client does with
  // it: a conforming relying party MUST reject a discovery document whose
  // `issuer` is not the identifier it fetched from, so a pinned http issuer
  // served over https fails at every client, at configuration time, with a
  // message about the issuer — and the person reading it has to work out that
  // the scheme is the part that moved. Nothing is gained by making that
  // reachable: the mismatch worth being able to produce on purpose is a
  // DIFFERENT HOST or path, and pinning still does that untouched.
  //
  // The upgrade is logged every time rather than done quietly, because a value
  // that comes back out of /admin/config differently from how it went in is
  // worth a line somebody can find.
  //
  // **THE BODY MOVED TO `jwt_access_token.ts`'s `issuerFor()` ON 2026-09-13**,
  // and this function is kept, by name, as the call every site here and
  // `gnap/gnap_grants.ts` already make. It moved because RFC 9068 section 4 has
  // the RESOURCE SERVER compare `iss` against this same identifier, and the
  // resource-server check lives in `dpop.ts`, which cannot require this module
  // — a second copy there would be two answers to what this service's issuer
  // is.
  // ---------------------------------------------------------------------------
  issuerOf(base: string): string {
    const { log, jwtAccessToken } = this.deps;
    log.debug("Entering OAuth2Server.issuerOf().");
    log.debug("Leaving OAuth2Server.issuerOf().");
    return jwtAccessToken.issuerFor(base);
  }

  // `raw` is set by capabilitiesFor() below and means "build the document this
  // service would publish, without applying a profile" — the DEFAULTS a profile
  // is merged onto. Without it, asking for the capabilities would apply the
  // profile, then merge the profile onto the result again: harmless today and
  // exactly the kind of thing that stops being harmless when a member is
  // computed from another.
  asMetadata(req: Req, raw?: boolean): Json {
    const { log, baseUrlOf, authorizationServers, config, assertionGrant,
            samlAssertionGrant, stsCrypto, richAuthorization, clientAuth,
            mtls, introspectionJwt, applications, mode, stepUp, dpop,
            bcp, fapi } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.asMetadata(). raw=" + !!raw);
    // A NAMED SERVER'S OWN FAPI PROFILE (#138). The discovery routes do not
    // pass through forProfile(), so the document is built inside that
    // server's profile here, once.
    const ownFapi = self.fapiOf(self.profileOf(req));
    if (ownFapi && !(req as Json).__fapiScoped) {
      (req as Json).__fapiScoped = true;
      log.debug("Leaving OAuth2Server.asMetadata(). Rebuilt inside the " +
                "server's FAPI profile.");
      return fapi.withProfile(ownFapi, function () {
        return self.asMetadata(req, raw);
      });
    }
    const base = baseUrlOf(req);
    // WHERE THIS AUTHORIZATION SERVER'S ENDPOINTS ARE. The default one is at
    // the unprefixed paths and a named one is under its own name, which is the
    // shape its routes are registered at — so the document a client reads names
    // the endpoints that belong to the authorization server it read it from,
    // and a client that follows the metadata cannot end up at somebody else's.
    const profileId = self.profileOf(req);
    const at = base +
      (profileId && profileId !== authorizationServers.DEFAULT_ID
        ? '/' + profileId : '');
    const metadata = {
      // --- REQUIRED --- A named authorization server IS its own issuer — `at`
      // carries the path — so the document and the tokens agree about who
      // issued what. A pinned oauth2.issuer still wins, for the reason
      // issuerOf() gives.
      issuer: self.issuerOf(at),
      authorization_endpoint: at + '/oauth2/authorize',
      token_endpoint: at + '/oauth2/token',
      // Every combination the authorization endpoint actually issues: it splits
      // response_type on whitespace and accepts any mixture of code, token and
      // id_token, so `id_token token` belongs here too — OpenID Connect Dynamic
      // Registration names it as one an OP should support, and leaving it out
      // of the list while honouring it is the same drift as the reverse.
      // `none` since #125: Multiple Response Type Encoding Practices section
      // 4, a response carrying `state` and nothing issued.
      response_types_supported: ['code', 'token', 'id_token', 'code token',
                                 'code ' +
          'id_token',
                                 'id_token token', 'code id_token token',
                                 'none'],
      // --- RECOMMENDED / OPTIONAL ---
      jwks_uri: at + '/oauth2/jwks',
      // NON-SPEC (#42, D8): the realm's public crypto metadata document —
      // every signer generation, its chain, its algorithms and the rotation
      // policy — at the realm's own base, since keys are the realm's and not
      // a named authorization server's. A member no specification defines,
      // which RFC 8414 section 2 lets a client ignore.
      crypto_metadata_uri: base + '/crypto/metadata.json',
      registration_endpoint: at + '/oauth2/register',
      // `address` and `phone` were listed here and are gone: OIDC Core section
      // 5.4 makes each of these scopes a request for a NAMED set of claims, and
      // userFor() mints no address and no phone_number, so the two were a
      // promise of claims that could never arrive. It reads as an omission next
      // to the claims_supported list in the OIDC document, which is the whole
      // reason the two documents are built from this one object. The two SCIM
      // scopes are here because /scim/v2 now READS them: it is the first
      // surface in this service to require a scope for anything, and a client
      // that cannot discover the name of the scope it needs has to be told it
      // out of band. They are advertised only while SCIM is on, for the reason
      // `tls_client_certificate_bound_access_tokens` is advertised only where
      // the port is TLS — a client reads a metadata member as a promise, and a
      // scope that opens nothing is a promise with nothing behind it. Their
      // NAMES come from config.js rather than being written here, so that
      // changing `scim.scopeRead` moves the advertisement and the check
      // together.
      // `address` and `phone` since #118: section 5.4's two scopes the
      // UserInfo endpoint answers from the directory entry.
      scopes_supported: ['openid', 'profile', 'email', 'address', 'phone',
                         'offline_access'].concat(
        config.value('scim.enabled') !== false
          ? [String(config.value('scim.scopeRead') || 'scim:read'),
             String(config.value('scim.scopeWrite') || 'scim:write')]
          : []).concat(
        // The two SSF scopes, on the same terms and for the same reason: a
        // receiver needs a token before it can create a stream, and a scope
        // this document does not advertise is one a client has to be told
        // about out of band. They go only where the family is on, so the
        // promise and what is behind it stay together.
        config.value('ssf.enabled') !== false
          ? [String(config.value('ssf.authScopeRead') || 'ssf:read'),
             String(config.value('ssf.authScopeWrite') || 'ssf:write')]
          : []),
      // All three, and form_post is the one that was advertised here and NOT
      // implemented for a long time — every request got a 302 whatever it asked
      // for, so a client that requested form_post sat waiting for a POST that
      // never arrived, which is the worst shape a metadata member can have
      // because the failure is silent at the client end. The member was removed
      // rather than left lying; it is back because the mode is now real.
      //
      // It is worth asking for: RFC 9700 section 4.3 is about the authorization
      // response ending up in browser history, in the address bar and in the
      // Referer of whatever the landing page fetches, and a form POST puts it
      // in a request body where none of that happens.
      // JARM's four (#139, #143) beside the three plain ones.
      response_modes_supported: ['query', 'fragment', 'form_post']
        .concat(jarm.MODES),
      // JARM section 4: what a JWT-secured authorization response may be
      // signed and encrypted with.
      authorization_signing_alg_values_supported: jarm.SIGNING_ALGS,
      authorization_encryption_alg_values_supported: jarm.ENCRYPTION_ALGS,
      authorization_encryption_enc_values_supported: jarm.ENCRYPTION_ENCS,
      // Only what the token endpoint below actually implements — the metadata
      // should not promise a grant this server would refuse. (No device_code:
      // there is no device authorization endpoint to start that flow.)
      grant_types_supported: ['authorization_code', 'implicit', 'refresh_token',
                              'client_credentials',
                              'password',
                              'urn:ietf:params:oauth:grant-type:token-exchange',
                              // OID4VCI's pre-authorized code grant, which the
                              // cross-device Credential Offers use.
                              'urn:ietf:params:oauth:grant-type:pre-authorized_code']
        // RFC 7523 section 2.1, and it is CONDITIONAL where the seven above are
        // not — `oauth2.jwtBearerGrant` can switch it off, and a
        // grant_types_supported member is a PROMISE. The check at the top of
        // the token endpoint refuses anything this list does not carry, so a
        // client that read the metadata and a client that guessed get the same
        // answer.
        .concat(assertionGrant.enabled() ? [assertionGrant.GRANT_TYPE] : [])
        // RFC 7522 section 2.1, and CONDITIONAL in exactly the same way and for
        // exactly the same reason. TWO settings and not one, because a
        // deployment legitimately offers one profile and not the other — a
        // single switch would make "turn the JWT grant off" also turn off a
        // grant a SAML deployment depends on.
        .concat(samlAssertionGrant.enabled()
          ? [samlAssertionGrant.GRANT_TYPE] : []),
      // RFC 7521 section 4.1 and OpenID Connect Core section 9's spelling of
      // the same thing: what a client_assertion_type may say. It is published
      // for the GRANT as well as for client authentication, because the one
      // thing a client author needs to know about this grant before writing any
      // code is that the assertion is a JWT.
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer_supported': true,
      // RFC 7522 section 2.2's spelling of the same member. Published
      // UNCONDITIONALLY like the one above, and for its reason: it says what a
      // client_assertion_type may be, and that is true of this server whether
      // or not any client has registered for the method — the one thing a
      // client author needs to know before writing code against this profile is
      // that the assertion is a base64url SAML 2.0 Assertion rather than a JWT.
      'urn:ietf:params:oauth:client-assertion-type:saml2-bearer_supported': true,
      // WHAT AN ASSERTION MAY BE SIGNED WITH, for BOTH halves of RFC 7523. It
      // is the whole JWS table — every algorithm `common/crypto.js` can verify,
      // post-quantum ones included — because the assertion is verified against
      // a key the PARTY registered and this service has no reason to hold an
      // opinion about which of them somebody's HSM produces.
      assertion_signing_alg_values_supported: stsCrypto.JWS_SIGNING_ALGS,
      // AND WHAT ONE MAY BE ENCRYPTED WITH (RFC 7523 section 3 claim 10). These
      // are the DECRYPT lists rather than the encrypt ones: what is being
      // described is a document arriving HERE, and the symmetric families are
      // usable because a client_secret is a shared key. See
      // `oauth-oidc/assertion_grant.js`'s `unwrapAssertion()`.
      assertion_encryption_alg_values_supported: stsCrypto.JWE_DECRYPT_ALGS,
      assertion_encryption_enc_values_supported:
        Object.keys(stsCrypto.JWE_ENCS),
      // RFC 9396. OID4VCI's openid_credential — its other way of saying which
      // credential is wanted — and every type an application in this realm
      // declares as a resource server (`oauthAuthorizationDetailsType`).
      authorization_details_types_supported:
        richAuthorization.typesSupported(),
      // Built from the list `client_auth.js` can actually VERIFY, rather than
      // written out here. It used to name private_key_jwt while nothing looked
      // at an assertion, which is the worst shape a metadata member can have: a
      // client author reads it as "checked" and configures the asymmetric
      // method believing it bought something. The two RFC 8705 methods appear
      // only where there is a TLS handshake to read a certificate from.
      token_endpoint_auth_methods_supported: clientAuth.METHODS.filter(
          function (method) {
        return mtls.available() || method.indexOf('tls_client_auth') < 0;
      }),
      // Every algorithm the shared verifier accepts, which since 2026-08-28 is
      // every one in the table: client_auth.js verifies through
      // stsCrypto.verifyJws(), and that gained EdDSA and ES256K when the shared
      // verifier did. A list written out here would have gone stale the moment
      // it did.
      token_endpoint_auth_signing_alg_values_supported:
        stsCrypto.JWS_SIGNING_ALGS,
      service_documentation: base + '/docs',
      // One locale, because there is one: the login screen is the only UI this
      // server renders and it is written in English. A request's ui_locales
      // is accepted and answered in English, which section 3.1.2.1 permits
      // ("An error SHOULD NOT result if some or all of the requested locales
      // are not supported"). The list used to name four, which a client is
      // entitled to read as "ask for fr-CA and you will get it".
      ui_locales_supported: ['en-US'],
      op_policy_uri: base + '/policy',
      op_tos_uri: base + '/tos',
      revocation_endpoint: at + '/oauth2/revoke',
      // THE METHODS THE REVOCATION ENDPOINT CAN VERIFY, which since #102
      // (2026-09-22) is introspection's list for introspection's reason: the
      // same `authenticateEndpointCaller()`, the same six methods, and `none`
      // for the public client RFC 7009 section 2.1 lets identify itself by
      // its client_id. It named three hard-coded methods while nothing
      // authenticated a caller there at all.
      revocation_endpoint_auth_methods_supported: clientAuth.METHODS.filter(
          function (method) {
        return mtls.available() || method.indexOf('tls_client_auth') < 0;
      }),
      revocation_endpoint_auth_signing_alg_values_supported:
        stsCrypto.JWS_SIGNING_ALGS,
      introspection_endpoint: at + '/oauth2/introspect',
      // THE METHODS THE INTROSPECTION ENDPOINT CAN VERIFY, which since RFC 9701
      // (2026-09-13) is every method the token endpoint can, through the same
      // `bcp.observeClientAuthentication()`. It named three while nothing
      // authenticated a caller there at all.
      introspection_endpoint_auth_methods_supported: clientAuth.METHODS.filter(
          function (method) {
        return mtls.available() || method.indexOf('tls_client_auth') < 0;
      }),
      introspection_endpoint_auth_signing_alg_values_supported:
        stsCrypto.JWS_SIGNING_ALGS,
      // RFC 9701 section 7. What a resource server may register as
      // introspection_signed_response_alg, _encrypted_response_alg and
      // _encrypted_response_enc — the application registry's own lists, which
      // are `common/crypto.js`'s tables, so nothing is advertised that the
      // registration would refuse or the endpoint could not produce.
      introspection_signing_alg_values_supported:
        introspectionJwt.SIGNING_ALGS,
      introspection_encryption_alg_values_supported:
        introspectionJwt.ENCRYPTION_ALGS,
      introspection_encryption_enc_values_supported:
        introspectionJwt.ENCRYPTION_ENCS,
      // RFC 9101 AND OPENID CONNECT DISCOVERY (2026-09-13). A request object by
      // value and by reference; a request_uri fetched only when the client
      // registered it, which is exactly what require_request_uri_registration
      // TRUE promises; `none` advertised only where an unsigned object would be
      // accepted; the decryption lists are what `request_object.ts` opens — the
      // asymmetric families to this realm's published `use: "enc"` keys and the
      // symmetric ones to the client's secret. A named authorization server's
      // profile may narrow any of it, and the endpoint follows the document.
      request_parameter_supported: true,
      request_uri_parameter_supported: true,
      require_request_uri_registration: true,
      require_signed_request_object:
        !!config.value('oauth2.requireSignedRequestObject'),
      request_object_signing_alg_values_supported:
        applications.REQUEST_OBJECT_SIGNING_ALGS.concat(
          mode.acceptsUnsignedRequestObjects() &&
          !config.value('oauth2.requireSignedRequestObject') ? ['none'] : []),
      request_object_encryption_alg_values_supported:
        applications.REQUEST_OBJECT_ENCRYPTION_ALGS,
      request_object_encryption_enc_values_supported:
        applications.REQUEST_OBJECT_ENCRYPTION_ENCS,
      // RFC 9126 SECTION 5 (2026-09-13). The endpoint, and the global policy.
      // `pushed_authorization_request_endpoint` is removed below where
      // `oauth2.pushedAuthorizationRequests` is off, because the endpoint then
      // answers 404; a client's policy is its own registration member and the
      // selected authorization server's profile may publish the requirement
      // for it
      pushed_authorization_request_endpoint: at + '/oauth2/par',
      require_pushed_authorization_requests:
        !!config.value('oauth2.requirePushedAuthorizationRequests'),
      code_challenge_methods_supported: ['S256', 'plain'],
      // RFC 9470 (2026-09-13). The context classes this service's own sign-in
      // produces, ordered weakest first, so a client building a step-up request
      // out of a resource server's challenge can see which it may ask for. A
      // Discovery member RFC 8414 section 7.1.2 registered for OAuth too, and
      // in this document rather than only the OpenID one because RFC 9470 is an
      // OAuth protocol — a request need not carry `openid` to step up. The
      // three RFC 8176 method names still accepted in acr_values are not
      // listed: they are not context classes. See `step_up.ts`.
      acr_values_supported: stepUp.SUPPORTED.slice(),
      // RFC 9207. redirectBack() puts `iss` on every authorization response
      // this server sends, success and error alike, so this is simply true —
      // and it was true and unadvertised, which is the half that buys a client
      // nothing: a client only knows it may REQUIRE the parameter (and so
      // refuse a mix-up attacker's response that lacks it) if the metadata says
      // the server sends it.
      authorization_response_iss_parameter_supported: true,
      // RFC 9449 section 5.1. Its presence is how a wallet learns DPoP is on
      // offer at all — there is no other signal, so an authorization server
      // that supports DPoP and does not advertise it will simply never be asked
      // for it.
      dpop_signing_alg_values_supported: dpop.SIGNING_ALGS,
      // RFC 8705 section 3.3. Advertised only when this deployment can actually
      // do it — the token endpoint has to be on a TLS listener that ASKS for a
      // client certificate, which is `global.https` — because a client reads
      // this as a promise and there is nothing to bind to on a plain HTTP
      // listener. The alternative, advertising it always, is the shape of drift
      // the two discovery documents are built from one object to avoid.
      tls_client_certificate_bound_access_tokens: mtls.available()
      // signed_metadata is added below — it is a JWT OF this object, so it
      // cannot be one of the claims it signs.
    };
    // RFC 7591 REGISTRATION IS NOT ADVERTISED WHERE IT IS CLOSED (2026-09-12).
    // A product realm refuses POST /oauth2/register unless
    // `oauth2.openRegistration` is on — see registrationOpen() — and a metadata
    // member is a promise a client acts on: publishing an endpoint that refuses
    // every caller would send every client that reads this document into a
    // refusal it could have been spared. Development is unchanged. A TRUSTED
    // SOFTWARE STATEMENT IS A SECOND DOOR (2026-09-13): where it opens the
    // endpoint, the endpoint is advertised — see registrationReachable().
    if (!self.registrationReachable()) {
      delete metadata.registration_endpoint;
    }
    // RFC 9126: NO PAR ENDPOINT IS ADVERTISED WHERE IT IS SWITCHED OFF, for the
    // registration endpoint's reason one block up. Section 5 makes the member's
    // presence the whole of how a client learns it may push.
    if (!config.value('oauth2.pushedAuthorizationRequests')) {
      delete metadata.pushed_authorization_request_endpoint;
    }
    // RFC 8705 SECTION 5 (#139, FAPI 1.0 Advanced item 6): where the main port
    // asks for a client certificate, every endpoint that reads one is its own
    // mTLS alias — this service has no second listener for them, and
    // publishing the same URLs is what the section permits. The OpenID
    // Provider Configuration adds UserInfo's.
    if (mtls.available()) {
      const aliases: Json = {};
      ['token_endpoint', 'revocation_endpoint', 'introspection_endpoint',
       'pushed_authorization_request_endpoint'].forEach(function (name) {
        if ((metadata as Json)[name]) {
          aliases[name] = (metadata as Json)[name];
        }
      });
      (metadata as Json).mtls_endpoint_aliases = aliases;
    }
    // RFC 9700 mode, when it is on, narrows three of the members above:
    // response_types_supported loses everything that would issue an access
    // token from the authorization endpoint, grant_types_supported loses
    // `implicit` and `password`, and code_challenge_methods_supported becomes
    // S256 alone (and OAuth 2.1 mode drops `saml2_bearer` from the client
    // authentication methods). It happens HERE rather than in each document
    // because the OIDC document is this one extended, and a mode that narrowed
    // one of the two would produce exactly the drift building them from one
    // object exists to prevent — a client configured from openid-configuration
    // being refused for a value oauth-authorization-server never advertised.
    bcp.applyToMetadata(metadata);
    // FAPI (#138): S256 alone, and the confidential client authentication
    // methods the profile allows.
    fapi.applyToMetadata(metadata);
    // The PROFILE, last, so it can override anything above it — including what
    // RFC 9700 mode just narrowed. That order is deliberate and it is the one a
    // reader of the form expects: a profile is somebody saying "publish this",
    // and a mode quietly winning would make the control appear not to work. It
    // is also the interesting case — a profile that re-advertises the implicit
    // grant the mode refuses is a document that lies about this server, which
    // is what the drift report on /admin/authorization-servers exists to show.
    if (raw) {
      log.debug("Leaving OAuth2Server.asMetadata(). The defaults, without " +
                "a profile.");
      return metadata;
    }
    authorizationServers.apply(metadata, self.profileOf(req));
    log.debug("Leaving OAuth2Server.asMetadata().");
    return metadata;
  }

  // Which authorization server profile this request selected. The two discovery
  // shapes carry it in different places — RFC 8414 section 3.1 INSERTS the path
  // after the well-known segment and OpenID Connect Discovery section 4 APPENDS
  // the well-known segment to it — so the routes hand it in rather than this
  // function guessing from the URL.
  // GET /oauth2/fapi and /{id}/oauth2/fapi (#138): fapi.js's report, and
  // which authorization server it is about.
  fapiReport(req: Req, res: Res): void {
    const { log, fapi } = this.deps;
    log.debug("Entering OAuth2Server.fapiReport().");
    const view = Object.assign({ authorization_server: this.profileOf(req),
                                 server_setting: this.fapiOf(
                                   this.profileOf(req)) || null,
                                 // What this server signs its access tokens
                                 // with now (#139).
                                 access_token_signing_alg:
                                   this.accessTokenAlg(req) },
                               fapi.state());
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(view, null, 2));
    log.debug("Leaving OAuth2Server.fapiReport(). " +
              (view.profile || 'no profile'));
  }

  // A named authorization server's own FAPI profile (#138): the `fapi` member
  // of its profile, which is published in no document. '' when it has none,
  // and `none` when it opts out of its realm's.
  // -------------------------------------------------------------------------
  // THE ALGORITHM THIS SERVER SIGNS ITS ACCESS AND REFRESH TOKENS WITH (#139).
  // A named authorization server's own `access_token_signing_alg` first, then
  // `oauth2.accessTokenSigningAlg`, then the FAPI profile's default (PS256
  // under Advanced), then RS256 — what it always was. Under FAPI 1.0 Advanced
  // an algorithm section 8.6 does not allow is replaced by the profile's
  // default rather than used: this is the server's own signature, and nothing
  // a client did asked for it.
  // -------------------------------------------------------------------------
  accessTokenAlg(req?: Req): string {
    const { log, config, fapi, authorizationServers } = this.deps;
    log.debug("Entering OAuth2Server.accessTokenAlg().");
    const profileId = req ? this.profileOf(req) : '';
    const own = profileId && profileId !== authorizationServers.DEFAULT_ID
      ? authorizationServers.capabilitiesOf(profileId, {}, 'server') : null;
    const named = String((own && own.access_token_signing_alg) || '');
    const set = String(config.value('oauth2.accessTokenSigningAlg') ||
                       'default');
    let alg = named || (set !== 'default' ? set : '') ||
              fapi.defaultSigningAlg() || 'RS256';
    if (!fapi.signingAlgAllowed(alg)) {
      log.debug("OAuth2Server.accessTokenAlg(): " + alg + " is not allowed " +
                "under the FAPI profile; " + fapi.defaultSigningAlg() +
                " instead.");
      alg = fapi.defaultSigningAlg();
    }
    log.debug("Leaving OAuth2Server.accessTokenAlg(). " + alg);
    return alg;
  }

  // The claims of a compact JWS, UNVERIFIED — read only to REFUSE by (a FAPI
  // 2.0 timestamp), never to grant anything. {} when unreadable.
  unverifiedClaimsOf(jws: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.unverifiedClaimsOf().");
    let claims: Json = {};
    try {
      claims = JSON.parse(Buffer.from(String(jws).split('.')[1] || '',
                                      'base64url').toString('utf8')) || {};
    } catch (e) {
      log.debug("Caught in OAuth2Server.unverifiedClaimsOf(): " +
                ((e && e.message) || e));
      // Unreadable: the verifier refuses it for that.
      claims = {};
    }
    log.debug("Leaving OAuth2Server.unverifiedClaimsOf().");
    return claims;
  }

  // The `alg` of a compact JWS's protected header, or '' when it cannot be
  // read. Read BEFORE verification, to refuse by algorithm.
  headerAlgOf(jws: Json): string {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.headerAlgOf().");
    let alg = '';
    try {
      alg = String(JSON.parse(Buffer.from(String(jws).split('.')[0],
                                          'base64url').toString('utf8'))
        .alg || '');
    } catch (e) {
      log.debug("Caught in OAuth2Server.headerAlgOf(): " +
                ((e && e.message) || e));
      // Unreadable: no algorithm, which no profile allows.
      alg = '';
    }
    log.debug("Leaving OAuth2Server.headerAlgOf(). " + alg);
    return alg;
  }

  fapiOf(profileId: string): string {
    const { log, authorizationServers } = this.deps;
    log.debug("Entering OAuth2Server.fapiOf().");
    const own = authorizationServers.capabilitiesOf(profileId, {}, 'server');
    log.debug("Leaving OAuth2Server.fapiOf().");
    return String((own && own.fapi) || '');
  }

  private profileOf(req: Req): string {
    const { log, authorizationServers } = this.deps;
    log.debug("Entering OAuth2Server.profileOf().");
    log.debug("Leaving OAuth2Server.profileOf().");
    return (req && req.__asProfile) || authorizationServers.DEFAULT_ID;
  }

  // -------------------------------------------------------------------------
  // EVERY OAUTH ENDPOINT EXISTS TWICE: once unprefixed, which is the `default`
  // authorization server, and once under `/{id}/…`, which is whichever one
  // the path names. The second form is what a named authorization server's
  // own metadata advertises, so a client that read that document is already
  // using it.
  //
  // The name is CREATED on first sight rather than 404'd — see `ensure()` —
  // so an arbitrary path works immediately, with the default capabilities,
  // and can then be configured. `seen` is counted here because this is the
  // one place every request for a named authorization server passes. (The
  // path parameter's schema is `AS_PROFILE_PARAMS`, at module level.)
  // -------------------------------------------------------------------------
  private forProfile(handler: (req: Req, res: Res) => unknown):
      (req: Req, res: Res) => unknown {
    const { log, authorizationServers, validation,
            errorCodes, fapi } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.forProfile().");
    log.debug("Leaving OAuth2Server.forProfile().");
    return function (req, res) {
      // A PATH SEGMENT THAT BECOMES A STORE KEY, and `ensure()` CREATES the
      // authorization server named here on first sight — so an unchecked value
      // is a registry anybody can put anything into. `vt.identifier` bounds it
      // and refuses whitespace and control characters; what it deliberately
      // does NOT do is refuse an unknown name, because creating one on sight is
      // the documented behaviour of this endpoint.
      const named = validation.checkParsed({ as: req.params.as }, 'params',
                                           AS_PROFILE_PARAMS);
      if (!named.ok) {
        log.debug("Leaving OAuth2Server.forProfile(). The authorization " +
                  "server name is malformed.");
        errorCodes.mark(res, 'STS-OAUTH-0186');
        return self.oauthError(res, 400, 'invalid_request', named.detail);
      }
      const id = String(named.value.as || '').trim();
      authorizationServers.ensure(id, { autoCreated: true, seen: true });
      req.__asProfile = id || authorizationServers.DEFAULT_ID;
      log.debug("This request is for the " + req.__asProfile +
                " authorization " +
          "server.");
      // ITS OWN FAPI PROFILE, ambient for the whole handler (#138), so RFC
      // 9700 mode and everything else that asks fapi.enabled() sees it.
      const ownFapi = self.fapiOf(req.__asProfile);
      if (ownFapi) {
        (req as Json).__fapiScoped = true;
        return fapi.withProfile(ownFapi, function () {
          return handler(req, res);
        });
      }
      return handler(req, res);
    };
  }

  // The path prefix this authorization server's endpoints live under: '' for
  // the default one and '/{id}' for a named one. One function, because getting
  // it wrong in one place sends a request to a different authorization server
  // with no sign that it happened.
  private asPathOf(req: Req): string {
    const { log, authorizationServers } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.asPathOf().");
    const id = self.profileOf(req);
    log.debug("Leaving OAuth2Server.asPathOf().");
    return (id && id !== authorizationServers.DEFAULT_ID) ? '/' + id : '';
  }

  // The base URL of THIS authorization server, which is what its issuer, its
  // tokens' `iss`, its `aud` and the RFC 9207 `iss` on its authorization
  // responses are all built from. A named one is its own issuer — the document
  // it publishes says so, and a token whose `iss` named the process rather than
  // the authorization server that minted it would be one a conforming client
  // refuses for the right reason.
  private asBaseOf(req: Req): string {
    const { log, baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.asBaseOf().");
    log.debug("Leaving OAuth2Server.asBaseOf().");
    return baseUrlOf(req) + self.asPathOf(req);
  }

  // The capabilities THIS request's authorization server has, which are the
  // members of the document it publishes. `asMetadata()` builds the defaults
  // and the profile is applied on top, so there is no second table to disagree
  // with what was advertised.
  private capabilitiesFor(req: Req): Json {
    const { log, authorizationServers } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.capabilitiesFor().");
    log.debug("Leaving OAuth2Server.capabilitiesFor().");
    return authorizationServers.capabilitiesOf(self.profileOf(req),
                                               self.asMetadata(req, true));
  }

  // One list-valued capability, or null where this authorization server says
  // nothing about it. Null means the check does not run: a client cannot learn
  // from an absent member that a capability is unavailable, so refusing on the
  // strength of an absence would be enforcing something never said.
  private capabilityFor(req: Req, member: string): Json {
    const { log, authorizationServers } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.capabilityFor().");
    log.debug("Leaving OAuth2Server.capabilityFor().");
    return authorizationServers.capabilityList(self.profileOf(req),
                                               self.asMetadata(req, true),
                                               member);
  }

  // The path component off whichever shape this route matched, normalised to
  // the first segment: a profile id is one segment by construction (see
  // ID_SHAPE), so `/tenant1/extra/.well-known/...` selects `tenant1` rather
  // than nothing.
  // -------------------------------------------------------------------------
  // WHICH REALM AND WHICH AUTHORIZATION SERVER A DISCOVERY PATH NAMES (#119,
  // rcbj's decision: discovery follows the realm model on the common
  // listener).
  //
  // An issuer here is `https://host[/realm/<id>][/<server>]`, and the two
  // discovery shapes put that path in two places. OIDC Discovery section 4
  // APPENDS the well-known segment, so `/realm/acme/t1/.well-known/…` arrives
  // with the realm already entered by `app.js` and only `t1` left. RFC 8414
  // section 3.1 INSERTS it, so `/.well-known/…/realm/acme/t1` arrives at the
  // host root with the whole issuer path after it — which, until #119, was
  // answered from the DEFAULT realm with an authorization server called
  // `realm` created on the spot, so a realm's RFC 8414 document named the
  // wrong issuer and the wrong keys.
  //
  // So one grammar for both: `[realm/<id>][/<server>]`, a realm that exists
  // (named only where no realm is entered yet) and at most one server segment
  // of `authorization_servers.ts`'s shape. Anything else — an unknown realm,
  // `/t1/x`, a nested `realm/` — names nothing, and the answer is Express's
  // 404 with no server created: a document claiming an issuer nothing issues
  // from is what Discovery section 4.3 tells a client to refuse.
  // -------------------------------------------------------------------------
  issuerPathTarget(raw: unknown): Json {
    const { log, realms, authorizationServers } = this.deps;
    log.debug("Entering OAuth2Server.issuerPathTarget().");
    let segments = String(raw || '').split('/').filter(Boolean);
    let realm: Json = realms.current();
    if (segments[0] === 'realm') {
      const named = segments.length >= 2 && realms.isDefault()
        ? realms.get(segments[1]) : null;
      if (!named || segments[1] === realms.DEFAULT_ID) {
        log.debug("Leaving OAuth2Server.issuerPathTarget(). No such realm.");
        return null;
      }
      realm = named;
      segments = segments.slice(2);
    }
    if (segments.length > 1 || (segments.length === 1 &&
        !authorizationServers.ID_SHAPE.test(segments[0]))) {
      log.debug("Leaving OAuth2Server.issuerPathTarget(). Not an issuer " +
                "path.");
      return null;
    }
    log.debug("Leaving OAuth2Server.issuerPathTarget().");
    return { realm: realm, server: segments[0] || '' };
  }

  // Answers a discovery request for the issuer path `raw` with `send`, inside
  // the realm the path names — or passes it on to Express's 404.
  private discoveryForPath(req: Req, res: Res, next: Json, raw: unknown,
                           send: (req: Req, res: Res) => void): void {
    const { log, realms, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.discoveryForPath().");
    const target = self.issuerPathTarget(raw);
    if (!target) {
      errorCodes.mark(res, 'STS-OAUTH-0594');
      log.debug("Leaving OAuth2Server.discoveryForPath(). Names nothing.");
      next();
      return;
    }
    realms.run(target.realm, function () {
      req.__asProfile = self.profileFromPath(target.server);
      send(req, res);
    });
    log.debug("Leaving OAuth2Server.discoveryForPath().");
  }

  // -------------------------------------------------------------------------
  // WEBFINGER — OPENID CONNECT DISCOVERY SECTION 2 AND RFC 7033 (#119).
  //
  // At the host root, as RFC 7033 section 4 requires, and answering for every
  // realm, because each realm has a DNS domain of its own and a WebFinger
  // resource names a domain. rcbj's decisions:
  //
  //   * `acct:alice@acme.example`, a bare `alice@acme.example`, and a host
  //     (`acme.example`, `acme.example:443`) resolve BY DOMAIN to the realm
  //     whose domain it is — the default realm's is `global.domain` — and
  //     answer that realm's issuer. **The person is never looked up**, so the
  //     endpoint cannot enumerate accounts: every name at a known domain gets
  //     the same answer, and an unknown domain gets 404.
  //   * An `https:` URL on THIS service resolves by its PATH, the realm model
  //     on the common listener: `https://host/realm/acme` is realm acme's
  //     issuer, `https://host/` the default realm's. An `https:` URL whose host
  //     is a realm's domain resolves by that domain.
  //
  // RFC 7033 section 5 makes CORS a MUST and recommends `*`; the answer is a
  // public issuer URL with no credential behind it, so this is the one place
  // `common/cors.js`'s allowlist is overruled, on purpose.
  // -------------------------------------------------------------------------
  webfingerTarget(req: Req, resource: string): Json {
    const { log, realms, baseUrlOf } = this.deps;
    log.debug("Entering OAuth2Server.webfingerTarget().");
    const text = String(resource || '').trim();
    let host = '';
    let path = '';
    let isUrl = false;
    if (/^acct:/i.test(text) || /^[^:/]+@[^@/]+$/.test(text)) {
      host = text.replace(/^acct:/i, '').split('@').pop() || '';
    } else if (/^https?:\/\//i.test(text)) {
      try {
        const url = new URL(text);
        host = url.host;
        path = url.pathname;
        isUrl = true;
      } catch (e) {
        log.debug("Caught in OAuth2Server.webfingerTarget(): " +
                  ((e && e.message) || e));
        // Not a URL: nothing it names.
        host = '';
      }
    } else if (/^[A-Za-z0-9.-]+(:\d+)?$/.test(text)) {
      host = text;
    }
    if (!host) {
      log.debug("Leaving OAuth2Server.webfingerTarget(). Unreadable.");
      return { malformed: true };
    }
    const bare = host.toLowerCase().replace(/:\d+$/, '');
    const byDomain = realms.list().filter(function (one: Json) {
      return String(realms.domainOf(one) || '').toLowerCase() === bare;
    })[0];
    if (byDomain) {
      log.debug("Leaving OAuth2Server.webfingerTarget(). By domain.");
      return { realm: byDomain };
    }
    let ownHost = '';
    try {
      ownHost = new URL(baseUrlOf(req)).host.toLowerCase();
    } catch (e) {
      log.debug("Caught in OAuth2Server.webfingerTarget(): " +
                ((e && e.message) || e));
      // No base to compare with: only a domain can match.
      ownHost = '';
    }
    if (isUrl && host.toLowerCase() === ownHost) {
      const match = /^\/realm\/([^/]+)/.exec(path);
      const realm = match ? realms.get(decodeURIComponent(match[1]))
                          : realms.get(realms.DEFAULT_ID);
      log.debug("Leaving OAuth2Server.webfingerTarget(). By path.");
      return realm ? { realm: realm } : {};
    }
    log.debug("Leaving OAuth2Server.webfingerTarget(). Unknown.");
    return {};
  }

  private webfingerEndpoint(req: Req, res: Res): void {
    const { log, realms, baseUrlOf, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering the WebFinger endpoint.");
    // RFC 7033 section 5.
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'no-store');
    const query = req.query || {};
    const resource = query.resource;
    if (typeof resource !== 'string' || !resource) {
      errorCodes.mark(res, 'STS-OAUTH-0592');
      log.debug("Leaving the WebFinger endpoint. No single resource.");
      res.status(400).type('text/plain')
        .send('RFC 7033 section 4.2: the query must carry the resource ' +
              'parameter exactly once.');
      return;
    }
    const target = self.webfingerTarget(req, resource);
    if (target.malformed) {
      errorCodes.mark(res, 'STS-OAUTH-0592');
      log.debug("Leaving the WebFinger endpoint. Malformed.");
      res.status(400).type('text/plain')
        .send('The resource is not an acct: URI, an e-mail address, an ' +
              'https URL or a host (OpenID Connect Discovery section 2.1).');
      return;
    }
    if (!target.realm) {
      errorCodes.mark(res, 'STS-OAUTH-0593');
      log.debug("Leaving the WebFinger endpoint. Unknown.");
      res.status(404).type('text/plain')
        .send('This service holds no information about that resource ' +
              '(RFC 7033 section 4.2).');
      return;
    }
    const rels = ([] as string[]).concat(query.rel === undefined ? []
                                                               : query.rel)
      .map(String);
    const issuer = realms.run(target.realm, function () {
      return self.issuerOf(baseUrlOf(req));
    });
    const links = (!rels.length || rels.indexOf(WEBFINGER_ISSUER_REL) >= 0)
      ? [{ rel: WEBFINGER_ISSUER_REL, href: issuer }] : [];
    res.status(200).type('application/jrd+json')
      .send(JSON.stringify({ subject: resource, links: links }, null, 2));
    log.debug("Leaving the WebFinger endpoint. " + issuer);
  }

  private profileFromPath(raw: unknown): string {
    const { log, authorizationServers } = this.deps;
    log.debug("Entering OAuth2Server.profileFromPath().");
    const path = String(raw || '').replace(/^\/+|\/+$/g, '');
    const id = path ? path.split('/')[0] : authorizationServers.DEFAULT_ID;
    // FETCHING THE METADATA IS ACCESSING THE AUTHORIZATION SERVER, so a name
    // that arrives here is created with the defaults exactly as one that
    // arrives at an endpoint is. It is the commonest way a name appears — a
    // client is pointed at an issuer and reads its document first — and a name
    // that could be read from and not seen on the console would be the one
    // somebody is actually using.
    if (id !== authorizationServers.DEFAULT_ID) {
      authorizationServers.ensure(id, { autoCreated: true, seen: true });
    }
    log.debug("Leaving OAuth2Server.profileFromPath().");
    return id;
  }

  private signedMetadataTtlMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering OAuth2Server.signedMetadataTtlMs().");
    const seconds = Number(config.value('oauth2.signedMetadataCacheS'));
    log.debug("Leaving OAuth2Server.signedMetadataTtlMs().");
    return isFinite(seconds) && seconds >= 0 ? Math.floor(seconds) * 1000 :
           SIGNED_METADATA_TTL_MS;
  }

  private maxSignedMetadata(): number {
    const { log, config } = this.deps;
    log.debug("Entering OAuth2Server.maxSignedMetadata().");
    const entries = Number(config.value('oauth2.maxSignedMetadataEntries'));
    log.debug("Leaving OAuth2Server.maxSignedMetadata().");
    return isFinite(entries) && entries > 0 ? Math.floor(entries) :
           MAX_SIGNED_METADATA;
  }

  // ---------------------------------------------------------------------------
  // SIGN A PUBLISHED DOCUMENT WITH THE CONFIGURED ALGORITHM (2026-09-12).
  //
  // It was RS256 unconditionally. `oauth2.signedMetadataAlgorithm` offers every
  // algorithm this realm holds a SYNCHRONOUS key for — the RSA key and the
  // curve keys — and deliberately none of the post-quantum ones, because
  // discovery is signed on the request thread. RS256 keeps the exact call that
  // was here, so a service with the setting untouched signs byte-for-byte the
  // way it did; any other algorithm takes its key from
  // `helpers.signingKeyFor()`, which is the one answer to "which key signs
  // which algorithm", and puts `iss`, `iat` and `exp` on the claims itself
  // rather than through jsonwebtoken's options, which the two algorithms that
  // library cannot sign (EdDSA, ES256K) do not go through.
  //
  // Exported, because the OID4VCI issuer metadata's `signed_metadata` is the
  // same RFC 8414 construct and must be signed the same way.
  //
  // `useCase` names whose `x5c` / `x5u` setting applies —
  // `oauth-signed-metadata` here, `vci-signed-metadata` for the credential
  // issuer's — because the two documents are fetched by different clients
  // (common/jose_certificate_header.js).
  // ---------------------------------------------------------------------------
  signPublishedDocument(claims: Json, issuer: string, lifetimeS: number,
                        useCase: string): string {
    const { stsCrypto, log, STS, nowSec, signingKeyFor,
            certificateHeaderFor, publishedKidFor, config } = this.deps;
    log.debug("Entering OAuth2Server.signPublishedDocument().");
    const alg = String(config.value('oauth2.signedMetadataAlgorithm') ||
                       'RS256');
    if (alg === 'RS256') {
      log.debug("Leaving OAuth2Server.signPublishedDocument(). RS256.");
      return stsCrypto.signJws(claims, STS.privateKey,
        { algorithm: 'RS256', issuer: issuer, expiresIn: lifetimeS,
          keyid: publishedKidFor(STS.kid),
          header: certificateHeaderFor(useCase, 'RS256', STS.kid) });
    }
    const signer = signingKeyFor(alg);
    const iat = nowSec();
    const payload = Object.assign({}, claims,
                                  { iss: issuer, iat: iat,
                                    exp: iat + lifetimeS });
    log.debug("Leaving OAuth2Server.signPublishedDocument(). " + alg + ".");
    return stsCrypto.signJws(payload, signer.key,
                             { algorithm: alg,
                               keyid: publishedKidFor(signer.kid),
                               header: certificateHeaderFor(useCase, alg,
                                                           signer.kid) });
  }

  // RFC 8414 section 2.1: signed_metadata is a JWT whose claims are the
  // metadata members, signed by the issuer, and carrying iss and sub. Genuinely
  // signed with the STS key, in `oauth2.signedMetadataAlgorithm`, so it can be
  // verified (the JWKS below).
  private signedMetadata(meta: Json): string | undefined {
    const { log, logArtifact, joseKid, config, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.signedMetadata().");
    const claims = Object.assign({}, meta, { sub: meta.issuer });
    // THE CERTIFICATE HEADER'S SETTING IS PART OF THE KEY TOO (2026-09-13), for
    // the algorithm's reason below: the same claims with and without an `x5c`
    // are two artefacts, and without it a changed setting would go unseen for
    // the life of the cache entry. The `x5u` origin needs no place of its own —
    // it is the request's, and so is the issuer inside the claims.
    //
    // **AND SO IS `keys.kidFormat`**, for the same reason: the header names the
    // key by one of two names, and a document signed under the internal kid
    // would otherwise go on being served for a minute after the realm switched
    // to the RFC 9278 URI (common/jose_kid.js).
    const key = String(config.value('oauth2.signedMetadataAlgorithm') ||
                       'RS256') + ' ' +
                config.value('oauth2.signedMetadataCertificateHeader') + ' ' +
                joseKid.formatFor() + ' ' +
                JSON.stringify(claims);
    const now = Date.now();
    const held = signedMetadataCache.get(key);
    if (held && held.until > now) {
      signedMetadataCount.hit();
      // Logged, because a reader of this log comparing two fetches has to be
      // able to tell a document that was signed again from one that was not —
      // they are byte-identical and nothing else would say which happened.
      log.debug("Leaving OAuth2Server.signedMetadata(). It was already " +
                "signed " + Math.round((now - held.at) / 1000) +
                "s ago and is reused.");
      return held.signed;
    }
    signedMetadataCount.miss();
    logArtifact('RFC 8414 signed_metadata', 'before signing', claims);
    try {
      const signed = self.signPublishedDocument(claims, meta.issuer, 3600,
                                           'oauth-signed-metadata');
      logArtifact('RFC 8414 signed_metadata', 'after signing', signed);
      // THE ALGORITHM IS PART OF THE KEY, because the claims alone are not what
      // was signed: a document signed RS256 a moment before the setting moved
      // to ES256 is the same claims and a different artefact.
      while (signedMetadataCache.size >= self.maxSignedMetadata()) {
        // Map iterates in insertion order, so the first key is the oldest.
        signedMetadataCache.delete(signedMetadataCache.keys().next().value);
      }
      signedMetadataCache.set(key, { signed: signed, at: now,
                                     issuer: meta.issuer,
                                     until: now + self.signedMetadataTtlMs() });
      log.debug("Leaving OAuth2Server.signedMetadata().");
      return signed;
    } catch (e) {
      log.error(errorCodes.tag('STS-OAUTH-0183') + 'signed_metadata: ' +
                e.message);
      log.debug("Leaving OAuth2Server.signedMetadata(). Nothing was signed.");
      return undefined;
    }
  }

  private sendAsMetadata(req: Req, res: Res): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.sendAsMetadata().");
    const meta = self.asMetadata(req);
    const signed = self.signedMetadata(meta);
    if (signed) meta.signed_metadata = signed;
    res.status(200)
       .type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(meta, null, 2));
    log.debug("Leaving OAuth2Server.sendAsMetadata().");
  }

  // ---------------------------------------------------------------------------
  // OpenID Connect Discovery 1.0 — GET /.well-known/openid-configuration
  //
  // The OTHER discovery document, and the one most OIDC clients look for first:
  // a relying party given nothing but an issuer identifier finds this path and
  // expects everything it needs to be in what comes back. Without it this
  // server spoke OIDC — id_token, nonce, at_hash, c_hash, three flows — and
  // could not be CONFIGURED by an OIDC client, which is a strange thing for a
  // mock whose whole job is to be pointed at by clients.
  //
  // **It is built by extending the RFC 8414 document rather than beside it.**
  // The two documents describe one server, they overlap in about twenty
  // members, and two hand-kept copies of twenty members disagree the first time
  // somebody edits one of them — a client configured from openid-configuration
  // would then behave differently from one configured from
  // oauth-authorization-server against the same endpoints, and nothing would
  // report it. So asMetadata() is the single source and this function adds only
  // what OpenID Connect Discovery defines on top of it. RFC 8414 was written
  // from this document and the member names are the same registry, so the
  // overlap is genuine and not a coincidence worth preserving by hand.
  //
  // What is DELIBERATELY ABSENT, since a discovery document is read as a
  // promise:
  //
  //   * `check_session_iframe` while `oauth2.sessionManagement` is off
  //     (#121 built it, off by default), and an empty or invented value for
  //     any of them is worse than the member's absence, which says exactly
  //     the right thing. (`acr_values_supported` left this
  //     list on 2026-09-13, when RFC 9470 made acr_values something the
  //     authorization endpoint honours; asMetadata() publishes it.)
  //   (WebFinger, section 2, is its own endpoint since #119 —
  //   webfingerEndpoint().)
  //
  // One honesty note that has no metadata member to live in, so it lives here:
  // since #118 the ID Token carries the scope claims only for
  // response_type=id_token, where no access token exists to fetch them with
  // (section 5.4); every other flow's ID Token carries the protocol claims and
  // what a claims request named, and the UserInfo endpoint answers the scopes.
  // ---------------------------------------------------------------------------
  private oidcMetadata(req: Req, issuer?: string): Json {
    const { stsCrypto, log, baseUrlOf, authorizationServers, config,
            frontchannel, backchannel } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.oidcMetadata(). issuer=" +
              (issuer || '(the request ' +
        'base URL)'));
    const base = baseUrlOf(req);
    // The same rule the RFC 8414 document follows: a named authorization
    // server's endpoints are under its own name.
    const profileId = self.profileOf(req);
    const at = base +
      (profileId && profileId !== authorizationServers.DEFAULT_ID
        ? '/' + profileId : '');
    const metadata = Object.assign(self.asMetadata(req), {
      // --- REQUIRED by OpenID Connect Discovery 1.0 section 3
      // ----------------- issuer, authorization_endpoint, token_endpoint,
      // jwks_uri and response_types_supported come from the RFC 8414 document
      // above.
      //
      // RECOMMENDED, and here: the section 5.3 UserInfo Endpoint. It is a
      // protected resource, it accepts a Bearer or a DPoP-bound token through
      // the same check as every other protected endpoint in this service, and —
      // unlike them — it verifies the token before answering, because a profile
      // is a statement about somebody this server authenticated.
      userinfo_endpoint: at + '/oauth2/userinfo',
      // Section 5.3.2's signed and ENCRYPTED responses, offered because RFC
      // 7591 registration is offered: a client that registers
      // `userinfo_signed_response_alg` gets `application/jwt` back instead of
      // JSON, and one that registers `userinfo_encrypted_response_alg` gets a
      // JWE. Register both and it is signed THEN encrypted — a Nested JWT,
      // which is the order section 5.3.2 requires and the only order that lets
      // a recipient know who signed it.
      //
      // The signing list is what this service can actually do with the key
      // material it holds: the RSA key (the RSASSA-PKCS1 and RSASSA-PSS
      // families), the curve and post-quantum keys the JWKS publishes beside
      // it, plus the HMAC family, whose key is the client_secret this service
      // already issued to that client (OIDC Core section 10.1's symmetric case
      // — it needs no published key, which is exactly why it works here). An
      // algorithm whose key a client cannot fetch would be worse than not
      // offering it, which is why the curve algorithms waited for their keys —
      // see USERINFO_EC_ALGS.
      //
      // `none` is the default and means the plain JSON of section 5.3.2.
      userinfo_signing_alg_values_supported: USERINFO_SIGNING_ALGS,
      // **THE ASYMMETRIC LIST AND NOT `JWE_ALGS`, SINCE 2026-09-10.** That
      // table grew the symmetric families for RFC 7523's encrypted assertions,
      // which are encrypted TO this service with a key both ends hold. This
      // member is the other direction — this service encrypts a UserInfo
      // response to the key the CLIENT registered — so a client could otherwise
      // register `userinfo_encrypted_response_alg="dir"` off this list and be
      // answered by a key derived from the JSON of its own public key.
      userinfo_encryption_alg_values_supported: stsCrypto.JWE_ASYMMETRIC_ALGS,
      userinfo_encryption_enc_values_supported: Object.keys(stsCrypto.JWE_ENCS),
      //
      // `public`: the `sub` userFor() gives — the person's urn:uuid:<entryUUID>
      // since 2026-09-14 — the same value for every client that asks. And
      // `pairwise` since #118 (OIDC Core section 8): a client that registers
      // subject_type=pairwise is told a sub of its own sector's, computed by
      // `pairwise_subjects.ts`.
      subject_types_supported: ['public', 'pairwise'],
      // OIDC Core section 10.2 (2026-09-17): an ID Token is encrypted — signed
      // first, then encrypted to the key in the client's inline `jwks` — when
      // the client registered `id_token_encrypted_response_alg`. The lists
      // are the UserInfo response's, for its reason; `id_token_encryption.ts`
      // argues the rest. A Logout Token follows the same registration.
      id_token_encryption_alg_values_supported: idTokenEncryption.ALGS,
      id_token_encryption_enc_values_supported: idTokenEncryption.ENCS,
      // OIDC Core section 3.1.3.7: a client may register
      // `id_token_signed_response_alg`. This service holds a key for every
      // asymmetric algorithm in the table and can use a client's own secret for
      // the symmetric ones, so the advertised list is the table.
      id_token_signing_alg_values_supported: ID_TOKEN_SIGNING_ALGS,

      // --- RECOMMENDED / OPTIONAL, and true of this server
      // -------------------- WHAT THE PROTOCOL ITSELF PUTS IN AN ID TOKEN, in
      // the order idToken() puts it there. It was the whole answer to "what
      // claims can I get from this server" until 2026-08-26 and is no longer,
      // so what it is NOT is worth stating rather than leaving a client to work
      // out: it does not list what /admin/userinfo-claims has been configured
      // to add, and it does not list the LDAP-attribute catalogue that section
      // 5.5's claims request can now reach. Neither could honestly go here —
      // this document is fetched and cached by clients, and both of those
      // change at runtime from a console page, so a list that tracked them
      // would be stale in every cache the moment somebody ticked a box. `GET
      // /admin-api/userinfo-claims` is the live answer, and it names every
      // claim a request may ask for.
      // The protocol's own claims, then every claim section 5.4's four scopes
      // name (#118) — an ID Token carries those only for response_type
      // id_token, and the UserInfo endpoint for the scopes granted.
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'auth_time',
                         'nonce', 'azp', 'jti', 'at_hash', 'c_hash',
                         's_hash', 'amr',
                         'acr', 'sid'].concat(
                           USERINFO_SCOPE_CLAIMS.profile,
                           USERINFO_SCOPE_CLAIMS.email,
                           USERINFO_SCOPE_CLAIMS.address,
                           USERINFO_SCOPE_CLAIMS.phone),
      claim_types_supported: ['normal'],
      // Three parameters this server reads and two it does not, stated as the
      // booleans the specification defines rather than left to a client to
      // discover by sending one and watching it be ignored. The authorization
      // endpoint honours prompt=none and prompt=login (and nothing else).
      //
      // `claims_parameter_supported` BECAME TRUE ON 2026-08-26 and it is the
      // one of these that changed. Section 5.5's request is parsed, refused by
      // name when it is malformed, carried on the authorization code and INSIDE
      // the access token, honoured in the ID Token and at the UserInfo
      // endpoint, and resolved against the person's entry under ou=users. What
      // it still does not do is enforce `value`/`values` or treat `essential`
      // as anything but a hint, which section 5.5.1 permits and which
      // /admin/userinfo-claims states out loud. A REQUEST OBJECT IS ACCEPTED
      // SINCE 2026-09-13 (RFC 9101): the request members —
      // request_parameter_supported, request_uri_parameter_supported,
      // require_request_uri_registration and the algorithm lists — are RFC 8414
      // members too, so they are set in asMetadata() and this document inherits
      // them rather than overwriting.
      // Every value OIDC Core section 3.1.2.1 defines (#118): `consent` was
      // honoured and not listed, and `select_account` — the sign-in screen,
      // where whoever signs in is the account selected — was ignored.
      prompt_values_supported: ['none', 'login', 'consent', 'select_account'],
      // Section 3.1.2.1's `display` (#118): the sign-in screen is one page that
      // renders at any width, so it is what `page`, `popup` and `touch` all
      // get. `wap` is not claimed.
      display_values_supported: ['page', 'popup', 'touch'],
      // Section 5.2's `claims_locales` (#118): the directory holds claim
      // values without a language tag, so every claim is answered in the one
      // language it has; the parameter is accepted and an unsupported locale
      // is, as the section says, not an error.
      claims_locales_supported: ['en-US'],
      claims_parameter_supported: true,
      // OpenID Connect RP-Initiated Logout 1.0 (#124, #115): GET and POST, an
      // id_token_hint verified, the return held to the client's registered
      // post_logout_redirect_uris in every mode (development still follows
      // one no client registered), the person asked to confirm unless the
      // hint is this session's, and `state` handed back. `logoutEndpoint()`.
      end_session_endpoint: at + '/oauth2/logout',
      // OpenID Connect Session Management 1.0 section 3.3 (#121): the OP
      // iframe, only while `oauth2.sessionManagement` is on in this realm —
      // an absent member is the honest answer while it is off. At the
      // REALM's base under a named server too: the session, and so the
      // browser state, is the realm's, one across its authorization servers.
      ...(sessionManagement.enabled()
        ? { check_session_iframe: base + sessionManagement.IFRAME_PATH }
        : {}),
      // BOTH LOGOUT SPECIFICATIONS, EACH FOLLOWING ITS OWN SETTING. The
      // members are stated whichever way they read, because "the OP did not
      // mention it" and "the OP said no" read identically to a client and only
      // one of them is a fact this server is prepared to stand behind.
      //
      // Front-Channel Logout 1.0: a relying party registers a
      // `frontchannel_logout_uri` and every sign-out here loads it in a hidden
      // iframe, with `iss` and `sid` where the RP registered
      // `frontchannel_logout_session_required`. `oauth2.frontchannelLogout`
      // turns it off, and this member follows it — a document advertising a
      // capability whose claim is switched off would be a document that lies.
      //
      // `frontchannel_logout_session_supported` is section 3's PROVIDER
      // member: "this provider can send iss and sid", which it can for every
      // token issued on a browser session. Until #122 (2026-09-22) this
      // document published `frontchannel_logout_session_required` instead —
      // the per-client REGISTRATION member, which a conforming relying party
      // does not read here, so it concluded that sessions were not supported.
      //
      // BACK-CHANNEL LOGOUT 1.0 (2026-09-17, #36; this member read `false`
      // until then): a signed Logout Token POSTed server-to-server to every
      // relying party on an ending session that registered a
      // `backchannel_logout_uri` — see `backchannel_logout.ts`.
      // `oauth2.backchannelLogout` turns both members and the fan-out off
      // together. `backchannel_logout_session_supported` is section 2.1's
      // "the OP can pass a sid", which it can whenever the feature is on:
      // every Logout Token here carries one.
      frontchannel_logout_supported: frontchannel.enabled(),
      frontchannel_logout_session_supported: frontchannel.enabled(),
      backchannel_logout_supported: backchannel.enabled(),
      backchannel_logout_session_supported: backchannel.enabled()
    });
    // The path-appended form's issuer (see below). Assigned after the merge so
    // it replaces the base URL asMetadata() derived, and assigned rather than
    // merged so the member keeps its position at the top of the document.
    //
    // A PINNED oauth2.issuer beats it, and has to: pinning is an explicit
    // instruction that this service has one identifier, and a tenant path that
    // went on answering with its own would leave two documents from one process
    // disagreeing about who issued the tokens they describe.
    if (issuer && !config.value('oauth2.issuer')) metadata.issuer = issuer;
    // FAPI, AGAIN (#139), for the profile's reason below: the merge above put
    // back the OIDC members Advanced narrows — the ID Token and UserInfo
    // algorithm lists — and UserInfo reads a client certificate too. Inside a
    // named server's own profile, as asMetadata() builds it.
    const ownFapi = self.fapiOf(self.profileOf(req));
    const reapply = function (): void {
      log.debug("Entering reapply().");
      self.deps.fapi.applyToMetadata(metadata);
      log.debug("Leaving reapply().");
    };
    if (ownFapi) {
      self.deps.fapi.withProfile(ownFapi, reapply);
    } else {
      reapply();
    }
    if (metadata.mtls_endpoint_aliases && metadata.userinfo_endpoint) {
      metadata.mtls_endpoint_aliases = Object.assign({},
        metadata.mtls_endpoint_aliases,
        { userinfo_endpoint: metadata.userinfo_endpoint });
    }
    // THE PROFILE, AGAIN, and it has to be applied twice.
    //
    // asMetadata() applied it already — and then the Object.assign above
    // overwrote every member OpenID Connect Discovery adds, which is most of
    // the ones somebody would want to override in an OIDC document:
    // userinfo_endpoint, end_session_endpoint, id_token_signing_alg_values_
    // supported. A profile that set one of those would have appeared to work in
    // the RFC 8414 document and done nothing in the OIDC one, which is the kind
    // of half-working control somebody debugs for an hour.
    //
    // Applying it in both places rather than only here is deliberate: the RFC
    // 8414 document is served by its own routes and never passes through this
    // function at all.
    authorizationServers.apply(metadata, self.profileOf(req));
    log.debug("Leaving OAuth2Server.oidcMetadata(). " +
              Object.keys(metadata).length + " " +
        "member(s).");
    return metadata;
  }

  // signed_metadata is an RFC 8414 member and OpenID Connect Discovery does not
  // define it. It is included anyway: the two documents share one member
  // registry, an OIDC client ignores members it does not know, and a signed
  // copy of THIS document — the OIDC members included — is the only way to
  // check that what arrived is what the issuer published.
  private sendOidcMetadata(req: Req, res: Res, issuer?: string): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.sendOidcMetadata().");
    const meta = self.oidcMetadata(req, issuer);
    const signed = self.signedMetadata(meta);
    if (signed) meta.signed_metadata = signed;
    res.status(200).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(meta, null, 2));
    log.debug("Leaving OAuth2Server.sendOidcMetadata().");
  }

  // The JWKS the metadata advertises, so jwks_uri actually resolves: the STS
  // RSA signing key first, then the curve and post-quantum signing keys, then
  // the request object encryption keys (the ordering rule is inside).
  //
  // ASYNCHRONOUS SINCE THE WORKER POOL EXISTED, and this endpoint is the reason
  // the pool reaches key GENERATION at all. The eleven post-quantum keys are
  // made on first use and this is the call that brings them into being — about
  // 1.9 seconds, nearly all of it one SLH-DSA-SHAKE keygen — so until they were
  // made in child processes, the first JWKS fetch on a realm stopped this whole
  // service for two seconds. It is the one request here that was slow BY DESIGN
  // and stopped everything else as a side effect.
  private jwksEndpoint(req: Req, res: Res): void {
    const { log, allSigningKeysAsync, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering the JWKS endpoint.");
    allSigningKeysAsync().then(function (signingKeys) {
      self.sendJwks(req, res, signingKeys);
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-OAUTH-0184') +
                'could not publish the JWKS: ' + e.message);
      errorCodes.mark(res, 'STS-OAUTH-0184');
      res.status(500).type('application/json')
        .send(JSON.stringify({ error: e.message }));
      log.debug("Leaving the JWKS endpoint. The keys could not be made.");
    });
    log.debug("Leaving the JWKS endpoint. Answering.");
  }

  private sendJwks(req: Req, res: Res, signingKeys: Json[]): void {
    // Not `b64u` from the deps: the body declares its own, for hex.
    const { forge, log, STS, joseKid, errorCodes,
            requestObjectKeysFor } = this.deps;
    log.debug("Entering OAuth2Server.sendJwks().");
    try {
      const pub = forge.pki.certificateFromPem(STS.certPem).publicKey;
      // The base64 of a PEM's DER, for `x5c` — which is base64 and NOT
      // base64url (RFC 7517 section 4.7 is explicit, and a base64url `x5c`
      // parses as garbage in every library that reads it).
      const forX5c = function (pem) {
        log.debug("Entering forX5c().");
        log.debug("Leaving forX5c().");
        return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      };

      const b64u = function (hex) {
        log.debug("Entering b64u().");
        log.debug("Leaving b64u().");
        return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex')
                     .toString('base64')
          .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      };
      res.status(200)
         .type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify({
        // NO `alg` MEMBER, and its absence is deliberate. RFC 7517 section 4.4
        // makes `alg` OPTIONAL and says it identifies the algorithm INTENDED
        // for use with the key — and this one key now signs the whole RSA
        // family: RS256/384/512 for id_tokens and access tokens, and any of
        // those or PS256/384/512 for a UserInfo response the client registered
        // for.
        //
        // It said `alg: 'RS256'` until 2026-08-28, and that was a promise the
        // service had stopped keeping. Web Crypto REFUSES to import a JWK whose
        // `alg` disagrees with the operation asked of it — so a PS512 UserInfo
        // response, correctly signed with this very key, could not be verified
        // by a conforming client at all. The error it produces names the JWK
        // and not the algorithm ("JWK alg does not match the requested
        // algorithm"), which reads as a broken key rather than an over-narrow
        // advertisement.
        //
        // Omitting it leaves the key usable for every algorithm it can actually
        // perform, which is what is true. Selection is by `kid` — every token
        // this service signs carries one — so nothing depended on `alg` to find
        // this key in the first place. THE RSA KEY IS FIRST AND MUST STAY
        // FIRST. Everything this service signs by default is RS256 with it, and
        // more than one test here reads `jwks.keys[0]` to verify a token — a
        // JWKS whose first entry became an EC key would fail those in a way
        // that names the signature rather than the ordering. New keys go on the
        // END.
        //
        // **AND UNDER `keys.kidFormat: jwk-thumbprint-uri` EACH SIGNING KEY IS
        // THERE TWICE (2026-09-13)**: the entries below under their internal
        // kids, unchanged and in the same order, then the same entries under
        // their RFC 9278 thumbprint URIs — which is what a token's header names
        // while the setting is on. A token signed before it was turned on still
        // finds its key. `common/jose_kid.js` argues it.
        //
        // The others exist so that ES256/384/512 and EdDSA are things a client
        // can actually VERIFY, not merely things this service can sign. A
        // signing algorithm advertised with no published key to check it
        // against is worse than one not offered at all: the client gets a
        // signature it cannot verify and reports a broken issuer.
        keys: joseKid.withThumbprintUriEntries([{
          kty: 'RSA', use: 'sig', kid: STS.kid,
          n: b64u(pub.n.toString(16)), e: b64u(pub.e.toString(16)),
          // **THE CHAIN AND NOT ONLY THE LEAF, SINCE 2026-09-11.** RFC 7517
          // section 4.7 defines `x5c` as the certificate CHAIN, leaf first —
          // and this service's signing key stopped being self-signed on that
          // date: it is issued by this realm's JOSE Issuing CA under the
          // service Root. A client given only the leaf cannot build a path to
          // the Root it was told to trust, and the failure is `unable to get
          // local issuer certificate`, which names nothing. `certChainPem` is
          // empty while a key is still self-signed, so this is byte for byte
          // what it always was on a service whose hierarchy has not been built.
          x5c: [STS.certB64].concat((STS.certChainPem || []).map(forX5c))
        // The whole key list and not STS.extraKeys: the post-quantum keys are
        // made on FIRST USE (see helpers.js), and the call above is what brings
        // them into being. That makes the first JWKS fetch on a realm slow —
        // about two seconds, nearly all of it one SLH-DSA keygen — and every
        // one after it free. Publishing them lazily one at a time would be
        // worse: a client that cached the JWKS before a key existed would be
        // missing exactly the key it later needs.
        }].concat(signingKeys.map(function (k) { return k.publicJwk; }))
        // THE STANDBY KEY GENERATIONS (2026-09-22, #42), after every current
        // key: each unit's `next` key, published AHEAD of its promotion so a
        // relying party holds it before it signs anything, and every retired
        // key still in its grace, so what it signed goes on verifying. An RSA
        // one carries its own chain, from its own generation slot.
          .concat(helpers.ownRsaCertificates('jose')
            .filter(function (one: any): boolean {
              return one.role !== 'current';
            }).map(function (one: any): Json {
              const jwk: any = crypto.createPublicKey(one.certPem)
                .export({ format: 'jwk' });
              return { kty: 'RSA', use: 'sig', kid: one.kid, n: jwk.n,
                       e: jwk.e,
                       x5c: [forX5c(one.certPem)].concat(
                         (one.chainPem || []).map(forX5c)) };
            }))
          .concat(helpers.standbyOf(STS).filter(function (one: any): boolean {
            return one.kind !== 'rsa' && one.useCase === 'jose' &&
                   (one.role === 'next' || !(Number(one.retiredUntil) > 0) ||
                    Number(one.retiredUntil) > Date.now());
          }).map(function (one: any): Json {
            return one.publicJwk;
          })))
        // THE REQUEST OBJECT ENCRYPTION KEYS (RFC 9101 section 6.1,
        // 2026-09-13), LAST — after every signing key, for the ordering rule
        // above — and marked `use: "enc"`, which is what tells a client these
        // are the keys to encrypt a request object TO rather than keys that
        // verify anything.
          .concat((function () {
            const encKeys = requestObjectKeysFor();
            return [encKeys.rsa.publicJwk, encKeys.ec.publicJwk];
          })())
      }, null, 2));
      log.debug("Leaving OAuth2Server.sendJwks().");
    } catch (e) {
      log.error(errorCodes.tag('STS-OAUTH-0184') +
                'could not publish the JWKS: ' + e.message);
      errorCodes.mark(res, 'STS-OAUTH-0184');
      res.status(500)
         .type('application/json')
         .send(JSON.stringify({ error: e.message }));
      log.debug("Leaving OAuth2Server.sendJwks(). It failed.");
    }
    log.debug("Leaving OAuth2Server.sendJwks().");
  }

  // ---------------------------------------------------------------------------
  // HOW LONG WHAT THIS ENDPOINT ISSUES IS GOOD FOR.
  //
  // These were three module-level `const`s until 2026-08-24 —
  // `ACCESS_TOKEN_TTL` at an hour, `REFRESH_TOKEN_TTL` at thirty days, and the
  // ID Token reusing the first — and they are four functions now for the reason
  // `common/CLAUDE.md` states as a rule: **a runtime setting must be READ WHERE
  // IT IS USED**. A `const` captured at require time is the one thing
  // `/admin/config` cannot change, and it fails in the direction that looks
  // like the console is broken — the page reports the new value, the next token
  // carries the old one, and nothing anywhere says which is in force.
  //
  // So each is a function called per issuance, and each is one line so that the
  // call sites read the way the constants did.
  //
  // TWO THINGS ARE WORTH KNOWING BEFORE CHANGING ANY OF THEM.
  //
  //   *  THE ACCESS TOKEN AND THE ID TOKEN NO LONGER SHARE A NUMBER. They
  //     shared `ACCESS_TOKEN_TTL` because an hour suited both, which is not the
  //     same thing as their being one setting: an ID Token is consumed once at
  //     sign-in and an access token is presented to a resource server, and the
  //     interesting test is the one where the two disagree.
  //   *  THE REFRESH DEFAULT IS TWENTY-FOUR HOURS AND WAS THIRTY DAYS. Every
  //     sentence in this repository that said "thirty-day" about a refresh
  //     token was changed with it rather than left to be discovered; `2592000`
  //     in `oauth2.refreshTokenTtlS` is exactly the old behaviour.
  //
  // The lifetime is stamped into the token as `exp` at signing time, so
  // changing a setting changes THE NEXT token and nothing already issued. That
  // is a fact about signed statements rather than a limitation of this
  // implementation, and the console says so where somebody might expect
  // otherwise.
  // ---------------------------------------------------------------------------
  // ---------------------------------------------------------------------------
  // THE THREE LIFETIMES ARE PER CLIENT SINCE 2026-08-27, AND THESE THREE
  // FUNCTIONS ARE THE ONLY PLACE THAT IS DECIDED.
  //
  // Each takes the `client_id` the token is being issued to and answers what
  // THAT client should get: `oauthAccessTokenTtlS` and its two siblings on the
  // application entry where they are set, and the service-wide setting where
  // they are not. `/admin/token-lifetimes` draws the defaults and names the
  // attribute that overrides each.
  //
  // A CALLER WITH NO CLIENT PASSES NOTHING and gets the service-wide value,
  // which is what every caller got before this existed. That is not a rare
  // path: a token minted for a direct grant or an exchange may have no
  // client_id at all, and this service issues one anyway.
  //
  // THE LOOKUP IS BY `client_id`, WHICH IS THE STRING THE REGISTRY FILES AN
  // OAUTH APPLICATION UNDER — `oauthClientId` is that attribute, and
  // `applications.get()` resolves an identifier or any of the per-family
  // identifiers to one entry. So the same entry a person edits on
  // /admin/applications is the one read here.
  private accessTokenTtl(clientId: Json): Json {
    const { log, config, applications } = this.deps;
    log.debug("Entering OAuth2Server.accessTokenTtl().");
    log.debug("Leaving OAuth2Server.accessTokenTtl().");
    return applications.settingFor(clientId || '', 'oauth2.accessTokenTtlS',
                                   config);
  }

  private idTokenTtl(clientId: Json): Json {
    const { log, config, applications } = this.deps;
    log.debug("Entering OAuth2Server.idTokenTtl().");
    log.debug("Leaving OAuth2Server.idTokenTtl().");
    return applications.settingFor(clientId || '', 'oauth2.idTokenTtlS',
                                   config);
  }

  private refreshTokenTtl(clientId: Json): Json {
    const { log, config, applications } = this.deps;
    log.debug("Entering OAuth2Server.refreshTokenTtl().");
    log.debug("Leaving OAuth2Server.refreshTokenTtl().");
    return applications.settingFor(clientId || '', 'oauth2.refreshTokenTtlS',
                                   config);
  }

  // The allowance applied to `exp` and `nbf` EVERY time this file reads back a
  // token it signed — not to what it puts in one. It is passed to jwt.verify()
  // as `clockTolerance`, which is the library's own name for the same idea, and
  // it is deliberately a different setting from `oauth2.clientAssertionSkewS`
  // (that one is about a CLIENT'S clock; see the row in config.js).
  //
  // EVERY jwt.verify() OF ONE OF OUR OWN TOKENS TAKES IT — and until 2026-08-27
  // that promise was scoped to "IN THIS FILE", which was the only part of it
  // that was true. Four verifications elsewhere (`vc_issuer.js` twice,
  // `vc_verifier.js` twice) omitted it entirely: a second, stricter opinion
  // about what "expired" means, reachable only through whichever endpoint had
  // forgotten, whose symptom is a token that introspects active and is refused
  // at a credential endpoint thirty seconds before it should be — a client bug
  // from every side.
  //
  // It is not scoped to this file any more. `stsCrypto.verifyJws()` APPLIES
  // THIS VALUE BY DEFAULT, so a caller now has to opt OUT deliberately rather
  // than remember to opt in, and the five call sites below read it through that
  // default rather than passing it. This function stays because the value is
  // still named here in prose and because `oauth2.clientAssertionSkewS` is a
  // DIFFERENT setting about a CLIENT'S clock; keeping both names visible is
  // what stops somebody collapsing them.
  private tokenClockSkew(): Json {
    const { log, config } = this.deps;
    log.debug("Entering OAuth2Server.tokenClockSkew().");
    log.debug("Leaving OAuth2Server.tokenClockSkew().");
    return config.value('oauth2.clockSkewS');
  }

  authCodeTtlMs(): Json {
    const { log, config, oauth21 } = this.deps;
    log.debug("Entering OAuth2Server.authCodeTtlMs().");
    const seconds = Number(config.value('oauth2.authorizationCodeTtlS'));
    log.debug("Leaving OAuth2Server.authCodeTtlMs().");
    // OAuth 2.1 mode caps it at ten minutes (section 4.1.2); a no-op otherwise.
    // And FAPI 2.0 at sixty seconds (section 5.3.2.1 item 11, #140).
    return this.deps.fapi.codeLifetimeMs(oauth21.codeTtlMs(
      isFinite(seconds) && seconds > 0 ? Math.floor(seconds) * 1000
                                       : AUTH_CODE_TTL_MS));
  }

  // The browser session, the login screen it comes out of and the WebAuthn step
  // beside it all used to be declared here. They are `authn.js` now — see its
  // header for why, and note that this module reads the session and never
  // writes one: authenticating is somebody else's endpoint.

  // Which tokens are no longer valid. This was a `new Set()` here, and it moved
  // into admin_stats.js when the admin console gained a page that revokes
  // tokens too: there must be exactly ONE set, because two would each look
  // correct alone and never see each other — a token revoked from the console
  // would keep introspecting as active, and there would be no error anywhere to
  // point at. It is the same reasoning that keeps WS-Federation out of a
  // session store of its own.
  //
  // Read wherever a token of this service is judged (UserInfo and the other
  // resource servers, introspection, the refresh grant, the console) and
  // written wherever one is retired (RFC 7009's /oauth2/revoke below, the RFC
  // 9700 rotation and replay refusals, sign-out, and the console).

  // The RFC 7591 registrations used to be a Map here. They are entries under
  // `ou=applications` in the embedded directory now, reached through
  // `applications.js` — one store, and the one the RFC 9700 checks read, so an
  // operator who edits a client's redirect URIs with ldapmodify changes what
  // this endpoint accepts. `registrationOf(id)` is what
  // `registeredClients.get(id)` was; there is no `.set()` any more, because
  // writing goes through `register()`, `updateRegistration()` and
  // `forgetRegistration()`, which know how a registration becomes attributes.

  // Client credentials from either client_secret_basic or client_secret_post.
  //
  // The secret is CARRIED now and still not checked by default — what matters
  // here is which client is being claimed. The exceptions are RFC 9700 and
  // OAuth 2.1 mode, where a client that declared a confidential method must
  // present its credential (`bcp.checkClientAuthentication()`, `oauth21.js`),
  // product mode — which implies RFC 9700 mode and holds the same
  // confidential clients to the same rule
  // (`mode.requiresConfidentialClientAuthentication()`) — and a caller of
  // `/oauth2/introspect` that RFC 9701 requires to authenticate; this function
  // is where the value those checks compare comes from. It is read for every
  // request either way, because a function that returned the secret only in one
  // mode would be two functions with one name.
  private clientFrom(req: Req, body: Json): Json {
    const { log, STS, clientAuth, samlAssertionGrant, errorCodes } = this.deps;
    log.debug("Entering OAuth2Server.clientFrom().");
    const auth = req.headers['authorization'] || '';
    if (/^Basic\s+/i.test(auth)) {
      try {
        const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64')
                              .toString('utf8');
        const i = decoded.indexOf(':');
        // RFC 6749 section 2.3.1: both halves are form-urlencoded before the
        // pair is base64'd, so both are decoded — separately, and each falling
        // back to the raw text if it will not decode. That is not defensiveness
        // for its own sake: decodeURIComponent THROWS on a lone `%`, and a
        // secret containing one would otherwise take the whole credential down
        // the catch below and lose the CLIENT_ID with it, turning "my secret
        // has an odd character in it" into "this server does not know which
        // client I am".
        const decodePart = function (text) {
          log.debug("Entering decodePart().");
          try {
            log.debug("Leaving decodePart().");
            return decodeURIComponent(text);
          } catch (e) {
            log.debug("Caught in decodePart(): " + ((e && e.message) || e));
            log.debug("Leaving decodePart().");
            // Not percent-encoded, or not validly so. The raw text is what was
            // sent and is the best available reading of it.
            return text;
          }
        };
        const client = {
          client_id: decodePart(i < 0 ? decoded : decoded.slice(0, i)),
          client_secret: i < 0 ? '' : decodePart(decoded.slice(i + 1)),
          method: 'client_secret_basic'
        };
        log.debug("Leaving OAuth2Server.clientFrom(). client_secret_basic " +
                  "named " + client.client_id + ".");
        return client;
      } catch (e) {
        log.error(errorCodes.tag('STS-OAUTH-0185') + 'could not read the ' +
                  'Basic credential: ' + e.message);
        // Fall through to the form parameter.
      }
    }
    // A CLIENT ASSERTION NAMES THE CLIENT, and may be the only thing that does.
    // OpenID Connect Core section 9 lets a private_key_jwt request omit
    // client_id entirely, because the assertion's `sub` says which client this
    // is — so the name is read from there when there is nothing else. It is
    // read UNVERIFIED, and that is safe for exactly one purpose: choosing which
    // registered client to check the assertion AGAINST. The assertion is then
    // verified against that client's keys, and `verifyAssertion()` requires
    // `iss` and `sub` to be the same name it was given — so a forged `sub`
    // selects a client whose key will not verify the signature. Believing
    // anything else from an unverified assertion would be reading a name an
    // attacker wrote.
    let assertedClientId = '';
    if (body.client_assertion && !body.client_id) {
      // WHICH DOCUMENT IT IS decides how the name is read, and the
      // `client_assertion_type` is what says so — read here rather than guessed
      // from the shape, because a base64url SAML assertion and a JWT are both
      // "a long opaque string" and guessing between them is the kind of
      // sniffing that goes wrong exactly once and silently.
      const type = String(body.client_assertion_type || '');
      if (type === clientAuth.SAML_ASSERTION_TYPE) {
        // RFC 7522 section 3 item 3B: for client authentication the <Subject>
        // MUST be the client_id. Read UNVERIFIED and for the same single
        // purpose the JWT branch below reads `sub` for — choosing which
        // registered client to check the assertion AGAINST. The assertion is
        // then verified against THAT client's registered certificate, and
        // `saml_assertion_grant.js` requires the Subject to be the name it was
        // given, so a forged Subject selects a client whose certificate will
        // not verify the signature.
        const parsed = samlAssertionGrant.read(
          (samlAssertionGrant.decode(body.client_assertion) || {}).xml || '');
        assertedClientId = (parsed && parsed.ok) ?
          String(parsed.subject || '') : '';
        if (!assertedClientId) {
          log.debug("The SAML client_assertion could not be read for its " +
                    "subject.");
        }
      } else {
        try {
          const part = String(body.client_assertion).split('.')[1];
          const claims = JSON.parse(Buffer.from(part, 'base64url')
                                          .toString('utf8'));
          assertedClientId = String((claims && claims.sub) || '');
        } catch (e) {
          // Not a readable JWT. The assertion will be refused on its own merits
          // a moment later, with a message about the assertion rather than
          // about a missing client_id.
          log.debug("The client_assertion could not be read for its subject: " +
                    e.message);
        }
      }
    }
    log.debug("Leaving OAuth2Server.clientFrom(). client_id from the body: " +
              (body.client_id || assertedClientId || '(none)'));
    return { client_id: body.client_id || assertedClientId,
             client_secret: body.client_secret || '',
             assertion: body.client_assertion || '',
             assertionType: body.client_assertion_type || '',
             method: body.client_secret ? 'client_secret_post'
                                        : (body.client_assertion ? 'assertion' :
                                           'none') };
  }

  // What a custom claim's ${placeholders} may refer to. Built from the payload
  // that is about to be signed rather than from the request, so a claim reading
  // "${sub}" says what the token itself says — including under token exchange,
  // where the subject is not the person who signed in.
  //
  // Refresh tokens get no custom claims and that is deliberate: a refresh token
  // is presented back to this server and to nothing else, so a claim in one
  // reaches no relying party and would only make the two halves of a grant
  // disagree.
  private customClaimContext(base: Json, payload: Json, user: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.customClaimContext().");
    log.debug("Leaving OAuth2Server.customClaimContext().");
    return {
      username: (user && user.username) || payload.username || '',
      sub: payload.sub || '',
      email: (user && user.email) || '',
      name: (user && user.name) || '',
      given_name: (user && user.given_name) || '',
      family_name: (user && user.family_name) || '',
      client_id: payload.client_id || payload.azp || '',
      audience: Array.isArray(payload.aud) ? payload.aud.join(' ') :
                (payload.aud || base || '')
    };
  }

  // What the token registry is told that the token itself does not say: which
  // browser sign-on session this issuance ran on, and which grant produced it.
  // Neither is a claim — see the note on signJwt() — and both are what let the
  // admin console's user drill-down put a token under the session it belongs
  // to. A call site that leaves `session_id` out is stating that there was no
  // session, which is true of every direct grant, and the console prints that
  // rather than "unknown".
  private issuanceContext(opts: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.issuanceContext().");
    log.debug("Leaving OAuth2Server.issuanceContext().");
    return { sessionId: (opts && opts.session_id) || '',
             // Carried into the registry beside the session id so that a
             // REFRESH of this token can be judged on what was true when the
             // person signed in. See admin_stats.js's `sessionAuthenticated`.
             sessionAuthenticated:
               (opts && opts.sessionAuthenticated) !== false,
             // WHICH RESPONSE THIS TOKEN WENT BACK IN (2026-09-05), and it is
             // the third thing here that no token carries as a claim. **OAuth
             // 2.0 and OIDC are the only families in this service that hand
             // back several credentials at once** — an access token, an ID
             // Token and a refresh token out of one code redemption; an access
             // token and an ID Token out of one implicit response — and
             // /admin/tokens now lists what was issued TOGETHER rather than
             // three rows a reader has to reassemble by comparing timestamps.
             //
             // It is minted at the TWO CALL SITES that produce a response and
             // passed down here, rather than derived: see the note on
             // admin_stats.js's `setId` for why no heuristic over sub, client
             // and instant can tell two simultaneous redemptions apart. A
             // caller that sets nothing — the credential issuer, the OID4VP
             // Request Object, WS-Trust's JWT — is stating that this credential
             // was issued alone, which is true of every one of them, and the
             // console draws it as a set of one.
             setId: (opts && opts.set_id) || '',
             grant: (opts && opts.grant) || '' };
  }

  accessToken(base: Json, opts: Json): Json {
    const { log, nowSec, randomId, signJwt, userFor, mtls, stats,
            jwtAccessToken } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.accessToken().");
    const iat = nowSec();
    const user = opts.user || userFor(opts.username);
    // RFC 9068 section 2.2's seven REQUIRED claims are the first seven below,
    // and `aud`'s default is the default resource indicator section 3 requires
    // — spelt by `jwt_access_token.ts`, which the resource-server check reads
    // too.
    //
    // `typ: 'Bearer'` is NOT RFC 9068's type and never was: it is this
    // service's own claim, older than the header, and SCIM, SSF, UserInfo and
    // the token registry all still read it. The JOSE header below is what the
    // profile defines, and the claim is kept beside it rather than removed from
    // under four readers.
    const payload: Json = {
      iss: self.issuerOf(base), sub: opts.sub || user.sub,
      aud: opts.audience || jwtAccessToken.defaultAudienceFor(base),
      client_id: opts.client_id, typ: 'Bearer',
      jti: randomId(16), iat: iat, nbf: iat,
      exp: iat + self.accessTokenTtl(opts.client_id),
      username: user.username
    };
    // Section 2.2.3: the scope claim describes what was granted, so a token
    // granted nothing carries no claim — not `scope: ""`, a member every reader
    // had to learn meant the same as its absence.
    if (opts.scope) {
      payload.scope = opts.scope;
    }
    // Section 2.2.2: an identity attribute goes under its REGISTERED name where
    // one exists, and `preferred_username` is OpenID Connect's for exactly what
    // `username` holds. `username` stays — the token registry, SCIM's principal
    // and the audit log read it. Not on a client_credentials token, where
    // `username` is the client_id and there is no end user to have a name.
    if (opts.grant !== 'client_credentials' && user.preferred_username) {
      payload.preferred_username = user.preferred_username;
    }
    // Section 2.2.1: WHEN the resource owner authenticated, and HOW. Only where
    // an authentication event is behind the grant — a session, carried on the
    // code, the refresh token or the implicit response — and never invented,
    // since a resource server stepping a user up (RFC 9470) reads their absence
    // as "not known".
    if (opts.auth_time) {
      payload.auth_time = opts.auth_time;
      if (opts.amr) payload.amr = opts.amr;
      if (opts.acr) payload.acr = opts.acr;
    }
    if (opts.act) payload.act = opts.act;
    // RFC 9449 section 6.1: a DPoP-bound access token names the key it is bound
    // to in the `cnf.jkt` confirmation claim (RFC 7800's `cnf`, with RFC 9449's
    // `jkt` member). The claim travels INSIDE the signed token, which is what
    // lets a resource server check the binding without asking the authorization
    // server anything — and what stops the wallet nominating its own key.
    if (opts.jkt) payload.cnf = { jkt: opts.jkt };
    // RFC 8705 section 3 — the other sender constraint. When the Token Request
    // arrived over a TLS connection carrying a client certificate, the token
    // names its thumbprint too. MERGED with the DPoP confirmation rather than
    // replacing it: a client that presented a certificate AND sent a proof
    // demonstrated both, and a token recording one of them would be discarding
    // a check somebody performed. `opts.request` is the Token Request, and it
    // is absent for every token minted without one (the authorization
    // endpoint's implicit responses), where there is no connection to read a
    // certificate off.
    if (opts.request) payload.cnf = mtls.confirmationFor(opts.request,
                                                         payload.cnf);
    // FAPI 1.0 Part 1 section 5.2.2 item 21 (#138): under ten minutes unless
    // the token is sender-constrained — which the cnf just decided.
    payload.exp = payload.iat +
      this.deps.fapi.accessTokenLifetime(payload.exp - payload.iat,
                                         !!payload.cnf);
    // OID4VCI section 6.2: when the authorization was expressed as
    // authorization_details, the token response grants credential_identifiers
    // and the Credential Request must use one of them. They ride in the access
    // token so the credential endpoint can verify one without consulting any
    // state — the token is signed, so the wallet cannot award itself an
    // identifier.
    if (opts.authorization_details) payload.authorization_details =
        opts.authorization_details;
    // OIDC Core section 5.5's claims request, as the authorization endpoint
    // understood it. It rides here for the reason authorization_details does:
    // the UserInfo endpoint sees this token and NOTHING ELSE — no code, no
    // session, no request record — so a side table keyed by jti would have to
    // be swept, would not survive a refresh, and would stop the token being the
    // record of what was authorized. The whole parsed object goes in rather
    // than only its `userinfo` member, because a token dumped into a debugger
    // should show what the client asked for rather than what this endpoint
    // kept.
    if (opts.claims) payload.claims = opts.claims;
    // Whatever the admin console was told to add — see admin_stats.js. The
    // merge is this way round, custom claims UNDER the protocol's own, so that
    // a claim the console somehow accepted which collides with one of these
    // loses. The console refuses the reserved names outright, so this is the
    // second of two defences rather than the only one; a token whose `exp` came
    // from a web form would fail to verify with nothing anywhere pointing back
    // at the form.
    // ---------------------------------------------------------------------
    // AND WHATEVER THE ASSERTION CARRIED (2026-09-10). RFC 7523 section 3 claim
    // 8 says an assertion MAY carry claims beyond the seven the profile names,
    // and the only useful thing an authorization server can do with a statement
    // a trusted party made about somebody is put it on the token it issues.
    //
    // **THREE LAYERS AND THE ORDER IS THE ARGUMENT.** The protocol's own claims
    // win over everything, as they already did — an `exp` from anywhere but
    // this function would be a token lifetime chosen by somebody else. Below
    // them the ASSERTION beats the console's configured claims, because the
    // console's are a service-wide default and an assertion is a statement
    // about THIS issuance. Below that, the console's.
    //
    // `assertion_grant.js` has already stripped the profile's own claims, so
    // nothing here can be `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`,
    // `scope`, `cnf`, `typ`, `azp` or `client_id` — the protocol layer above is
    // the second of two defences rather than the only one, which is the same
    // arrangement the console's reserved-name refusal has.
    // ---------------------------------------------------------------------
    const payloadWithCustom = Object.assign(
      stats.jwtClaims('access_token',
                      self.customClaimContext(base, payload, user)),
      opts.assertionClaims || {}, payload);
    // A token granted no scope carries no scope claim, and the merge above is
    // the one way a layer beneath the protocol's could supply one: the protocol
    // layer wins by OVERWRITING, and a claim it deliberately left out has
    // nothing to overwrite with. Both layers already refuse the name; this is
    // the third defence for the one claim that is now sometimes absent on
    // purpose.
    if (payload.scope === undefined) {
      delete payloadWithCustom.scope;
    }
    // `oauth2.accessTokenCertificateHeader` decides the `x5c` / `x5u` — see
    // common/jose_certificate_header.js. The `typ` is RFC 9068 section 2.1's,
    // and it is passed as a header member rather than set by signJwt() because
    // signJwt() also signs the refresh token, which is not an access token.
    const token = signJwt(payloadWithCustom, self.issuanceContext(opts),
                          { certificateHeader: 'access-token',
                            header: jwtAccessToken.header(),
                            algorithm: self.accessTokenAlg(opts.request) });
    log.debug("Leaving OAuth2Server.accessToken().");
    return token;
  }

  private refreshToken(base: Json, opts: Json): Json {
    const { log, nowSec, randomId, signJwt, userFor, mtls, bcp,
            refreshTokenCrypto } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.refreshToken().");
    const iat = nowSec();
    const user = opts.user || userFor(opts.username);
    // Hoisted out of the payload so the LINEAGE can be recorded below. This is
    // the single function that mints a refresh token — every grant that issues
    // one goes through tokenSet() and therefore through here — which is
    // why RFC 9700 mode's family bookkeeping needs no per-grant call site to
    // forget. The same reasoning keeps signJwt() the one place a token is
    // counted.
    const refreshJti = randomId(16);
    const payload = {
      // username travels with the refresh token, so refreshing keeps describing
      // the person who actually signed in.
      iss: self.issuerOf(base), sub: opts.sub || user.sub, aud: base,
      client_id: opts.client_id,
      scope: opts.scope ||
             '', typ: 'Refresh', jti: refreshJti, username: user.username,
      // RFC 9700 section 2.2.2: a refresh token MUST be bound to the authorized
      // scope AND RESOURCE SERVERS. The scope was here from the beginning; the
      // resources were not, and their absence was a hole rather than an
      // omission — an access token narrowed to one resource server by RFC 8707
      // could be refreshed into one carrying this service's DEFAULT audience,
      // which is wider than what was authorized. A grant cannot widen itself by
      // being renewed.
      resources: (opts.resources && opts.resources.length) ? opts.resources :
                  undefined,
      iat: iat, nbf: iat, exp: iat + self.refreshTokenTtl(opts.client_id),
      // RFC 9449 section 5: a refresh token issued to a PUBLIC client alongside
      // a DPoP-bound access token is itself bound to the same key. A wallet is
      // a public client and cannot authenticate, so without this the long-lived
      // half of the grant would stay a bearer credential and binding the
      // short-lived half would buy very little. The refresh grant enforces it,
      // which is what makes the OID4VCI section 14.5 refresh on step 4 carry a
      // proof of its own. RFC 9449 section 5's binding, and RFC 8705 section
      // 3's beside it: a refresh token is the LONG-LIVED half of the grant, so
      // leaving it a bearer credential while binding the short-lived half buys
      // very little. The certificate confirmation is added below, after the
      // payload exists, for the same reason the access token's is.
      cnf: opts.jkt ? { jkt: opts.jkt } : undefined,
      // What this grant authorized in OID4VCI terms — the Credential Dataset
      // identifiers and, where the wallet asked for one, its claims selection.
      // Carried here because the refresh grant reads it back off this token:
      // the access token it mints has to authorize the same credential, or a
      // section 14.5 refresh would be refused by the credential endpoint for
      // naming an identifier "that was not granted".
      authorization_details: opts.authorization_details || undefined,
      // OIDC Core 5.5's claims request, for the same reason the line above it
      // is here: the refresh grant reads this token back and mints an access
      // token from it, and a refreshed token that had forgotten the claims
      // request would make the UserInfo response change under a client that did
      // nothing but renew. A grant does not narrow itself by being renewed any
      // more than it widens itself.
      claims: opts.claims || undefined,
      // THE AUTHENTICATION THIS GRANT DESCENDS FROM (2026-09-12). OpenID
      // Connect Core section 12.2: an ID Token issued in a refresh response
      // keeps the `auth_time` of the ORIGINAL authentication. This token is
      // what the refresh grant reads back, so without these three the renewed
      // ID Token said `auth_time` = now and carried no `amr` or `acr` — a
      // relying party renewing a session would have been told somebody had just
      // authenticated, by no method. Absent where the grant had no person
      // behind it.
      auth_time: opts.auth_time || undefined,
      amr: opts.amr || undefined,
      acr: opts.acr || undefined,
      // THE SIGN-ON SESSION THIS GRANT CAME FROM (#118), inside the JWE where
      // no client reads it. A refresh token whose scope lacks
      // `offline_access` is an ONLINE one (OIDC Core section 11) and the
      // refresh grant refuses it once this session has ended.
      sid: opts.session_id || undefined
    };
    if (opts.request) {
      payload.cnf = mtls.confirmationFor(opts.request, payload.cnf);
    }
    // THE FAMILY THIS TOKEN BELONGS TO, IN THE TOKEN (2026-09-14, #46), and
    // inside the JWE, so no client reads it. It is what lets a node that never
    // heard of the parent mint the child into the parent's family, where
    // looking the parent up here would start a new one and split the chain.
    // See `oauth2_bcp.js` above `familyForIssuance()`. IN EVERY MODE since
    // #102 (2026-09-22), where it was only while rotation was required: RFC
    // 7009's revocation of a refresh token takes the whole grant, and a chain
    // that does not rotate is still one grant.
    const familyId = bcp.familyForIssuance(refreshJti, opts.parent_refresh_jti,
                                           opts.parent_refresh_family);
    payload[bcp.FAMILY_CLAIM] = familyId;
    // SIGNED, THEN ENCRYPTED (2026-09-12): the JWS is what `signJwt()` records
    // and what the refresh grant verifies once it has decrypted; the JWE around
    // it is what leaves this service. See `refresh_token_crypto.ts`.
    // The certificate header goes on the JWS, not on the JWE: the JWE is
    // encrypted to a key of this realm that has no certificate at all.
    const token = refreshTokenCrypto.seal(signJwt(payload,
                                                  self.issuanceContext(opts),
                                                  { certificateHeader:
                                                      'refresh-token',
                                                    algorithm:
                                                      self.accessTokenAlg(
                                                        opts.request) }));
    // RFC 9700 section 2.2.2. `parent_refresh_jti` is set only by the refresh
    // grant, so an empty one means this token is the root of its own family:
    // any grant minting its first refresh token. A no-op while rotation is not
    // required (neither compliance mode nor `oauth2.refreshTokenRotation`).
    bcp.noteRefreshIssued(refreshJti, opts.parent_refresh_jti, opts.client_id,
                          opts.parent_refresh_family);
    // WHAT THIS GRANT ISSUED (#102): this refresh token and the access token
    // `tokenSet()` minted beside it, so that RFC 7009's revocation of any
    // refresh token of the family reaches both. Kept until the later of the
    // two expires.
    bcp.noteGrantTokens(familyId, refreshJti, opts.access_jti, opts.client_id,
                        Math.max(payload.exp, Number(opts.access_exp) || 0));
    log.debug("Leaving OAuth2Server.refreshToken().");
    return token;
  }

  // OIDC Core sections 3.1.3.6 and 3.3.2.11: at_hash and c_hash are the
  // base64url of the left-most half of the hash of the ASCII of the value,
  // with the hash of the ID Token's own `alg`. It was SHA-256 for every alg
  // until #118. The table of which hash an algorithm uses — and this
  // service's choice where the specification names none — is
  // `common/crypto.js`'s `idTokenHashFor()`.
  private halfHash(value: Json, alg?: Json): Json {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering OAuth2Server.halfHash(). alg=" + (alg || 'RS256'));
    log.debug("Leaving OAuth2Server.halfHash().");
    return stsCrypto.idTokenHalfHash(String(value), String(alg || 'RS256'));
  }

  // The `sub` this client is told for a person whose public subject is
  // `localSub` — itself, or OIDC Core section 8's pairwise value. The one
  // place every reader of a CLIENT-facing subject asks: the ID Token, the
  // UserInfo response and the Logout Tokens that must name what the ID Token
  // named. `pairwise_subjects.ts` decides.
  subjectFor(clientId: Json, localSub: Json): Json {
    const { log, pairwiseSubjects } = this.deps;
    log.debug("Entering OAuth2Server.subjectFor().");
    log.debug("Leaving OAuth2Server.subjectFor().");
    return pairwiseSubjects.subjectFor(clientId, localSub);
  }

  // -------------------------------------------------------------------------
  // `offline_access`, AS OIDC CORE SECTION 11 ALLOWS IT (#118, 2026-09-22).
  //
  // "The Authorization Server MUST ignore the offline_access request unless
  // the Client is using a response_type value that would result in an
  // Authorization Code being returned", and it "MUST ensure that the prompt
  // parameter contains consent unless other conditions for processing the
  // request permitting offline access to the requested resources are in
  // place". The other condition here is the CONSENT REGISTER: a person who
  // agreed to `offline_access` for this client on the consent screen — which
  // is where prompt=consent sends them, and which the sign-in hop's return
  // trip no longer carries the prompt past — has consented to exactly this.
  // Where neither holds, the scope comes off the grant, so the refresh token
  // issued for it is ONLINE: it ends with the sign-on session (see the
  // refresh grant). It was advertised and ignored until this date.
  // -------------------------------------------------------------------------
  offlineAccessScope(scope: Json, query: Json, types: Json, user: Json): Json {
    const { log, hasScope, consent } = this.deps;
    log.debug("Entering OAuth2Server.offlineAccessScope().");
    if (!hasScope(scope, 'offline_access')) {
      log.debug("Leaving OAuth2Server.offlineAccessScope(). Not asked.");
      return scope;
    }
    const without = String(scope).split(/\s+/).filter(function (one) {
      return one && one !== 'offline_access';
    }).join(' ');
    if ((types || []).indexOf('code') < 0) {
      log.info('oauth2: offline_access was asked for by "' +
               (query.client_id || '') + '" with a response_type that ' +
               'returns no authorization code, and is ignored (OIDC Core ' +
               'section 11).');
      log.debug("Leaving OAuth2Server.offlineAccessScope(). No code.");
      return without;
    }
    const prompted = String(query.prompt || '').split(/\s+/)
      .indexOf('consent') >= 0;
    // A RECORDED consent — the person's own, or the register's global one
    // an application carries (`oauthGlobalConsent`, which is how this
    // service's own surfaces hold it) — counts whether or not
    // `oauth2.consentRequired` is on: it is a fact about the grant, and the
    // setting only decides whether a missing one is ASKED for.
    let consented = false;
    if (!prompted) {
      const asked = consent.outstanding({
        username: (user || {}).username, clientId: query.client_id,
        scope: 'offline_access', all: false });
      consented = asked.outstanding.length === 0;
    }
    if (!prompted && !consented) {
      log.info('oauth2: offline_access was asked for by "' +
               (query.client_id || '') + '" without prompt=consent and ' +
               'without a recorded consent to it, and is ignored (OIDC Core ' +
               'section 11); the refresh token issued is an online one.');
      log.debug("Leaving OAuth2Server.offlineAccessScope(). No consent.");
      return without;
    }
    log.debug("Leaving OAuth2Server.offlineAccessScope(). Granted.");
    return scope;
  }

  // -------------------------------------------------------------------------
  // SECTION 5.4's CLAIMS FOR THE SCOPES GRANTED (#118). What the person object
  // holds first, then the directory entry through the claim catalogue for the
  // rest — the same order UserInfo has always used for `profile` and `email`,
  // now for every claim of all four scopes. A claim neither holds is absent.
  // -------------------------------------------------------------------------
  scopeClaimsOf(user: Json, scope: Json): Json {
    const { log, hasScope, claimAttributes, errorCodes } = this.deps;
    log.debug("Entering OAuth2Server.scopeClaimsOf().");
    const out: Json = {};
    const wanted: string[] = [];
    Object.keys(USERINFO_SCOPE_CLAIMS).forEach(function (name) {
      if (hasScope(scope, name)) {
        USERINFO_SCOPE_CLAIMS[name].forEach(function (claim) {
          wanted.push(claim);
        });
      }
    });
    const missing: string[] = [];
    wanted.forEach(function (claim) {
      if (user && user[claim] !== undefined && user[claim] !== null &&
          user[claim] !== '') {
        out[claim] = user[claim];
      } else {
        missing.push(claim);
      }
    });
    if (missing.length && user && user.username) {
      try {
        const built = claimAttributes.requestedClaimsFor(user.username,
                                                         missing);
        missing.forEach(function (claim) {
          if (built.claims[claim] !== undefined &&
              built.claims[claim] !== '') {
            out[claim] = built.claims[claim];
          }
        });
      } catch (e) {
        // The rule personFromDirectory() follows: a directory that threw must
        // not fail an issuance, and the claims are simply absent.
        log.error(errorCodes.tag('STS-OAUTH-0181') + 'scopeClaimsOf(): the ' +
                  'directory threw while being read for ' + user.username +
                  '\'s scope claims and they are omitted: ' + e.message);
      }
    }
    log.debug("Leaving OAuth2Server.scopeClaimsOf(). " +
              Object.keys(out).length + " claim(s).");
    return out;
  }

  // ASYNCHRONOUS, AND THIS IS THE SECOND OF THE TWO SIGNING CALL SITES A CLIENT
  // CAN POINT AT A POST-QUANTUM ALGORITHM. `id_token_signed_response_alg` is
  // chosen out of `id_token_signing_alg_values_supported`, which is the WHOLE
  // shared table — all eleven post-quantum and composite entries included — and
  // one of those signatures takes seconds on the thread that owns every
  // listener this service has. See common/worker.js.
  //
  // The RS256 default below does not go near the pool and is not deferred: it
  // is microseconds, and it is the branch that records the token in the
  // console's count.
  async idToken(base: Json, opts: Json): Promise<Json> {
    const { log, nowSec, randomId, signJwt, signJwtAsAsync, userFor, stats,
            config, frontchannel, backchannel, applications,
            idTokenEncryption, mode } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.idToken().");
    const iat = nowSec();
    // `personFromDirectory()` is a no-op in development; in a realm that
    // invents no claim values it fills the profile claims from the person's own
    // entry, and `definedOnly()` then keeps an absent one ABSENT — see
    // both, beside PERSONA_CLAIMS.
    const user = self.personFromDirectory(opts.user || userFor(opts.username));
    // THE ALGORITHM FIRST (#118): at_hash and c_hash below are hashed with the
    // hash of the algorithm this token is SIGNED with (OIDC Core 3.1.3.6 and
    // 3.3.2.11), so it has to be known before they are. The refusal of an
    // unsupported one stays where it was, below.
    const registered = applications.registrationOf(opts.client_id) || {};
    // PS256 under FAPI 1.0 Advanced when the client registered none (section
    // 8.6, #139); RS256 otherwise, as Core section 3.1.3.7 says.
    const idAlg = String(registered.id_token_signed_response_alg ||
                         self.deps.fapi.defaultSigningAlg() || 'RS256');
    // -----------------------------------------------------------------------
    // WHAT THE PAYLOAD CARRIES, AND WHAT IT STOPPED CARRYING ON 2026-09-22
    // (#118).
    //
    //   * NO `typ` CLAIM. It said `typ: 'ID'`, a member no specification
    //     defines for an ID Token and one a JOSE-aware reader can confuse with
    //     the header's `typ`.
    //   * NO INVENTED `auth_time`. When the time the person authenticated is
    //     unknown the claim is ABSENT; it used to be `iat`, which asserts an
    //     authentication at the moment of issue that did not happen then.
    //   * THE PROFILE CLAIMS ONLY WHERE SECTION 5.4 PUTS THEM. Scope-requested
    //     claims are returned by the UserInfo endpoint, and in the ID Token
    //     only "when using a response_type value that results in no Access
    //     Token being issued" — `response_type=id_token`. They used to be in
    //     every ID Token whatever was granted. `opts.scopeClaims` is set by
    //     the implicit branch that issues no access token; a claim a client
    //     asked for by name through section 5.5 still arrives, below.
    // -----------------------------------------------------------------------
    const payload = self.definedOnly(Object.assign({
      iss: self.issuerOf(base),
      sub: opts.sub || self.subjectFor(opts.client_id, user.sub),
      aud: opts.client_id,
      iat: iat, nbf: iat, exp: iat +
                               self.idTokenTtl(opts.client_id),
      auth_time: opts.auth_time || undefined,
      azp: opts.client_id, jti: randomId(16)
    }, opts.scopeClaims ? self.scopeClaimsOf(user, opts.scope) : {}));
    // How the End-User authenticated, and to what level. RFC 8176 for amr;
    // `hwk` is proof of possession of a hardware key, which is what a WebAuthn
    // assertion demonstrates. A relying party that asked for a second factor
    // through acr_values checks these — so they are emitted whenever the
    // session recorded them, and their absence is then meaningful rather than
    // ambiguous.
    if (opts.amr) payload.amr = opts.amr;
    if (opts.acr) payload.acr = opts.acr;
    // The nonce, as the authorization request gave it — unless somebody has
    // asked for it to be WRONG.
    //
    // `oauth2.breakIdTokenNonce` exists for one requirement that cannot be
    // enforced from here: RFC 9700 sections 2.1.1 and 4.5.3.2 say the CLIENT
    // must validate this value, and no observation this server can make tells a
    // client that checks from one that does not. Spoiling it on purpose does: a
    // client that accepts the result is a client that is not checking. It is
    // the same device as /spnego's three knobs and the literal password
    // `invalid` — a reachable negative, off by default, and loud every single
    // time, because an ID Token that is wrong in a way nobody remembers turning
    // on would be the most expensive hour in this repository.
    //
    // DEVELOPMENT MODE ONLY (#104, `mode.spoilsOnPurpose()`): read through
    // `mode.valueInForce()`, which answers the default in a product realm
    // whatever is stored — the mode can be switched at runtime, so this read
    // is the guard and the refused write beside it is not.
    if (opts.nonce) {
      if (mode.valueInForce('oauth2.breakIdTokenNonce')) {
        payload.nonce = 'broken-' + randomId(8);
        log.warn('oauth2.breakIdTokenNonce is ON: this ID Token carries the ' +
                 'nonce "' + payload.nonce + '" where the authorization ' +
                 'request asked for "' + opts.nonce +
                 '". A client that accepts this token is NOT validating the ' +
                 'nonce, which RFC 9700 section 4.5.3.2 says it must. Turn ' +
                 'the setting off to stop spoiling them.');
      } else {
        payload.nonce = opts.nonce;
      }
    }
    // ---------------------------------------------------------------------
    // `sid` — WHICH BROWSER SESSION THIS TOKEN WAS ISSUED ON.
    //
    // OpenID Connect Front-Channel Logout 1.0 section 3. The provider sends the
    // same value to the relying party's frontchannel_logout_uri when the
    // sign-out happens, and it is how an RP holding two sessions in one browser
    // knows WHICH one ended. Without it a notification says only "somebody
    // signed out".
    //
    // Emitted only when the token was issued ON a session, which is every
    // authorization-code and hybrid response and none of the direct grants — a
    // client_credentials token has no session and a `sid` on one would name
    // nothing. `admin_stats.js` used to argue at length that no token here
    // should carry a session identifier; that argument was about inventing one
    // to make a console page easier, and the setting is what keeps it honoured
    // for anybody who wants it back.
    //
    // BACK-CHANNEL LOGOUT NEEDS IT TOO (2026-09-17, #36): a relying party
    // matches a Logout Token's `sid` against the one in the ID Token it holds,
    // so the claim is on while EITHER feature is — and only both settings off
    // restore the tokens issued before either existed.
    if (opts.session_id && (frontchannel.enabled() || backchannel.enabled())) {
      payload.sid = opts.session_id;
    }
    if (opts.access_token) {
      payload.at_hash = self.halfHash(opts.access_token, idAlg);
    }
    if (opts.code) payload.c_hash = self.halfHash(opts.code, idAlg);
    if (opts.state !== undefined && opts.state !== null &&
        String(opts.state) !== '') {
      payload.s_hash = self.halfHash(String(opts.state), idAlg);
    }
    // The ID Token's own custom claim set, separate from the access token's:
    // the two go to different readers (a client reads the ID Token, a resource
    // server reads the access token) and configuring them together would mean
    // never being able to test that a claim reached one and not the other.
    const payloadWithCustom = Object.assign(
      stats.jwtClaims('id_token', self.customClaimContext(base, payload, user)),
      payload);
    // ---------------------------------------------------------------------
    // AND THE ONE LAYER ABOVE ALL OF THEM: a claim THIS CLIENT asked for by
    // name, in the `id_token` member of OIDC Core section 5.5's claims request.
    //
    // LAST, so it wins, and that is the whole precedence rule of this service
    // read to its end: the groups claim is what everybody gets, a ticked
    // directory attribute is what this service was configured to add, a typed
    // claim is what somebody wrote about it, the protocol's own claims are what
    // the specification requires — and a claim a client NAMED is the most
    // specific statement of all, so it is answered from the directory even
    // where one of the layers below already carried something under that name.
    // A request for `email` answered with the invented persona value while the
    // entry holds a real one would defeat the only reason this feature is worth
    // having.
    //
    // IT CANNOT REACH A STRUCTURAL CLAIM and that is by construction rather
    // than by a guard: every name it can resolve comes from the LDAP attribute
    // catalogue or from PERSONA_CLAIMS, and no member of either is `iss`,
    // `sub`, `aud`, `exp`, `nonce` or any of the rest. A guard here would
    // suggest to the next reader that one of them is reachable.
    // ---------------------------------------------------------------------
    const asked = self.requestedClaimsOf(opts.claims, 'id_token',
                                         user.username, user);
    if (asked.report.length) {
      log.debug("idToken(): " + asked.report.length + " claim(s) this " +
                "client asked for by name.");
      // The federation release policy applies to these TOO, and this is the one
      // line that says so. A partner with a release list naming `email` must
      // not be able to ASK for `birthdate` and be given it — the list is about
      // what this audience may see, not about which mechanism produced the
      // value. It removes only, and it cannot reach anything outside this
      // object.
      Object.assign(payloadWithCustom,
                    stats.applyClaimRelease(asked.claims,
                                            self.customClaimContext(
                                              base, payload, user),
                                            'requested claim(s)'));
    }
    // OIDC Core section 3.1.3.7: an ID Token is signed with the algorithm the
    // client REGISTERED as `id_token_signed_response_alg`, and with RS256 when
    // it registered none — which is what every client here does unless it says
    // otherwise, so the common path is unchanged.
    //
    // Refused rather than downgraded, for the reason the UserInfo endpoint
    // refuses: a client that registered an algorithm and got RS256 has no way
    // to notice, and would verify against a key that was never going to match.
    if (ID_TOKEN_SIGNING_ALGS.indexOf(idAlg) === -1 ||
        !self.deps.fapi.signingAlgAllowed(idAlg)) {
      log.debug("Leaving OAuth2Server.idToken(). Unsupported " +
                "id_token_signed_response_alg.");
      throw new Error('This client registered id_token_signed_response_alg="' +
        idAlg + '" and this service signs ID Tokens with ' +
        ID_TOKEN_SIGNING_ALGS.join(', ') +
        ' (see id_token_signing_alg_values_supported).');
    }
    const token = OWN_SYNC_SIGNING.test(idAlg)
      // The default keeps going through signJwt(), which is what records the
      // token in the admin console's count — see the note on that function —
      // and since #139 so does every RSA or curve algorithm it can sign with
      // (PS256 is FAPI 1.0 Advanced's default).
      // The KIND goes with it (#118): an ID Token carries no `typ` claim for
      // the register to read it off, so the one place that knows says so.
      ? signJwt(payloadWithCustom,
                Object.assign({}, self.issuanceContext(opts),
                              { kind: 'id_token' }),
                { certificateHeader: 'id-token', algorithm: idAlg })
      // `session` is the pool's routing hint — this person's `sub`, so that one
      // session's signatures queue behind each other rather than across the
      // pool.
      : await signJwtAsAsync(payloadWithCustom, idAlg, registered.client_secret,
                             { session: opts.user && opts.user.sub,
                               certificateHeader: 'id-token' });
    // OIDC Core section 10.2 (2026-09-17): SIGNED, THEN ENCRYPTED, when the
    // client registered `id_token_encrypted_response_alg` — a Nested JWT with
    // `cty: "JWT"`. The signature above is unchanged by it (any algorithm of
    // the table, the post-quantum ones included); what is added is the JWE
    // around it, to the key in the client's inline `jwks`. A registration
    // that cannot be honoured any longer THROWS with the sentence, as an
    // unusable signing algorithm does above: an ID Token sent in the clear to
    // a client that asked for encryption is not a downgrade it can notice.
    // The console's count was recorded by `signJwt()` on the inner token,
    // which is the credential; the envelope is not a second one.
    const protectedToken = idTokenEncryption.protect(token, registered);
    log.debug("Leaving OAuth2Server.idToken(). alg=" + idAlg +
              (protectedToken.encrypted
                ? ', encrypted ' + protectedToken.alg + ' ' +
                  protectedToken.enc
                : ''));
    return protectedToken.token;
  }

  // What a token response is about to mint, in the gate's own words. Derived
  // from the SAME expressions `tokenSet()` uses to decide — `withRefresh` and
  // the `openid` scope — rather than from a list kept beside them, because two
  // lists that had to agree would eventually not.
  private issuanceKindsOf(opts: Json): Json {
    const { log, hasScope, gate } = this.deps;
    log.debug("Entering OAuth2Server.issuanceKindsOf().");
    const kinds = [gate.ISSUANCE.ACCESS_TOKEN];
    if (opts.withRefresh !== false) {
      kinds.push(gate.ISSUANCE.REFRESH_TOKEN);
    }
    if (hasScope(opts.scope, 'openid')) {
      kinds.push(gate.ISSUANCE.ID_TOKEN);
    }
    log.debug("Leaving OAuth2Server.issuanceKindsOf().");
    return kinds;
  }

  // The party the requirement is about. In every browser grant it is the
  // PERSON; in `client_credentials` there is no person at all and it is the
  // CLIENT — see `common/roles.js`, where an application being a first-class
  // member of a role exists for exactly this request. Whether it
  // `authenticated` is the block below.
  // ---------------------------------------------------------------------------
  // WHO THE ROLE GATE IS BEING ASKED ABOUT, AND WHETHER THEY AUTHENTICATED.
  //
  // BOTH ANSWERS WERE THE CONSTANT `true` UNTIL 2026-09-05, and that is the one
  // thing worth knowing about this function. Three of the six built-in roles
  // are about the difference — ALL_UNAUTHENTICATED_USERS,
  // ALL_AUTHENTICATED_APPLICATIONS and ALL_UNAUTHENTICATED_APPLICATIONS — so
  // while this said `true` twice, a policy could name them and nothing arriving
  // at this endpoint could ever hold or fail to hold them. They were names with
  // no facts behind them.
  //
  // **THE TWO KINDS TAKE THEIR ANSWER FROM DIFFERENT PLACES, and that is the
  // whole shape of it.**
  //
  //   *  A USER's answer belongs to the SESSION the authorization happened on,
  //     and the session is not here — the token endpoint is a back channel with
  //     no cookie on it. So the authorization code carries it
  //     (`session_authenticated`), frozen at the moment the code was minted. A
  //     grant with no session behind it — the password grant, a token exchange
  //     — has authenticated somebody by presenting a credential at this
  //     endpoint, so `true` is the honest answer there and stays.
  //
  //   *  An APPLICATION's answer belongs to THIS REQUEST, because client
  //     authentication is something the client does every time it calls. It is
  //     observed by `oauth2_bcp.js` and handed in as `clientAuthenticated`. **A
  //     missing observation is `false` and not `true`**, which is the one place
  //     in this function that fails closed: an application that did not
  //     demonstrably authenticate has not authenticated, and the permissive
  //     reading would hand ALL_AUTHENTICATED_APPLICATIONS to every public
  //     client in the service. Nothing is refused by that alone — an
  //     application requiring EVERYBODY is unaffected, which is every
  //     application that has not been told otherwise.
  // ---------------------------------------------------------------------------
  private issuanceSubjectOf(opts: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.issuanceSubjectOf(). grant=" +
              (opts.grant || '?'));
    const username = String((opts.user && opts.user.username) ||
                            opts.username || '');
    if (opts.grant === 'client_credentials') {
      log.debug("Leaving OAuth2Server.issuanceSubjectOf(). The client IS " +
                "the subject.");
      return { kind: 'application', name: String(opts.client_id || username),
               authenticated: opts.clientAuthenticated === true };
    }
    // `!== false` rather than `=== true`: a code minted by a process that did
    // not carry the field, or a grant that never had a session, must go on
    // meaning what it meant.
    log.debug("Leaving OAuth2Server.issuanceSubjectOf(). A person.");
    return { kind: 'user', name: username,
             authenticated: opts.sessionAuthenticated !== false };
  }

  private checkIssuance(opts: Json): Json {
    const { log, gate, authn } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.checkIssuance(). client_id=" +
              opts.client_id);
    const subject = self.issuanceSubjectOf(opts);
    const kinds = self.issuanceKindsOf(opts);
    // THE SESSION THESE TOKENS REST ON (#62 P3), where they name one: its
    // risk and its factors are what the issuance policy decides the risk
    // question on, so a code redeemed or a token refreshed on a session its
    // sign-in left at HIGH is refused here as the session itself would be.
    // Without one — client credentials, a grant with nobody behind it — the
    // gate finds the person's standing, or nothing.
    const held = opts.session_id ? authn.sessionById(String(opts.session_id))
                                 : null;
    for (let i = 0; i < kinds.length; i += 1) {
      const answer = gate.check(Object.assign({
        application: String(opts.client_id || ''),
        kind: kinds[i],
        subject: subject,
        // The claims of a token the caller PRESENTED, where this grant is built
        // on one. A refresh and a token exchange both are, and the roles claim
        // in either is what the issuance policy's second arm reads.
        claims: opts.presentedClaims || null
      }, held ? { session: held } : {}));
      if (!answer.allowed) {
        log.debug("Leaving OAuth2Server.checkIssuance(). Refused: " + kinds[i]);
        throw new IssuanceRefused(log, answer, kinds[i]);
      }
    }
    log.debug("Leaving OAuth2Server.checkIssuance(). Allowed.");
    return null;
  }

  // `exp` - `iat` of a JWT this service just signed, or `fallback` when it
  // cannot be read.
  lifetimeOf(token: string, fallback: number): number {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.lifetimeOf().");
    let lifetime = fallback;
    try {
      const claims = JSON.parse(Buffer.from(String(token).split('.')[1] || '',
                                            'base64url').toString('utf8'));
      const read = Number(claims.exp) - Number(claims.iat);
      lifetime = read > 0 ? read : fallback;
    } catch (e) {
      log.debug("Caught in OAuth2Server.lifetimeOf(): " +
                ((e && e.message) || e));
      // Not a JWS this module can read: the configured lifetime is the
      // answer the response always gave.
      lifetime = fallback;
    }
    log.debug("Leaving OAuth2Server.lifetimeOf(). " + lifetime);
    return lifetime;
  }

  // ASYNCHRONOUS BECAUSE idToken() IS, and for no other reason: everything else
  // it mints is RS256 and stays in this process.
  async tokenSet(base: Json, opts: Json): Promise<Json> {
    const { log, randomId, hasScope, mtls, bcp, debuggerAccess,
            scopePolicy } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.tokenSet(). scope=" +
              (opts.scope || '(none)'));
    // ONE IDENTIFIER FOR EVERYTHING THIS REPLY CARRIES, minted here because
    // this is the single function every grant that issues a token set goes
    // through — the same property that already makes it the one place the RFC
    // 9700 binding note is written and refreshToken() the one place a
    // refresh token is minted. Every token below is told it, and admin_stats.js
    // records it, so /admin/tokens can draw the reply as the one thing the
    // client received.
    //
    // The parameter object is REPLACED rather than mutated, and a copy rather
    // than a new name so that the twenty-odd reads of `opts` below are
    // untouched. A mutation would reach back into the caller's object —
    // `issue()` hands the same one to checkIssuance() and to the audit —
    // and a set id appearing in a record nobody minted is worse than none at
    // all.
    //
    // A REFRESH GETS A NEW ONE. This function is entered once per response, so
    // the second generation of a grant is a set of its own; what joins the
    // generations is `parent_refresh_jti`, which is a different relation and is
    // drawn as one at /admin/tokens/credential.
    opts = Object.assign({}, opts, { set_id: randomId(12) });
    // THE SCOPES THIS CLIENT MAY BE ISSUED (#110) — the backstop. The
    // endpoints REFUSE a scope the client did not declare (scopeRefusal());
    // what reaches here undeclared is a grant carrying its scope from earlier
    // — a refresh after an allowance was removed, an exchange inheriting the
    // subject token's scope, an assertion grant — and it is taken off rather
    // than refused, with an audit row, so the `scope` member below reports
    // what was issued (RFC 6749 section 5.1). This service's protected scopes
    // in every mode; every other scope in product only.
    const allowedScope = scopePolicy.narrow(opts.scope, opts.client_id,
      { grant: opts.grant, defaults: self.credentialScopes() });
    if (allowedScope !== String(opts.scope == null ? '' : opts.scope)) {
      opts.scope = allowedScope;
    }
    // THE EMBEDDED DEBUGGER'S PERMISSION IS A CONSOLE ADMINISTRATOR'S AND
    // NOBODY ELSE'S (2026-09-13). Here, the one function every grant mints
    // through, so no grant — a refresh after a role was revoked, a token
    // exchange, a client_credentials request naming the scope — can carry it
    // for somebody who may not hold it. The authorization endpoint narrows
    // first; this is the backstop. A no-op for every scope that does not name
    // it. See `debugger/debugger_access.ts`.
    if (debuggerAccess.asksForPermission(opts.scope)) {
      opts.scope = debuggerAccess.narrowScope(opts.scope,
        self.issuanceSubjectOf(opts),
        { clientId: opts.client_id, grant: opts.grant });
    }
    // A SCOPE NAMING ANOTHER APPLICATION BECOMES THE AUDIENCE — see
    // audienceScopes(). Here rather than inside accessToken(),
    // because the decision changes three things and only one of them is the
    // access token: the scope claim on it, the `scope` member of the token
    // response, and the `resources` the refresh token remembers.
    // accessToken() can only reach the first, and a call site that set the
    // other two would be a fourth place this has to be got right — which is the
    // argument that keeps `issue()` the single entry to this function and
    // signJwt() the single counter.
    //
    // An audience that arrived some other way WINS and nothing is derived: RFC
    // 8707's `resource` is the mechanism a client used deliberately, an
    // exchange's `audience` is RFC 8693 section 2.1's parameter, and a refresh
    // carries forward what its grant was authorized for. Deriving a second
    // audience beside any of those would WIDEN a set the two narrowing checks
    // at the token endpoint exist to stop widening — and since 2026-09-13 a
    // scope naming a DIFFERENT one is refused rather than dropped (RFC 9068
    // section 2.2.3; see accessTokenPlan()).
    //
    // THIS IS THE BACKSTOP AND NOT THE USUAL PLACE A REQUEST IS REFUSED. The
    // authorization endpoint and the token endpoint ask the same plan before
    // anything is spent; what reaches a refusal here is a grant carrying its
    // scope from earlier — a refresh token minted before the rule existed — and
    // a token must not be issued ambiguous because the grant is old.
    const explicit = self.audienceList(opts.audience);
    const plan = self.accessTokenPlan(base, opts.scope, opts.client_id,
                                      explicit, opts.authorization_details);
    if (plan.refusal) {
      log.debug("Leaving OAuth2Server.tokenSet(). RFC 9068 refused the " +
                "audience.");
      throw new AccessTokenRefused(log, plan.refusal);
    }
    const derived = !explicit.length && plan.derived.length > 0;
    const issuing = Object.assign({}, opts, {
      scope: plan.scope,
      audience: self.audienceClaim(plan.audiences),
      // Onto the refresh token as well, for the reason the RFC 8707 call sites
      // give: a grant cannot widen itself by being renewed, and the refresh
      // grant reads the audience of what it mints off this list. The
      // APPLICATIONS only, not this service's own resource server: putting the
      // default in here would put it in the RFC 8707 narrowing check, where a
      // client asking to narrow to the API it already had would be told it was
      // asking for something new.
      resources: derived && !(opts.resources && opts.resources.length)
        ? plan.derived.slice(0) : opts.resources
    });
    const access = self.accessToken(base, issuing);
    // RFC 9700 section 2.2, and it refuses nothing: whether a token is
    // sender-constrained is the CLIENT's decision, since it binds by sending a
    // DPoP proof or presenting a certificate (the settings that REQUIRE one are
    // `sender_constraints.js`'s, asked elsewhere). Noted at the one place every
    // grant mints a token set, so that "this server issued a bearer token" is a
    // line somebody can find rather than an absence they have to notice. A
    // no-op while the mode is off.
    bcp.noteTokenBinding({
      // The scope the token actually CARRIES. Section 2.3's least-privilege
      // note reads what was issued, so a scope that became the audience must
      // not be reported here as one this server does not advertise — it is not
      // on the token to be least-privileged about.
      jkt: opts.jkt, clientId: opts.client_id, scope: issuing.scope,
      // Whether the connection this token was minted on carried a client
      // certificate — a token bound that way is sender-constrained too, and
      // reporting it as a bearer token would be the note contradicting the cnf
      // on the token beside it.
      certificateBound: !!(opts.request &&
                           mtls.presentedThumbprint(opts.request))
    });
    const body: Json = {
      access_token: access,
      // RFC 9449 section 5: `DPoP`, not `Bearer`, when the token is bound. This
      // is how the wallet learns it must send a proof on every subsequent call
      // — a bound token announced as Bearer would be presented as one and
      // refused.
      token_type: opts.jkt ? 'DPoP' : 'Bearer',
      // The lifetime the token CARRIES, so FAPI's cap (#138), applied in
      // accessToken() by whether the token has a cnf, is the one reported.
      expires_in: self.lifetimeOf(access, self.accessTokenTtl(opts.client_id)),
      // RFC 6749 section 5.1: `scope` describes the ACCESS TOKEN that was
      // issued, and this one no longer carries the value that became its
      // audience. It is therefore not identical to what was requested, which is
      // the case that section makes the member REQUIRED rather than optional —
      // it is always sent here, so nothing changes about when.
      scope: issuing.scope || ''
    };
    if (opts.authorization_details) body.authorization_details =
        opts.authorization_details;
    if (opts.withRefresh !== false) {
      // THE REFRESH TOKEN KEEPS THE WHOLE SCOPE, and that is the one place the
      // two halves of a grant deliberately disagree. The access token's scope
      // claim is what the token can do; the refresh token's is what was
      // AUTHORIZED, which is what RFC 9700 section 2.2.2 binds it to and what
      // oauth2_bcp.js's `scope-not-widened` compares a refresh request against.
      // Strip it here as well and a client that refreshes with the scope list
      // it originally sent — the ordinary thing to do — is refused for asking
      // for a scope its own grant supposedly never carried.
      //
      // AND A REFRESH HANDS ON THE GRANT IT WAS GIVEN, NOT THE ONE IT ASKED FOR
      // (2026-09-13, in both modes). RFC 6749 section 6 and OAuth 2.1 section
      // 4.3.3 (draft-ietf-oauth-v2-1-16) say the same sentence: a new refresh
      // token's scope MUST be identical to that of the refresh token presented.
      // The refresh grant narrows `scope` and `resources` for the ACCESS token
      // it mints, and until this date the rotated refresh token was minted from
      // the same narrowed values — so one narrow refresh shrank the grant for
      // good, and the next refresh asking for the original scope was refused as
      // a widening in RFC 9700 mode. `grantScope` / `grantResources` are what
      // the presented refresh token carried; they are OWN-PROPERTY tests rather
      // than `||`, because a grant with an empty scope is a value and must not
      // fall back to the narrowed request. Every other grant passes neither, so
      // what they mint is what it always was.
      const hasGrantScope =
          Object.prototype.hasOwnProperty.call(opts, 'grantScope');
      const hasGrantResources =
          Object.prototype.hasOwnProperty.call(opts, 'grantResources');
      // RFC 9396 section 6 the same way: a token request that asked for a
      // subset of the authorized details narrows the ACCESS token, and the
      // refresh token keeps what the grant authorized.
      const hasGrantDetails =
          Object.prototype.hasOwnProperty.call(opts,
                                               'grantAuthorizationDetails');
      // The access token beside it, for RFC 7009 (#102): recorded on the
      // refresh token's family so that revoking the grant revokes it too.
      body.refresh_token = self.refreshToken(base,
        Object.assign({}, issuing, {
          access_jti: self.jtiOf(access),
          access_exp: this.deps.nowSec() + Number(body.expires_in || 0),
          scope: hasGrantScope ? String(opts.grantScope || '') :
                 (opts.scope || ''),
          resources: hasGrantResources ? opts.grantResources :
            issuing.resources,
          authorization_details: hasGrantDetails
            ? opts.grantAuthorizationDetails : issuing.authorization_details
        }));
    }
    if (hasScope(opts.scope, 'openid')) {
      // From `opts` and not from `issuing`: an ID Token carries no scope claim
      // and its audience is the CLIENT, so neither of the two things above
      // applies to it. Passing the derived audience here would readdress it to
      // the resource server and every relying party would refuse its own ID
      // Token.
      body.id_token = await self.idToken(base,
        Object.assign({}, opts, { access_token: access }));
    }
    log.debug("Leaving OAuth2Server.tokenSet(). Issued: " +
              Object.keys(body).join(', '));
    return body;
  }

  // --- the authorization endpoint
  // ---------------------------------------------- A browser flow, so it
  // behaves like one: an unauthenticated request is sent to the AUTHENTICATION
  // SERVICE (authn.js), and only once the person comes back signed in does this
  // endpoint issue the authorization code (or the implicit/hybrid tokens) and
  // redirect back to the client.
  //
  //   GET /oauth2/authorize   no session  -> 302 to /authn/login, with a return
  //                                          URL carrying this request whole
  //                           session     -> issue and redirect to redirect_uri
  //
  // So the endpoint is entered TWICE for a sign-in and once afterwards, and the
  // second entry is the first request over again — which is exactly what makes
  // it safe to keep no state here: everything the response is built from is on
  // the query string both times.
  //
  // In development mode no password is checked over there — the username typed
  // in is simply who the tokens then describe (product mode verifies it). A
  // session cookie means the next authorization request does not prompt again;
  // prompt=login forces it to, and is dropped from the return URL so that it
  // forces it exactly once.
  // ---------------------------------------------------------------------------
  // The request as it arrived, rebuilt — which is what the authentication
  // service is given as a return URL, so that the second pass through the
  // authorization endpoint sees the SAME request the client made.
  //
  // A REPEATED PARAMETER STAYS REPEATED, and that is not a refinement. Express
  // hands back an array when a parameter appears more than once, and
  // `URLSearchParams.set()` stringifies an array by joining it with commas — so
  // `?resource=a&resource=b` came back from the sign-in screen as the single
  // value "a,b", which is one resource indicator that names nothing. It was
  // latent until RFC 8707 gave this endpoint a parameter that is DEFINED to
  // repeat; the same collapse would have happened to any other. `append` per
  // value is the fix, and the array test has to be explicit because a string is
  // iterable too and appending it per character is a worse bug than the one
  // being fixed.
  queryString(query: Json, omit: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.queryString().");
    const usp = new URLSearchParams();
    Object.keys(query).forEach(function (k) {
      if (omit && omit.indexOf(k) >= 0) {
        return;
      }
      const value = query[k];
      if (Array.isArray(value)) {
        value.forEach(function (one) {
          usp.append(k, one);
        });
        return;
      }
      usp.set(k, value);
    });
    log.debug("Leaving OAuth2Server.queryString().");
    return usp.toString();
  }

  // The OPTIONAL `claims` member of an openid_credential authorization detail
  // (OID4VCI section 5.1.1): which claims the Wallet wants the issued
  // Credential to carry, as claims description objects (Appendix A.1) holding
  // claims path pointers (Appendix B).
  //
  // Three kinds of refusal, and each is a refusal rather than a silent drop for
  // the same reason unreadable authorization_details are
  // (`parseAuthorizationDetails()`): a wallet whose selection was quietly
  // ignored gets a credential carrying claims it did not ask for and no way to
  // discover why.
  //
  //   *  a shape Appendix A.1 does not allow — a path that is not a non-empty
  //     array of strings, nulls and integers;
  //   *  a repeated claim, which Appendix A.3 says MUST abort the processing;
  //   *  a path this issuer does not advertise for that credential's format,
  //     which is the one check that is this issuer's own. Its metadata says
  //     what it can put in a credential; honouring a request for anything else
  //     would mean issuing a credential the wallet was told was impossible, or
  //     (more likely) issuing one silently missing the claim.
  //
  // Absent is not empty: `{ claims: null }` means the wallet expressed no
  // preference and gets everything, which is what every authorization made
  // before this member existed did.
  parseClaimsDescriptions(raw: Json, configId: Json): Json {
    const { log, vciFormatOf, vcClaims } = this.deps;
    log.debug("Entering OAuth2Server.parseClaimsDescriptions(). " +
              "configId=" + configId);
    if (raw === undefined || raw === null) {
      log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). No claims " +
                "member.");
      return { claims: null };
    }
    if (!Array.isArray(raw) || !raw.length) {
      log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). Not a " +
                "non-empty array.");
      return { error: 'the claims member of an authorization detail must be ' +
                      'a non-empty array of claims description objects ' +
                      '(OID4VCI ' +
                      'Appendix A.1).' };
    }
    const out = [];
    const seen = new Set();
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (!c || typeof c !== 'object' || Array.isArray(c)) {
        log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). Entry " +
                  i + " is not an object.");
        return { error: 'claims[' + i + '] is not a claims description ' +
                        'object.' };
      }
      const path = c.path;
      if (!Array.isArray(path) || !path.length) {
        log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). Entry " +
                  i + " has no usable path.");
        return { error: 'claims[' + i + '].path must be a non-empty claims ' +
                        'path pointer array (OID4VCI Appendix B).' };
      }
      const badPart = path.findIndex(function (part) {
        return !(typeof part === 'string' || part === null ||
                 Number.isInteger(part));
      });
      if (badPart >= 0) {
        log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). Entry " +
                  i + " has a bad path component.");
        return { error: 'claims[' + i + '].path[' + badPart + '] must be a ' +
                        'string, null or an integer (OID4VCI Appendix B).' };
      }
      const key = vcClaims.pathKey(path);
      if (seen.has(key)) {
        log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). Entry " +
                  i + " repeats a claim.");
        return { error: 'the claim ' + key + ' is described twice; OID4VCI ' +
                        'Appendix A.3 says a repeated claims description ' +
                        'MUST ' +
                        'abort the processing.' };
      }
      seen.add(key);
      const entry: Json = { path: path.slice() };
      if (c.mandatory !== undefined) {
        if (typeof c.mandatory !== 'boolean') {
          log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). Entry " +
                    i + " has a non-boolean mandatory.");
          return { error: 'claims[' + i + '].mandatory must be a boolean.' };
        }
        entry.mandatory = c.mandatory;
      }
      out.push(entry);
    }
    const unknown = vcClaims.unknownPaths(out.map(function (c) {
      return c.path;
    }), vciFormatOf(configId));
    if (unknown.length) {
      log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). " +
                unknown.length + " unadvertised path(s).");
      return { error: 'this issuer does not advertise ' +
                      unknown.map(vcClaims.pathKey).join(', ') + ' for ' +
                          'credential_configuration_id "' +
                      configId + '". Its metadata lists the claims it can ' +
                      'carry in credential_configurations_supported.' };
    }
    log.debug("Leaving OAuth2Server.parseClaimsDescriptions(). " +
              out.length + " claim(s) requested.");
    return { claims: out };
  }

  maxRequestedClaims(): Json {
    const { log, config } = this.deps;
    log.debug("Entering OAuth2Server.maxRequestedClaims().");
    const count = Number(config.value('oauth2.maxRequestedClaims'));
    log.debug("Leaving OAuth2Server.maxRequestedClaims().");
    return isFinite(count) && count > 0 ? Math.floor(count) :
           MAX_REQUESTED_CLAIMS;
  }

  // One individual claim request (section 5.5.1). `null` means "asked for, no
  // further constraint", which is by far the common shape; an object may carry
  // `essential`, `value` and `values`, and any member not understood MUST be
  // ignored — so unknown members are dropped here rather than refused, which is
  // the one place in this parser that section says to be permissive.
  parseIndividualClaimRequest(member: Json, name: Json, raw: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.parseIndividualClaimRequest().");
    if (raw === null || raw === undefined) {
      log.debug("Leaving OAuth2Server.parseIndividualClaimRequest().");
      return { entry: null };
    }
    if (typeof raw !== 'object' || Array.isArray(raw)) {
      log.debug("Leaving OAuth2Server.parseIndividualClaimRequest().");
      return { error: 'claims.' + member + '["' + name + '"] must be null or ' +
                      'a JSON object (OpenID Connect Core section 5.5.1); ' +
                      'this one is ' +
                      (Array.isArray(raw) ? 'an array' : 'a ' + typeof raw) +
                      '.' };
    }
    const entry: Json = {};
    if (raw.essential !== undefined) {
      if (typeof raw.essential !== 'boolean') {
        log.debug("Leaving OAuth2Server.parseIndividualClaimRequest().");
        return { error: 'claims.' + member + '["' + name +
                        '"].essential must ' +
            'be a boolean.' };
      }
      entry.essential = raw.essential;
    }
    if (raw.value !== undefined) {
      entry.value = raw.value;
    }
    if (raw.values !== undefined) {
      if (!Array.isArray(raw.values) || !raw.values.length) {
        log.debug("Leaving OAuth2Server.parseIndividualClaimRequest().");
        return { error: 'claims.' + member + '["' + name +
                        '"].values must be ' +
            'a non-empty array.' };
      }
      entry.values = raw.values.slice(0);
    }
    log.debug("Leaving OAuth2Server.parseIndividualClaimRequest().");
    // An object with nothing in it is legal and means exactly what null means.
    // Normalised to null so that everything downstream has two shapes to read
    // rather than three.
    return { entry: Object.keys(entry).length ? entry : null };
  }

  // Returns { claims: null } when the parameter was not sent — ABSENT IS NOT
  // EMPTY, exactly as parseClaimsDescriptions() above says of the OID4VCI
  // member: `{}` is a client that asked for no individual claims, and no
  // parameter at all is a client that has never heard of the section. Both
  // behave the same today and they are still different facts, and the one that
  // is recorded on the token is the one the client actually sent.
  parseClaimsRequest(raw: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.parseClaimsRequest().");
    if (raw === undefined || raw === null || raw === '') {
      log.debug("Leaving OAuth2Server.parseClaimsRequest(). No claims " +
                "parameter.");
      return { claims: null };
    }
    let parsed = raw;
    if (typeof raw === 'string') {
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        log.debug("Leaving OAuth2Server.parseClaimsRequest(). The parameter " +
                  "is not JSON.");
        return { error: 'the claims parameter must be a JSON object (OpenID ' +
                        'Connect Core section ' +
                        '5.5): ' + e.message + '. It is sent as ' +
                        'ordinary URL-encoded JSON — no base64, no JWT — ' +
                        'unless it is inside a Request Object.' };
      }
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      log.debug("Leaving OAuth2Server.parseClaimsRequest(). Not an object.");
      return { error: 'the claims parameter must be a JSON OBJECT with a ' +
                      '"userinfo" and/or an "id_token" member (OpenID ' +
                      'Connect ' +
                      'Core section 5.5).' };
    }
    const out = {};
    const ignored = [];
    let total = 0;
    const members = Object.keys(parsed);
    for (let i = 0; i < members.length; i++) {
      const member = members[i];
      if (CLAIMS_REQUEST_MEMBERS.indexOf(member) < 0) {
        // Section 5.5: other members MAY be defined. Ignored, and named, so
        // that a client can tell "ignored" from "not understood".
        ignored.push(member);
        continue;
      }
      const value = parsed[member];
      if (value === null || value === undefined) {
        continue;
      }
      if (typeof value !== 'object' || Array.isArray(value)) {
        log.debug("Leaving OAuth2Server.parseClaimsRequest(). The " +
                  member + " member is not an object.");
        return { error: 'claims.' + member + ' must be a JSON object whose ' +
                        'members are claim names (OpenID Connect Core ' +
                        'section 5.5); this one is ' +
                        (Array.isArray(value) ? 'an array' :
                         'a ' + typeof value) + '.' };
      }
      const names = Object.keys(value);
      const bucket = {};
      for (let j = 0; j < names.length; j++) {
        const name = String(names[j]).trim();
        if (!name) {
          log.debug("Leaving OAuth2Server.parseClaimsRequest(). An empty " +
                    "claim name.");
          return { error: 'claims.' + member +
                          ' has a member with an empty name.' };
        }
        total++;
        if (total > self.maxRequestedClaims()) {
          log.debug("Leaving OAuth2Server.parseClaimsRequest(). Over the cap.");
          return { error: 'a claims request may name at most ' +
                          self.maxRequestedClaims() + ' claims here. The ' +
                          'parsed request is copied into the access token, ' +
                          'and one large enough to overflow a header would ' +
                          'fail at a client in a way nothing ' +
                          'points back here.' };
        }
        const one = self.parseIndividualClaimRequest(member, name,
                                                     value[names[j]]);
        if (one.error) {
          log.debug("Leaving OAuth2Server.parseClaimsRequest(). " + one.error);
          return { error: one.error };
        }
        bucket[name] = one.entry;
      }
      out[member] = bucket;
    }
    if (ignored.length) {
      log.info('A claims request carried the member(s) ' + ignored.join(', ') +
               ', which OpenID Connect Core section 5.5 does not define and ' +
               'this service therefore ignores. The two it acts on are ' +
               'userinfo and ' +
               'id_token.');
    }
    if (!Object.keys(out).length) {
      log.debug("Leaving OAuth2Server.parseClaimsRequest(). Nothing this " +
                "service acts on.");
      return { claims: null, ignored: ignored };
    }
    log.debug("Leaving OAuth2Server.parseClaimsRequest(). " +
              total + " claim(s) requested across " +
              Object.keys(out).length + " member(s).");
    return { claims: out, ignored: ignored };
  }

  // The names one member of a parsed claims request asks for, in the order the
  // client wrote them. A helper rather than an inline Object.keys() because
  // three call sites need it and one of them is the console.
  requestedClaimNames(request: Json, member: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.requestedClaimNames().");
    const asked = request && request[member];
    log.debug("Leaving OAuth2Server.requestedClaimNames().");
    return asked ? Object.keys(asked) : [];
  }

  // ---------------------------------------------------------------------------
  // A GRANT WITH NO BROWSER STILL NEEDS A PERSON WITH AN ENTRY (2026-09-14).
  //
  // A person's `sub` is their directory entry's `entryUUID` (see
  // `authn/CLAUDE.md`, *What an authenticated identity is here*). The password
  // grant and the two assertion grants record the authentication FIRST — that
  // is what makes the directory create the entry — and then ask for the person,
  // and where the directory still holds nobody (`ldap.autocreateUsers` off and
  // the person never provisioned) they refuse `invalid_grant` rather than
  // minting a token whose `sub` is empty. A process with no directory has no
  // subjects for anybody and refuses nothing, for `authn.startSession()`'s
  // reason.
  // ---------------------------------------------------------------------------
  provisionedPerson(username: Json): Json {
    const { log, userFor, hasSubjectResolver } = this.deps;
    log.debug("Entering OAuth2Server.provisionedPerson().");
    const user = userFor(username);
    if (!user.sub && hasSubjectResolver()) {
      log.debug("Leaving OAuth2Server.provisionedPerson(). No entry.");
      return null;
    }
    log.debug("Leaving OAuth2Server.provisionedPerson().");
    return user;
  }

  // The person a refresh token's next generation is minted for, taken from the
  // token's SUBJECT and not from the username beside it: a person renamed since
  // the grant is found under their new name, and one deleted since it — or
  // deleted and re-created under the same name, which is a different subject —
  // is nobody, and the refresh is refused. A refresh token whose subject is not
  // a person's (a client's, an exchange's) is minted as it always was.
  refreshedPerson(claims: Json): Json {
    const { log, userFor, nameForSubject, hasSubjectResolver,
            LEGACY_SUBJECT_PREFIX } = this.deps;
    log.debug("Entering OAuth2Server.refreshedPerson().");
    const sub = String((claims && claims.sub) || '');
    const personal = /^urn:uuid:/i.test(sub) ||
                     sub.indexOf(LEGACY_SUBJECT_PREFIX) === 0;
    if (!personal || !hasSubjectResolver()) {
      log.debug("Leaving OAuth2Server.refreshedPerson(). Not a person's " +
                "subject.");
      return userFor(claims.username);
    }
    const name = nameForSubject(sub);
    const user = name ? userFor(name) : null;
    log.debug("Leaving OAuth2Server.refreshedPerson(). " +
              (user && user.sub ? 'Found.' : 'Nobody.'));
    if (!user || !user.sub) {
      return null;
    }
    // THE SUBJECT THE TOKEN FAMILY WAS ISSUED UNDER, where it is one of this
    // entry's: an alias left by a create race (`ldap_server.js`'s
    // `mergeCreateRace()`) still names this person, and a relying party that
    // links on `sub` must see the same value on every refresh — OIDC Core 12.2.
    return /^urn:uuid:/i.test(sub) ?
      Object.assign({}, user, { sub: sub }) : user;
  }

  personFromDirectory(user: Json): Json {
    const { log, mode, errorCodes, claimAttributes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.personFromDirectory().");
    if (!user || mode.inventsClaimValues()) {
      log.debug("Leaving OAuth2Server.personFromDirectory(). Nothing to fill.");
      return user;
    }
    const missing = DIRECTORY_PERSONA_CLAIMS.filter(function (name) {
      return user[name] === undefined || user[name] === null ||
             user[name] === '';
    });
    if (!missing.length || !user.username) {
      log.debug("Leaving OAuth2Server.personFromDirectory(). The person " +
                "object is already complete.");
      return user;
    }
    const out = Object.assign({}, user);
    let built = { claims: {} };
    try {
      built = claimAttributes.requestedClaimsFor(user.username, missing);
    } catch (e) {
      // A directory that threw must not fail an issuance — the rule
      // `vc_claims.js`'s directory reader follows for the same reason. The
      // claims are simply absent, which is the honest answer in a realm that
      // invents nothing.
      log.error(errorCodes.tag('STS-OAUTH-0181') + 'personFromDirectory(): ' +
                'the directory threw while being read for ' +
                user.username + '\'s profile claims and they are omitted: ' +
                e.message);
    }
    missing.forEach(function (name) {
      const value = built.claims[name];
      if (typeof value === 'string' && value !== '') {
        out[name] = value;
      } else {
        delete out[name];
      }
    });
    log.debug("Leaving OAuth2Server.personFromDirectory(). " +
              DIRECTORY_PERSONA_CLAIMS.filter(function (n) {
                return out[n] !== undefined;
              }).length +
              " of " + DIRECTORY_PERSONA_CLAIMS.length + " profile claim(s) " +
              "from the directory.");
    return out;
  }

  // A copy of an object with every `undefined` member removed. JSON drops them
  // on the way out anyway; the reason for doing it BEFORE a merge is that
  // `Object.assign(configured, payload)` copies an undefined member too, and a
  // protocol claim that is merely absent would erase a configured claim of the
  // same name that should have survived.
  definedOnly(object: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.definedOnly().");
    const out = {};
    Object.keys(object || {}).forEach(function (key) {
      if (object[key] !== undefined) {
        out[key] = object[key];
      }
    });
    log.debug("Leaving OAuth2Server.definedOnly().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHAT A CLAIMS REQUEST ACTUALLY PRODUCES FOR ONE PERSON.
  //
  // TWO SOURCES, IN THIS ORDER, and the order is the point:
  //
  //   1.  the DIRECTORY, through the catalogue every claim-set page chooses
  //      from — the person's entry under ou=users, or, where the entry has
  //      nothing, the persona invented from their username, deterministically.
  //      This is the whole reason the feature is worth having: a client asks
  //      for `birthdate` and gets what an `ldapmodify` put there, so an LDAP
  //      client and an OIDC client pointed at this service are shown one
  //      person.
  //   2.  the six claims userFor() invents, for the names the catalogue has no
  //      attribute type for — `email_verified` above all, which is a fact about
  //      a sign-in rather than a value on an entry.
  //
  // A name neither can produce comes back in `unknown`, and NOTHING IS REFUSED
  // FOR IT. Section 5.5.1 is explicit that a server MUST NOT return an error
  // because a requested claim is unavailable, and `essential` does not change
  // that — it says what the client will do without it, not what this server
  // must do about it. So an unresolvable name is LOGGED and reported, which is
  // the only thing that will ever tell a client the difference between "asked
  // for and absent" and "never asked for".
  //
  // `value` and `values` are CHECKED AND NOT HONOURED, deliberately. A mock
  // that echoed back whatever value a client asked it to assert would be the
  // one surface here that cannot be used to test anything — everything this
  // service says about a person comes from the directory or from the invented
  // persona. The mismatch is reported instead, which is what a client's error
  // path is for.
  // ---------------------------------------------------------------------------
  requestedClaimsOf(request: Json, member: Json, username: Json, user: Json)
    : Json {
    const { log, claimAttributes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.requestedClaimsOf(). member=" + member);
    const names = self.requestedClaimNames(request, member);
    const out = { names: names, claims: {}, report: [], unknown: [],
                  mismatched: [],
                  missingEssential: [], entryFound: false };
    if (!names.length) {
      log.debug("Leaving OAuth2Server.requestedClaimsOf(). Nothing was asked " +
                "for.");
      return out;
    }
    const built = claimAttributes.requestedClaimsFor(username, names);
    out.claims = Object.assign({}, built.claims);
    out.report = built.report.slice(0);
    out.entryFound = built.entryFound;
    built.unknown.forEach(function (name) {
      if (PERSONA_CLAIMS.indexOf(name) >= 0 && user &&
          user[name] !== undefined) {
        out.claims[name] = user[name];
        out.report.push({ requested: name, claim: name, ldap: '',
                          value: user[name], source: 'the sign-in' });
        return;
      }
      out.unknown.push(name);
    });

    // What the request asked for that this answer does not satisfy. Reported
    // and never refused — see the header.
    const asked = request[member] || {};
    names.forEach(function (name) {
      const spec = asked[name];
      const resolved = out.unknown.indexOf(name) < 0;
      if (!resolved && spec && spec.essential) {
        out.missingEssential.push(name);
        return;
      }
      if (!resolved || !spec) {
        return;
      }
      const item = out.report.filter(function (row) {
        return row.requested === name;
      })[0];
      const held = item ? item.value : undefined;
      if (spec.value !== undefined && String(spec.value) !== String(held)) {
        out.mismatched.push(name + ' (asked for "' + spec.value + '", holds "' +
                            held + '")');
      }
      if (spec.values &&
          !spec.values.some(function (v) {
            return String(v) === String(held);
          })) {
        out.mismatched.push(name + ' (asked for one of "' +
                            spec.values.join('", ' +
            '"') +
                            '", holds "' + held + '")');
      }
    });

    if (out.unknown.length) {
      log.info('A claims request asked the ' + member + ' for ' +
               out.unknown.join(', ') +
               ', which neither the LDAP attribute catalogue nor the sign-in ' +
               'can produce. OpenID Connect Core section 5.5.1 says a server ' +
               'MUST NOT error for that, so the claim is simply absent. GET ' +
               '/admin/userinfo-claims lists every name that can be asked ' +
               'for.');
    }
    if (out.missingEssential.length) {
      log.warn('A claims request marked ' + out.missingEssential.join(', ') +
          ' ' +
          'ESSENTIAL in the ' +
               member + ' and this service cannot produce ' +
               (out.missingEssential.length > 1 ? 'them' : 'it') + '. That ' +
               'is still not an error (section 5.5.1); the client is the ' +
               'half ' +
               'that decides what to do without it.');
    }
    if (out.mismatched.length) {
      log.warn('A claims request asked for particular VALUES in the ' + member +
               ' ' +
               'and this service holds ' +
               'others: ' + out.mismatched.join('; ') + '. The values held ' +
               'are what is returned — a mock that echoed back whatever a ' +
               'client asked it to assert could not be used to test ' +
               'anything.');
    }
    log.debug("Leaving OAuth2Server.requestedClaimsOf(). " +
              Object.keys(out.claims).length + " claim(s), " +
              out.unknown.length + " unresolvable.");
    return out;
  }

  // ONE openid_credential detail (OID4VCI section 5.1.1), as the built-in half
  // of `authorization_details.parse()`: it names a credential_configuration_id
  // this issuer offers, and its `claims` selection is one the metadata
  // advertises. `{ entry }`, or a refusal carrying STS-OAUTH-0153.
  vciAuthorizationDetail(d: Json): Json {
    const { log, VCI_CONFIGS, VCI_CONFIG_ID, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.vciAuthorizationDetail().");
    const configId = d.credential_configuration_id;
    if (configId && !VCI_CONFIGS[configId]) {
      log.debug("Leaving OAuth2Server.vciAuthorizationDetail(). Unknown " +
                "configuration: " +
                configId);
      return errorCodes.mark({ error: 'credential_configuration_id "' +
        configId + '" is not one this issuer offers.' }, 'STS-OAUTH-0153');
    }
    const entry: Json = {
      type: 'openid_credential',
      credential_configuration_id: configId || VCI_CONFIG_ID
    };
    const claims = self.parseClaimsDescriptions(d.claims,
                                           entry.credential_configuration_id);
    if (claims.error) {
      log.debug("Leaving OAuth2Server.vciAuthorizationDetail(). " +
                claims.error);
      return errorCodes.mark({ error: claims.error }, 'STS-OAUTH-0153');
    }
    if (claims.claims) {
      entry.claims = claims.claims;
    }
    log.debug("Leaving OAuth2Server.vciAuthorizationDetail().");
    return { entry: entry };
  }

  // RFC 9396's authorization_details, wherever a request carries them: the
  // authorization endpoint, the token endpoint and the pushed authorization
  // request endpoint. `context` is `{ clientId, req }`, and both are optional:
  // the client narrows the TYPES to its registered authorization_details_types,
  // and the request selects the authorization server whose published
  // authorization_details_types_supported narrows them again.
  //
  // Answers `{ details }` — null where none were sent — or `{ error }` MARKED
  // with its code (`errorCodes.codeOf()`), the sentence for
  // invalid_authorization_details. Unreadable JSON is not silently dropped, for
  // the reason the type check is not: a client that sent nonsense should be
  // told.
  parseAuthorizationDetails(raw: Json, context?: Json): Json {
    const { log, applications, errorCodes, richAuthorization } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.parseAuthorizationDetails().");
    if (raw === undefined || raw === null || raw === '') {
      // The ordinary request, answered before the metadata document and the
      // registry are read for a narrowing nothing needs.
      log.debug("Leaving OAuth2Server.parseAuthorizationDetails(). None were " +
                "sent.");
      return { details: null };
    }
    const ctx = context || {};
    const client: Json = ctx.clientId
      ? applications.clientConfigOf(String(ctx.clientId)) : {};
    const profileTypes = ctx.req
      ? self.capabilityFor(ctx.req, 'authorization_details_types_supported')
      : null;
    const parsed = richAuthorization.parse(raw, {
      clientTypes: client.authorization_details_types || [],
      profileTypes: Array.isArray(profileTypes) ? profileTypes : null,
      builtIn: self.vciAuthorizationDetail.bind(self)
    });
    if (!parsed.ok) {
      log.debug("Leaving OAuth2Server.parseAuthorizationDetails(). " +
                parsed.error);
      return errorCodes.mark({ error: parsed.error },
                             errorCodes.codeOf(parsed) || 'STS-OAUTH-0153');
    }
    log.debug("Leaving OAuth2Server.parseAuthorizationDetails(). " +
              (parsed.details ? parsed.details.length : 0) + " detail(s).");
    return { details: parsed.details };
  }

  // ---------------------------------------------------------------------------
  // RFC 8707 — RESOURCE INDICATORS, which is how a client asks for an
  // audience-restricted access token.
  //
  // RFC 9700 section 2.3 says an access token SHOULD be restricted to one
  // resource server, or to a small set where that is impractical. Every token
  // this service issues has always been audience-restricted —
  // `<base>/resource`, one audience — but the client had no way to say WHICH
  // resource server it wanted, which made the restriction true and useless: one
  // audience that is always the same restricts a token to everything this
  // service protects.
  //
  // So `resource` is read at the authorization endpoint and at the token
  // endpoint, and it becomes the `aud`. Three rules, and each is section 2 of
  // RFC 8707:
  //
  //   *  it MUST be an absolute URI with no FRAGMENT. A fragment is the part a
  //     server never sees on a redirect, so an audience carrying one names
  //     something the resource server cannot match.
  //   *  it may be repeated, and the token then names several — the "small set"
  //     the BCP allows for when one is impractical.
  //   *  at the TOKEN endpoint it may only NARROW what the authorization
  //     request asked for. A grant that let a client widen its own audience
  //     afterwards would be the same privilege escalation the refresh scope
  //     check refuses, one step earlier.
  //
  // A request that names none is unaffected and gets the default audience,
  // which is what keeps this invisible to every existing caller.
  // ---------------------------------------------------------------------------
  parseResourceIndicators(raw: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.parseResourceIndicators().");
    const asked = raw === undefined || raw === null ? []
      : (Array.isArray(raw) ? raw : [raw]);
    const wanted = [];
    for (let i = 0; i < asked.length; i++) {
      const text = String(asked[i] || '').trim();
      if (!text) {
        continue;
      }
      let parsed = null;
      try {
        parsed = new URL(text);
      } catch (e) {
        log.debug("Caught in OAuth2Server.parseResourceIndicators(): " +
                  ((e && e.message) || e));
        log.debug("Leaving OAuth2Server.parseResourceIndicators(). Not an " +
                  "absolute URI.");
        return { error: 'RFC 8707 section 2: the resource parameter must be ' +
                        'an absolute URI. "' +
                        text + '" is not one.' };
      }
      if (parsed.hash) {
        log.debug("Leaving OAuth2Server.parseResourceIndicators(). " +
                  "It carries a fragment.");
        return { error: 'RFC 8707 section 2: the resource parameter must not ' +
                        'include a fragment component. ' +
                        '"' + text + '" does — and a fragment is ' +
                        'the part of a URI a server never receives, so an ' +
                        'audience carrying one names something no resource ' +
                        'server can match.' };
      }
      if (wanted.indexOf(text) < 0) {
        wanted.push(text);
      }
    }
    log.debug("Leaving OAuth2Server.parseResourceIndicators(). " +
              wanted.length + " resource(s).");
    return { resources: wanted };
  }

  // ---------------------------------------------------------------------------
  // A SCOPE THAT NAMES ANOTHER APPLICATION IS AN AUDIENCE, and the access token
  // says so instead.
  //
  // RFC 8707 above is how a client SHOULD ask which resource server a token is
  // for, and it is what this service already honoured. It is not what clients
  // actually do. The overwhelmingly common shape — the one every deployment of
  // this pattern has, and the one the debugger sends — is a scope list carrying
  // the name of the API the token is meant for:
  //
  //     scope=openid email profile offline_access apigw1
  //
  // and no `resource` parameter at all. Before this, such a request produced an
  // access token audienced to `<base>/resource`, the stand-in for a resource
  // nobody named — so the ONE fact in the request about which party the token
  // was for went into a string nothing reads, and the token said it was for
  // everything this service protects. Every downstream reader inherited that:
  // /admin/tokens showed a party column with a placeholder in it, and
  // /admin/delegation/user could not draw the first hop of a chain, because the
  // only line it has to draw a `reaches` from is the audience.
  //
  // So a scope value that is the CLIENT_ID OF ANOTHER APPLICATION in this
  // registry becomes the audience, and comes out of the scope list. Four things
  // about that are decisions rather than mechanics.
  //
  // **THE MATCH IS AGAINST `oauthClientId`, NOT AGAINST THE IDENTIFIER OR THE
  // AUDIENCE.** `applications.forClientId()` is a lookup of its own for the
  // reason its header gives — matching `oauthAudience` would mean a scope had
  // to be a URL to work, and matching the entry's `cn` would mean an
  // application created from the console under one name and registered under
  // another matched on the wrong one. A scope is a bare name, so it is compared
  // with the bare name a client answers to.
  //
  // **THE AUDIENCE IS THE SCOPE VALUE VERBATIM, not the matched application's
  // `oauthAudience`.** The client said `apigw1`, so the token says `aud:
  // apigw1`, which is the same spelling the ID Token uses for the party it is
  // for and the same one `applications.get()` and the delegation register file
  // everything under. Substituting the registered URL would be this endpoint
  // deciding that a client asking for one string meant another — and it would
  // break the moment an application has no `oauthAudience`, which most of them
  // do not.
  //
  // **A SPEC-DEFINED SCOPE IS NEVER AN AUDIENCE, whatever the registry says.**
  // `PROTOCOL_SCOPES` below is that vocabulary, and the guard is not
  // theoretical: nothing stops somebody registering a client called `profile`,
  // and without this every OIDC request in the service would start issuing
  // tokens audienced to it. A protocol's own word wins over a registration,
  // always.
  //
  // **THE CLIENT'S OWN client_id IS SKIPPED.** `scope=webapp1` from webapp1 is
  // a token addressed to itself, which is what an ID Token already is; drawing
  // it would put a line from a box to itself on every picture in the console.
  //
  // A request that names none of these is unaffected in every respect — same
  // scope, same default audience — which is what keeps this invisible to every
  // caller that was working before, exactly like the RFC 8707 block above.
  // ---------------------------------------------------------------------------

  // The scope values this service's protocols define, which is the whole of
  // what is exempt above. Computed rather than written out, because three of
  // the four groups can change while the process runs: the SCIM scope names are
  // settings, and the OpenID4VCI ones come from the credential configurations.
  // A list written here would have gone stale the first time `scim.scopeRead`
  // was set from /admin/config, and the symptom would have been a token quietly
  // audienced to whatever an application had registered that name as.
  protocolScopes(): Json {
    const { log, VCI_CONFIGS, config } = this.deps;
    log.debug("Entering OAuth2Server.protocolScopes().");
    // OpenID Connect Core 1.0 section 5.4, plus section 11's offline_access.
    // All six, including the two this service issues no claims for: `address`
    // and `phone` are still OpenID Connect's words and must not become an
    // audience because nothing here answers them.
    const names = ['openid', 'profile', 'email', 'address', 'phone',
                   'offline_access'];
    // RFC 7644 section 2, by way of scim_auth.js. Their names are settings,
    // which is why they are read and not written — see the note above.
    names.push(String(config.value('scim.scopeRead') || 'scim:read'));
    names.push(String(config.value('scim.scopeWrite') || 'scim:write'));
    // OpenID4VCI 1.0 section 5.1.2: a credential configuration may name a
    // scope, and a wallet asks for the credential by asking for it.
    Object.keys(VCI_CONFIGS).forEach(function (id) {
      const scope = VCI_CONFIGS[id] && VCI_CONFIGS[id].scope;
      if (scope && names.indexOf(scope) < 0) {
        names.push(String(scope));
      }
    });
    log.debug("Leaving OAuth2Server.protocolScopes(). " +
              names.length + " reserved name(s).");
    return names;
  }

  // Split a scope list into the scopes it really is and the audiences it was
  // naming. Returns the scope string to put ON the access token and the
  // audiences to address it to; `audiences` is empty for every request that
  // names none, and the caller then changes nothing.
  audienceScopes(scope: Json, clientId: Json): Json {
    const { log, logArtifact, applications, delegation } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.audienceScopes(). " +
              "scope=" + (scope || '(none)'));
    const asked = String(scope || '').split(/\s+/).filter(Boolean);
    if (!asked.length) {
      log.debug("Leaving OAuth2Server.audienceScopes(). Nothing was asked " +
                "for.");
      return { scope: String(scope || ''), audiences: [], matched: [],
               permissions: [], ungranted: [] };
    }
    const reserved = self.protocolScopes();
    const mine = String(clientId || '').trim();
    const kept = [];
    const audiences = [];
    const matched = [];
    // The delegated permissions among them, and the subset of those this client
    // has not been granted. Both are carried out of here rather than recomputed
    // by the caller, because recomputing means a second walk of the registry
    // per token and a second implementation of `base + name`.
    const permissions = [];
    const ungranted = [];
    asked.forEach(function (one) {
      if (reserved.indexOf(one) >= 0 || (mine && one === mine)) {
        // A protocol's own word, or this client naming itself. Both stay scopes
        // and neither is looked up — see the third and fourth decisions above.
        kept.push(one);
        return;
      }
      // A DEFINED PERMISSION IS TRIED FIRST, and it is the more specific of the
      // two matches: a permission identifier is a whole URI with a name on the
      // end of it and a client_id is a bare word, so the two cannot collide in
      // practice — but where a registration ever managed to make them, the
      // permission is the one that carries more information and is the one a
      // client that wrote a URI meant.
      const permission = applications.forPermission(one);
      if (permission) {
        // THE BASE URI IS THE AUDIENCE AND THE NAME IS THE SCOPE, which is
        // Microsoft Entra ID's behaviour exactly and is the whole point of the
        // feature: `scope=https://example.com/write` produces `aud:
        // https://example.com/` and `scope: write`, so a resource server checks
        // its audience once and then reads bare permission names.
        //
        // This is the ONE place in the block that SUBSTITUTES rather than
        // carrying the value through, and it is the exception to the second
        // decision above ("the audience is the scope value verbatim"). The
        // reason it is right here and wrong there is that a permission is a
        // COMPOSITE identifier that this service composed: the base and the
        // name are two facts written on an entry, and taking the whole string
        // as the audience would address the token to a permission rather than
        // to the API — nothing would ever be able to check that `aud` against
        // anything, because no application answers to
        // `https://example.com/write`.
        if (audiences.indexOf(permission.baseUri) < 0) {
          audiences.push(permission.baseUri);
        }
        // The name, unless a scope of that name is already on the list. Two
        // permissions on two different resources may legitimately both be
        // called `read`, and a scope claim carrying `read read` is one this
        // service wrote badly rather than two grants.
        if (kept.indexOf(permission.name) < 0) {
          kept.push(permission.name);
        }
        // WHETHER THE CLIENT HOLDS THE GRANT, asked here and REFUSED NOWHERE in
        // this function. This is a translation, and a translation that also
        // decided policy would have to be called from the two places that
        // refuse AND from the six grants that mint — see
        // `permissionRefusal()`, which is where the decision is, and which
        // asks the same question through the same lookup.
        const held = applications.holdsPermission(mine, permission.id);
        permissions.push({ scope: one, identifier: permission.identifier,
                           permission: permission.name,
                           audience: permission.baseUri,
                           granted: held });
        if (!held) {
          ungranted.push(one);
        }
        matched.push({ scope: one, identifier: permission.identifier,
                       permission: permission.name });
        return;
      }
      const application = applications.forClientId(one);
      if (!application) {
        // An ordinary scope nobody here has heard of, which is most of them and
        // is exactly what a caller comes to this service to send. Kept
        // verbatim — this function translates; whether the client may HAVE
        // it is scopeRefusal()'s question (#110), asked before this runs.
        kept.push(one);
        return;
      }
      if (audiences.indexOf(one) < 0) {
        audiences.push(one);
        matched.push({ scope: one, identifier: application.identifier });
      }
    });
    if (permissions.length) {
      logArtifact('scopes naming a delegated permission',
                  'read as an audience and a scope',
                  permissions);
      permissions.forEach(function (one) {
        log.info('The scope "' + one.scope + '" is the permission "' +
                 one.permission +
                 '" exposed by the application "' + one.identifier + '". The ' +
                 'access token for client ' +
                 '"' + (mine || '(unnamed)') + '" is being ' +
                                                          'addressed to ' +
                 one.audience + ' and carries "' + one.permission + '" on ' +
                 'its scope claim, which is how Microsoft Entra ID spells ' +
                 'the same arrangement. That client ' +
                 (one.granted
                   ? 'HOLDS this grant (oauthDelegatedPermission on its entry).'
                   : 'has NOT been granted it. In development it is honoured ' +
                     'and recorded as ungranted — set ' +
                     'oauth2.delegatedPermissionsEnforced to refuse it ' +
                     'instead; product mode refuses it. /admin/delegation ' +
                     'is where the grant is made.'));
      });
    }
    if (audiences.length) {
      logArtifact('scopes naming an application', 'read as an audience',
                  matched);
      log.info('An access token for client "' + (mine || '(unnamed)') +
               '" is ' +
               'being addressed to ' + audiences.join(', ') + ', named as ' +
               (audiences.length === 1 ? 'a scope' : 'scopes') + ' rather ' +
               'than through RFC 8707\'s resource ' +
               'parameter. ' + matched.map(function (one) {
                 return '"' + one.scope + '" is the client_id of the ' +
                                          'application "' +
                        one.identifier + '"';
               }).join('; ') + '. It is the audience now and not a scope, so ' +
               'it is not on the token\'s scope claim; the grant still ' +
               'remembers it, which is what keeps a refresh from widening ' +
               'the ' +
               'audience.');
    }
    log.debug("Leaving OAuth2Server.audienceScopes(). " +
              audiences.length + " audience(s), " +
              kept.length + " scope(s), " + permissions.length +
              " permission(s).");
    return { scope: kept.join(' '), audiences: audiences, matched: matched,
             permissions: permissions, ungranted: ungranted };
  }

  // ---------------------------------------------------------------------------
  // THE ONE REFUSAL DELEGATED PERMISSIONS MAKE, AND WHERE IT IS MADE.
  //
  // `audienceScopes()` above TRANSLATES and refuses nothing: it turns a
  // permission identifier into an audience and a scope whether or not the
  // client holds the grant, and reports which. This function is the policy, and
  // it is separate for the reason that keeps `oauth2_bcp.js` out of the minting
  // path — a translation called from six grants must not also be the place a
  // request is turned away, or the decision is made six times and one of them
  // will get it wrong.
  //
  // **PRODUCT MODE ALWAYS ENFORCES IT (#110, 2026-09-22)**
  // (`mode.honoursUngrantedPermissions()`). In development it is off unless
  // `oauth2.delegatedPermissionsEnforced` is set, which is off by default, for
  // the reason README.md gives on its first page: a mock exists to exercise
  // clients, and a client is exercised by both answers.
  //
  // **IT IS NOT PART OF RFC 9700 MODE and must never be folded into it.** Every
  // check in `oauth2_bcp.js` cites a section of a published Best Current
  // Practice; a delegated permission cites nothing, because no RFC says an
  // authorization server must have one. It is Microsoft Entra ID's model, which
  // is a product's design rather than a standard, and putting it behind
  // `oauth2.rfc9700` would make `GET /oauth2/rfc9700` advertise a requirement
  // no document contains.
  //
  // **IT IS CALLED IN TWO PLACES AND THEY ARE THE TWO PLACES A CLIENT ASKS.**
  // The AUTHORIZATION endpoint, beside the `resource` and `claims` refusals and
  // for their stated reason — it is the last point at which the client is still
  // being talked to. And the TOKEN endpoint, once above the grant switch beside
  // `parseResourceIndicators()`, for the grants that never pass through the
  // authorization endpoint at all: client credentials, the password grant, the
  // token exchange, and a refresh that names a scope explicitly.
  //
  // **A GRANT ALREADY ISSUED IS NEVER RE-JUDGED.** An authorization code
  // redeemed without a `scope` of its own carries what was authorized, and this
  // service does not go back and ask whether that is still allowed — the same
  // rule federation follows about not re-checking a person after the session
  // exists. Turning the setting on therefore refuses the next REQUEST rather
  // than invalidating what is outstanding, which is what makes it safe to turn
  // on while something is running.
  // ---------------------------------------------------------------------------
  permissionRefusal(scope: Json, clientId: Json): Json {
    const { log, config, applications, delegation, mode } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.permissionRefusal().");
    // PRODUCT ALWAYS ENFORCES (#110, 2026-09-22); the setting turns it on in
    // development. See `mode.honoursUngrantedPermissions()`.
    const enforced = !mode.honoursUngrantedPermissions() ||
                     !!config.value('oauth2.delegatedPermissionsEnforced');
    if (!enforced) {
      log.debug("Leaving OAuth2Server.permissionRefusal(). Not enforced.");
      return '';
    }
    const named = self.audienceScopes(scope, clientId);
    if (!named.ungranted.length) {
      log.debug("Leaving OAuth2Server.permissionRefusal(). Nothing ungranted.");
      return '';
    }
    const who = String(clientId || '').trim();
    // The message names the grant that is missing AND where to make it, because
    // this is the one refusal in this service whose fix is a configuration
    // change in this service rather than a change to the request. A client
    // developer reading `invalid_scope` about a scope their own product defines
    // has no way to guess that.
    const description = (mode.honoursUngrantedPermissions()
      ? 'oauth2.delegatedPermissionsEnforced is on, and '
      : 'Product mode enforces delegated permissions, and ') +
      (who ? 'the client "' + who + '"' : 'this client') + ' has not been ' +
          'granted ' +
      (named.ungranted.length === 1 ? 'the permission ' : 'the permissions ') +
      named.ungranted.map(function (one) {
        return '"' + one + '"';
      }).join(', ') +
      '. ' + (named.ungranted.length === 1 ? 'It is' : 'They are') + ' ' +
          'defined by ' +
      named.permissions.filter(function (one) {
        return !one.granted;
      })
        .map(function (one) {
          return 'the application "' + one.identifier + '"';
        })
        .join(', ') +
      ', and a grant is a value of `oauthDelegatedPermission` on the ' +
      'requesting application\'s own entry in ou=applications — made at ' +
      '/admin/delegation, or through POST /admin-api/permissions/grant. In ' +
      'development with the setting OFF this request is honoured and the ' +
      'token is audienced and scoped exactly as a granted one would be.';
    log.debug("Leaving OAuth2Server.permissionRefusal(). " +
              named.ungranted.length + " ungranted.");
    return description;
  }

  // ---------------------------------------------------------------------------
  // THE SCOPES A CLIENT MAY BE ISSUED (#110, 2026-09-22) — rule 3au.
  //
  // `audienceScopes()` translates and `permissionRefusal()` decides the one
  // question delegated permissions ask; this is the OTHER policy, and it is a
  // function of its own for that header's reason: a translation must not also
  // be a policy. The decision is `common/scope_policy.ts`'s, shared with GNAP;
  // what this adds is this server's DEFAULT SET — OpenID Connect's six and
  // this realm's OpenID4VCI credential scopes, which is what a client that
  // declares no `oauthAllowedScope` may have in product mode.
  //
  // IT IS ASKED WHERE `permissionRefusal()` IS — the authorization endpoint,
  // the pushed authorization request endpoint and the token endpoint, before
  // anything is spent — and REFUSES, `invalid_scope` (RFC 6749 sections
  // 4.1.2.1 and 5.2), so a misconfigured client fails at the request that was
  // wrong. `tokenSet()` NARROWS instead, as the backstop for a grant carrying
  // its scope from earlier: a refresh, an exchange's inherited scope.
  //
  // **UNLIKE `permissionRefusal()`, A GRANT ALREADY ISSUED IS RE-JUDGED** at
  // that backstop. A permission is a relationship the client was granted; a
  // protected scope is a key to this service's own API, and removing it from a
  // client has to stop the next refresh minting it again — which is what the
  // resource servers' own re-check (`scopePolicy.declares()`) does for the
  // tokens already out.
  // ---------------------------------------------------------------------------
  credentialScopes(): string[] {
    const { log, VCI_CONFIGS } = this.deps;
    log.debug("Entering OAuth2Server.credentialScopes().");
    const names: string[] = [];
    Object.keys(VCI_CONFIGS).forEach(function (id) {
      const scope = VCI_CONFIGS[id] && VCI_CONFIGS[id].scope;
      if (scope && names.indexOf(String(scope)) < 0) {
        names.push(String(scope));
      }
    });
    log.debug("Leaving OAuth2Server.credentialScopes(). " + names.length);
    return names;
  }

  // This service's own protected scopes — `common/scope_policy.ts` reads
  // each resource server's own settings for them.
  protectedScopes(): string[] {
    const { log, scopePolicy } = this.deps;
    log.debug("Entering OAuth2Server.protectedScopes().");
    const names = scopePolicy.protectedScopes();
    log.debug("Leaving OAuth2Server.protectedScopes().");
    return names;
  }

  // null, or `{ code, error, description, scopes }` to refuse with.
  scopeRefusal(scope: Json, clientId: Json): Json {
    const { log, scopePolicy } = this.deps;
    log.debug("Entering OAuth2Server.scopeRefusal().");
    const refused = scopePolicy.refusal(scope, clientId,
                                        { defaults: this.credentialScopes() });
    log.debug("Leaving OAuth2Server.scopeRefusal(). " +
              (refused ? refused.code : 'allowed'));
    return refused;
  }

  // ---------------------------------------------------------------------------
  // THE `jti` OF A TOKEN THIS FUNCTION JUST SIGNED, for the delegation
  // register.
  //
  // Read back off the string rather than threaded out of `issue()`: that is one
  // decode of a value the caller already holds, against changing the return
  // type of the one helper every grant here mints through — and
  // `jsonFromB64u()` is the same reader an `actor_token` is decoded with.
  //
  // **IT IS AT MODULE SCOPE AND WAS A `const` INSIDE THE TOKEN EXCHANGE UNTIL
  // 2026-09-10.** The RFC 7523 assertion grant records a delegation act too and
  // sits ABOVE that branch, so the second caller either shared this one or
  // carried a copy — and a copy would be a second answer to what identifies a
  // credential on `/admin/delegation`, which is exactly what that register's
  // own header says goes wrong.
  //
  // It CANNOT THROW, for the reason the whole of `delegation.record()` is
  // wrapped: a token this endpoint has already issued must not be failed by a
  // console page.
  jtiOf(token: Json): Json {
    const { log, jsonFromB64u, errorCodes, refreshTokenCrypto } = this.deps;
    log.debug("Entering OAuth2Server.jtiOf().");
    // NO TOKEN IS NOT AN UNREADABLE TOKEN (2026-09-14). The token exchange asks
    // this about `exchanged.id_token` and `exchanged.refresh_token` whether or
    // not the exchange minted them, and the delegation act drops the absent
    // ones itself. Without this line `String(undefined || '').split('.')[1]` is
    // `undefined`, `b64uDecode()` base64-decodes the WORD "undefined", and the
    // bytes fail JSON.parse — so every exchange that minted no ID Token logged
    // STS-OAUTH-0182 at error with `Unexpected token '�', "�w^~)�"`, once per
    // suite mode, about a token that was never issued.
    const parts = String(token || '').trim().split('.');
    if (!token || parts.length < 2) {
      log.debug("Leaving OAuth2Server.jtiOf(). No token, or not a JWT.");
      return '';
    }
    try {
      // An encrypted refresh token is opened first; every other token this
      // service issues is a JWS and is read as it always was.
      if (refreshTokenCrypto.isEncrypted(token)) {
        const opened = refreshTokenCrypto.claimsOfIssued(token);
        if (!opened) {
          throw new Error('an encrypted refresh token just issued could ' +
                          'not be opened');
        }
        log.debug("Leaving OAuth2Server.jtiOf(). Opened.");
        return opened.jti || '';
      }
      log.debug("Leaving OAuth2Server.jtiOf().");
      return (jsonFromB64u(String(token || '').split('.')[1]) || {}).jti || '';
    } catch (e) {
      log.error(errorCodes.tag('STS-OAUTH-0182') + 'a token just issued ' +
                                                   'could not be re-read for ' +
                                                   'its jti: ' +
                e.message);
      log.debug("Leaving OAuth2Server.jtiOf(). It could not be read.");
      return '';
    }
  }

  // The `aud` claim for a list of them: one value where there is one, an array
  // where there are several. The same shape rule the RFC 8707 call sites use,
  // in one place because there are now four of them — a single-element array is
  // a shape some libraries read differently from a string, so the ordinary case
  // stays a string.
  audienceClaim(list: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.audienceClaim().");
    if (!list || !list.length) {
      log.debug("Leaving OAuth2Server.audienceClaim().");
      return undefined;
    }
    log.debug("Leaving OAuth2Server.audienceClaim().");
    return list.length === 1 ? list[0] : list.slice(0);
  }

  // ---------------------------------------------------------------------------
  // AN `openid` TOKEN WAS FOR THIS SERVICE AS WELL — UNTIL 2026-09-13, AND THE
  // REVERSAL IS RFC 9068's.
  //
  // This block held `withOwnResource()`, which APPENDED this service's own
  // resource indicator beside an API a scope had named, so that `scope=openid
  // email profile apigw1` produced a token that could still call UserInfo. Its
  // argument was sound for RFC 9700 section 2.3, which allows "a small set of
  // resource servers", and it is kept here because the reason for reversing it
  // is a different RFC rather than a mistake in it: RFC 9068 section 2.2.3 says
  // every scope on a JWT access token MUST have meaning for the resources in
  // its aud, and section 5 that each must "unambiguously correlate" to one.
  // `apigw1` handed `openid email profile` cannot tell which of those are its
  // own. rcbj chose (2026-09-13) the Entra ID answer over refusing the request
  // and over keeping both: the token is for the API alone, and the OIDC scopes
  // stay GRANTED — the ID Token is minted, the refresh token keeps the whole
  // scope — without riding on a token for somebody else. A client that wants
  // UserInfo asks for a token without the API in it.
  //
  // `accessTokenPlan()` is what replaced it, and it is ONE decision where there
  // were two: which audiences an access token names AND which scopes it may
  // carry for them, made by `jwt_access_token.ts`'s `audiencePlan()` from a
  // classification only this module can make — which scope values name an
  // application or a delegated permission is the registry's answer, through
  // `audienceScopes()`. It is asked in four places and they are the four the
  // audience derivation was already asked in: `tokenSet()` for every grant, the
  // authorization endpoint's implicit and hybrid mint, and — so that a client
  // is told while it can still be talked to — the authorization endpoint before
  // a code is minted and the token endpoint above the grant switch.
  // ---------------------------------------------------------------------------

  // An `aud`-shaped value — undefined, one string, or a list — as a list.
  audienceList(value: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.audienceList().");
    if (value === undefined || value === null || value === '') {
      log.debug("Leaving OAuth2Server.audienceList(). None.");
      return [];
    }
    log.debug("Leaving OAuth2Server.audienceList().");
    return (Array.isArray(value) ? value : [value]).map(String);
  }

  accessTokenPlan(base: Json, scope: Json, clientId: Json, explicit: Json,
                  details: Json): Json {
    const { log, jwtAccessToken, richAuthorization } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.accessTokenPlan(). scope=" +
              (scope || '(none)'));
    const named = self.audienceScopes(scope, clientId);
    const permissionOf: Json = {};
    named.permissions.forEach(function (one) {
      permissionOf[one.scope] = one;
    });
    // The client_ids a scope named, which are the `matched` rows that are not
    // permissions: audienceScopes() writes both into one list.
    const applicationScopes = named.matched.filter(function (one) {
      return !one.permission;
    }).map(function (one) {
      return one.scope;
    });
    const seen = [];
    const scopes = [];
    String(scope || '').split(/\s+/).filter(Boolean).forEach(function (one) {
      if (seen.indexOf(one) >= 0) {
        return;
      }
      seen.push(one);
      const permission = permissionOf[one];
      if (permission) {
        scopes.push({ value: one, kind: 'permission',
                      name: permission.permission,
                      audience: permission.audience });
        return;
      }
      if (applicationScopes.indexOf(one) >= 0) {
        scopes.push({ value: one, kind: 'audience' });
        return;
      }
      scopes.push({ value: one,
                    kind: jwtAccessToken.OIDC_SCOPES.indexOf(one) >= 0 ?
                          'oidc' : 'ordinary' });
    });
    const plan = jwtAccessToken.audiencePlan({
      ownResource: jwtAccessToken.defaultAudienceFor(base),
      explicit: self.audienceList(explicit),
      scopes: scopes,
      // RFC 9396: the resource server the details' types belong to.
      details: richAuthorization.audienceFor(details)
    });
    // What the scope list named, for the refresh token's `resources` — see
    // tokenSet().
    plan.derived = named.audiences.slice(0);
    if (plan.stripped.length) {
      log.info('RFC 9068 section 2.2.3: the access token for client "' +
               String(clientId || '(unnamed)') + '" is addressed to ' +
               plan.audiences.join(', ') + ', which is not this service\'s ' +
               'own resource server, so the OpenID Connect scope(s) ' +
               plan.stripped.join(', ') + ' are not on its scope claim. They ' +
               'are still granted: the ID Token and the refresh token carry ' +
               'them, and a token without the API in its request is the one ' +
               'UserInfo accepts.');
    }
    log.debug("Leaving OAuth2Server.accessTokenPlan(). " +
              (plan.refusal ? 'Refused.' : plan.audiences.length +
                                           ' audience(s).'));
    return plan;
  }

  // A refusal accessTokenPlan() made at the point a token was about to be
  // minted, carried out of tokenSet() to the token endpoint the way
  // IssuanceRefused carries the role gate's: every grant mints through issue(),
  // and that is where one catch can answer all of them.


  // A refusal by one of the two REFRESH TOKEN sender-constraint settings (#34,
  // 2026-09-15), carried the same way and for the same reason. It is thrown
  // from `issue()` rather than checked once at the top of the token endpoint
  // because the question is "is a refresh token about to be minted", and the
  // only honest answer to that is `withRefresh`, which the grant decides — a
  // list of grants kept beside it would be the second list that eventually
  // disagrees, which is the argument `issuanceKindsOf()` already makes.
  //
  // THE WHOLE REQUEST IS REFUSED, access token included. Minting the access
  // token and dropping the refresh token silently would leave a client that
  // believes it has a durable grant and discovers otherwise an hour later,
  // which is a worse failure than the error it gets instead.


  // Build the authorization response for a signed-in user and redirect back to
  // the client. Everything after authentication — which is "as normal".
  //
  // ASYNCHRONOUS BECAUSE idToken() IS — the implicit and hybrid flows mint one
  // here rather than at the token endpoint, and a client may have registered a
  // post-quantum `id_token_signed_response_alg` for either.
  //
  // `issuedAcr` is RFC 9470 section 5's: the requested acr value the session
  // met, which is what the code, the ID Token and the access token carry in
  // place of the session's own. Absent where nothing was requested.
  async issueAuthorizationResponse(req: Req, res: Res, query: Json,
                                   user: Json, authTime: Json,
                                   authInfo: Json,
                                   issuedAcr?: Json): Promise<any> {
    const { log, logArtifact, randomId, hasScope, bcp, oauth21, frontchannel,
            applications, errorCodes, par, gate, debuggerAccess,
            clusterClaims, requestObject } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.issueAuthorizationResponse().");
    // Everything minted below is this authorization server's, so the base it is
    // built from is this authorization server's.
    const amr = (authInfo && authInfo.amr) || null;
    const acr = issuedAcr || (authInfo && authInfo.acr) || null;
    // The session this response is being issued ON. Every path into this
    // function has one — an unauthenticated request is shown the login screen
    // instead — so an empty id here would mean a session object arrived from
    // somewhere that did not make it, which is worth seeing on the console
    // rather than defaulting quietly.
    const sessionId = (authInfo && authInfo.id) || '';
    log.debug("Entering OAuth2Server.issueAuthorizationResponse(). " +
              "response_type=" + (query.response_type || '(none)') +
              ", user=" + user.username);
    const base = self.asBaseOf(req);
    const redirectUri = String(query.redirect_uri);
    const types = String(query.response_type || '').split(/\s+/)
      .filter(Boolean);
    // The debugger permission comes off here for anybody who may not hold it,
    // before a code carries it — see `debugger/debugger_access.ts`, and the
    // backstop in tokenSet().
    // NO SCOPE IS NO SCOPE (#118): a missing one used to be `openid`, which
    // made a plain OAuth request an OpenID Connect one it had not asked to be.
    // And `offline_access` is kept only where OIDC Core section 11 allows it —
    // see offlineAccessScope().
    const scope = debuggerAccess.narrowScope(
      self.offlineAccessScope(String(query.scope || ''), query, types, user),
      { kind: 'user', name: user.username,
        authenticated: !authInfo || authInfo.authenticated !== false },
      { clientId: query.client_id, grant: 'authorization_code' });
    const out: Json = {};
    const parsedDetails = self.parseAuthorizationDetails(
      query.authorization_details, { clientId: query.client_id, req: req });
    if (parsedDetails.error) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). " +
                parsedDetails.error);
      errorCodes.mark(res,
                      errorCodes.codeOf(parsedDetails) || 'STS-OAUTH-0153');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: 'invalid_authorization_details',
          error_description: parsedDetails.error },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }
    const authorizationDetails = parsedDetails.details;
    if (authorizationDetails) {
      logArtifact('authorization_details', 'as requested',
                  authorizationDetails);
    }

    // RFC 8707. Refused here rather than at the token endpoint because this is
    // where the client can still be told: an authorization response goes back
    // to a redirect_uri the client controls, and a token endpoint refusal for a
    // parameter sent an interaction earlier is a message nobody is reading for.
    const parsedResources = self.parseResourceIndicators(query.resource);
    if (parsedResources.error) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). " +
                parsedResources.error);
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      errorCodes.mark(res, 'STS-OAUTH-0154');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: 'invalid_target', error_description: parsedResources.error },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }
    const resources = parsedResources.resources;
    if (resources.length) {
      logArtifact('RFC 8707 resource indicators', 'as requested', resources);
    }

    // DELEGATED PERMISSIONS, refused here for exactly the reason `resource` is
    // refused in the block above: this is the last point at which the client is
    // still being talked to. `invalid_scope` is RFC 6749 section 4.1.2.1's own
    // code for a scope that is invalid or exceeds what this client may have,
    // which is precisely what an ungranted permission is — so no new code had
    // to be invented and a client library's existing handling applies.
    //
    // Always in product mode; in development a no-op unless
    // `oauth2.delegatedPermissionsEnforced` is on. See permissionRefusal().
    const permissionProblem = self.permissionRefusal(scope, query.client_id);
    if (permissionProblem) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). An " +
                "ungranted permission was asked for.");
      errorCodes.mark(res, 'STS-OAUTH-0155');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: 'invalid_scope', error_description: permissionProblem },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }

    // THE SCOPES THIS CLIENT MAY BE ISSUED (#110), for the same reason and in
    // the same shape: `invalid_scope`, redirected, while the client is still
    // being talked to. This service's own protected scopes in every mode,
    // every other undeclared scope in product. See scopeRefusal().
    const scopeProblem = self.scopeRefusal(scope, query.client_id);
    if (scopeProblem) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). A scope " +
                "the client did not declare was asked for.");
      // STS-OAUTH-0577 (protected) or STS-OAUTH-0578 (undeclared).
      errorCodes.mark(res, scopeProblem.code);
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: 'invalid_scope', error_description: scopeProblem.description },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }

    // RFC 9068 SECTION 3, refused here for the reason the two blocks above are:
    // a code for a request whose access token could never be issued
    // unambiguously is a code the client will spend for an error it cannot
    // connect to this request. The same plan mints the implicit and hybrid
    // token below, and tokenSet() asks it again when the code is redeemed. In
    // every mode — see `jwt_access_token.ts`'s header.
    const audiencePlan = self.accessTokenPlan(base, scope, query.client_id,
                                         resources, authorizationDetails);
    if (audiencePlan.refusal) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). RFC 9068 " +
                "refused the audience.");
      errorCodes.mark(res, errorCodes.codeOf(audiencePlan.refusal) ||
                           'STS-OAUTH-0244');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: audiencePlan.refusal.error,
          error_description: audiencePlan.refusal.description },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }

    // THE ROLE GATE, and it is asked HERE for the same reason as the two blocks
    // around it: this is the last point at which the client is still being
    // talked to. A person who holds none of the roles this application requires
    // is turned away with `access_denied` — RFC 6749 section 4.1.2.1's own code
    // for a request the authorization server denied — sent back to the
    // redirect_uri the client controls, so a relying party sees a refusal it
    // can render rather than a page on this service that its user has to read.
    //
    // WHAT IS BEING ISSUED HERE IS THE AUTHORIZATION CODE, and that is the word
    // the policy is asked about even where the response type is `token
    // id_token` and no code is minted. The alternative — asking about whichever
    // of the three this response type happens to carry — would make an implicit
    // flow decidable by a rule an authorization-code flow was not, on a
    // distinction no policy author is thinking about. The TOKEN endpoint asks
    // about the tokens, which is where they are actually made, and this asks
    // about the interaction.
    //
    // ALSO ASKED AFTER THE CONSENT SCREEN AND NOT BEFORE IT, which falls out of
    // where this function is reached from rather than being arranged: a person
    // is asked what they agree to and then told whether they may. The other
    // order would ask somebody to consent to something they were about to be
    // refused.
    const roleAnswer = gate.check({
      application: String(query.client_id || ''),
      kind: gate.ISSUANCE.AUTHORIZATION_CODE,
      // READ OFF THE SESSION SINCE 2026-09-05, where it was the constant
      // `true`. `issueAuthorizationResponse()` is handed the session's user,
      // and until unauthenticated sessions existed there was no session whose
      // answer could be anything else. `!== false` keeps a session made before
      // the field existed meaning what it meant.
      subject: { kind: 'user', name: String(user.username || ''),
                 authenticated: (authInfo || {}).authenticated !== false },
      claims: null,
      // The session this response is issued on, whose risk the policy reads
      // (#62 P3).
      session: authInfo || null
    });
    // -----------------------------------------------------------------------
    // A STEP-UP ON RISK IS A SIGN-IN, NOT AN ERROR (#62 P3). The policy
    // denied on the risk of the session this response would rest on and
    // named a factor; the person is here, in a browser, so they are sent to
    // re-authenticate with that factor demanded — the same road RFC 9470's
    // step-up takes, back to this same request — rather than handed an
    // access_denied the client can do nothing about. A person holding no
    // such factor is refused at the screen (STS-RISK-0018), and a session
    // the re-authentication met is permitted when the request comes round.
    // -----------------------------------------------------------------------
    if (!roleAnswer.allowed && roleAnswer.risk &&
        roleAnswer.risk.action === 'step-up' && !roleAnswer.risk.observed &&
        (authInfo || {}).authenticated !== false) {
      errorCodes.mark(res, 'STS-RISK-0017');
      log.info('oauth2: the issuance policy asks for a ' +
               roleAnswer.risk.factor + ' on the risk of the session of "' +
               String(user.username || '') + '"; sent to re-authenticate.');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). A " +
                "step-up on risk.");
      return res.redirect(302, this.deps.authn.beginAuthentication({
        returnTo: self.asPathOf(req) + '/oauth2/authorize?' +
                  self.authorizationReturnQuery(req, query),
        hint: String(user.username || ''),
        forceMfa: roleAnswer.risk.factor === 'second-factor',
        forceKey: roleAnswer.risk.factor === 'security-key',
        protocol: 'OAuth 2.0 / OIDC',
        application: String(query.client_id || '')
      }));
    }
    if (!roleAnswer.allowed) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). The " +
                "issuance policy refused it.");
      errorCodes.mark(res, 'STS-OAUTH-0156');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: 'access_denied', error_description: roleAnswer.why },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }

    // OpenID Connect Core section 5.5 — the claims request. Refused HERE for
    // the same reason `resource` is refused two blocks up: this is the last
    // point at which the client is still being talked to, and a token endpoint
    // refusal for a parameter sent an interaction earlier is a message nobody
    // is reading for. `invalid_request` rather than a name of its own, because
    // section 5.5 defines no error code for it and inventing one would send a
    // client looking for a code no other provider returns.
    const parsedClaims = self.parseClaimsRequest(query.claims);
    if (parsedClaims.error) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). " +
                parsedClaims.error);
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      errorCodes.mark(res, 'STS-OAUTH-0157');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: 'invalid_request', error_description: parsedClaims.error },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }
    const claimsRequest = parsedClaims.claims;
    if (claimsRequest) {
      logArtifact('claims request', 'as understood (OIDC Core 5.5)',
                  claimsRequest);
    }

    // RFC 9700 section 2.1.1 — the code_challenge and the nonce must be
    // transaction-specific. Checked HERE, immediately before anything is
    // minted, and nowhere else: this same request runs through the
    // authorization endpoint TWICE — once before the sign-in screen and once on
    // the way back with a session — so a check at the top of that endpoint
    // would refuse every request in the service for reusing its own values
    // between its own two passes. Reaching this function is the point at which
    // the values are about to be spent, which is the thing being made specific.
    const transactionCheck = bcp.checkTransactionValues({
      query: query, clientId: String(query.client_id) });
    if (!transactionCheck.ok) {
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). RFC 9700 " +
                "mode refused a reused transaction value " +
                "(" + transactionCheck.requirement + ").");
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      errorCodes.mark(res, transactionCheck.errorCode || 'STS-OAUTH-0158');
      log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
      return self.redirectBack(res, base, redirectUri, query.state,
        { error: transactionCheck.error,
          error_description: transactionCheck.description },
        self.usesFragment(types, query.response_mode),
        query.response_mode);
    }

    // RFC 9126: A PUSHED REQUEST_URI IS SPENT HERE, where something is issued
    // on it, and not where it was first read — the browser reads it before the
    // sign-in screen and again after, and both are this one request (`par.ts`,
    // decision 2). Below every refusal above, so a request refused for its
    // audience or its role is not also a request_uri thrown away; above the
    // minting, so a replay racing this response finds it spent.
    //
    // THROUGH A CLAIM FIRST (2026-09-14, #46). `par.spend()` marks the record,
    // and `resolve()` refusing a marked one is the fast refusal — but two
    // authorization responses on one request_uri racing on two nodes both read
    // an unmarked record, and the mark reaches the other node a moment after it
    // is written. The claim is atomic in the store, so exactly one of them
    // issues. Bound to the response like the code's: a redirect or a form_post
    // page keeps it, a failure after this line gives it back.
    if (req.stsJar && req.stsJar.source === 'par' && req.stsJar.pushed) {
      const pushedUri = req.stsJar.pushed.requestUri;
      const parClaim = await clusterClaims.claim({
        scope: 'oauth.par', value: pushedUri,
        ttlMs: Math.max(0, Number(req.stsJar.pushed.expiresAt || 0) -
                           Date.now()) +
               Number(self.tokenClockSkew() || 0) * 1000
      });
      if (!parClaim.ok) {
        const stored = parClaim.reason === 'used';
        log.warn(errorCodes.tag(stored ? 'STS-OAUTH-0514' : 'STS-OAUTH-0515') +
                 'oauth2: an authorization response on a pushed request_uri ' +
                 'was refused: ' + (stored ? 'another response was issued on ' +
                 'it at the same moment' : 'the claim store could not be ' +
                 'asked (' + (parClaim.why || 'no reason given') + ')') + '.');
        log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). The " +
                  "request_uri's claim was refused.");
        if (stored) {
          errorCodes.mark(res, 'STS-OAUTH-0514');
          return self.oauthError(res, 400, 'invalid_request_uri',
            'the request_uri was already used: an authorization response was ' +
            'issued on it by another request at the same moment. A client ' +
            '"MUST only use a request_uri value once" (RFC 9126 section 4); ' +
            'push the request again.');
        }
        errorCodes.mark(res, 'STS-OAUTH-0515');
        return self.oauthError(res, 500, 'server_error',
          'This authorization server could not record that the request_uri ' +
          'is being used, so it has issued nothing on it.');
      }
      clusterClaims.releaseUnlessSucceeded(res, parClaim.handle);
      par.spend(pushedUri);
    }

    // RFC 9101: A REQUEST OBJECT'S `jti` IS SPENT HERE (#35), for the pushed
    // request_uri's reason above — every pass before this one only looked at
    // it (`request_object.ts`'s `lookUp()`). An atomic claim in the
    // used-assertion history, bound to this response and kept by anything
    // under 400: a redirect and a form_post page are what issuing looks like
    // here. A pushed request carries no `once`; its push was its use.
    if (req.stsJar && req.stsJar.once) {
      const spent = await requestObject.spend({
        once: req.stsJar.once, request: req, keepBelow: 400,
        clientId: String(query.client_id)
      });
      if (!spent.ok) {
        log.debug("Leaving OAuth2Server.issueAuthorizationResponse(). The " +
                  "request object's jti was not spent.");
        errorCodes.mark(res, errorCodes.codeOf(spent) || 'STS-OAUTH-0374');
        return self.oauthError(res, spent.status || 400, spent.error,
                               spent.description);
      }
    }

    // THE APPLICATION. Recorded here and not at the authentication funnel,
    // because the funnel cannot see it: the person was authenticated in
    // authn.js, which knows nothing about OAuth by design and never reads a
    // client_id. This is the first point at which both are in scope, and it is
    // the point at which this service decides the client is real enough to be
    // issued something.
    //
    // `counts: true` — a credential WAS accepted for this application, which is
    // what appAuthentications means. The token endpoint below records the same
    // client with counts:false, since redeeming the code is the same
    // transaction continuing rather than a second acceptance.
    //
    // The redirect_uri goes on as appRedirectUriObserved and NOT as
    // oauthRedirectUri: "registered" and "used" are different facts, and RFC
    // 9700 section 2.1 is entirely about not confusing them — the exact-match
    // check reads the registered list, and writing an accepted URI into it
    // would make this endpoint quietly widen its own allow-list.
    applications.seen({
      identifier: String(query.client_id),
      kind: hasScope(scope, 'openid') ? 'oidc-relying-party' : 'oauth2-client',
      protocol: 'OAuth 2.0 / OIDC',
      sessionId: sessionId,
      user: (user && user.username) || '',
      note: 'issued an authorization response',
      fields: {
        oauthClientId: String(query.client_id),
        // Which of this process's authorization servers it used. Recorded
        // rather than restricted: every client may use every one of them, so
        // this says where it has been.
        appAuthorizationServer: self.profileOf(req),
        appRedirectUriObserved: redirectUri,
        oauthResponseType: types.join(' '),
        oauthScope: scope.split(/\s+/).filter(Boolean)
      }
    });

    // THE RELYING PARTY, ON THE SESSION. Front-Channel Logout 1.0 needs to know
    // which clients a session signed into so that a sign-out has somewhere to
    // fan out to, and this is the one point where both the client and the
    // session are in scope — the person was authenticated in authn.js, which
    // never reads a client_id, and the token endpoint sees the client without
    // the browser.
    //
    // It lives ON the session object, which is the same decision wsfed.ts makes
    // about `wsfedRealms` and saml2_sso.ts makes about `saml2ServiceProviders`:
    // the list should die exactly when the session does, and nothing then has
    // to sweep it.
    //
    // With the issuer and the subject the ID Token is issued under (2026-09-17,
    // #36), which is what a Logout Token for this client has to name — see
    // `noteClient()`.
    // The `sub` is the one the ID Token names — pairwise where the client
    // registered for it (#118) — because a Logout Token must match it.
    frontchannel.noteClient(authInfo, String(query.client_id),
                            { iss: self.issuerOf(base),
                              sub: self.subjectFor(query.client_id,
                                                   user.sub) });

    if (types.indexOf('code') >= 0) {
      const code = randomId(24);
      authzCodes.set(code, {
        client_id: String(query.client_id), redirect_uri: redirectUri,
        scope: scope,
        nonce: query.nonce, user: user, auth_time: authTime, amr: amr, acr: acr,
        // Carried on the code so that the tokens the code is redeemed for can
        // name the session it was issued on. It is the only route between the
        // two: the code arrives at the token endpoint with no cookie behind it,
        // and a browser session cannot be inferred from a back-channel request.
        session_id: sessionId,
        // WHETHER ANYBODY AUTHENTICATED FOR THE SESSION THIS CODE WAS ISSUED ON
        // (2026-09-05), carried for the same reason `session_id` is: the code
        // arrives at the token endpoint over a back channel with no cookie
        // behind it, so the session cannot be looked up and its answer cannot
        // be inferred. Without this the token endpoint would have to assume,
        // and what it used to assume was `true` for everybody.
        //
        // It is a fact ABOUT THE SESSION frozen when the code was minted, which
        // is the right reading rather than a limitation: what a required role
        // asks is who was authenticated when this authorization happened, and a
        // session that has since ended does not change what happened then.
        session_authenticated: (authInfo || {}).authenticated !== false,
        // WHICH AUTHORIZATION SERVER ISSUED IT. A code from one is not
        // redeemable at another's token endpoint, and that is not a formality:
        // they publish different capabilities, may have different clients
        // configured and are presented to a client as separate servers. One
        // process serving several must not let a credential leak between them.
        authorization_server: self.profileOf(req),
        // RFC 8707: what the authorization request asked the token to be for.
        // The token endpoint may narrow this and may not widen it.
        resources: resources,
        code_challenge: query.code_challenge,
        code_challenge_method: query.code_challenge_method || 'plain',
        // RFC 9449 section 10: the JWK Thumbprint of the DPoP key the client
        // intends to use, taken at the authorization request so the code itself
        // is bound. Stored verbatim and never derived — the whole value of the
        // parameter is that it was fixed BEFORE the code existed.
        dpop_jkt: query.dpop_jkt ? String(query.dpop_jkt) : '',
        // What the wallet asked to be authorized for, if it used
        // authorization_details rather than a scope. The token response has to
        // echo it back with the credential_identifiers it grants.
        authorization_details: authorizationDetails,
        // OIDC Core 5.5's claims request, carried on the code for the same
        // reason everything else here is: the token endpoint has the client and
        // not the browser, so this is the only route between the request that
        // was made and the tokens it is redeemed for.
        claims: claimsRequest,
        // OAUTH 2.1: whether this code was issued without PKCE under section
        // 7.5.1.1's OpenID Connect nonce exemption. The token endpoint then
        // requires the client to authenticate and still requires redirect_uri.
        // Empty outside that mode.
        pkce_exempt: oauth21.codeRecordFields(query, types).pkce_exempt || '',
        ttlMs: self.authCodeTtlMs(),
        expires: Date.now() + self.authCodeTtlMs()
      });
      out.code = code;
    }
    // Which grant the console will say issued these. A response carrying a code
    // AND a token is the hybrid flow rather than the implicit one, and the
    // distinction is worth keeping: it is the difference between a token that
    // came back through the browser and one that will come back through the
    // token endpoint.
    const flow = types.indexOf('code') >= 0 ?
                 'hybrid (authorization endpoint)' : 'implicit';
    // THE SECOND OF THE TWO PLACES A SET ID IS MINTED, and it is here for the
    // same reason the audience derivation two lines down is: a token that comes
    // back from the AUTHORIZATION endpoint never goes through tokenSet() at
    // all. `response_type=id_token token` hands the browser two credentials in
    // one fragment, and leaving this out would draw them as two unrelated rows
    // on /admin/tokens while the identical pair from the token endpoint drew as
    // one.
    //
    // It is minted even when the response carries only ONE credential, or none
    // at all (a bare `code`). An id nothing records costs a random string; a
    // conditional here would be a second rule about when a set exists, and the
    // one rule — a set is a response — is what makes "a set of one" mean the
    // same thing on every row of that table.
    const setId = randomId(12);
    if (types.indexOf('token') >= 0) {
      // The same reading tokenSet() does one grant later — see
      // audienceScopes(). It is done here TOO rather than only there because a
      // token that comes back from the AUTHORIZATION endpoint never goes
      // through tokenSet() at all: implicit and hybrid mint it on the spot, and
      // leaving this out would mean one flow's token said `apigw1` and
      // another's said `<base>/resource` for the same request. `resources`
      // still wins, for the reason given there. The plan is the one asked
      // above, before anything was minted.
      out.access_token = self.accessToken(base, {
        user: user,
        client_id: String(query.client_id),
        scope: audiencePlan.scope,
        audience: self.audienceClaim(audiencePlan.audiences),
        session_id: sessionId, grant: flow,
        set_id: setId,
        // RFC 9068 section 2.2.1: the authentication event behind this token,
        // as the ID Token beside it states it.
        auth_time: authTime, amr: amr,
        acr: acr,
        // The claims request travels on the token minted HERE too, or a
        // client using the implicit flow would send a section 5.5 request and
        // find the UserInfo endpoint had never heard of it.
        claims: claimsRequest });
      out.token_type = 'Bearer';
      out.expires_in = self.accessTokenTtl(String(query.client_id || ''));
      // What the ACCESS TOKEN carries, which is RFC 6749 section 5.1's rule
      // read through section 4.2.2 — and the code beside it in a hybrid
      // response is unaffected: `authzCodes` above holds the scope as
      // AUTHORIZED, so redeeming it derives the same audience again at the
      // token endpoint.
      out.scope = audiencePlan.scope;
    }
    if (types.indexOf('id_token') >= 0) {
      out.id_token = await self.idToken(base, {
        user: user, client_id: String(query.client_id), nonce: query.nonce,
        auth_time: authTime,
        amr: amr, acr: acr, session_id: sessionId, grant: flow, set_id: setId,
        access_token: out.access_token, code: out.code,
        // FAPI 1.0 Part 2 section 5.2.2.1 item 5 (#139): the ID Token from
        // the authorization endpoint is a detached signature over the state
        // too, when the client sent one. Added in every mode — a claim a
        // relying party does not know is one it ignores.
        state: query.state,
        claims: claimsRequest,
        // OIDC Core section 5.4: the scope-requested claims go in the ID
        // Token only when NO access token is issued — response_type=id_token
        // alone. See idToken().
        scope: scope,
        scopeClaims: types.length === 1
      });
    }
    // Remembered now that they have been spent, so the NEXT authorization
    // request carrying either of them can be told apart from this one being
    // retried. A response with no code in it ends its transaction here, so it
    // is recorded as finished rather than left open for a token endpoint call
    // that will never come.
    bcp.rememberTransactionValues({ query: query,
                                    clientId: String(query.client_id),
                                    completed: !out.code });

    // Only a bare code goes in the query; anything carrying a token uses the
    // fragment, per OAuth 2.0 / OIDC.
    logArtifact('Authorization response', 'as returned to the client', out);
    self.redirectBack(res, base, redirectUri, query.state, out,
      self.usesFragment(types, query.response_mode),
        query.response_mode);
    log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
    log.debug("Leaving OAuth2Server.issueAuthorizationResponse().");
  }

  formPostResponse(res: Res, redirectUri: Json, fields: Json): Json {
    const { app, log, xmlEscape } = this.deps;
    log.debug("Entering OAuth2Server.formPostResponse(). fields=" +
              Object.keys(fields).join(', '));
    const inputs = Object.keys(fields).map(function (name) {
      return '<input type="hidden" name="' + xmlEscape(name) + '" value="' +
             xmlEscape(String(fields[name])) + '">';
    }).join('');
    const rows = Object.keys(fields).map(function (name) {
      // The VALUES are shown because this is a debugger and seeing what went
      // back is most of the point — the same reason every artifact here is
      // logged before and after signing. It is also why this page must never be
      // cached: it has the response in it.
      return '<div>' + xmlEscape(name) + ': <code>' +
             xmlEscape(String(fields[name])) +
             '</code></div>';
    }).join('');
    const html = '<!doctype html><html lang="en"><head><meta ' +
      'charset="utf-8"><title>Returning to the client</title><style>' +
      'body{font-family:system-ui,sans-serif;margin:2rem;max-width:52rem;' +
      'color:#222}code{font-family:ui-monospace,Menlo,monospace;' +
      'font-size:.85rem;background:#f4f4f8;padding:.1rem .25rem;' +
      'border-radius:3px;word-break:break-all}.sub{color:#666}' +
      '.meta{margin-top:1.5rem;font-size:.9rem;color:#444}' +
      'button{font:inherit;padding:.4rem .9rem}</style></head><body>' +
      '<h1>Returning to the ' +
      'client</h1><p class="sub">OAuth 2.0 Form Post Response Mode — the ' +
      'authorization response travels in a form POST rather than in a ' +
      'redirect, so it never appears in a URL, in browser history or in a ' +
      '<code>Referer</code> header (RFC 9700 section 4.3).</p><form ' +
      'method="post" action="' + xmlEscape(redirectUri) + '" ' +
          'id="oauth2-form">' + inputs +
      '<div><button type="submit">Continue to the client</button></div>' +
      '</form>' +
      '<div class="meta"><div>posting to: <code>' + xmlEscape(redirectUri) +
      '</code></div>' +
      rows +
      '<div>The form submits itself from <code>/oauth2/autopost.js</code>. ' +
      'It is a separate resource because this service sets <code>script-src ' +
      '\'none\'</code> on every response and this page relaxes it to ' +
      '<code>\'self\'</code>; with scripting off the button IS the mechanism.' +
      '</div></div><script ' +
      'src="/oauth2/autopost.js"></script></body></html>';
    // The same shape of exception the WebAuthn and WS-Federation pages take,
    // and no wider: a named resource, never 'unsafe-inline'. Through the
    // builder, so the framing clauses survive any future edit to this line.
    res.set('Content-Security-Policy',
            app.contentSecurityPolicy({ 'script-src': "'self'" }));
    // The response is IN this page, so it must not be stored anywhere — which
    // is the whole reason the caller asked for form_post.
    res.status(200).type('text/html').set('Cache-Control', 'no-store')
       .send(html);
    log.debug("Leaving OAuth2Server.formPostResponse().");
  }

  // The URL a redirect WOULD have gone to, built by the same rules
  // `redirectBack()` follows so the interstitial's link and the automatic
  // redirect cannot differ — including WHERE the parameters go (#118): an
  // error from an implicit or hybrid request is in the fragment, as its
  // success would have been, and the link used to put it in the query.
  redirectTarget(base: Json, redirectUri: Json, state: Json, params: Json,
                 fragment?: Json): Json {
    const { log, oauth21 } = this.deps;
    log.debug("Entering OAuth2Server.redirectTarget().");
    const usp = new URLSearchParams();
    Object.keys(params)
          .forEach(function (k) {
            if (params[k] !== undefined) {
              usp.set(k, k === 'error_description'
                ? oauth21.sanitizeDescription(params[k]) : params[k]);
            }
          });
    if (state !== undefined) {
      usp.set('state', state);
    }
    usp.set('iss', base);
    const sep = fragment ? '#' : (redirectUri.indexOf('?') >= 0 ? '&' : '?');
    log.debug("Leaving OAuth2Server.redirectTarget().");
    return redirectUri + sep + usp.toString();
  }

  // ---------------------------------------------------------------------------
  // THE PAGE THAT IS SHOWN INSTEAD OF AN AUTOMATIC REDIRECT.
  //
  // It exists because of one sentence in RFC 9700 section 4.11.2 — authenticate
  // the user before redirecting them — and it is written for the PERSON looking
  // at it rather than for the client: they arrived at an authorization server
  // they may never have heard of, something is wrong with a request they did
  // not compose, and the next thing that happens is a hop to another site.
  // Telling them where and letting them choose is the section's own "inform the
  // user and rely on the user to make the correct decision".
  //
  // It carries no script and needs none: the link is a link. That is worth
  // saying because the two other pages here that post somewhere have a script
  // and a button, and this one deliberately has neither — an interstitial that
  // submitted itself would be an automatic redirect with an extra page in front
  // of it.
  // ---------------------------------------------------------------------------
  sendRedirectInterstitial(res: Res, info: Json): Json {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering OAuth2Server.sendRedirectInterstitial(). error=" +
              info.error);
    const html = '<!doctype html><html lang="en"><head><meta ' +
      'charset="utf-8"><title>This request could not be completed</title>' +
      '<style>body{font-family:system-ui,sans-serif;margin:2rem;' +
      'max-width:46rem;color:#222}code{font-family:ui-monospace,Menlo,' +
      'monospace;font-size:.85rem;background:#f4f4f8;padding:.1rem .25rem;' +
      'border-radius:3px;word-break:break-all}' +
      '.sub{color:#666;font-size:.92rem}' +
      '.warn{background:#fff8e1;border:1px solid #ffe082;padding:.7rem ' +
      '.9rem;border-radius:4px;margin:1rem ' +
      '0}dt{font-weight:600;margin-top:.7rem}dd{margin:.15rem 0 0 ' +
      '0}</style></head><body><h1>This request could not be completed</h1>' +
      '<div ' +
      'class="warn"><strong>' + xmlEscape(info.error) + '</strong><br>' +
      xmlEscape(info.description) + '</div>' +
      '<p class="sub">' + xmlEscape(info.why) + '</p>' +
      '<dl>' +
      '<dt>The application that sent you here</dt><dd><code>' +
      xmlEscape(info.clientId || '(it named none)') + '</code></dd>' +
      '<dt>Where it wants you sent next</dt><dd><code>' +
      xmlEscape(info.redirectUri) +
      '</code></dd>' +
      (info.state !== undefined && info.state !== ''
        ? '<dt>The state it chose</dt><dd><code>' +
          xmlEscape(String(info.state)) + '</code></dd>'
        : '') +
      '</dl>' +
      (info.form
        ? '<form method="post" action="' + xmlEscape(info.redirectUri) +
          '">' + Object.keys(info.form).map(function (name: string): string {
            return '<input type="hidden" name="' + xmlEscape(name) +
                   '" value="' + xmlEscape(String(info.form[name])) + '">';
          }).join('') + '<button type="submit">Continue to ' +
          xmlEscape(info.redirectUri) + '</button></form>'
        : '<p><a href="' + xmlEscape(info.target) + '">Continue to ' +
          xmlEscape(info.redirectUri) + '</a></p>') +
      '<p class="sub">Nothing has been ' +
      'sent anywhere yet. Following that link delivers the error above to ' +
      'the application, which is what would have happened automatically if ' +
      'you were signed in here.</p></body></html>';
    // error-code: none — every caller of fail() marks its own condition before this is reached
    res.status(400).type('text/html').set('Cache-Control', 'no-store')
       .send(html);
    log.debug("Leaving OAuth2Server.sendRedirectInterstitial().");
  }

  // -------------------------------------------------------------------------
  // QUERY OR FRAGMENT, FOR A SUCCESS AND AN ERROR ALIKE (#118, 2026-09-22).
  //
  // OAuth 2.0 Multiple Response Type Encoding Practices section 2.1 gives
  // each response type a DEFAULT response mode — `query` for `code` alone and
  // `fragment` for every type that returns a token or an ID Token — and OIDC
  // Core sections 3.2.2.6 and 3.3.2.6 send an ERROR the same way the
  // successful response would have gone. Until this date an error from an
  // implicit or hybrid request went in the query, where the client's
  // fragment-reading code never saw it. An explicit `fragment` is honoured
  // for any type; an explicit `query` only where nothing in the response can
  // be a token (section 2.1 of that document: "MUST NOT use the query
  // encoding" for those) — and since #125 such a request is REFUSED in
  // `vetAuthorizationRequest()` (STS-OAUTH-0607), so the refusal is the one
  // place that decides this for a token-bearing type; `none` (section 4) is
  // the query. `form_post` is redirectBack()'s own branch and never reaches
  // here.
  // -------------------------------------------------------------------------
  usesFragment(types: Json, responseMode?: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.usesFragment().");
    const list: string[] = (Array.isArray(types) ? types
      : String(types || '').split(/\s+/)).filter(Boolean);
    const tokenBearing = list.some(function (one) {
      return one !== 'code' && one !== 'none';
    });
    const asked = String(responseMode || '');
    log.debug("Leaving OAuth2Server.usesFragment().");
    if (asked === 'fragment') {
      return true;
    }
    return tokenBearing;
  }

  // The OP iframe and its script while Session Management is off (#121): a
  // 404 that says why. The caller has marked STS-OAUTH-0601.
  sessionManagementOff(res: Res): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.sessionManagementOff().");
    // error-code: none — both callers mark STS-OAUTH-0601 first
    res.status(404).type('text/plain').set('Cache-Control', 'no-store')
       .send('OpenID Connect Session Management is off in this realm ' +
             '(oauth2.sessionManagement), so there is no OP iframe.');
    log.debug("Leaving OAuth2Server.sessionManagementOff().");
    return undefined;
  }

  // ---------------------------------------------------------------------------
  // `session_state` for the authorization response on `res` (#121), and the
  // OP browser state written to the browser beside it; null where none is
  // owed. The client is the one `authorizeRequest()` remembered for JARM, the
  // scope and the session the request's own — `res.req`, because every
  // authorization response leaves through a function that is handed `res`.
  // ---------------------------------------------------------------------------
  // The same, as the fields of a link (the interstitial's): `{}` or
  // `{ session_state }`.
  sessionStateField(res: Res, redirectUri: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.sessionStateField().");
    const found = this.sessionStateOf(res, redirectUri);
    log.debug("Leaving OAuth2Server.sessionStateField().");
    return found ? { session_state: found.value } : {};
  }

  sessionStateOf(res: Res, redirectUri: Json): Json {
    const { log, sessionOf } = this.deps;
    log.debug("Entering OAuth2Server.sessionStateOf().");
    const req: any = res && (res as any).req;
    const held = (res && res.locals && res.locals.stsJarm) || {};
    if (!req || !sessionManagement.enabled()) {
      log.debug("Leaving OAuth2Server.sessionStateOf(). Not on.");
      return null;
    }
    const session = sessionOf(req);
    const value = sessionManagement.sessionStateFor(held.clientId,
      redirectUri, (req.query || {}).scope, session);
    if (!value) {
      log.debug("Leaving OAuth2Server.sessionStateOf(). None owed.");
      return null;
    }
    sessionManagement.writeCookie(res,
                                  sessionManagement.browserStateOf(session));
    log.debug("Leaving OAuth2Server.sessionStateOf().");
    return { value: value };
  }

  redirectBack(res: Res, base: Json, redirectUri: Json, state: Json,
               params: Json, fragment?: Json, mode?: Json): any {
    const { log, oauth21 } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.redirectBack(). fragment=" + !!fragment +
              ", mode=" + (mode || 'default'));
    const fields: Json = {};
    Object.keys(params)
          .forEach(function (k) {
            if (params[k] !== undefined) {
              // OAuth 2.1 section 4.1.2.1's character set, in that mode only.
              fields[k] = k === 'error_description'
                ? oauth21.sanitizeDescription(params[k]) : params[k];
            }
          });
    if (state !== undefined) {
      fields.state = state;
    }
    // RFC 9207 on every response, in every mode: a form POST is still an
    // authorization response and a client that requires `iss` requires it here.
    fields.iss = base;
    // OPENID CONNECT SESSION MANAGEMENT section 3 (#121), where it is on: the
    // `session_state` on every authentication response, an error included,
    // and the OP browser state it was computed from written beside it — so
    // the cookie the OP iframe reads can never lag the value the relying
    // party holds. Inside a JARM response it is a claim like the rest.
    const sessionState = self.sessionStateOf(res, redirectUri);
    if (sessionState) {
      fields.session_state = sessionState.value;
    }
    // JARM (#139, #143): every one of the fields above goes into ONE signed
    // JWT, sent as `response` — `iss` becomes its claim.
    if (self.deps.jarm.isJarm(mode)) {
      log.debug("Leaving OAuth2Server.redirectBack(). A JARM response.");
      return self.jarmRedirect(res, base, redirectUri, fields, String(mode));
    }
    if (String(mode || '') === 'form_post') {
      log.debug("Leaving OAuth2Server.redirectBack(). Answering with a form " +
                "POST.");
      return self.formPostResponse(res, redirectUri, fields);
    }
    const usp = new URLSearchParams();
    Object.keys(fields).forEach(function (k) { usp.set(k, fields[k]); });
    const sep = fragment ? '#' : (redirectUri.indexOf('?') >= 0 ? '&' : '?');
    res.redirect(302, redirectUri + sep + usp.toString());
    log.debug("Leaving OAuth2Server.redirectBack().");
  }

  // ---------------------------------------------------------------------------
  // THE JWT-SECURED AUTHORIZATION RESPONSE (JARM, #139, #143), sent. The
  // client and its response type are the request's, remembered on
  // `res.locals.stsJarm` by `authorizeRequest()` before any answer; the JWT is
  // `jarm.ts`'s. A response that cannot be made — a registration this service
  // can no longer honour — is answered here as a 400 rather than sent
  // unsecured: a client that asked for JARM reads nothing else.
  // ---------------------------------------------------------------------------
  jarmUrl(res: Res, issuer: Json, redirectUri: Json, fields: Json,
          mode: string): Promise<Json> {
    const { log, applications, jarm } = this.deps;
    log.debug("Entering OAuth2Server.jarmUrl(). " + mode);
    const held = (res.locals && res.locals.stsJarm) || {};
    const clientId = String(held.clientId || '');
    const registered = applications.registrationOf(clientId) || {};
    log.debug("Leaving OAuth2Server.jarmUrl(). Signing.");
    return jarm.respond(fields, { clientId: clientId, issuer: issuer,
                                  registered: registered })
      .then(function (jwt: string): Json {
        const transport = jarm.transportOf(mode, held.types);
        // A form_post.jwt response has a URL too, in the query, for the one
        // place a link has to stand in for a POST: the interstitial page.
        const sep = transport === 'fragment' ? '#'
          : (String(redirectUri).indexOf('?') >= 0 ? '&' : '?');
        return { formPost: transport === 'form_post', response: jwt,
                 url: redirectUri + sep + 'response=' +
                      encodeURIComponent(jwt) };
      });
  }

  jarmRedirect(res: Res, issuer: Json, redirectUri: Json, fields: Json,
               mode: string): Promise<void> {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.jarmRedirect().");
    log.debug("Leaving OAuth2Server.jarmRedirect(). Answering.");
    return self.jarmUrl(res, issuer, redirectUri, fields, mode)
      .then(function (target: Json): void {
        if (target.formPost) {
          self.formPostResponse(res, redirectUri,
                                { response: target.response });
          return;
        }
        res.redirect(302, target.url);
      }).catch(function (e: Json): void {
        log.error(errorCodes.tag(errorCodes.codeOf(e) || 'STS-OAUTH-0588') +
                  'oauth2: a JARM response could not be made: ' +
                  ((e && e.message) || e));
        if (!res.headersSent) {
          errorCodes.mark(res, errorCodes.codeOf(e) || 'STS-OAUTH-0588');
          self.oauthError(res, 400, 'invalid_request',
                          String((e && e.message) || e));
        }
      });
  }

  // ---------------------------------------------------------------------------
  // RFC 9101: THE AUTHORIZATION ENDPOINT RESOLVES A REQUEST OBJECT FIRST
  // (2026-09-13), AND THE ENDPOINT BELOW RUNS ON WHAT IT ANSWERS.
  //
  // `request` or `request_uri` on the query makes this a JWT-secured request,
  // and `request_object.ts` turns it into the parameters it carries — verified,
  // decrypted, and ASSEMBLED as section 6.3 says: only the request object's
  // parameters are used, even where the query repeats one. So the request's
  // query is REPLACED with them before `authorizeRequest()` reads anything, and
  // every check below it — RFC 9700 mode, OAuth 2.1, PKCE, the redirect URI —
  // runs on the request the client signed. That is one line of replacement
  // rather than a second copy of eight hundred lines of checks.
  //
  // A REFUSAL IS A 400 ON THIS SERVER, NEVER A REDIRECT: the redirect_uri is
  // inside the object, and an address from a document that did not verify is
  // the open redirector `authorizeRequest()`'s shape check refuses to become.
  //
  // A request that is NOT JWT-secured, and that nothing requires to be, goes
  // straight through, synchronously, exactly as it did before this existed.
  // `req.stsJar` records how the request arrived, which is what the two
  // round-trip URLs are rebuilt from (see `authorizationReturnQuery()`) and
  // what the sign-in and consent screens show (section 11.1).
  // ---------------------------------------------------------------------------
  private authorizationProfileOf(req: Req): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.authorizationProfileOf().");
    const caps = self.capabilitiesFor(req);
    log.debug("Leaving OAuth2Server.authorizationProfileOf().");
    return {
      requestSupported: caps.request_parameter_supported,
      requestUriSupported: caps.request_uri_parameter_supported,
      requireSigned: caps.require_signed_request_object,
      signingAlgs: self.capabilityFor(req,
        'request_object_signing_alg_values_supported'),
      encryptionAlgs: self.capabilityFor(req,
        'request_object_encryption_alg_values_supported'),
      encryptionEncs: self.capabilityFor(req,
        'request_object_encryption_enc_values_supported')
    };
  }

  private authorizeEndpoint(req: Req, res: Res): Json {
    const { log, STS, config, applications, errorCodes, requestObject
} = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.authorizeEndpoint().");
    // -----------------------------------------------------------------------
    // POST (#118, OIDC Core section 3.1.2.1: "Authorization Servers MUST
    // support the use of the HTTP GET and POST methods"). Only GET was
    // registered until 2026-09-22. A POST carries the request as
    // application/x-www-form-urlencoded form serialization, and it is turned
    // into the query every check below reads — repeated names as arrays, the
    // way the query parser keeps them, so OAuth 2.1's repeated-parameter
    // refusal sees them too. Only the body counts: a POST whose URL also
    // carries parameters is answered from the body alone.
    // -----------------------------------------------------------------------
    if (req.method === 'POST') {
      const type = String((req.headers || {})['content-type'] || '')
        .split(';')[0].trim().toLowerCase();
      if (type !== 'application/x-www-form-urlencoded') {
        errorCodes.mark(res, 'STS-OAUTH-0564');
        log.debug("Leaving OAuth2Server.authorizeEndpoint(). A POST that is " +
                  "not a form.");
        return self.oauthError(res, 400, 'invalid_request',
          'An authorization request sent with POST is form-serialized — ' +
          'Content-Type application/x-www-form-urlencoded (OIDC Core section ' +
          '3.1.2.1, section 13.2). This one is "' + (type || '(none)') + '".');
      }
      const raw = typeof req.body === 'string' ? req.body
        : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
      const fromBody: Json = {};
      new URLSearchParams(raw).forEach(function (value, name) {
        if (fromBody[name] === undefined) {
          fromBody[name] = value;
        } else {
          fromBody[name] = [].concat(fromBody[name], value);
        }
      });
      Object.defineProperty(req, 'query', { value: fromBody, writable: true,
                                            configurable: true,
                                            enumerable: true });
    }
    const outer = Object.assign({}, req.query || {});
    const client = applications.clientConfigOf(outer.client_id);
    const jwtSecured = (outer.request !== undefined && outer.request !== '') ||
                       (outer.request_uri !== undefined &&
                        outer.request_uri !== '');
    if (!jwtSecured && !config.value('oauth2.requireSignedRequestObject') &&
        !client.require_signed_request_object &&
        !self.deps.fapi.requiresSignedRequestObject() &&
        self.capabilitiesFor(req).require_signed_request_object !== true) {
      log.debug("Leaving OAuth2Server.authorizeEndpoint(). Not a " +
                "JWT-secured request.");
      return self.withIdTokenHint(req, res);
    }
    const base = self.asBaseOf(req);
    requestObject.resolve({
      query: outer, client: client, issuer: self.issuerOf(base), asBase: base,
      profile: self.authorizationProfileOf(req), keySet: STS,
      authorizationServer: self.profileOf(req), req: req
    }).then(function (result) {
      res.set('Cache-Control', 'no-store');
      if (!result.ok) {
        log.info('oauth2: an authorization request from "' +
                 (outer.client_id || '(no client_id)') + '" was refused (' +
                 result.error + '): ' + result.description);
        log.debug("Leaving OAuth2Server.authorizeEndpoint(). The request " +
                  "object is refused.");
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-OAUTH-0340');
        return self.oauthError(res, 400, result.error, result.description);
      }
      if (result.used) {
        req.stsJar = { outer: outer, source: result.source, alg: result.alg,
                       encrypted: result.encrypted || '',
                       pushed: result.pushed || null,
                       once: result.once || null };
        Object.defineProperty(req, 'query', { value: result.params,
                                              writable: true,
                                              configurable: true,
                                              enumerable: true });
      }
      log.debug("Leaving OAuth2Server.authorizeEndpoint(). Resolved.");
      return self.withIdTokenHint(req, res);
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-OAUTH-0373') + 'the authorization ' +
                'endpoint failed while resolving a request object: ' +
                (e && e.stack ? e.stack : e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-OAUTH-0373');
        self.oauthError(res, 500, 'server_error',
                        String((e && e.message) || e));
      }
    });
    log.debug("Leaving OAuth2Server.authorizeEndpoint(). Resolving a " +
              "request object.");
  }

  // THE QUERY THE SIGN-IN AND CONSENT HOPS RETURN TO. For a plain request it is
  // the request with `prompt` dropped, as it always was. For a JWT-secured one
  // it is NOT the resolved parameters — putting those back in the URL would
  // turn a signed request into an unsigned one on the second pass — but the
  // request object again, as it arrived (`request` or `request_uri`, with
  // `client_id`), so the second pass verifies it a second time. `prompt` is
  // inside the signed object and cannot be dropped from it, so
  // `jar_prompt_honoured` tells the second pass the first one honoured it, or
  // `prompt=login` would ask for ever.
  //
  // AND A REQUEST WITH acr_values OR max_age CARRIES `step_up_honoured=1` BACK
  // (RFC 9470, 2026-09-13), so the second pass refuses a requirement the
  // sign-in did not meet rather than sending the person round again. For a
  // request object it rides beside the object, as `jar_prompt_honoured` does.
  private authorizationReturnQuery(req: Req, q: Json): Json {
    const { log, stepUp } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.authorizationReturnQuery().");
    const jar = req.stsJar;
    // With the client's registered defaults (#120).
    const stepping = stepUp.requirementOf(q,
      this.deps.applications.registrationOf(q.client_id)).present;
    if (!jar) {
      log.debug("Leaving OAuth2Server.authorizationReturnQuery(). A plain " +
                "request.");
      return self.queryString(stepping
        ? Object.assign({}, q, { step_up_honoured: '1' }) : q, ['prompt']);
    }
    const back: Json = { client_id: String(jar.outer.client_id || '') };
    if (jar.outer.request !== undefined) {
      back.request = jar.outer.request;
    }
    if (jar.outer.request_uri !== undefined) {
      back.request_uri = jar.outer.request_uri;
    }
    if (q.prompt !== undefined || jar.outer.jar_prompt_honoured !== undefined) {
      back.jar_prompt_honoured = '1';
    }
    if (stepping) {
      back.step_up_honoured = '1';
    }
    log.debug("Leaving OAuth2Server.authorizationReturnQuery(). A request " +
              "object.");
    return self.queryString(back, []);
  }

  // What the sign-in and consent screens show about HOW the request arrived —
  // RFC 9101 section 11.1: the consent screen "SHOULD indicate that the request
  // has been vetted". Nothing for a plain request.
  private requestObjectDetail(req: Req): Json {
    const { log, par } = this.deps;
    log.debug("Entering OAuth2Server.requestObjectDetail().");
    const jar = req.stsJar;
    if (!jar) {
      log.debug("Leaving OAuth2Server.requestObjectDetail(). A plain request.");
      return [];
    }
    const signed = jar.alg && jar.alg !== 'none';
    if (jar.source === 'par' && !jar.alg) {
      // A push of plain form parameters is not a request object at all, and
      // calling it an unsigned one would read as a warning about nothing.
      log.debug("Leaving OAuth2Server.requestObjectDetail(). A plain pushed " +
                "request.");
      return [{
        label: 'request',
        value: 'pushed over the back channel (RFC 9126)' +
               (jar.encrypted ? ', encrypted (' + jar.encrypted + ')' : ''),
        note: 'sent by the client directly to this server'
      }];
    }
    log.debug("Leaving OAuth2Server.requestObjectDetail().");
    return [{
      label: 'request',
      value: (signed ? 'a signed request object (' + jar.alg + ')'
                     : 'an UNSIGNED request object') +
             (jar.encrypted ? ', encrypted (' + jar.encrypted + ')' : '') +
             (jar.source === 'request_uri' ? ', fetched from its registered ' +
              'request_uri' : jar.source === 'par' ? ', pushed' : ''),
      note: signed
        ? 'verified with this application\'s registered key (RFC 9101)'
        : 'NOT verified: anybody could have written these parameters'
    }];
  }

  // ---------------------------------------------------------------------------
  // THE REQUEST-LEVEL CHECKS OF AN AUTHORIZATION REQUEST, AS ONE FUNCTION
  // (2026-09-13).
  //
  // Everything the authorization endpoint decides about the REQUEST before it
  // asks who is answering it — the shape, OAuth 2.1's client and default
  // redirect_uri, the redirect_uri itself, the response type, mode and PKCE
  // method this authorization server advertises, and RFC 9700 mode's own list —
  // in the order it always ran and with the codes it always had. It became a
  // function because RFC 9126 section 2.1 says a PUSHED authorization request
  // is validated "as it would an authorization request sent to the
  // authorization endpoint", and a second copy of these checks at `/oauth2/par`
  // would be a second opinion about what a valid authorization request is,
  // which is the one fact the two endpoints must never disagree on.
  //
  // **IT DECIDES; EACH CALLER ANSWERS.** `authorizeRequest()` turns a refusal
  // into a 400 on this server or into `fail()`'s redirect, as it did before;
  // the PAR endpoint turns every refusal into RFC 9126 section 2.3's JSON
  // error. So an answer says only whether it MAY be redirected (`redirect`),
  // and never touches `res`.
  //
  //   options.input         an object to validate instead of `req.query` (the
  //                         pushed parameters)
  //   options.where         the label the validator reports it under
  //   options.repeated      the names repeated in the raw request, for
  //                         OAuth 2.1
  //   options.relaxRedirect RFC 9126 section 2.4: an authenticated client's
  //                         pushed redirect_uri need not be registered
  //
  // Answers `{ ok: true, q, types, registeredClient, redirectUri, relaxed }`,
  // `{ ok: false, redirect: false, status, error, description, code }`, or `{
  // ok: false, redirect: true, error, description, code, q, redirectUri }`.
  // ---------------------------------------------------------------------------
  private vetAuthorizationRequest(req: Req, options?: Json): Json {
    const { log, STS, mode, bcp, oauth21, fapi, applications, validation,
            stepUp, hasScope } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.vetAuthorizationRequest().");
    const opts = options || {};
    const refuse = function (code, error, description) {
      log.debug("Entering refuse(). " + code);
      log.debug("Leaving refuse().");
      return { ok: false, redirect: false, status: 400, error: error,
               description: description, code: code };
    };

    // --- SHAPE FIRST, AND ANSWERED HERE RATHER THAN REDIRECTED
    // ----------------
    //
    // This runs BEFORE the redirect_uri is looked at, and a refusal is reported
    // ON THIS SERVER as a 400 — never by redirecting — for the reason the RFC
    // 9700 block below gives at length: forwarding a browser to a URI this
    // service has not yet decided it trusts is an open redirector whatever
    // parameters ride along. Here the case is sharper still, because **the
    // malformed parameter may BE the redirect_uri**: answering
    // `error=invalid_request` by redirecting to a value just refused for its
    // shape would be using it as an address in the act of rejecting it.
    //
    // The schema passes unknown parameters through (see AUTHORIZE_QUERY), so
    // nothing a client sent is lost across the consent round trip.
    const asked = opts.input
      ? validation.checkParsed(opts.input, opts.where || 'body',
                               AUTHORIZE_QUERY)
      : validation.check(req, 'query', AUTHORIZE_QUERY);
    if (!asked.ok) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). The " +
                "request is malformed: " +
                asked.code + " on \"" + asked.field + "\".");
      return refuse('STS-OAUTH-0159', 'invalid_request', asked.detail);
    }
    const q = asked.value;

    // --- OAUTH 2.1: THE CLIENT FIRST, AND A DEFAULT redirect_uri -------------
    //
    // In that mode a client must have registered its own redirect URI (section
    // 2.3.1), and a request may OMIT redirect_uri when exactly one is
    // registered (section 4.1.1) — so the client's entry is needed before the
    // URI is known, and a missing client_id has to be answered first or it
    // would be reported as an unregistered client. Both refusals are answered
    // HERE, as a 400, for the reason the block below gives: there is no
    // validated address yet.
    //
    // The DEFAULT is checked against the same allowlist a presented URI was
    // checked against by the schema, because it comes off the entry and an
    // `ldapmodify` reaches the entry without passing any check at all.
    const registeredClient = applications.clientConfigOf(q.client_id);
    if (oauth21.enabled()) {
      const repeated = oauth21.repeatedParameterRefusal(
          opts.repeated || oauth21.repeatedNames(req.query),
          opts.what || 'authorization request');
      if (repeated) {
        log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). OAuth " +
                  "2.1: a repeated " +
                  "parameter.");
        return refuse(repeated.errorCode || 'STS-OAUTH-0285', repeated.error,
                      repeated.description);
      }
      const idCheck = bcp.checkClientIdPresent(q.client_id);
      if (!idCheck.ok) {
        log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). OAuth " +
                  "2.1: no client_id.");
        return refuse(idCheck.errorCode || 'STS-OAUTH-0158', idCheck.error,
                      idCheck.description);
      }
      // Never under a FAPI profile, each of which requires redirect_uri to
      // be SENT (Baseline item 9, FAPI 2.0 section 5.3.2.2 item 6, #140).
      if (!q.redirect_uri && !fapi.enabled()) {
        const chosen = oauth21.defaultRedirectUri(registeredClient,
                                                  String(q.client_id));
        if (!chosen.ok) {
          log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). OAuth " +
                    "2.1: no " +
                    "redirect_uri to default to (" + chosen.requirement + ").");
          return refuse(chosen.errorCode || 'STS-OAUTH-0273', chosen.error,
                        chosen.description);
        }
        const storedProblem = validation.redirectUriProblem(chosen.uri);
        if (storedProblem) {
          log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). OAuth " +
                    "2.1: the one " +
                    "registered redirect URI is not usable.");
          return refuse('STS-OAUTH-0274', 'invalid_request',
            'OAuth 2.1 (' + oauth21.DRAFT + ') section 4.1.1: this request ' +
            'named no redirect_uri, and the one client "' + q.client_id + '" ' +
            'has registered cannot be used — it ' + storedProblem +
            '. Correct ' +
            'the entry on /admin/applications.');
        }
        q.redirect_uri = chosen.uri;
        log.debug("OAuth 2.1: redirect_uri defaulted to the one registered.");
      }
    }
    const redirectUri = String(q.redirect_uri || '');

    // Without a usable redirect_uri there is nowhere to report an error TO, so
    // it is reported here instead (OAuth 2.0 section 4.1.2.1). WHAT IS USABLE
    // is the schema's question since 2026-09-13 — AUTHORIZE_QUERY types it with
    // `vt.redirectUri`, which accepts http(s) and a private-use scheme named
    // for a domain and refuses everything else — so what is left here is its
    // absence.
    if (!redirectUri) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). There is " +
                "no usable " +
                "redirect_uri to report to.");
      return refuse('STS-OAUTH-0160', 'invalid_request',
                    'A valid absolute redirect_uri is required.');
    }

    // --- RFC 9700 section 2.1, and it has to be FIRST
    // --------------------------
    //
    // Every refusal below this point is reported BY REDIRECTING to
    // redirect_uri, which is right once that URI is known to be one the client
    // registered and is an open redirector until then: "error=invalid_request"
    // forwarded to an arbitrary URL is still the browser being forwarded to an
    // arbitrary URL, and an attacker does not mind which parameters ride along.
    // So the URI is matched here, before there is a `fail` to report anything
    // with, and a refusal is answered ON THIS SERVER as a 400.
    //
    // The registered client record is passed in rather than looked up in the
    // check: the registry lives in the directory and there is exactly one of
    // it. The lookup misses for every client_id this service has never
    // registered, which is the ordinary case, and that is not an error — it
    // means the oauth2.redirectUris setting is what this request is judged
    // against (not in OAuth 2.1 mode, which reads no service-wide list), and it
    // also means the client is treated as PUBLIC and must therefore use PKCE.
    // The application's ENTRY, normalised — not its RFC 7591 registration. The
    // two stopped being the same thing when the console gained the ability to
    // create an application and give it redirect URIs without a registration
    // behind it, and this check wants what the client is ALLOWED to do rather
    // than what it once registered. `clientConfigOf()` reads the attributes, so
    // an ldapmodify, a console form and a registration all reach it alike.
    //
    // RFC 9126 SECTION 2.4 IS THE ONE WAY PAST IT, and only for a pushed
    // request whose client AUTHENTICATED at the push, with
    // `oauth2.parAllowUnregisteredRedirectUris` on — the caller decides both
    // and passes `relaxRedirect`. The URI has still been refused above for its
    // SHAPE, which section 2.4's "restrictions on supplied redirect_uri values"
    // leaves to this server, and it is recorded (`relaxed`) so the
    // authorization endpoint can ask the setting again when the request_uri is
    // used.
    let relaxed = false;
    const redirectCheck = bcp.checkRedirectUri({ redirectUri: redirectUri,
                                                 client: registeredClient,
                                                 clientId: q.client_id });
    if (!redirectCheck.ok && opts.relaxRedirect) {
      relaxed = true;
      log.info('oauth2: client "' + q.client_id + '" pushed the unregistered ' +
               'redirect_uri "' + redirectUri + '" after authenticating, ' +
               'which oauth2.parAllowUnregisteredRedirectUris accepts (RFC ' +
               '9126 ' +
               'section 2.4) where ' + redirectCheck.requirement + ' would ' +
               'have refused it.');
    } else if (!redirectCheck.ok) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). RFC 9700 " +
                "mode refused the " +
                "redirect_uri (" + redirectCheck.requirement +
                "), so nothing " +
                "is redirected anywhere.");
      return refuse(redirectCheck.errorCode || 'STS-OAUTH-0158',
                    redirectCheck.error, redirectCheck.description);
    }
    if (redirectCheck.how) {
      log.debug("The redirect_uri was accepted by " + redirectCheck.how + ".");
    }

    // A FORM POST CANNOT REACH A PROTOCOL HANDLER (2026-09-13, every mode). An
    // operating system hands a native app the URL a browser was sent to and
    // never a request body, so `response_mode=form_post` at a private-use
    // redirect URI would deliver the code nowhere, with the failure at the
    // client and nothing here pointing at it. Answered HERE, before `fail`
    // exists, because every refusal made through `fail` honours the response
    // mode and would itself be a form nobody receives.
    if (String(q.response_mode || '') === 'form_post' &&
        validation.isPrivateUseRedirect(redirectUri)) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). form_post " +
                "to a " +
                "private-use redirect URI.");
      return refuse('STS-OAUTH-0270', 'invalid_request',
        'response_mode=form_post cannot be answered at "' + redirectUri +
        '": ' +
        'it is a native application\'s private-use URI, and an operating ' +
        'system hands a protocol handler the URL and never a request body. ' +
        'Use ' +
        'response_mode=query (or fragment).');
    }

    // From here a refusal may be REPORTED TO THE CLIENT — the address is known
    // — and the caller decides how (`fail()` at the authorization endpoint).
    const redirectable = function (code, error, description) {
      log.debug("Entering redirectable(). " + code);
      log.debug("Leaving redirectable().");
      return { ok: false, redirect: true, error: error,
               description: description, code: code, q: q,
               redirectUri: redirectUri };
    };

    // RFC 6749 section 4.1.2.1, cited by section 4.11.2: an invalid combination
    // of client_id and redirect_uri must not be redirected. A missing client_id
    // is the plainest one, and this used to be reported BY redirecting to the
    // URI — which is the thing that paragraph forbids. Answered here instead,
    // ABOVE the `fail` closure's first use so there is no path where it is
    // reported the old way.
    const clientIdCheck = bcp.checkClientIdPresent(q.client_id);
    if (!clientIdCheck.ok) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). " +
                clientIdCheck.requirement + ".");
      return refuse(clientIdCheck.errorCode || 'STS-OAUTH-0158',
                    clientIdCheck.error, clientIdCheck.description);
    }
    if (!q.client_id) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). No " +
                "client_id.");
      return redirectable('STS-OAUTH-0161', 'invalid_request',
                          'client_id is required.');
    }
    const types = String(q.response_type || '').split(/\s+/).filter(Boolean);
    const known = ['code', 'token', 'id_token', 'none'];
    // OAuth 2.0 Multiple Response Type Encoding Practices section 4 (#125):
    // `none` asks for NOTHING to be issued — the response carries `state`
    // (and RFC 9207's `iss`) alone — so it is not combined with any other
    // value.
    if (types.length > 1 && types.indexOf('none') >= 0) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). none " +
                "combined.");
      return redirectable('STS-OAUTH-0606', 'unsupported_response_type',
        'response_type "none" asks for no credential at all (Multiple ' +
        'Response Type Encoding Practices section 4), so it cannot be ' +
        'combined with "' + types.filter(function (t) {
          return t !== 'none';
        }).join(' ') + '".');
    }
    if (!types.length ||
        types.some(function (t) { return known.indexOf(t) < 0; })) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). " +
                "Unsupported response_type.");
      return redirectable('STS-OAUTH-0162', 'unsupported_response_type',
                          'response_type "' + (q.response_type || '') + '" ' +
                          'is not supported.');
    }
    // WHAT THIS AUTHORIZATION SERVER SAYS IT DOES. `response_types_supported`
    // in the document a client read is the list this endpoint answers — the
    // document is not a description of the server, it IS the server, so a value
    // outside it is refused here rather than accepted by an endpoint that never
    // read its own metadata. The comparison is on the whole space-separated
    // value because that is how the member is defined: `code id_token` is one
    // entry, not two.
    const advertisedTypes = self.capabilityFor(req, 'response_types_supported');
    if (advertisedTypes) {
      const sorted = types.slice(0).sort().join(' ');
      const offered = advertisedTypes.some(function (one) {
        return String(one).split(/\s+/)
                          .filter(Boolean)
                          .sort()
                          .join(' ') === sorted;
      });
      if (!offered) {
        log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). " +
                  self.profileOf(req) +
                  " does not advertise that response type.");
        return redirectable('STS-OAUTH-0163', 'unsupported_response_type',
          'The "' + self.profileOf(req) + '" authorization server advertises ' +
          'response_types_supported ' + JSON.stringify(advertisedTypes) + ' ' +
          'and this request asks for ' +
          '"' + (q.response_type || '') + '". What its metadata says is what ' +
          'it does — the document is this authorization server rather ' +
          'than a description of one.');
      }
    }
    // ---------------------------------------------------------------------
    // WHICH RESPONSE MODES THIS AUTHORIZATION SERVER ANSWERS, and why an
    // unrecognised one has to be refused rather than ignored.
    //
    // `redirectBack()` answers `form_post` with a form and everything else with
    // a redirect. That "everything else" was the hole: a client asking for
    // `web_message` — the postMessage mode SPAs use for silent renewal, and the
    // subject of RFC 9700's in-browser communication section — got a 302 and
    // sat waiting for a message that never arrived. It is the same silent
    // failure `form_post` itself had while it was advertised and missing, and
    // the same reason that one was worth fixing: the failure is at the CLIENT
    // end, with nothing anywhere pointing back at this service.
    //
    // Checked against what this authorization server ADVERTISES rather than
    // against a list here, so the document and the endpoint cannot disagree —
    // and so a server configured to offer only `form_post` refuses the other
    // two at its own endpoint. Not gated on RFC 9700 mode, like the other
    // capability checks: the default document advertises everything this
    // service does, so a request that would have worked still works.
    // ---------------------------------------------------------------------
    if (q.response_mode !== undefined && String(q.response_mode) !== '') {
      const advertisedModes = self.capabilityFor(req,
                                                 'response_modes_supported');
      if (advertisedModes &&
          advertisedModes.indexOf(String(q.response_mode)) < 0) {
        log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). " +
                  "response_mode " +
                  q.response_mode +
                  " is not one " + self.profileOf(req) + " advertises.");
        return redirectable('STS-OAUTH-0164', 'invalid_request',
          'The "' + self.profileOf(req) + '" authorization server advertises ' +
          'response_modes_supported ' + JSON.stringify(advertisedModes) + ' ' +
          'and this request asks for ' +
          '"' + q.response_mode + '". It is refused rather than answered ' +
          'with a redirect, because a client that asked for a mode this ' +
          'server does not perform would otherwise wait for a response that ' +
          'never arrives — which is a failure with nothing at this end to ' +
          'point at.' +
          (String(q.response_mode) === 'web_message'
            ? ' `web_message` in particular is postMessage-based, and this ' +
              'service has no browser messaging of any kind: no page here ' +
              'posts a message, receives one, or frames anything.'
            : ''));
      }
    }

    // MULTIPLE RESPONSE TYPE ENCODING PRACTICES section 2.1 (#125): a
    // response type that returns a token or an ID Token "MUST NOT use the
    // query encoding" — so an explicit `response_mode=query` for one is
    // refused, in every mode. It was quietly overridden to the fragment since
    // #118, which answered a request the client did not make. The refusal
    // itself goes in the fragment, where the success would have gone.
    if (String(q.response_mode || '') === 'query' &&
        types.some(function (t) { return t === 'token' || t === 'id_token'; })) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). query for " +
                "a token-bearing response type.");
      return redirectable('STS-OAUTH-0607', 'invalid_request',
        'response_mode=query cannot carry response_type "' +
        String(q.response_type) + '": a response returning a token or an ID ' +
        'Token MUST NOT use the query encoding (OAuth 2.0 Multiple Response ' +
        'Type Encoding Practices section 2.1). Use fragment or form_post.');
    }

    // JARM section 2.3.1 (#139, #143): `query.jwt` carries no token in clear.
    const jarmProblem = self.deps.jarm.modeProblem(q.response_mode,
                                                   q.response_type,
                                                   registeredClient);
    if (jarmProblem) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). JARM " +
                "refused the response mode.");
      return redirectable(jarmProblem.errorCode, jarmProblem.error,
                          jarmProblem.description);
    }

    // The same for the PKCE methods. A server advertising S256 alone refuses
    // `plain` HERE, whatever the other authorization servers in this process
    // do.
    if (q.code_challenge_method) {
      const advertisedPkce = self.capabilityFor(
        req, 'code_challenge_methods_supported');
      if (advertisedPkce &&
          advertisedPkce.indexOf(String(q.code_challenge_method)) < 0) {
        log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). " +
                  self.profileOf(req) +
                  " does not advertise that code_challenge_method.");
        return redirectable('STS-OAUTH-0165', 'invalid_request',
          'The "' + self.profileOf(req) + '" authorization server advertises ' +
          'code_challenge_methods_supported ' + JSON.stringify(advertisedPkce) +
          ' ' +
          'and this request asks for "' + q.code_challenge_method + '".');
      }
    }

    // RFC 9470: an acr value is repeated in a WWW-Authenticate challenge and
    // compared as a string, so one outside RFC 6749's NQCHAR (less the quote
    // and backslash a quoted-string cannot carry) is refused by name rather
    // than dropped — a request asking for less than it wrote would be met by an
    // authentication it never asked for. Redirected: the redirect_uri is
    // validated above.
    const acrAsked = stepUp.parseAcrValues(q.acr_values);
    if (acrAsked.invalid.length) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). An " +
                "unusable acr value.");
      return redirectable('STS-OAUTH-0509', 'invalid_request',
        'acr_values: ' + acrAsked.invalid.map(function (one) {
          return JSON.stringify(one.slice(0, 60));
        }).join(', ') +
        ' cannot be an acr value — a value is printable ASCII ' +
        'with no double quote or backslash.');
    }
    // -----------------------------------------------------------------------
    // OPENID CONNECT CORE'S OWN RULES ABOUT THE REQUEST, IN EVERY MODE (#118,
    // 2026-09-22). Redirected: the redirect_uri is validated above.
    //
    //   * An ID Token is an OpenID Connect response, and OpenID Connect
    //     requests "MUST contain the openid scope value" (section 3.1.2.1).
    //     A response_type naming id_token without it used to be answered, and
    //     a request with no scope at all was given `openid` it had not asked
    //     for (both gone).
    //   * `prompt=none` MUST NOT be combined with another value (section
    //     3.1.2.1: "If this parameter contains none with any other value, an
    //     error is returned").
    //   * THE IMPLICIT FLOW (response_type `id_token` or `id_token token`):
    //     section 3.2.2.1 makes `nonce` REQUIRED and forbids an http
    //     redirect_uri unless it is a native client's loopback. Both were RFC
    //     9700 mode's alone; they are Core's in every mode now. The hybrid flow
    //     keeps nonce optional, as section 3.3.2.1 does, and RFC 9700 mode
    //     still requires it for any id_token.
    // -----------------------------------------------------------------------
    const idTokenAsked = types.indexOf('id_token') >= 0;
    if (idTokenAsked && !hasScope(q.scope, 'openid')) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). An id_token " +
                "without the openid scope.");
      return redirectable('STS-OAUTH-0560', 'invalid_scope',
        'response_type "' + q.response_type + '" asks for an ID Token, and ' +
        'an ' +
        'OpenID Connect request MUST carry the openid scope (OIDC Core ' +
        'section 3.1.2.1). Add openid to scope.');
    }
    const promptValues = String(q.prompt || '').split(/\s+/).filter(Boolean);
    if (promptValues.indexOf('none') >= 0 && promptValues.length > 1) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). prompt=none " +
                "with another value.");
      return redirectable('STS-OAUTH-0561', 'invalid_request',
        'prompt "' + q.prompt + '" combines none with another value, and ' +
        'OIDC Core section 3.1.2.1 says that is an error: none forbids every ' +
        'prompt the others ask for.');
    }
    const implicit = idTokenAsked && types.indexOf('code') < 0;
    if (implicit && !q.nonce) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). The " +
                "implicit " +
                "flow with no nonce.");
      return redirectable('STS-OAUTH-0562', 'invalid_request',
        'response_type "' + q.response_type + '" is the implicit flow, and ' +
        'OIDC Core section 3.2.2.1 makes nonce REQUIRED for it — it is what ' +
        'the client checks the ID Token against to detect a replay.');
    }
    if (implicit) {
      let parsedRedirect: Json = null;
      try {
        parsedRedirect = new URL(redirectUri);
      } catch (e) {
        log.debug("Caught in OAuth2Server.vetAuthorizationRequest(): " +
                  ((e && e.message) || e));
        // Refused above for its shape; nothing more to judge here.
        parsedRedirect = null;
      }
      if (parsedRedirect && parsedRedirect.protocol === 'http:' &&
          ['localhost', '127.0.0.1', '[::1]']
            .indexOf(parsedRedirect.hostname) < 0) {
        log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). The " +
                  "implicit flow to an http redirect_uri.");
        return refuse('STS-OAUTH-0563', 'invalid_request',
          'OIDC Core section 3.2.2.1: the implicit flow MUST NOT use an http ' +
          'redirect_uri unless the client is a native application ' +
          'redirecting to localhost, 127.0.0.1 or [::1]. "' + redirectUri +
          '" is neither, and the tokens would cross the network in clear.');
      }
    }
    // The rest of what RFC 9700 mode has to say about this request: no response
    // type that issues an access token here (section 2.1.2), PKCE from any
    // client this server cannot see to be confidential and S256 when there is
    // one (section 2.1.1), and a nonce with any id_token. These CAN be reported
    // to the client, because redirect_uri has been validated above — and they
    // are, rather than answered as a 400, because a client that asked for
    // something this server will not do has a protocol error handler and no
    // reason to be looking at this server's own output.
    //
    // Note where this sits: above the session check, so it is answered on the
    // first pass and the person is never sent to sign in for a request that was
    // going to be refused when they came back.
    // RFC 7591 SECTION 2 (#120, in every mode): a client that REGISTERED its
    // response_types is held to them — unauthorized_client, RFC 6749 section
    // 4.1.2.1's word for a client not allowed this method.
    const registeredFlows = applications.registeredFlowsOf(q.client_id);
    const askedType = String(q.response_type || '').split(/\s+/)
      .filter(Boolean).sort().join(' ');
    if (registeredFlows && registeredFlows.response_types &&
        registeredFlows.response_types.indexOf(askedType) < 0) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). A response " +
                "type the client did not register.");
      return redirectable('STS-OAUTH-0597', 'unauthorized_client',
        'Client "' + q.client_id + '" registered response_types ' +
        JSON.stringify(registeredFlows.response_types) + ', and this ' +
        'request asks for "' + q.response_type + '" (RFC 7591 section 2).');
    }
    const requestCheck = bcp.checkAuthorizationRequest({ query: q, types: types,
                                                         client:
                                                           registeredClient });
    if (!requestCheck.ok) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). RFC 9700 " +
                "mode refused the " +
                "authorization request (" + requestCheck.requirement + ").");
      return redirectable(requestCheck.errorCode || 'STS-OAUTH-0158',
                          requestCheck.error, requestCheck.description);
    }
    // FAPI (#138): what a FAPI profile asks beyond RFC 9700 mode — PKCE S256
    // of every client, nonce with openid, state without it, and a redirect_uri
    // that was SENT and is https. The last is answered here as a 400 rather
    // than at the address it concerns.
    // Advanced (#139) asks PKCE only of a PUSHED request: one arriving at
    // /oauth2/par now, or at this endpoint by a PAR request_uri.
    const fapiCheck = fapi.authorizationRefusal(q, {
      pushed: !!opts.input || !!(req.stsJar && req.stsJar.source === 'par')
    });
    if (fapiCheck) {
      log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). FAPI " +
                "refused the authorization request (" + fapiCheck.requirement +
                ").");
      return fapiCheck.requirement === 'redirect-uri'
        ? refuse(fapiCheck.errorCode, fapiCheck.error, fapiCheck.description)
        : redirectable(fapiCheck.errorCode, fapiCheck.error,
                       fapiCheck.description);
    }
    log.debug("Leaving OAuth2Server.vetAuthorizationRequest(). Vetted.");
    return { ok: true, q: q, types: types, registeredClient: registeredClient,
             redirectUri: redirectUri, relaxed: relaxed };
  }

  // ---------------------------------------------------------------------------
  // RFC 9126 AT THE AUTHORIZATION ENDPOINT: THE TWO QUESTIONS ASKED BEFORE A
  // REQUEST IS VETTED (2026-09-13).
  //
  // **MUST THIS REQUEST HAVE BEEN PUSHED?** Section 4's "authorization server
  // policy MAY dictate, either globally or on a per-client basis, that PAR be
  // the only means", answered `invalid_request` — and here ON THIS SERVER as a
  // 400, because the redirect_uri of a request that should never have been sent
  // this way is not one to trust with an error. Three sources, ORed: the
  // setting, the client's `require_pushed_authorization_requests`, and the
  // selected authorization server's profile publishing it.
  //
  // **WAS IT PUSHED PLAIN WHILE A SIGNED OBJECT IS NOW REQUIRED?** RFC 9126
  // section 2.3 refuses a plain push where RFC 9101 section 10.5 requires a
  // signed request object, and section 7.4 asks for the client's policy to be
  // checked again when the request_uri is used — so a request pushed plain
  // before the requirement was switched on is refused rather than honoured.
  // ---------------------------------------------------------------------------
  private pushedRequestPolicyRefusal(req: Req): Json {
    const { log, STS, config, applications, errorCodes, requestObject, par,
            oauthMonitor } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.pushedRequestPolicyRefusal().");
    const jar = req.stsJar || null;
    const pushed = !!(jar && jar.source === 'par');
    const clientId = String((req.query || {}).client_id || '');
    const client = applications.clientConfigOf(clientId);
    const caps = self.capabilitiesFor(req);
    const requiredBy = [
      config.value('oauth2.requirePushedAuthorizationRequests')
        ? 'oauth2.requirePushedAuthorizationRequests' : '',
      client.require_pushed_authorization_requests
        ? 'client "' + clientId + '"\'s require_pushed_authorization_requests'
        : '',
      caps.require_pushed_authorization_requests === true
        ? 'the "' + self.profileOf(req) + '" authorization server\'s ' +
          'require_pushed_authorization_requests' : '',
      // FAPI 2.0 section 5.3.2.2 item 3 (#140).
      self.deps.fapi.requiresPar() ? 'the FAPI 2.0 Security Profile' : ''
    ].filter(Boolean);
    if (!pushed && requiredBy.length) {
      oauthMonitor.record(clientId, 'par.required_refused',
                        { error: 'invalid_request' });
      log.debug("Leaving OAuth2Server.pushedRequestPolicyRefusal(). PAR is " +
                "required.");
      return errorCodes.mark({ error: 'invalid_request',
        description: 'this authorization request was not pushed, and ' +
          requiredBy.join(' and ') + ' says pushed authorization requests ' +
          'are the only means of sending one here (RFC 9126 section 4). POST ' +
          'the ' +
          'parameters to ' + self.asBaseOf(req) +
          '/oauth2/par first and send the ' +
          'request_uri it answers with.' }, 'STS-OAUTH-0419');
    }
    if (pushed && !jar.alg &&
        requestObject.signedRequired(client,
                                     self.authorizationProfileOf(req))) {
      log.debug("Leaving OAuth2Server.pushedRequestPolicyRefusal(). Pushed " +
                "plain, and a " +
                "signed request object is now required.");
      return errorCodes.mark({ error: 'invalid_request',
        description: 'this request_uri was pushed as plain parameters, and a ' +
          'signed request object is required here now (RFC 9101 section ' +
          '10.5, RFC 9126 sections 2.3 and 7.4). Push the request again as a ' +
          'signed ' +
          '`request`.' }, 'STS-OAUTH-0426');
    }
    log.debug("Leaving OAuth2Server.pushedRequestPolicyRefusal(). Nothing " +
              "refused.");
    return null;
  }

  // Whether RFC 9126 section 2.4 lets a pushed request's redirect_uri past the
  // registration check at the authorization endpoint: it was let through at the
  // push on the strength of a VERIFIED credential, and the setting still says
  // so.
  private pushedRedirectRelaxed(req: Req): Json {
    const { log, config, par } = this.deps;
    log.debug("Entering OAuth2Server.pushedRedirectRelaxed().");
    const jar = req.stsJar || null;
    const pushed = jar && jar.source === 'par' ? (jar.pushed || {}) : null;
    const relaxed = !!(pushed && pushed.clientAuthenticated &&
                       pushed.redirectUriAuthenticated &&
                       config.value('oauth2.parAllowUnregisteredRedirectUris'));
    log.debug("Leaving OAuth2Server.pushedRedirectRelaxed(). " + relaxed);
    return relaxed;
  }

  // -------------------------------------------------------------------------
  // THE id_token_hint (OIDC Core section 3.1.2.1, #118, 2026-09-22).
  //
  // "ID Token previously issued by the Authorization Server being passed as a
  // hint about the End-User's current or past authenticated session with the
  // Client." It was declared in the schema and never read. Now it is
  // VERIFIED as an ID Token this service issued — its signature with the key
  // of the algorithm it names (this realm's own RSA generations for RS256,
  // the client's secret for HS*, the published key whose kid it names for the
  // rest, post-quantum included), its `iss` this authorization server's and
  // its `aud` naming this client — and an EXPIRED one is still a hint: it
  // describes a past session, which is what the member is for. An encrypted
  // hint (a JWE the client re-encrypted to this server, which section
  // 3.1.2.1 says it MAY send) is refused by name: this service does not
  // decrypt one.
  //
  // It runs here, asynchronously, after a request object is resolved (the
  // hint may be inside one), and leaves its verdict on `req.stsIdTokenHint`
  // for `authorizeRequest()` to act on once the redirect_uri is vetted — so
  // a bad hint is reported to the client rather than on this server.
  // -------------------------------------------------------------------------
  private withIdTokenHint(req: Req, res: Res): Json {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.withIdTokenHint().");
    const hint = String((req.query || {}).id_token_hint || '');
    if (!hint) {
      log.debug("Leaving OAuth2Server.withIdTokenHint(). None.");
      return self.authorizeRequest(req, res);
    }
    log.debug("Leaving OAuth2Server.withIdTokenHint(). Verifying.");
    return self.verifyIdTokenHint(req, hint,
                                  String((req.query || {}).client_id || ''))
      .then(function (verdict: Json) {
        req.stsIdTokenHint = verdict;
        return self.authorizeRequest(req, res);
      }).catch(function (e: Json) {
        log.error(errorCodes.tag('STS-OAUTH-0565') + 'the authorization ' +
                  'endpoint failed while reading an id_token_hint: ' +
                  ((e && e.stack) || e));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-OAUTH-0565');
          self.oauthError(res, 500, 'server_error',
                          String((e && e.message) || e));
        }
      });
  }

  // `{ ok: true, sub, claims }` or `{ ok: false, why }`. Never rejects for a
  // bad token — only for a failure to ask at all.
  private async verifyIdTokenHint(req: Req, hint: Json,
                                  clientId: Json): Promise<Json> {
    const { log, stsCrypto, allSigningKeysAsync, applications } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.verifyIdTokenHint().");
    const parts = String(hint).split('.');
    if (parts.length === 5) {
      log.debug("Leaving OAuth2Server.verifyIdTokenHint(). Encrypted.");
      return { ok: false, why: 'the id_token_hint is encrypted (a JWE), and ' +
               'this service reads only the signed ID Token it issued — send ' +
               'that, as section 3.1.2.1 has the client do.' };
    }
    let header: Json = null;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url')
                                .toString('utf8'));
    } catch (e) {
      log.debug("Caught in OAuth2Server.verifyIdTokenHint(): " +
                ((e && e.message) || e));
      log.debug("Leaving OAuth2Server.verifyIdTokenHint(). Unreadable.");
      return { ok: false, why: 'the id_token_hint is not a JWT.' };
    }
    const alg = String((header && header.alg) || '');
    let verified: Json = null;
    try {
      if (/^(RS|PS)(256|384|512)$/.test(alg)) {
        // The RSA key signs RS* and PS* alike (PS256 is FAPI 1.0 Advanced's
        // default, #139).
        verified = helpers.verifyOwnCompactJws(hint, { algorithms: [alg] });
      } else if (/^HS(256|384|512)$/.test(alg)) {
        const registered = applications.registrationOf(clientId) || {};
        if (!registered.client_secret) {
          log.debug("Leaving OAuth2Server.verifyIdTokenHint(). No secret.");
          return { ok: false, why: 'the id_token_hint is signed with ' + alg +
                   ' and client "' + clientId + '" has no client_secret to ' +
                   'verify it with.' };
        }
        verified = stsCrypto.verifyCompactJws(hint,
          Buffer.from(String(registered.client_secret), 'utf8'),
          { algorithms: [alg] });
      } else {
        const keys: Json[] = await allSigningKeysAsync();
        const entry = keys.filter(function (one: Json) {
          return one.publicJwk && one.publicJwk.kid === header.kid &&
                 (!one.publicJwk.alg || one.publicJwk.alg === alg);
        })[0];
        if (!entry) {
          log.debug("Leaving OAuth2Server.verifyIdTokenHint(). No such key.");
          return { ok: false, why: 'the id_token_hint names key "' +
                   (header.kid || '') + '" for ' + alg + ', and this service ' +
                   'holds no such key.' };
        }
        verified = await stsCrypto.verifyCompactJwsAsync(hint,
          entry.publicJwk, { algorithms: [alg] });
      }
    } catch (e) {
      log.debug("Caught in OAuth2Server.verifyIdTokenHint(): " +
                ((e && e.message) || e));
      log.debug("Leaving OAuth2Server.verifyIdTokenHint(). It did not " +
                "verify.");
      return { ok: false, why: 'the id_token_hint did not verify as an ID ' +
               'Token this service issued: ' + ((e && e.message) || e) + '.' };
    }
    const claims = (verified && verified.claims) || verified || {};
    const issuer = self.issuerOf(self.asBaseOf(req));
    const audiences = [].concat(claims.aud || []).map(String);
    if (String(claims.iss || '') !== issuer) {
      log.debug("Leaving OAuth2Server.verifyIdTokenHint(). Another issuer.");
      return { ok: false, why: 'the id_token_hint was issued by "' +
               (claims.iss || '') + '", and this authorization server is "' +
               issuer + '".' };
    }
    if (audiences.indexOf(String(clientId)) < 0) {
      log.debug("Leaving OAuth2Server.verifyIdTokenHint(). Another client.");
      return { ok: false, why: 'the id_token_hint was issued to ' +
               JSON.stringify(claims.aud) + ', not to client "' + clientId +
               '".' };
    }
    log.debug("Leaving OAuth2Server.verifyIdTokenHint(). Verified.");
    return { ok: true, sub: String(claims.sub || ''), claims: claims };
  }

  private authorizeRequest(req: Req, res: Res): Json {
    const { log, STS, hasScope, issuerStates, authn, bcp, applications,
            errorCodes, stepUp, richAuthorization, consent, consentScreen,
            sessionOf, nameForSubject } = this.deps;
    const self = this;
    log.debug("Entering the authorization endpoint.");
    // This authorization server's own base, so the RFC 9207 `iss` on the
    // response and every token minted below name the server the client is
    // talking to.
    const base = self.asBaseOf(req);
    // What a JARM response (#139, #143) is signed for, whichever answer below
    // sends it: the client and its response type, from the request as it
    // stands now — the resolved request object's, where there was one.
    res.locals.stsJarm = { clientId: String((req.query || {}).client_id || ''),
                           types: String((req.query || {}).response_type ||
                                         '') };

    // RFC 9126's two policies, before anything in the request is believed. See
    // pushedRequestPolicyRefusal().
    const policy = self.pushedRequestPolicyRefusal(req);
    if (policy) {
      log.debug("Leaving the authorization endpoint. " + policy.description);
      errorCodes.mark(res, errorCodes.codeOf(policy) || 'STS-OAUTH-0419');
      log.debug("Leaving OAuth2Server.authorizeRequest().");
      return self.oauthError(res, 400, policy.error, policy.description);
    }

    // The request-level checks, in `vetAuthorizationRequest()` so that the PAR
    // endpoint asks the same ones of a pushed request. A refusal it says may
    // not be redirected is answered here as a 400; the rest go through `fail()`
    // below, which needs the vetted redirect_uri to exist first.
    const vetted = self.vetAuthorizationRequest(req, {
      relaxRedirect: self.pushedRedirectRelaxed(req)
    });
    if (!vetted.ok && !vetted.redirect) {
      log.debug("Leaving the authorization endpoint. Refused on this server (" +
                vetted.code + ").");
      errorCodes.mark(res, vetted.code);
      log.debug("Leaving OAuth2Server.authorizeRequest().");
      // error-code: none — the code is vetAuthorizationRequest()'s, marked
      // above
      return self.oauthError(res, vetted.status, vetted.error,
                             vetted.description);
    }
    const q = vetted.q;
    const redirectUri = vetted.redirectUri;

    const fail = function (error, description) {
      log.debug("Entering fail().");
      // RFC 9700 section 4.11.2: an authorization server must authenticate the
      // user BEFORE redirecting them. With nobody signed in, an error
      // redirected to a client's registered redirect_uri turns this endpoint
      // into a hop an attacker can send a victim through with no interaction at
      // all — the URI is legitimate, which is what makes it worth having.
      //
      // The session is read here rather than passed in because this closure is
      // called from a dozen places above and below the session lookup, and a
      // policy that depended on WHERE it was called from would be one that
      // eventually got it wrong.
      const policy = bcp.redirectPolicyFor({
        hasSession: !!sessionOf(req), prompt: q.prompt,
        fromSignIn: !!q.authn_error
      });
      if (!policy.redirect) {
        log.debug("Leaving the authorization endpoint. Showing " + error +
                  " rather than redirecting it (" + policy.requirement + ").");
        log.debug("Leaving fail().");
        const shown: Json = {
          error: error, description: description, redirectUri: redirectUri,
          clientId: q.client_id, state: q.state, why: policy.why,
          // The link the person can choose. It carries the same parameters the
          // redirect would have — including the RFC 9207 iss — because the
          // point is to make the redirect a DECISION rather than to change it.
          target: self.redirectTarget(base, redirectUri, q.state,
                                      Object.assign({ error: error,
                                        error_description: description },
                                        self.sessionStateField(res,
                                                               redirectUri)),
                                      self.usesFragment(q.response_type,
                                                        q.response_mode))
        };
        // A FORM POST REQUEST GETS A FORM (#126). The link above is a GET
        // carrying the error in the URL — exactly what a client that asked
        // for form_post asked NOT to receive (OAuth 2.0 Form Post Response
        // Mode, section 2). So the person's choice is a button that POSTs
        // the same fields to the redirect URI; no script, because this page is
        // a decision and a form that submitted itself would be the redirect
        // with an extra page in front of it.
        if (String(q.response_mode || '') === 'form_post') {
          const posted: Json = Object.assign({ error: error,
            error_description:
              self.deps.oauth21.sanitizeDescription(description) },
            self.sessionStateField(res, redirectUri));
          if (q.state !== undefined) {
            posted.state = q.state;
          }
          posted.iss = base;
          shown.form = posted;
        }
        // A JARM request's link carries the JWT-secured error (#139, #143),
        // which is what its client reads.
        if (self.deps.jarm.isJarm(q.response_mode)) {
          const fields: Json = Object.assign({ error: error,
                                 error_description: description, iss: base },
                                 self.sessionStateField(res, redirectUri));
          if (q.state !== undefined) {
            fields.state = q.state;
          }
          return self.jarmUrl(res, base, redirectUri, fields,
                              String(q.response_mode))
            .then(function (target: Json): Json {
              // form_post.jwt (#126): the JWT as a form field, POSTed.
              return self.sendRedirectInterstitial(res,
                Object.assign(shown, { target: target.url },
                              target.formPost
                                ? { form: { response: target.response } }
                                : {}));
            }).catch(function (e: Json): void {
              log.debug("Caught in fail(): " + ((e && e.message) || e));
              errorCodes.mark(res, errorCodes.codeOf(e) || 'STS-OAUTH-0588');
              self.oauthError(res, 400, 'invalid_request',
                              String((e && e.message) || e));
            });
        }
        return self.sendRedirectInterstitial(res, shown);
      }
      log.debug("Leaving the authorization endpoint. Reporting " + error + " " +
          "to the client" +
                (policy.why ? " (" + policy.why + ")" : "") + ".");
      // The response mode applies to an ERROR as much as to a success: a client
      // that asked for form_post and got a 302 carrying `error` in a query
      // string has had the failure put in its browser history, which is the one
      // place section 4.3 is asking for it not to be.
      // IN THE FRAGMENT FOR AN IMPLICIT OR HYBRID REQUEST (#118): where its
      // success would have gone. See usesFragment().
      // error-code: none — every caller of fail() marks its own code first
      self.redirectBack(res, base, redirectUri, q.state,
                        { error: error, error_description: description },
                        self.usesFragment(q.response_type, q.response_mode),
                        q.response_mode);
      log.debug("Leaving fail().");
    };
    if (!vetted.ok) {
      log.debug("Leaving the authorization endpoint. Reporting a refusal to " +
                "the client (" + vetted.code + ").");
      errorCodes.mark(res, vetted.code);
      log.debug("Leaving OAuth2Server.authorizeRequest().");
      // error-code: none — the code is vetAuthorizationRequest()'s, marked
      // above
      return fail(vetted.error, vetted.description);
    }
    // An id_token_hint that did not verify (#118) — see withIdTokenHint().
    const idTokenHint = req.stsIdTokenHint || null;
    if (idTokenHint && !idTokenHint.ok) {
      log.debug("Leaving the authorization endpoint. The id_token_hint was " +
                "refused.");
      errorCodes.mark(res, 'STS-OAUTH-0566');
      log.debug("Leaving OAuth2Server.authorizeRequest().");
      return fail('invalid_request', 'id_token_hint: ' + idTokenHint.why);
    }

    // issuer_state (OID4VCI section 4.1.1): if this request came from a
    // Credential Offer this server issued, say so — it is what ties the
    // authorization request back to the offer, and seeing it arrive is most of
    // its debugging value.
    if (q.issuer_state) {
      const known = issuerStates.get(String(q.issuer_state));
      if (known && known.expires >= Date.now()) {
        log.debug("The authorization request carries an issuer_state from a " +
                  "Credential Offer this issuer made " +
                  "(credential_configuration_ids=" +
                  (known.configurationIds || []).join(', ') + ").");
      } else {
        log.debug("The authorization request carries an issuer_state this " +
                  "issuer does not recognise: " +
                  q.issuer_state);
      }
    }

    // Did the person come back from the authentication service having refused?
    // Checked BEFORE the session, because there is no session in that case and
    // the next thing this endpoint would otherwise do is send them straight
    // back to the screen they just declined — a redirect loop with a login form
    // in it.
    //
    // The service names the outcome and this endpoint decides what OAuth does
    // about it, which is what keeps protocol knowledge here: `redirectBack()`
    // knows about response_mode, and in form_post the answer is not a redirect
    // at all but a self-submitting form.
    if (q.authn_error) {
      log.debug("Leaving the authorization endpoint. The authentication " +
                "service reported " +
                q.authn_error + ".");
      errorCodes.mark(res, 'STS-OAUTH-0166');
      log.debug("Leaving OAuth2Server.authorizeEndpoint().");
      return fail(String(q.authn_error),
                  String(q.authn_error_description ||
                         'Authentication did not ' + 'complete.'));
    }

    // ---------------------------------------------------------------------
    // AND THE SAME QUESTION FOR THE CONSENT SCREEN, one line below the sign-in
    // screen's for one reason and a different one.
    //
    // The shared reason: `consent_screen.ts` names the OUTCOME and this
    // endpoint decides what OAuth does about it, because `redirectBack()` knows
    // about `response_mode` and in `form_post` the answer is not a redirect at
    // all.
    //
    // The reason it must be HERE rather than below the session check is the
    // opposite of the sign-in screen's. A refused sign-in leaves no session, so
    // the branch below would draw the login screen again — a loop with a form
    // in it. A refused CONSENT leaves the session standing, so the branch below
    // would find it, ask `consent.outstanding()` again, and send the person
    // straight back to the screen they just said no on. Same loop, one door
    // along, and the only way out would be closing the tab.
    // ---------------------------------------------------------------------
    if (q.consent_error) {
      log.debug("Leaving the authorization endpoint. The consent screen " +
                "reported " +
                q.consent_error + ".");
      errorCodes.mark(res, 'STS-OAUTH-0167');
      log.debug("Leaving OAuth2Server.authorizeEndpoint().");
      return fail(String(q.consent_error),
                  String(q.consent_error_description ||
                         'Consent was not given.'));
    }

    // Already signed in? Then this is the second pass — back from the
    // authentication service, or a later request on the same session — and the
    // response goes out now.
    const session = sessionOf(req);
    const promptList = String(q.prompt || '').split(/\s+/);
    // `select_account` (#118): "The Authorization Server SHOULD prompt the
    // End-User to select a user account" — which, with one session per
    // browser here, is the sign-in screen: whoever signs in is the account
    // selected. It was silently ignored.
    // AND A SESSION FOR SOMEBODY OTHER THAN THE id_token_hint NAMES is not an
    // answer to this request (section 3.1.2.1): with prompt=none it is
    // login_required, and otherwise the person signs in again.
    const hintMismatch = !!(idTokenHint && idTokenHint.ok && session &&
      self.subjectFor(q.client_id, (session.user || {}).sub) !==
        idTokenHint.sub);
    // THE SECOND PASS: the person was sent to sign in because of the hint and
    // came back as somebody else again. Refused rather than sent round again,
    // which would loop for as long as they kept choosing that account.
    const hintPrompted = String(((req.stsJar && req.stsJar.outer) || q)
      .hint_prompted || '') === '1';
    if (hintMismatch && (promptList.indexOf('none') >= 0 || hintPrompted)) {
      log.debug("Leaving the authorization endpoint. The session is not the " +
                "id_token_hint's person, and prompt=none.");
      errorCodes.mark(res, 'STS-OAUTH-0567');
      return fail('login_required', 'The id_token_hint names a different ' +
        'person from the one signed in here, and prompt=none forbids asking ' +
        'them to sign in (OIDC Core section 3.1.2.1).');
    }
    const forcePrompt = promptList.indexOf('login') >= 0 ||
                        promptList.indexOf('select_account') >= 0 ||
                        hintMismatch;
    // -------------------------------------------------------------------------
    // RFC 9470 AND OPENID CONNECT CORE 3.1.2.1: A SESSION IS NOT AN ANSWER TO A
    // REQUEST IT DOES NOT MEET (2026-09-13).
    //
    // Until this block a session was answered from whatever it was, so a client
    // stepping up with `acr_values=mfa` on a password session was handed the
    // password session's token — the resource server challenged it again, and
    // the loop never closed. Now the session is ASSESSED first: met, it is
    // answered and the token carries the most preferred requested acr it met;
    // not met, the person is sent to sign in again, once; not met on the way
    // back from that sign-in, the request is refused `unmet_authentication_
    // requirements` in every mode. `prompt=none` cannot send anybody anywhere
    // and is answered `login_required`. `step_up.ts` decides all four.
    // -------------------------------------------------------------------------
    // OpenID Connect Registration section 2's default_max_age and
    // default_acr_values apply where the request names neither (#120).
    const stepUpNeed = stepUp.requirementOf(q,
      applications.registrationOf(q.client_id));
    const stepUpHonoured = String(((req.stsJar && req.stsJar.outer) || q)
      .step_up_honoured || '') === '1';
    const promptNone = String(q.prompt || '').split(/\s+/).indexOf('none') >= 0;
    let stepUpAssessed = null;
    if (session && !forcePrompt && stepUpNeed.present) {
      stepUpAssessed = stepUp.assessSession(stepUpNeed, session, {
        honoured: stepUpHonoured,
        windowS: Math.floor(authn.pendingTtlMs() / 1000)
      });
      if (!stepUpAssessed.met && (promptNone || !stepUpAssessed.retry)) {
        const unmet = stepUp.unmetRefusal(stepUpNeed, stepUpAssessed,
                                          promptNone);
        stepUp.record(q.client_id, promptNone ? 'stepup.login_required'
                                              : 'stepup.unmet',
                      { error: unmet.error });
        log.info('oauth2: RFC 9470: an authorization request from "' +
                 (q.client_id || '') + '" was refused ' + unmet.error + ': ' +
                 unmet.description);
        errorCodes.mark(res, errorCodes.codeOf(unmet) || 'STS-OAUTH-0500');
        log.debug("Leaving OAuth2Server.authorizeRequest(). The step-up " +
                  "requirement was " +
                  "not met.");
        // error-code: none — marked on the line above from the refusal's code
        return fail(unmet.error, unmet.description);
      }
    }
    const stepUpReauth = !!(stepUpAssessed && !stepUpAssessed.met);
    if (session && !forcePrompt && !stepUpReauth) {
      // -------------------------------------------------------------------
      // SINGLE SIGN-ON JUST HAPPENED, AND THIS IS THE ONLY PLACE THAT KNOWS IT.
      //
      // An authorization request answered out of a session that already existed
      // is CAEP's `session-presented` — the one CAEP event about something
      // entirely ordinary, and the one a receiver needs in order to see a live
      // session it is not itself being asked about. `authn.notePresented()`
      // drops the FIRST presentation of a brand-new session, because that one
      // is the sign-in's own return trip and not single sign-on; its header
      // argues it.
      //
      // Here rather than in `sessionOf()`, which is called several times per
      // request — an event there would be several events for one act — and
      // before the consent check on purpose: the session WAS presented and
      // honoured whatever the person then answers about scopes.
      // -------------------------------------------------------------------
      authn.notePresented(session, 'OAuth 2.0 / OIDC', req);
      // -------------------------------------------------------------------
      // CONSENT, AND IT IS THE LAST THING BETWEEN A SIGNED-IN PERSON AND AN
      // ISSUED CREDENTIAL.
      //
      // It sits HERE — inside the branch that has a session, above
      // issueAuthorizationResponse() — because the question is about a PERSON
      // and there is no person until there is a session. Everything above this
      // line is about the request; this is the only check in this endpoint that
      // is about who is answering it.
      //
      // WHAT IS ASKED is `common/consent.ts`'s to decide and not this
      // endpoint's: which scopes this username has already agreed to for this
      // client_id, which the application's `oauthGlobalConsent` covers for
      // everybody, and therefore which are outstanding. A copy of that rule
      // here would be the second place it was decided — `permissionRefusal()`
      // one screen up carries the same argument for the same reason.
      //
      // `prompt=consent` (OIDC Core section 3.1.2.1) makes every requested
      // scope outstanding whatever is on the entry. It does NOT delete what was
      // agreed: re-consenting adds nothing new, and somebody who denies keeps
      // what they had.
      // -------------------------------------------------------------------
      const wantsConsent = String(q.prompt || '').split(/\s+/)
                                                 .indexOf('consent') >= 0;
      const decision: Json = consent.required()
        ? consent.outstanding({ username: (session.user || {}).username,
                                clientId: q.client_id,
                                scope: q.scope, all: wantsConsent })
        : { outstanding: [], scopes: [] };
      // RFC 9396: details of a declared type are asked about EVERY time, and an
      // Allow is spent here, on the pass that follows it — see
      // `authorization_details.ts`'s header. Unusable details are left for
      // issueAuthorizationResponse() to refuse, rather than asked about.
      const consentDetails = consent.required()
        ? self.parseAuthorizationDetails(q.authorization_details,
                                         { clientId: q.client_id, req: req })
        : { details: null };
      // Nor are details the audience rule will refuse (two APIs, or a resource
      // or scope naming another): asking somebody to agree to a request that is
      // then refused is a question with no answer.
      const detailsPlannable = !!consentDetails.details &&
        !self.accessTokenPlan(
          self.asBaseOf(req), String(q.scope || ''), q.client_id,
          self.parseResourceIndicators(q.resource).resources || [],
          consentDetails.details).refusal;
      const detailsDigest = detailsPlannable &&
        richAuthorization.needsConsent(consentDetails.details)
        ? richAuthorization.digestOf(consentDetails.details) : '';
      const detailsOutstanding = !!detailsDigest &&
        !richAuthorization.consumeConsented((session.user || {}).username,
                                            q.client_id, detailsDigest);
      if (decision.outstanding.length || detailsOutstanding) {
        // prompt=none FORBIDS ANY UI, and OIDC Core section 3.1.2.6 gives this
        // exact case its own error code. Answering `interaction_required` — the
        // general one — would be true and less useful: a client that gets
        // `consent_required` knows to retry WITHOUT prompt=none, and one that
        // gets `interaction_required` cannot tell a missing session from a
        // missing consent.
        if (String(q.prompt || '').split(/\s+/).indexOf('none') >= 0) {
          log.debug("Leaving the authorization endpoint. Consent is " +
                    "outstanding and prompt=none forbids showing the screen.");
          errorCodes.mark(res, 'STS-OAUTH-0168');
          log.debug("Leaving OAuth2Server.authorizeEndpoint().");
          return fail('consent_required',
            '"' + ((session.user || {}).username || '') +
            '" has not consented ' +
            decision.names.map(function (one) { return '"' + one + '"'; })
              .concat(detailsOutstanding
                ? ['this request\'s authorization_details (RFC 9396), which ' +
                   'are asked about every time'] : [])
              .join(', ') +
            ' for the client "' + (q.client_id || '') + '", and prompt=none ' +
            'forbids showing the consent screen. Retry without prompt=none, ' +
            'or consent the scope for every user of this application at ' +
            '/admin/consent — which is what an application that must never ' +
            'interrupt anybody is configured with. oauth2.consentRequired ' +
            'turns the screen off entirely.');
        }
        // THE SAME `returnTo` THE SIGN-IN HOP USES, built the same way and with
        // `prompt` dropped for the same reason: it has been honoured by the
        // time they come back, and leaving `prompt=consent` on would ask again
        // for ever. Everything else goes back untouched, because the second
        // pass has to be the request the client actually made.
        const consentReturnTo = self.asPathOf(req) + '/oauth2/authorize?' +
                                self.authorizationReturnQuery(req, q);
        // -----------------------------------------------------------------
        // THE APPLICATION IS RECORDED HERE AS WELL, AND IT HAS TO BE.
        //
        // `issueAuthorizationResponse()` is where a client_id is normally
        // written into `ou=applications`, and it is not reached on this path:
        // nothing is issued until the person answers. Without this, an
        // application whose very first request meets the consent screen has NO
        // ENTRY — so the screen shows a bare client_id where a name belongs,
        // and (much worse) `/admin/consent` cannot offer it in the list of
        // applications a scope can be consented for. An operator who wanted to
        // pre-consent a new client would have had to sign in to it first, agree
        // to everything by hand, and then configure the thing that was supposed
        // to stop them being asked.
        //
        // `counts: false`, and that is the whole of what makes it honest. Being
        // ASKED for consent is not an authentication — nothing has been issued
        // and the person may be about to say no — so this records the SIGHTING
        // and leaves `appAuthentications` alone. The call below in
        // `issueAuthorizationResponse()` is the one that counts, and it counts
        // once whether or not this ran.
        // -----------------------------------------------------------------
        applications.seen({
          identifier: String(q.client_id),
          kind: hasScope(q.scope, 'openid') ? 'oidc-relying-party' :
                'oauth2-client',
          protocol: 'OAuth 2.0 / OIDC',
          user: (session.user || {}).username || '',
          counts: false,
          note: 'asked a person for consent',
          fields: {
            oauthClientId: String(q.client_id),
            appAuthorizationServer: self.profileOf(req),
            oauthScope: String(q.scope || '').split(/\s+/).filter(Boolean)
          }
        });
        const entry = applications.get(String(q.client_id || ''));
        log.debug("Leaving the authorization endpoint. " +
                  decision.outstanding.length +
                  " scope(s) need consent first" +
                  (detailsOutstanding ? ", and authorization_details." : "."));
        return res.redirect(302, consentScreen.beginConsent({
          returnTo: consentReturnTo,
          // THE TYPED NAME AND NOT THE CLAIMS OBJECT. `session.user` is what
          // `helpers.userFor()` built — `sub`, `email`, `name` and the rest —
          // and handing that to the screen put `[object Object]` where a
          // person's name belongs and filed their consent under nobody.
          username: (session.user || {}).username || '',
          clientId: String(q.client_id || ''),
          clientName: (entry && entry.name) || String(q.client_id || ''),
          scopes: decision.outstanding,
          authorizationDetails: detailsOutstanding
            ? richAuthorization.describe(consentDetails.details) : [],
          detailsDigest: detailsOutstanding ? detailsDigest : '',
          already: decision.scopes.filter(function (one) {
            return decision.outstanding.indexOf(one) < 0;
          }),
          protocol: 'OAuth 2.0 / OIDC',
          details: [
            { label: 'client_id', value: q.client_id || '' },
            { label: 'scope', value: q.scope || '(none requested)' },
            { label: 'redirect_uri', value: q.redirect_uri || '' }
          ].concat(self.requestObjectDetail(req))
        }));
      }
      log.debug("Leaving the authorization endpoint. The session stands, so " +
                "the response goes out now.");
      // A CATCH RATHER THAN AN `async` HANDLER. That function became
      // asynchronous when the ID Token's signature moved to the worker pool,
      // and its return value was never used — but a promise nobody catches is a
      // request that hangs where a throw used to be a 500, so the rejection is
      // turned back into an answer here. Everything else in this handler still
      // throws synchronously, which express still catches.
      if (stepUpAssessed) {
        stepUp.record(q.client_id, stepUpHonoured ? 'stepup.met_after_sign_in'
                                                  : 'stepup.met_by_session');
      }
      return self.issueAuthorizationResponse(req, res, q, session.user,
                                             session.authTime, session,
                                             stepUpAssessed ? stepUpAssessed.acr
                                                            : null)
        .catch(function (e) {
          log.error(errorCodes.tag('STS-OAUTH-0169') + 'the authorization ' +
                                                       'response could not ' +
                                                       'be issued: ' +
                    e.message);
          errorCodes.mark(res, 'STS-OAUTH-0169');
          return fail('server_error', e.message);
        });
    }
    if (String(q.prompt || '').split(/\s+/).indexOf('none') >= 0) {
      // OIDC: prompt=none must not show any UI.
      errorCodes.mark(res, 'STS-OAUTH-0170');
      log.debug("Leaving OAuth2Server.authorizeEndpoint().");
      return fail('login_required', 'No session, and prompt=none forbids ' +
                                    'showing the login screen.');
    }

    // Otherwise: hand the person to the authentication service, and say where
    // to bring them back to — this same endpoint, with this same request.
    //
    // `prompt` is dropped from the return URL and only from it: it has been
    // honoured by the time they come back, and leaving it on would send them
    // round again for ever. Everything else goes back untouched, because what
    // runs on the return leg has to be the request the client actually made —
    // the PKCE challenge, the nonce, authorization_details and the rest are all
    // read on that second pass. THE PATH OF THIS AUTHORIZATION SERVER'S OWN
    // ENDPOINT, not the default one's. This was hard-coded to
    // `/oauth2/authorize`, which sent every named authorization server's second
    // pass — the one after the sign-in screen, the one that actually issues the
    // code — to the DEFAULT server. The request looked right the whole way
    // through and the code came out belonging to somebody else, which is the
    // kind of bug that only shows up as a refusal two steps later.
    const returnTo = self.asPathOf(req) + '/oauth2/authorize?' +
                     self.authorizationReturnQuery(req, q) +
                     (hintMismatch ? '&hint_prompted=1' : '');
    // acr_values is how a relying party demands a second factor. A request
    // whose every producible value needs two — `mfa`, or a hardware key named
    // by its RFC 8176 method — forces the second-factor step and disables the
    // opt-out, so the checkbox cannot be used to answer a request for step-up
    // with a password. SINCE RFC 9470 (2026-09-13) the values are read as the
    // ordered preference list they are: `mfa 1` accepts one factor and does not
    // force a second, and a value is matched whole and case-sensitively, where
    // a regex used to find `mfa` inside any word.
    //
    // AND A REQUEST NAMING ONLY KEY ALIASES (`hwk`, `phr`, `phrh`) FORCES THE
    // KEY TOO (2026-09-17): those are met by a password with a security key,
    // so the screen offers exactly that and not a one-time code, which would
    // only be refused on the way back. `step_up.screenDemandFor()`.
    const screen = stepUp.screenDemandFor(stepUpNeed.acrValues);
    const forceMfa = !!screen.forceMfa;
    if (stepUpReauth) {
      stepUp.record(q.client_id, 'stepup.reauth_' + stepUpAssessed.reason);
      log.info('oauth2: RFC 9470: the session does not meet the request ' +
               'from "' +
               (q.client_id || '') + '" (' + stepUpAssessed.reason + '), so ' +
               'the person is sent to sign in again.');
    } else if (stepUpNeed.present) {
      stepUp.record(q.client_id, 'stepup.sign_in');
    }
    // What the screen tells the person they are signing in FOR. Written here
    // because these are OAuth's parameters and only this module knows what they
    // mean — the issuer_state note in particular, which says whether the
    // request came from a Credential Offer this issuer actually made.
    const details: Json[] = [
      { label: 'client_id', value: q.client_id || '' },
      { label: 'scope', value: q.scope || '(none requested)' },
      { label: 'redirect_uri', value: q.redirect_uri || '' }
    ].concat(self.requestObjectDetail(req));
    if (q.issuer_state) {
      details.push({ label: 'issuer_state', value: q.issuer_state,
                     note: issuerStates.has(String(q.issuer_state))
                       ? 'from a Credential Offer this issuer made' : '' });
    }
    res.redirect(302, authn.beginAuthentication({
      returnTo: returnTo, details: details,
      // The login_hint, or the person a verified id_token_hint names where
      // that subject is one this directory can name (#118).
      hint: q.login_hint ||
            (idTokenHint && idTokenHint.ok
              ? (nameForSubject(idTokenHint.sub) || '') : ''),
      forceMfa: forceMfa, forceKey: !!screen.forceKey,
      protocol: 'OAuth 2.0 / OIDC',
      // WHICH APPLICATION this is, so that an entry naming a federation
      // relationship sends the person to that partner instead of to the sign-in
      // screen. It is the raw client_id: the registry is keyed by the
      // identifier exactly as a protocol presented it, and one this service has
      // never heard of simply has no entry, which is not an error.
      application: q.client_id || ''
    }));
    log.debug("Leaving the authorization endpoint. Sent to the " +
              "authentication " +
              "service first.");
  }

  // The shell for the sign-out page, the one page here drawn in this shell (the
  // form_post page and the authorization error interstitial build their own
  // markup). Deliberately tiny and local: this module is an authorization
  // server and not a web site, `admin.js` owns the console's shell, and
  // requiring that module from here would invert rule 5.
  // `head` is markup for the <head>, already escaped — the one caller that
  // passes it is the front-channel return's <meta> refresh (#122).
  private logoutPage(inner: Json, head?: string): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.logoutPage().");
    log.debug("Leaving OAuth2Server.logoutPage().");
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta ' +
      'name="viewport" content="width=device-width, ' +
      'initial-scale=1"><title>Signed ' +
      'out</title>' + (head || '') +
      '<style>body{font-family:system-ui,-apple-system,"Segoe ' +
      'UI",Roboto,sans-serif;margin:2rem auto;max-width:52rem;padding:0 1rem;' +
      'line-height:1.5;color:#111}h1{font-size:1.4rem}h2{font-size:1.1rem;' +
      'margin-top:1.6rem}.sub{color:#555;font-size:.9rem}' +
      '.ok{background:#e8f5e9;border-left:4px solid #2e7d32;padding:.6rem ' +
      '.8rem;margin:1rem ' +
      '0}table{border-collapse:collapse;width:100%;margin:.6rem ' +
      '0}th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid ' +
      '#ddd;vertical-align:top}code{background:#f4f4f4;padding:.05rem ' +
      '.25rem;border-radius:3px;word-break:break-all}</style></head><body>' +
      inner + '</body></html>';
  }

  // WHETHER A post_logout_redirect_uri IS ONE THIS ENDPOINT WILL CONSIDER
  // FOLLOWING AT ALL: http(s), or a native application's private-use address
  // — which `bcp.checkPostLogoutRedirectUri()` then believes only when the
  // client registered it (#124: in every mode). Anything else was refused by
  // the schema already.
  private logoutTargetConsidered(target: Json): Json {
    const { log, validation } = this.deps;
    log.debug("Entering OAuth2Server.logoutTargetConsidered().");
    const text = String(target || '');
    log.debug("Leaving OAuth2Server.logoutTargetConsidered().");
    return !!text && (/^https?:\/\//i.test(text) ||
                      validation.isPrivateUseRedirect(text));
  }

  // The return address with RP-Initiated Logout section 3's `state` on it —
  // the value the relying party sent, handed back unchanged (#124).
  private withLogoutState(target: string, state: Json): string {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.withLogoutState().");
    if (state === undefined || state === null || state === '') {
      log.debug("Leaving OAuth2Server.withLogoutState(). No state.");
      return target;
    }
    const at = target.indexOf('#');
    const base = at >= 0 ? target.slice(0, at) : target;
    const sep = base.indexOf('?') >= 0 ? '&' : '?';
    log.debug("Leaving OAuth2Server.withLogoutState().");
    return base + sep + 'state=' + encodeURIComponent(String(state)) +
           (at >= 0 ? target.slice(at) : '');
  }

  // A sign-out answer that is a PAGE for the person (#124, gap 8): a refusal
  // was a JSON `oauthError` shown to a browser. `status` 400 for a refusal.
  private logoutAnswer(res: Res, status: number, title: string,
                       body: string): Json {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering OAuth2Server.logoutAnswer(). " + status);
    res.status(status).type('text/html').set('Cache-Control', 'no-store')
       .send(this.logoutPage('<h1>' + xmlEscape(title) + '</h1>' + body)
         .replace('<title>Signed out</title>',
                  '<title>' + xmlEscape(title) + '</title>'));
    log.debug("Leaving OAuth2Server.logoutAnswer().");
    return undefined;
  }

  // The value the confirmation form carries (#124): a digest of the session's
  // CURRENT handle hash, which only a request carrying that session's cookie
  // can have been shown. A page confirmed for one session cannot end another,
  // and a re-authentication in between (a new handle) voids it.
  private logoutConfirmFor(session: Json): string {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering OAuth2Server.logoutConfirmFor().");
    log.debug("Leaving OAuth2Server.logoutConfirmFor().");
    return session && session.handleHash
      ? stsCrypto.truncatedSha256Hex(String(session.handleHash) +
                                     ':rp-initiated-logout', 32)
      : '';
  }

  // Does a `logout_hint` name the person signed in (#124)? Section 2 leaves
  // its form to the OP; this one answers to the username, the entry's mail
  // and the session's public subject, case-insensitively. No hint matches.
  private logoutHintMatches(session: Json, hint: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.logoutHintMatches().");
    const asked = String(hint || '').trim().toLowerCase();
    if (!asked) {
      log.debug("Leaving OAuth2Server.logoutHintMatches(). No hint.");
      return true;
    }
    const user = (session && session.user) || {};
    const names = [user.username, user.email, user.mail, user.sub,
                   session && session.subject]
      .filter(Boolean).map(function (one: Json): string {
        return String(one).toLowerCase();
      });
    log.debug("Leaving OAuth2Server.logoutHintMatches().");
    return names.indexOf(asked) >= 0;
  }

  // The client an id_token_hint was issued to, read UNVERIFIED and only to
  // choose what it is verified against: `azp` where there is one, else the
  // one audience. `verifyIdTokenHint()` then requires it among the verified
  // `aud`.
  private hintClientOf(hint: Json): string {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.hintClientOf().");
    let claims: Json = {};
    try {
      claims = JSON.parse(Buffer.from(String(hint).split('.')[1] || '',
                                      'base64url').toString('utf8')) || {};
    } catch (e) {
      log.debug("Caught in OAuth2Server.hintClientOf(): " +
                ((e && e.message) || e));
      // Unreadable: verifyIdTokenHint() says why.
      claims = {};
    }
    const audiences = [].concat(claims.aud || []).map(String);
    log.debug("Leaving OAuth2Server.hintClientOf().");
    return String(claims.azp || (audiences.length === 1 ? audiences[0] : ''));
  }

  // ---------------------------------------------------------------------------
  // OPENID CONNECT RP-INITIATED LOGOUT 1.0 (#124, which folded #115 in,
  // 2026-09-23). GET and POST (section 2's MUST). THE ORDER IS THE FIX:
  //
  //   1. the request is read — a form POST's body, or the query — and a
  //      malformed one is a PAGE (400, STS-OAUTH-0171) with the session
  //      untouched: it used to be ended first and validated after;
  //   2. an `id_token_hint` is VERIFIED (#115): this realm's issuer, a
  //      signature it made, an expired one still a hint; its audience is the
  //      client, and a `client_id` it was not issued to is refused
  //      (STS-OAUTH-0602, in every mode — section 2's MUST);
  //   3. `post_logout_redirect_uri` is decided — `bcp.checkPostLogoutRedirectUri()`,
  //      in every mode: the client's own list, exactly; development still
  //      follows one no client registered, product does not. A refused one is
  //      not followed and the person is told on the page;
  //   4. the person CONFIRMS, in every mode (rcbj), unless the request carries
  //      a verified hint for THIS session (its `sid`) and any `logout_hint`
  //      names them — so a link on another site cannot sign somebody out.
  //      A POST that arrived without the session cookie (cross-site, which
  //      `SameSite=Lax` does not send) is asked too, rather than answered with
  //      a cookie clear. The page has a real button and no script;
  //   5. only then the session ends, and the return carries `state`.
  //
  // `ui_locales` is accepted and English is the only language this service
  // has, so every page is `lang="en"`, which section 2 permits.
  // ---------------------------------------------------------------------------
  private logoutEndpoint(req: Req, res: Res): Json {
    const { log, validation, errorCodes, xmlEscape } = this.deps;
    const self = this;
    log.debug("Entering the logout endpoint.");
    if (req.method === 'POST') {
      const type = String((req.headers || {})['content-type'] || '')
        .split(';')[0].trim().toLowerCase();
      if (type !== 'application/x-www-form-urlencoded') {
        errorCodes.mark(res, 'STS-OAUTH-0604');
        log.debug("Leaving the logout endpoint. A POST that is not a form.");
        return self.logoutAnswer(res, 400, 'This sign-out request could not ' +
          'be read', '<p>A sign-out sent with POST is a form ' +
          '(application/x-www-form-urlencoded, RP-Initiated Logout 1.0 ' +
          'section 2). This one was <code>' + xmlEscape(type || '(none)') +
          '</code>. You are still signed in.</p>');
      }
      const raw = typeof req.body === 'string' ? req.body
        : (Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
      const fromBody: Json = {};
      new URLSearchParams(raw).forEach(function (value, name) {
        fromBody[name] = fromBody[name] === undefined ? value
          : [].concat(fromBody[name], value);
      });
      Object.defineProperty(req, 'query', { value: fromBody, writable: true,
                                            configurable: true,
                                            enumerable: true });
    }
    const asked = validation.check(req, 'query', LOGOUT_QUERY);
    if (!asked.ok) {
      log.debug("Leaving the logout endpoint. The request is malformed: " +
                asked.code + " on \"" + asked.field + "\".");
      errorCodes.mark(res, 'STS-OAUTH-0171');
      return self.logoutAnswer(res, 400, 'This sign-out request could not ' +
        'be read', '<p>' + xmlEscape(asked.detail) + '</p><p>Nothing has ' +
        'been done: you are still signed in.</p>');
    }
    self.logoutRequest(req, res, asked.value).catch(function (e: Json) {
      log.error(errorCodes.tag('STS-OAUTH-0605') + 'the logout endpoint ' +
                'failed: ' + ((e && e.stack) || e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-OAUTH-0605');
        self.logoutAnswer(res, 500, 'The sign-out failed', '<p>' +
          xmlEscape(String((e && e.message) || e)) + '</p>');
      }
    });
    log.debug("Leaving the logout endpoint. Handed on.");
    return undefined;
  }

  private async logoutRequest(req: Req, res: Res, q: Json): Promise<Json> {
    const { log, xmlEscape, bcp, backchannel, applications, errorCodes,
            endSession, sessionOf } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.logoutRequest().");
    // --- 2. the id_token_hint ---------------------------------------------
    let clientId = String(q.client_id || '');
    let hinted: Json = null;
    if (q.id_token_hint) {
      const hintClient = clientId || self.hintClientOf(q.id_token_hint);
      const verdict = await self.verifyIdTokenHint(req, q.id_token_hint,
                                                   hintClient);
      if (!verdict.ok) {
        errorCodes.mark(res, 'STS-OAUTH-0602');
        log.debug("Leaving OAuth2Server.logoutRequest(). The hint.");
        return self.logoutAnswer(res, 400, 'This sign-out request was ' +
          'refused', '<p>RP-Initiated Logout 1.0 section 2: ' +
          xmlEscape(verdict.why) + '</p><p>Nothing has been done: you are ' +
          'still signed in.</p>');
      }
      hinted = verdict.claims;
      clientId = hintClient;
    }
    const client = applications.clientConfigOf(clientId);
    // --- 3. the return -----------------------------------------------------
    let returnTo = '';
    let refusedNote = '';
    const target = q.post_logout_redirect_uri;
    if (target && self.logoutTargetConsidered(target)) {
      const check = bcp.checkPostLogoutRedirectUri({ target: String(target),
                                                     client: client });
      if (check.ok) {
        returnTo = self.withLogoutState(String(target), q.state);
      } else {
        errorCodes.mark(res, check.errorCode || 'STS-OAUTH-0123');
        log.info('oauth2: a post_logout_redirect_uri was not followed (' +
                 (check.errorCode || '') + '): ' + check.description);
        refusedNote = '<p class="sub">You were not returned to <code>' +
          xmlEscape(String(target)) + '</code>: ' +
          xmlEscape(check.description) + '</p>';
      }
    }
    // --- 4. confirmation ---------------------------------------------------
    const session = sessionOf(req);
    // The sign-on cookie, by name — `sts_session`, which `SameSite=Lax` keeps
    // off a cross-site POST.
    const cookiePresented = /(?:^|;\s*)sts_session=/.test(
      String((req.headers || {}).cookie || ''));
    const confirmed = req.method === 'POST' && q.confirm === 'yes' &&
      String(q.confirm_for || '') === self.logoutConfirmFor(session);
    if (req.method === 'POST' && q.confirm === 'no') {
      log.debug("Leaving OAuth2Server.logoutRequest(). Declined.");
      return self.logoutAnswer(res, 200, 'You are still signed in',
        '<p>Nothing was ended.</p>' + (returnTo
          ? '<p><a href="' + xmlEscape(returnTo) + '">Return to the ' +
            'application</a></p>' : ''));
    }
    const hintIsThisSession = !!(hinted && session && hinted.sid &&
                                 String(hinted.sid) === String(session.id));
    const mustAsk = !confirmed && (
      (session && !(hintIsThisSession &&
                    self.logoutHintMatches(session, q.logout_hint))) ||
      (!session && req.method === 'POST' && !cookiePresented));
    if (mustAsk) {
      log.debug("Leaving OAuth2Server.logoutRequest(). Asking.");
      return self.logoutConfirmPage(res, q, session, client);
    }
    // --- 5. the sign-out ---------------------------------------------------
    // The same session WS-Federation's wsignout1.0 ends, through the same
    // function — one browser session shared by both protocols means signing
    // out of either signs out of both.
    const backchannelMark = backchannel.mark();
    const ended = endSession(req, res);
    return self.logoutFinish(req, res, ended, backchannelMark, returnTo,
                             refusedNote);
  }

  // The page that asks (#124, #115). A real form that POSTs back here with
  // the request's own parameters and the value only this session's page can
  // carry; no script (the root CLAUDE.md: a form needs none).
  private logoutConfirmPage(res: Res, q: Json, session: Json,
                            client: Json): Json {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering OAuth2Server.logoutConfirmPage().");
    const carried = ['post_logout_redirect_uri', 'client_id',
                     'id_token_hint', 'state', 'logout_hint', 'ui_locales']
      .filter(function (name: string): boolean {
        return q[name] !== undefined && q[name] !== '';
      }).map(function (name: string): string {
        return '<input type="hidden" name="' + name + '" value="' +
               xmlEscape(String(q[name])) + '">';
      }).join('');
    const who = session && session.user ? session.user.username : '';
    const app = client && client.known
      ? (client.client_name || client.client_id) : (q.client_id || '');
    log.debug("Leaving OAuth2Server.logoutConfirmPage().");
    return this.logoutAnswer(res, 200, 'Sign out?',
      '<p>' + (app
        ? 'The application <code>' + xmlEscape(String(app)) + '</code> '
        : 'An application ') + 'asked to sign you out' +
      (who ? ' of <strong>' + xmlEscape(who) + '</strong>' : '') +
      '. This ends your session here, and every application signed in ' +
      'through it is told.</p>' +
      '<form method="post" action="logout">' + carried +
      '<input type="hidden" name="confirm_for" value="' +
      xmlEscape(this.logoutConfirmFor(session)) + '">' +
      '<button type="submit" name="confirm" value="yes">Sign out</button> ' +
      '<button type="submit" name="confirm" value="no">Stay signed in' +
      '</button></form><p class="sub">Asked because the request did not ' +
      'prove it came from an application you are signed in to with this ' +
      'session (RP-Initiated Logout 1.0 section 2).</p>');
  }

  // After the session has ended: the front-channel page, the return, or a
  // page saying it is done.
  private logoutFinish(req: Req, res: Res, session: Json,
                       backchannelMark: Json, returnTo: string,
                       refusedNote: string): Json {
    const { log, xmlEscape, frontchannel, backchannel, config } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.logoutFinish().");
    const backchannelRows = session
      ? backchannel.deliveriesFor([session.id], backchannelMark) : [];
    const notifications = frontchannel.enabled()
      ? frontchannel.notificationsFor(session,
                                      self.issuerOf(self.asBaseOf(req)))
      : [];
    const notifiable = notifications.filter(function (row) {
      return !!row.url;
    });
    if (notifiable.length) {
      const waitS = Number(config.value('oauth2.frontchannelLogoutWaitS'));
      // The return, already checked by the same rule a redirect is (#124):
      // an authorization server that refused to FORWARD a browser to an
      // unregistered URI and then printed it as a link on its own sign-out
      // page would be splitting a hair at the reader's expense.
      const checked = returnTo;
      const inner = '<h1>Signed out</h1><p class="sub">OpenID Connect ' +
        'RP-Initiated Logout 1.0, with Front-Channel Logout 1.0</p><div ' +
        'class="ok">' + (session
          ? 'The session for ' + xmlEscape(session.user.username) + ' has ' +
            'ended. It is the session WS-Federation and SAML 2.0 share, so ' +
            'those are signed out too.'
          : 'There was no session to end. The cookie has been cleared ' +
            'anyway.') +
        '</div>' + refusedNote +
        frontchannel.render(notifications) +
        backchannel.render(backchannelRows) +
        (checked
          ? '<h2>Return to the relying party</h2><p><a href="' +
            xmlEscape(checked) + '">' +
            xmlEscape(checked) + '</a></p><p class="sub">' +
            (waitS > 0
              ? 'This page returns there by itself after ' + waitS +
                ' second' + (waitS === 1 ? '' : 's') + ', once the ' +
                'notifications above have had time to load; the link is ' +
                'for a browser that does not follow a refresh.'
              : 'A link and not a redirect: the notifications above load ' +
                'with this page, and a 302 would abandon them before they ' +
                'were sent.') + '</p>'
          : '');
      // SECTION 4's RETURN (#122, 2026-09-22). The specification has the
      // provider send the browser on to post_logout_redirect_uri once the
      // iframes have loaded. No markup can observe an iframe loading and this
      // page runs no script, so the return is a <meta> refresh after
      // `oauth2.frontchannelLogoutWaitS` seconds, to the address that passed
      // the same check a redirect would. 0 keeps the link alone.
      const refresh = checked && waitS > 0
        ? '<meta http-equiv="refresh" content="' + waitS + ';url=' +
          xmlEscape(checked) + '">'
        : '';
      res.set('Content-Security-Policy',
              frontchannel.contentSecurityPolicyFor(notifications));
      res.status(200)
         .type('text/html')
         .set('Cache-Control', 'no-store')
         .send(self.logoutPage(inner, refresh));
      log.debug("Leaving OAuth2Server.logoutFinish(). " + notifiable.length + " " +
                "relying part" +
                (notifiable.length === 1 ? 'y was' : 'ies were') +
                " notified.");
      return;
    }
    if (returnTo) {
      log.debug("Leaving OAuth2Server.logoutFinish(). Returning.");
      return res.redirect(302, returnTo);
    }
    log.debug("Leaving OAuth2Server.logoutFinish().");
    return self.logoutAnswer(res, 200, 'Signed out',
      '<div class="ok">' + (session
        ? 'The session for ' + xmlEscape(session.user.username) + ' has ' +
          'ended, and every application signed in through it is told.'
        : 'There was no session to end.') + '</div>' + refusedNote +
      backchannel.render(backchannel.deliveriesFor(
        session ? [session.id] : [], backchannelMark)));
  }

  // ---------------------------------------------------------------------------
  // THE OUTSTANDING AUTHORIZATION CODES FOR ONE PERSON, AND HOW TO END THEM.
  //
  // An authorization code is a live credential: for five minutes it can be
  // redeemed for a token set naming whoever it was issued for. A sign-out that
  // revoked their tokens and left the codes alone would leave the one
  // credential that mints more of them, which is the gap this pair closes for
  // `logout/logout.ts`.
  //
  // They are FUNCTIONS rather than an exported Map for the reason
  // `registeredClients` is not exported any more: a caller holding the Map
  // would be a second place that decides what a code is, and the redemption
  // record beside it (`redeemedCodes`, which makes a repeat of one request
  // idempotent) would be missed by anything that only knew about the first.
  // Ending a code here ends BOTH, which is what makes a signed-out code
  // unredeemable rather than merely unissuable.
  //
  // The match is on the USERNAME the code was issued for, normalised by
  // admin_stats.js's identityKeyOf() so that `alice` and `alice@REALM` are one
  // person — the same normalisation every other door in this service uses.
  // ---------------------------------------------------------------------------
  outstandingCodesFor(key: Json): Json {
    const { log, stats } = this.deps;
    log.debug("Entering OAuth2Server.outstandingCodesFor(). key=" + key);
    const wanted = String(key || '');
    const at = Date.now();
    const out: Json[] = [];
    authzCodes.forEach(function (record, code) {
      const username = (record.user && record.user.username) || '';
      if (stats.identityKeyOf(username) !== wanted) return;
      // An expired code is not a live credential and listing it as one would be
      // offering to end something that has already ended. It is swept here
      // rather than reported, which is what every other reader of this Map
      // does.
      if (record.expires && record.expires < at) return;
      out.push({
        code: code,
        clientId: record.client_id || '',
        redirectUri: record.redirect_uri || '',
        scope: record.scope || '',
        username: username,
        sessionId: record.session_id || '',
        issuedAt: record.expires ?
                  record.expires - (record.ttlMs || AUTH_CODE_TTL_MS) : 0,
        expiresAt: record.expires || 0
      });
    });
    log.debug("Leaving OAuth2Server.outstandingCodesFor(). " + out.length +
              " code(s).");
    return out;
  }

  // End one code. Both stores, for the reason above. Returns whether there was
  // anything to end, so a caller can report "already gone" rather than claiming
  // a revocation it did not perform.
  dropCode(code: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.dropCode().");
    const key = String(code || '');
    const had = authzCodes.delete(key);
    // The redemption record too: it is what answers a REPEAT of the same token
    // request with the tokens it already got, so leaving it behind would let a
    // client that had already redeemed the code go on getting that answer after
    // the sign-out. Nothing new would be minted, but a sign-out that hands back
    // a token set is not a sign-out.
    const hadRedemption = redeemedCodes.delete(key);
    log.debug("Leaving OAuth2Server.dropCode(). " +
              (had || hadRedemption ? "Ended." : "There " +
        "was nothing to end."));
    return had || hadRedemption;
  }

  private directClaimsRequest(req: Req): Json {
    const { log, parseBody, bodyValues, validation } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.directClaimsRequest(). method=" +
              req.method);
    const body = req.method === 'POST' ? parseBody(req) : {};
    // The claims request is bounded and its `claim` shorthand is DECLARED
    // repeatable — OIDC Core section 5.5 puts a JSON document in `claims`, and
    // this service's own `claim` names one at a time, which is the whole reason
    // it may appear more than once. Declaring it is what keeps `flatten()` from
    // refusing the repeat that is the point of the parameter.
    const askedClaims = validation.check(req, 'query', USERINFO_CLAIMS_QUERY);
    if (!askedClaims.ok) {
      log.debug("Leaving OAuth2Server.directClaimsRequest(). The claims " +
                "request is " +
                "malformed.");
      return { request: null, error: askedClaims.detail };
    }
    const q = askedClaims.value;
    const raw = q.claims !== undefined ? q.claims : body.claims;
    const shorthand = []
      .concat(q.claim === undefined ? [] : q.claim)
      .concat(req.method === 'POST' ? bodyValues(req, body, 'claim') : []);
    if (raw === undefined && !shorthand.length) {
      log.debug("Leaving OAuth2Server.directClaimsRequest(). Nothing was " +
                "sent on the " +
                "request itself.");
      return { request: null };
    }
    let request = null;
    if (raw !== undefined) {
      const parsed = self.parseClaimsRequest(raw);
      if (parsed.error) {
        log.debug("Leaving OAuth2Server.directClaimsRequest(). " +
                  parsed.error);
        return { error: parsed.error };
      }
      request = parsed.claims;
    }
    if (shorthand.length) {
      const bucket = Object.assign({}, (request && request.userinfo) || {});
      shorthand.forEach(function (name) {
        const key = String(name).trim();
        if (key) bucket[key] = null;
      });
      request = Object.assign({}, request, { userinfo: bucket });
    }
    log.debug("Leaving OAuth2Server.directClaimsRequest(). " +
              self.requestedClaimNames(request, 'userinfo').length +
                                       " name(s) " +
                  "asked for.");
    return { request: request };
  }

  // The token's own claims request and the request's, as one. The token's wins
  // where both name a claim, because the token's entry is the one that was
  // AUTHORIZED and may carry an `essential` or a `value` the shorthand cannot
  // express — losing it to a bare `null` from a query string would quietly
  // discard what the client actually asked for.
  private mergedUserinfoRequest(fromToken: Json, fromRequest: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.mergedUserinfoRequest().");
    const merged = Object.assign({},
      (fromRequest && fromRequest.userinfo) || {},
      (fromToken && fromToken.userinfo) || {});
    log.debug("Leaving OAuth2Server.mergedUserinfoRequest().");
    return Object.keys(merged).length ? { userinfo: merged } : null;
  }

  // The reason a token failed to verify, in the words a person debugging it
  // needs. jwt.verify() throws one of a small set of named errors and the
  // distinction between them is the whole diagnosis, so it is not collapsed
  // into "invalid".
  private tokenFailure(token: Json): Json {
    const { stsCrypto, log, STS } = this.deps;
    log.debug("Entering OAuth2Server.tokenFailure().");
    try {
      helpers.verifyOwnJws(token);
      log.debug("Leaving OAuth2Server.tokenFailure(). It verifies after all.");
      return '';
    } catch (e) {
      let why;
      if (e.name === 'TokenExpiredError') {
        why = 'This access token expired at ' +
              new Date(e.expiredAt).toISOString() + '.';
      } else if (e.name === 'NotBeforeError') {
        why = 'This access token is not valid yet (nbf is in the future).';
      } else {
        // Everything else — a bad signature, a token from another issuer, an
        // opaque string that is not a JWT at all. They are one answer because
        // the server genuinely cannot tell them apart, and saying so is honest.
        why = 'This access token was not issued by this server, or its ' +
              'signature does not verify against the key at /oauth2/jwks ' +
              '(' + e.message + '). Unlike the ' +
              'OID4VCI credential endpoints, UserInfo cannot accept a token ' +
              'from a separate authorization server: it has nothing to say ' +
              'about a subject it did not authenticate.';
      }
      log.debug("Leaving OAuth2Server.tokenFailure(). " + e.name);
      return why;
    }
  }

  // The recipient's encryption key is `introspectionJwt.recipientKey()` since
  // 2026-09-13 — it was written here for this response and MOVED when RFC
  // 9701's introspection response became the second one a client may ask to
  // have encrypted to its own key. The sentences it refuses with are the ones
  // this endpoint always sent, with the member named by the caller.

  // ASYNCHRONOUS, AND THIS IS ONE OF THE TWO CALL SITES THE WORKER POOL WAS
  // BUILT FOR. `userinfo_signed_response_alg` is a CLIENT'S choice out of
  // `userinfo_signing_alg_values_supported`, which advertises all eleven
  // post-quantum and composite algorithms — and an SLH-DSA-SHAKE-128s signature
  // took 14.6 and 15.4 seconds on 2026-08-29, during which this service
  // answered nobody at all. See common/worker.js. Every other algorithm
  // resolves without leaving this process; signJwtAsAsync() decides which is
  // which, not this endpoint.
  private async signUserinfo(body: Json, alg: Json, registered: Json,
                             base: Json, claims: Json): Promise<Json> {
    const { log, signJwtAsAsync } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.signUserinfo(). alg=" + alg);
    // `iss` and `aud` are section 5.3.2's requirement and are added HERE rather
    // than by the caller, so that a response cannot be signed without them.
    const payload = Object.assign({ iss: self.issuerOf(base),
                                    aud: claims.client_id,
                                    typ: 'UserInfo' }, body);
    // WHICH KEY signs which algorithm is helpers.js's answer and not this
    // endpoint's — see signJwtAs(). It was written out here first and the ID
    // Token endpoint would have copied it.
    //
    // `session` is the pool's routing hint: this token's own `sub`, so that one
    // person's signatures queue behind each other rather than across the pool.
    const signed = await signJwtAsAsync(payload, alg, registered.client_secret,
                                        { session: claims.sub,
                                          certificateHeader: 'userinfo' });
    log.debug("Leaving OAuth2Server.signUserinfo().");
    return signed;
  }

  // Returns { contentType, body } or throws with a sentence fit to hand back as
  // an error_description.
  // ASYNCHRONOUS BECAUSE signUserinfo() IS. Everything it refuses, it refuses
  // before signing, so a client that registered an algorithm this service does
  // not have still gets that sentence back and not a rejected promise from
  // somewhere deeper.
  private async protectUserinfo(body: Json, registered: Json, base: Json,
                                claims: Json): Promise<Json> {
    const { jwt, stsCrypto, log, introspectionJwt } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.protectUserinfo().");
    const signAlg = String(registered.userinfo_signed_response_alg || 'none');
    const encAlg = registered.userinfo_encrypted_response_alg
      ? String(registered.userinfo_encrypted_response_alg) : '';
    // Section 2 of the registration spec: `enc` DEFAULTS to A128CBC-HS256 when
    // an `alg` was registered without one. Defaulting it here rather than
    // refusing is the difference between reading the registration as written
    // and making every client spell out something the spec already decided.
    const encEnc = encAlg
      ? String(registered.userinfo_encrypted_response_enc || 'A128CBC-HS256') :
                   '';

    if (signAlg === 'none' && !encAlg) {
      log.debug("Leaving OAuth2Server.protectUserinfo(). Plain JSON.");
      return { contentType: 'application/json',
               body: JSON.stringify(body, null, 2) };
    }
    if (signAlg !== 'none' && (USERINFO_SIGNING_ALGS.indexOf(signAlg) === -1 ||
        !self.deps.fapi.signingAlgAllowed(signAlg))) {
      // Refused rather than downgraded to JSON: silently ignoring the algorithm
      // a client registered would leave it verifying a signature that is not
      // there.
      log.debug("Leaving OAuth2Server.protectUserinfo(). Unsupported " +
                "signing alg.");
      throw new Error('This client registered userinfo_signed_response_alg="' +
        signAlg + '" and this service signs with ' +
        USERINFO_SIGNING_ALGS.join(', ') + ' (see ' +
        'userinfo_signing_alg_values_supported).');
    }
    if (encAlg && stsCrypto.JWE_ASYMMETRIC_ALGS.indexOf(encAlg) === -1) {
      log.debug("Leaving OAuth2Server.protectUserinfo(). Unsupported " +
                "encryption alg.");
      throw new Error('This client registered ' +
        'userinfo_encrypted_response_alg="' +
        encAlg + '" and this service encrypts a UserInfo response with ' +
        stsCrypto.JWE_ASYMMETRIC_ALGS.join(', ') + ' (see ' +
        'userinfo_encryption_alg_values_supported). The symmetric algorithms ' +
        'in this service\'s JWE table are for a document encrypted TO it, ' +
        'where both ends hold the key; there is no shared key here, only the ' +
        'one you registered.');
    }
    if (encAlg && !stsCrypto.JWE_ENCS[encEnc]) {
      throw new Error('This client asked for ' +
        'userinfo_encrypted_response_enc="' +
        encEnc + '" and this service encrypts with ' +
        Object.keys(stsCrypto.JWE_ENCS).join(', ') + ' (see ' +
        'userinfo_encryption_enc_values_supported).');
    }

    const inner = signAlg === 'none'
      ? JSON.stringify(body, null, 2)
      : await self.signUserinfo(body, signAlg, registered, base, claims);

    if (!encAlg) {
      log.debug("Leaving OAuth2Server.protectUserinfo(). Signed only.");
      return { contentType: 'application/jwt', body: inner };
    }
    const jwe = stsCrypto.encryptJweCompact(inner, {
      alg: encAlg,
      enc: encEnc,
      jwk: introspectionJwt.recipientKey(registered, encAlg,
                                         'userinfo_encrypted_response_alg'),
      // RFC 7519 section 5.2: the outer header announces a JWS inside with
      // cty:"JWT". Without it a recipient that decrypts finds a dot-separated
      // string where it expected a claims object, and has to guess.
      cty: signAlg === 'none' ? undefined : 'JWT',
      typ: 'JWT'
    });
    log.debug("Leaving OAuth2Server.protectUserinfo(). " +
              (signAlg === 'none' ? 'Encrypted.' : 'Signed then encrypted.'));
    return { contentType: 'application/jwt', body: jwe };
  }

  private userinfoResponse(req: Req, res: Res): Json {
    const { log, logArtifact, STS, baseUrlOf, userFor, hasScope, nameForSubject,
            dpop, stats, applications, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.userinfoResponse(). method=" + req.method);
    const base = baseUrlOf(req);

    // The Bearer/DPoP check every protected endpoint in this service shares. It
    // answers the request itself and returns null when the token is missing, is
    // bound and presented as Bearer, or comes with a proof that does not hold
    // up.
    // `formBody` (#118): RFC 6750 section 2.2's form-encoded body parameter,
    // which OIDC Core section 5.3.1 has this endpoint accept.
    const presented = dpop.presentedAccessToken(req, res,
                                                'the userinfo endpoint',
                                                { formBody: true });
    if (!presented) {
      log.debug("Leaving OAuth2Server.userinfoResponse(). No usable access " +
                "token was " +
                "presented.");
      return;
    }

    // RFC 6750 section 3: a 401 from a protected resource carries a challenge
    // naming the scheme, and 403 insufficient_scope names the scope that was
    // missing. Without them a client is told it failed but not what to change.
    //
    // The description goes out twice — in the header and in the JSON body — and
    // the header copy has to be cut down to ASCII first. An HTTP field value is
    // ASCII (RFC 9110 section 5.5), node's setHeader THROWS on anything else
    // rather than mangling it, and the descriptions in this file are prose
    // written with em dashes and curly quotes like every other comment here.
    // The first one that reached the header turned a 401 into a 500 — which is
    // the worst place in the service to have one, because the exception
    // replaces the very message that was explaining what went wrong. Quotes go
    // too: they would close the quoted-string early. The body keeps the real
    // text; JSON is UTF-8.
    const headerSafe = function (text) {
      log.debug("Entering headerSafe().");
      log.debug("Leaving headerSafe().");
      return String(text)
        .replace(/[‘’]/g, "'").replace(/[“”]/g, "'")
        .replace(/[–—]/g, '-').replace(/…/g, '...')
        .replace(/"/g, "'")
        .replace(/[^\x20-\x7E]/g, '');
    };

    const challenge = function (status, error, description, extra?) {
      log.debug("Entering challenge().");
      const scheme = presented.scheme === 'dpop' ? 'DPoP' : 'Bearer';
      res.set('WWW-Authenticate', scheme + ' error="' + error + '", ' +
          'error_description="' +
              headerSafe(description) + '"' + (extra || ''));
      log.debug("Leaving OAuth2Server.userinfoResponse(). " + error + ".");
      // error-code: none — each caller of challenge() marks its own condition
      // first
      return self.oauthError(res, status, error, description);
    };

    if (!presented.verified) {
      errorCodes.mark(res, 'STS-OAUTH-0172');
      log.debug("Leaving OAuth2Server.userinfoResponse().");
      return challenge(401, 'invalid_token',
                       self.tokenFailure(presented.accessToken));
    }
    const claims = presented.claims || {};
    if (claims.typ !== 'Bearer') {
      errorCodes.mark(res, 'STS-OAUTH-0173');
      log.debug("Leaving OAuth2Server.userinfoResponse().");
      return challenge(401, 'invalid_token',
        'This is a "' + (claims.typ || 'unknown') + '" token, not an access ' +
        'token. Every token this server issues is an RS256 JWT signed with ' +
        'the same key, so the typ claim is the only thing that tells a ' +
        'refresh ' +
        'token or an id_token apart from the access token UserInfo needs.');
    }
    if (stats.isRevoked(claims.jti)) {
      errorCodes.mark(res, 'STS-OAUTH-0174');
      log.debug("Leaving OAuth2Server.userinfoResponse().");
      return challenge(401, 'invalid_token',
        'This access token was revoked at /oauth2/revoke. Introspection ' +
        'reports it inactive, and UserInfo answers the same way — a ' +
        'revocation ' +
        'that only some endpoints honoured would be worse than none.');
    }
    if (!hasScope(claims.scope, 'openid')) {
      errorCodes.mark(res, 'STS-OAUTH-0175');
      log.debug("Leaving OAuth2Server.userinfoResponse().");
      return challenge(403, 'insufficient_scope',
        'UserInfo needs an access token issued with the "openid" scope; this ' +
        'one was issued with ' +
        (claims.scope ? '"' + claims.scope + '"' : 'no scope at all') + '. A ' +
        'client_credentials or token-exchange token has no end-user behind ' +
        'it, ' +
        'so there is no profile to return.',
        ', scope="openid"');
    }

    // A claims request sent to THIS endpoint rather than through the
    // authorization one — non-spec, and refused here rather than ignored,
    // because a debugging parameter that was typed wrong must not produce the
    // same response as one that was never sent. See directClaimsRequest().
    const direct = self.directClaimsRequest(req);
    if (direct.error) {
      errorCodes.mark(res, 'STS-OAUTH-0176');
      log.debug("Leaving OAuth2Server.userinfoResponse().");
      return challenge(400, 'invalid_request', direct.error);
    }

    // Who the token was issued for. `sub` comes from the token rather than from
    // userFor(), because section 5.3.2 requires the sub here to be the one the
    // client saw in the id_token and the token is the record of what that was;
    // the rest is rebuilt from the username that travels with it. In a realm
    // that invents no claim values, the profile claims come off the person's
    // directory entry instead — see personFromDirectory(). UNDER THE NAME
    // THE SUBJECT NAMES NOW (2026-09-14), so a person renamed since the token
    // was issued is answered with their current entry rather than with the
    // attributes of whoever holds the old name.
    const user = self.personFromDirectory(userFor(nameForSubject(claims.sub) ||
                                             claims.username));
    const username = String(user.username || claims.username || '');

    // -----------------------------------------------------------------------
    // WHAT THE RESPONSE CARRIES, IN FOUR LAYERS. LATER WINS, and every step up
    // is a step towards the more specific statement:
    //
    //   1. THE CONFIGURED SET — /admin/userinfo-claims. Typed claims, ticked
    //      directory attributes and the groups claim, in the precedence
    //      admin_stats.js already applies among those three. It is what EVERY
    //      client of this service is shown, and it is the layer that makes this
    //      response worth configuring separately from the ID Token: it is
    //      rebuilt on every call, so a change here is visible to a client
    //      already holding a token, where a change to the ID Token set is not
    //      visible until the next sign-in.
    //
    //   2. SECTION 5.4's SCOPE-DRIVEN CLAIMS. `profile` and `email` are
    //      requests for a named set of claims AT THIS ENDPOINT, which is the
    //      one place in this service where a scope genuinely changes an answer.
    //
    //   3. SECTION 5.5's INDIVIDUALLY REQUESTED CLAIMS, resolved off the
    //      person's entry under ou=users. They BEAT the layer above, and that
    //      is the one precedence decision here that is not obvious, so it is
    //      written down rather than left in the code: a scope asks for a
    //      category and a claims request names a claim, and answering
    //      `{"email":null}` with the persona value `alice@sts.example` while
    //      the entry holds a real `mail` would defeat the only reason the
    //      feature is worth having. Nothing in layer 3 can name a structural
    //      claim — see requestedClaimsOf().
    //
    //   4. `sub`, LAST AND UNCONDITIONALLY. Section 5.3.2: the client MUST
    //      verify that it matches the `sub` of the ID Token, so it is the one
    //      member of this response that no layer above may reach. It is
    //      assigned after everything else rather than defended by a check,
    //      because an assignment cannot be forgotten and a check in three
    //      places can.
    // -----------------------------------------------------------------------
    const body: Json = {};

    const configured = stats.jwtClaims(
      'userinfo', self.customClaimContext(base, claims, user));
    Object.assign(body, configured);
    if (Object.keys(configured).length) {
      log.debug("userinfoResponse(): " + Object.keys(configured).length +
                " claim(s) from the configured UserInfo set.");
    }

    // A claim nobody holds is SKIPPED rather than assigned `undefined`, which
    // would erase a layer-1 claim of the same name. All four section 5.4
    // scopes since #118 — see scopeClaimsOf().
    Object.assign(body, self.scopeClaimsOf(user, claims.scope));

    const request = self.mergedUserinfoRequest(claims.claims, direct.request);
    const asked = self.requestedClaimsOf(request, 'userinfo', username, user);
    if (asked.names.length) {
      logArtifact('UserInfo claims request', 'as understood (OIDC Core 5.5)',
                  { requested: asked.names, resolved: asked.report,
                    unresolvable: asked.unknown,
                    essentialAndAbsent: asked.missingEssential,
                    valueMismatches: asked.mismatched,
                    fromTheAccessToken: self.requestedClaimNames(claims.claims,
                                                            'userinfo'),
                    fromThisRequest: self.requestedClaimNames(direct.request,
                                                         'userinfo') });
      // The federation release policy applies to a REQUESTED claim exactly as
      // it applies to a configured one — see stats.applyClaimRelease(). Layer 1
      // above went through jwtClaims() and was filtered there; this layer did
      // not, and a layer that skipped it would be the hole the release list
      // exists to close.
      Object.assign(body, stats.applyClaimRelease(
        asked.claims, self.customClaimContext(base, claims, user),
        'requested claim(s)'));
    }

    // THE CLIENT'S SUBJECT (#118): pairwise when it registered for it, so
    // that section 5.3.2's rule — it MUST match the ID Token's `sub` — holds
    // for a pairwise client too. The access token keeps the public subject,
    // because it is what this endpoint looks the person up by.
    body.sub = self.subjectFor(claims.client_id, claims.sub || user.sub);
    logArtifact('UserInfo response', 'as returned', body);

    // Section 5.3.2: the response is JSON unless the client registered a
    // `userinfo_signed_response_alg` or a `userinfo_encrypted_response_alg`, in
    // which case it is a JWT. This is read from the RFC 7591 registration the
    // client already did here, so the two features meet where they should:
    // register asking for a signed or encrypted response and this endpoint
    // starts producing one for that client. See protectUserinfo() above.
    const registered = applications.registrationOf(claims.client_id) || {};
    // A PROMISE CHAIN RATHER THAN AN `async` HANDLER, deliberately. Everything
    // above this line throws synchronously on a defect and express catches a
    // synchronous throw out of a handler; an `async function` turns every one
    // of those into a rejected promise that express 4 does not see at all,
    // which would swap a 500 with a stack trace in the log for a request that
    // hangs. So the await is confined to the one expression that needs it.
    const protection = self.protectUserinfo(body, registered, base, claims);
    protection.then(function (protectedOut) {
      res.status(200).type(protectedOut.contentType)
         .set('Cache-Control', 'no-store').send(protectedOut.body);
      log.debug("Leaving OAuth2Server.userinfoResponse(). " +
                Object.keys(body).length +
                " claim(s) for " + body.sub + " as " +
                protectedOut.contentType + ".");
    }).catch(function (e) {
      // Everything protectUserinfo() rejects with is a sentence about what
      // this client registered, so it goes back as the error_description rather
      // than being collapsed into "server_error" with the reason in a log the
      // client cannot read. It is a 500 because the registration was accepted
      // and cannot now be honoured, which is this service's fault and not this
      // request's.
      log.error(errorCodes.tag('STS-OAUTH-0177') +
                'userinfoResponse(): the registered response protection ' +
                'could not be applied: ' + e.message);
      log.debug("Leaving OAuth2Server.userinfoResponse(). The registered " +
                "protection could not be applied.");
      errorCodes.mark(res, 'STS-OAUTH-0177');
      self.oauthError(res, 500, 'server_error', e.message);
    });
    log.debug("Leaving OAuth2Server.userinfoResponse(). Answering.");
  }

  // ---------------------------------------------------------------------------
  // GET|POST /oauth2/step-up/resource/{application} — RFC 9470's STAND-IN
  // RESOURCE (2026-09-13).
  //
  // NON-SPEC, AND IT IS THE RESOURCE SERVER HALF OF A SPECIFICATION WHOSE OTHER
  // HALF IS HERE. A registered API declares what it requires of the
  // authentication behind a token (`oauthStepUpAcrValues`, `oauthStepUpMaxAge`)
  // and this answers FOR it: the token must verify, be an `at+jwt` from an
  // authorization server this service publishes, and be addressed to that
  // application (RFC 9068 section 4, with step 4 asked of the application);
  // then section 3's question, whose "no" is the 401 challenge a client turns
  // into an authorization request. Its "yes" is 200 and what it decided on.
  //
  // It exists because the real API is somebody else's process: a client
  // developer testing a step-up flow against this service needs a resource that
  // challenges, and an operator configuring a requirement on an entry needs to
  // see what that requirement does to a token without deploying the API. It
  // holds no data and grants nothing — the body is the token's own claims about
  // authentication, read back to the person who presented it.
  //
  // **THE APPLICATION IS NAMED BY ITS REGISTRY IDENTIFIER OR ITS client_id**,
  // the two spellings `/admin/applications` shows. One that names no entry is
  // 404; an entry requiring nothing answers every valid token 200, and says so.
  // ---------------------------------------------------------------------------
  private stepUpResource(req: Req, res: Res): Json {
    const { log, STS, dpop, applications, errorCodes, stepUp } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.stepUpResource().");
    res.set('Cache-Control', 'no-store');
    const id = String(req.params.application || '');
    const entry = applications.get(id) || applications.forClientId(id);
    if (!entry) {
      log.debug("Leaving OAuth2Server.stepUpResource(). No such application.");
      errorCodes.mark(res, 'STS-OAUTH-0505');
      return self.oauthError(res, 404, 'invalid_request', 'No application "' +
        id.slice(0, 200) + '" is registered in this realm, so there is no ' +
        'resource here to answer for it. The path names an application by ' +
        'its ' +
        'identifier or client_id, as /admin/applications lists it.');
    }
    const requirement = applications.stepUpRequirementOf(entry);
    const presented = dpop.presentedAccessToken(req, res, 'the step-up ' +
      'resource for "' + entry.identifier + '"', {
      requireVerified: true,
      audience: {
        label: 'the application "' + entry.identifier + '"',
        names: function (audiences) {
          log.debug("Entering names().");
          log.debug("Leaving names().");
          return applications.audienceNamesEntry(entry, audiences);
        }
      },
      stepUp: requirement
    });
    if (!presented) {
      log.debug("Leaving OAuth2Server.stepUpResource(). The token was " +
                "refused or " +
                "challenged.");
      return undefined;
    }
    const claims = presented.claims || {};
    const now = Math.floor(Date.now() / 1000);
    res.status(200).type('application/json').send(JSON.stringify({
      resource: entry.identifier,
      requirement: {
        acr_values: requirement.acrValues.join(' ') || null,
        max_age: requirement.maxAge
      },
      met: true,
      token: {
        client_id: claims.client_id || null,
        sub: claims.sub || null,
        acr: claims.acr || null,
        amr: claims.amr || null,
        auth_time: claims.auth_time || null,
        authenticated_seconds_ago: claims.auth_time
          ? now - Number(claims.auth_time) : null,
        scheme: presented.scheme
      }
    }, null, 2));
    log.debug("Leaving OAuth2Server.stepUpResource(). Met.");
    return undefined;
  }

  // --- what became of an authorization code
  // ----------------------------------- The functions behind the relaxation
  // described where `redeemedCodes` is declared. They are here rather than
  // beside it because everything they exist for happens in the token endpoint
  // immediately below.

  private forgetStaleRedemptions(): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.forgetStaleRedemptions().");
    const now = Date.now();
    redeemedCodes.forEach(function (v, k) {
      if (v.forget < now) redeemedCodes.delete(k);
    });
    log.debug("Leaving OAuth2Server.forgetStaleRedemptions(). " +
              redeemedCodes.size +
              " redemption(s) remembered.");
  }

  // What makes two Token Requests for one code the SAME request. The client id
  // is the resolved one rather than the body parameter, so a client using
  // client_secret_basic is compared on what it authenticated as.
  private redemptionFingerprint(client: Json, body: Json, dpopJkt: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.redemptionFingerprint().");
    const parts = {
      client_id: String((client && client.client_id) || ''),
      redirect_uri: String(body.redirect_uri || ''),
      code_verifier: String(body.code_verifier || ''),
      dpop_jkt: String(dpopJkt || '')
    };
    log.debug("Leaving OAuth2Server.redemptionFingerprint(). client_id=" +
              (parts.client_id || '(none)'));
    return parts;
  }

  // The FIRST field that differs, by name, or "" when the two are the same
  // request. The name is the whole point: it is what the refusal says.
  private redemptionDifference(was: Json, now: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.redemptionDifference().");
    const names = ['client_id', 'redirect_uri', 'code_verifier', 'dpop_jkt'];
    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      if (String(was[name] || '') !== String(now[name] || '')) {
        log.debug("Leaving OAuth2Server.redemptionDifference(). " + name +
                  " differs.");
        return name;
      }
    }
    log.debug("Leaving OAuth2Server.redemptionDifference(). It is the same " +
              "request.");
    return '';
  }

  private rememberRedemption(code: Json, record: Json, fingerprint: Json,
                             issued: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.rememberRedemption().");
    self.forgetStaleRedemptions();
    // The bound (oauth2.redeemedCodeCacheSize). What this remembers is a
    // courtesy — the same request answered with the same tokens — and not the
    // refusal, which the code's own removal at redemption already makes, so
    // at the bound the OLDEST goes rather than the redemption being refused.
    if (!redeemedCodes.has(code)) {
      cacheRegistry.makeRoom(redeemedCodes,
                             Number(self.deps.config.value(
                               'oauth2.redeemedCodeCacheSize')),
                             { counter: redeemedCodesCount });
    }
    redeemedCodes.set(code, {
      when: Date.now(),
      // The code's OWN expiry, not a fresh one: the replay window is the rest
      // of the life the code already had, so this relaxation cannot outlive the
      // rule it relaxes.
      expires: record.expires,
      forget: record.expires + (record.ttlMs || AUTH_CODE_TTL_MS),
      ttlMs: record.ttlMs || AUTH_CODE_TTL_MS,
      client_id: fingerprint.client_id,
      fingerprint: fingerprint,
      response: issued
    });
    log.debug("Leaving OAuth2Server.rememberRedemption(). The tokens for " +
              "this code are replayable until " +
              new Date(record.expires).toISOString() + ".");
  }

  // How long this process has been up, in words, for the one refusal that needs
  // to say it: a code minted before a restart is not "already used", it is gone
  // with the Map that held it, and those two look identical from the client.
  private describeUptime(): Json {
    const { log, stats } = this.deps;
    log.debug("Entering OAuth2Server.describeUptime().");
    const seconds = Math.max(0,
      Math.round((Date.now() - stats.STARTED_AT) / 1000));
    if (seconds < 120) {
      log.debug("Leaving OAuth2Server.describeUptime().");
      return seconds + ' second(s)';
    }
    if (seconds < 7200) {
      log.debug("Leaving OAuth2Server.describeUptime().");
      return Math.round(seconds / 60) + ' minute(s)';
    }
    log.debug("Leaving OAuth2Server.describeUptime().");
    return Math.round(seconds / 3600) + ' hour(s)';
  }

  // A code the live map does not hold. Either it was redeemed here — in which
  // case the same request gets the same tokens back and a different one is
  // refused with the difference named — or this server never issued it, which
  // is its own sentence and not "already used".
  private replayOrRefuseRedemption(res: Res, code: Json, fingerprint: Json,
                                   respond: Json): Json {
    const { jwt, log, STS, mode, stats, bcp, errorCodes,
            refreshTokenCrypto } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.replayOrRefuseRedemption().");
    self.forgetStaleRedemptions();
    const done = redeemedCodes.get(code);
    if (done) {
      redeemedCodesCount.hit();
    } else {
      redeemedCodesCount.miss();
    }
    if (!done) {
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption(). This " +
                "server has no record " +
                "of that code at all.");
      errorCodes.mark(res, 'STS-OAUTH-0187');
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption().");
      return self.oauthError(res, 400, 'invalid_grant',
        'Unknown or already-used authorization code. Nothing is held here ' +
        'under that value and nothing was redeemed under it recently: this ' +
        'service keeps authorization codes in memory only, so a code issued ' +
        'before it was last restarted (it has been up ' +
        self.describeUptime() + ') went with them, as did one issued by a ' +
        'different authorization server.');
    }
    const ago = Math.max(0, Math.round((Date.now() - done.when) / 1000));
    const differs = self.redemptionDifference(done.fingerprint, fingerprint);
    if (differs) {
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption(). The " +
                differs +
                " differs from the request this code was redeemed with.");
      errorCodes.mark(res, 'STS-OAUTH-0188');
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption().");
      return self.oauthError(res, 400, 'invalid_grant',
        'This authorization code was redeemed ' + ago + ' second(s) ago by ' +
        'client "' + (done.client_id || '(none)') + '". A repeat of that ' +
        'same request would be answered with the same tokens, but this one ' +
        'differs ' +
        'in ' + differs + ', so it is refused (RFC 6749 section 4.1.2: an ' +
        'authorization code is single use).');
    }
    if (done.expires < Date.now()) {
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption(). The code " +
                "was redeemed and " +
                "its own lifetime has since run out.");
      errorCodes.mark(res, 'STS-OAUTH-0189');
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption().");
      return self.oauthError(res, 400, 'invalid_grant',
        'This authorization code was redeemed ' + ago + ' second(s) ago by ' +
        'client "' + (done.client_id || '(none)') + '", and the ' +
        Math.round((done.ttlMs || AUTH_CODE_TTL_MS) / 1000) + ' second ' +
        'lifetime it was issued with has since run out, so the tokens it ' +
        'bought are no longer replayed here. Start a new authorization ' +
        'request; the refresh token from the first redemption is still good.');
    }
    // RFC 9700 mode: no relaxation. The repeat is refused and everything the
    // code bought is revoked (section 4.5, and RFC 6749 section 10.5 for the
    // revocation). Checked HERE rather than above the two refusals before it,
    // because those two are more specific — a request that DIFFERS from the one
    // the code was redeemed with, and a code whose own lifetime has run out,
    // are both worth their own sentence, and both are already refusals in
    // either mode. This is the one case the two modes answer differently.
    //
    // The jtis come off the token set that was issued: `jwt.decode` rather than
    // `jwt.verify`, because these are this service's own tokens read back out
    // of its own store and the signature was made two lines after they were
    // minted.
    const replay = bcp.checkCodeReplay({
      clientId: done.client_id, secondsAgo: ago,
      issuedJtis: ['access_token', 'refresh_token', 'id_token'].map(
          function (name) {
        const token = done.response && done.response[name];
        if (!token) {
          return '';
        }
        try {
          // The refresh token in the set is ENCRYPTED; `claimsOfIssued()` opens
          // it and reads a JWS unchanged.
          const claims = refreshTokenCrypto.isEncrypted(token)
            ? refreshTokenCrypto.claimsOfIssued(token)
            : jwt.decode(token);
          return (claims && claims.jti) || '';
        } catch (e) {
          // Not decodable, which cannot happen for a token this service minted
          // — but a jti that cannot be read is a token that cannot be revoked,
          // and silently revoking nothing would be worse than saying so.
          log.error(errorCodes.tag('STS-OAUTH-0190') + 'could not read the ' +
                                                       'jti of ' +
                                                       'the ' + name + ' ' +
              'issued for this code: ' + e.message);
          return '';
        }
      })
    });
    if (!replay.ok) {
      (replay.revoke || []).forEach(function (jti) {
        stats.revoke(jti, 'RFC 9700 section 4.5: an authorization code was ' +
                          'presented twice');
      });
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption(). RFC 9700 " +
                "mode refused the " +
                "replay.");
      errorCodes.mark(res, replay.errorCode || 'STS-OAUTH-0158');
      log.debug("Leaving OAuth2Server.replayOrRefuseRedemption().");
      return self.oauthError(res, 400, replay.error, replay.description);
    }

    // Loud, because a client that redeems a code twice is doing something a
    // real authorization server would refuse, and reading this log is how
    // somebody finds that out from a server that did not.
    log.warn('An authorization code was presented a second time by client "' +
             (done.client_id || '(none)') + '" ' + ago + ' second(s) after ' +
             'it was redeemed. The request is identical and the code is ' +
             'still within its lifetime, so the SAME token set is being ' +
             'returned rather than an error. RFC 6749 section 4.1.2 permits ' +
             'a real authorization server to refuse this and section 10.5 to ' +
             'revoke ' +
             'what it issued.');
    log.debug("Leaving OAuth2Server.replayOrRefuseRedemption(). Replaying " +
              "the token set.");
    return respond(done.response);
  }

  private pause(ms: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.pause().");
    log.debug("Leaving OAuth2Server.pause().");
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  // The winner's redemption record, once it can be seen from here, or null when
  // the bound runs out first.
  private async awaitRedemptionRecord(code: Json): Promise<Json> {
    const { log, clusterBarrier } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.awaitRedemptionRecord().");
    const deadline = Date.now() + CONCURRENT_REDEMPTION_WAIT_MS;
    for (;;) {
      const done = redeemedCodes.get(code);
      if (done) {
        log.debug("Leaving OAuth2Server.awaitRedemptionRecord(). Found.");
        return done;
      }
      if (Date.now() >= deadline) {
        log.debug("Leaving OAuth2Server.awaitRedemptionRecord(). The bound " +
                  "ran out.");
        return null;
      }
      // Resolves rather than rejects, and at once where nothing coordinates.
      await clusterBarrier.syncShared();
      await self.pause(CONCURRENT_REDEMPTION_POLL_MS);
    }
  }

  // The code's claim was refused. `store` fails closed; `used` is a replay.
  private async refuseConcurrentRedemption(res: Res, code: Json,
                                           fingerprint: Json, respond: Json,
                                           answer: Json): Promise<Json> {
    const { log, STS, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.refuseConcurrentRedemption(). reason=" +
              answer.reason);
    if (answer.reason !== 'used') {
      log.error(errorCodes.tag('STS-OAUTH-0513') + 'oauth2: an authorization ' +
                'code could not be spent because the claim store could not ' +
                'be asked (' + (answer.why || 'no reason given') + '); the ' +
                'Token Request is refused and the code is left unspent.');
      errorCodes.mark(res, 'STS-OAUTH-0513');
      log.debug("Leaving OAuth2Server.refuseConcurrentRedemption(). The " +
                "store failed.");
      return self.oauthError(res, 500, 'server_error',
        'This authorization server could not record that the authorization ' +
        'code is being redeemed, so it has not redeemed it. The code has not ' +
        'been spent; retry the Token Request.');
    }
    log.warn('oauth2: an authorization code is being redeemed by another ' +
             'request at the same moment' +
             (answer.existing && answer.existing.origin
               ? ' (' + answer.existing.origin + ')' : '') +
             '; this one waits for that redemption and is answered as a ' +
             'replay of it.');
    const done = await self.awaitRedemptionRecord(code);
    if (!done) {
      errorCodes.mark(res, 'STS-OAUTH-0512');
      log.debug("Leaving OAuth2Server.refuseConcurrentRedemption(). No " +
                "record appeared.");
      return self.oauthError(res, 400, 'invalid_grant',
        'This authorization code is being redeemed by another Token Request ' +
        'at the same moment, and that redemption had not completed within ' +
        Math.round(CONCURRENT_REDEMPTION_WAIT_MS / 1000) + ' second(s). An ' +
        'authorization code is single use (RFC 6749 section 4.1.2).');
    }
    log.debug("Leaving OAuth2Server.refuseConcurrentRedemption(). Answered " +
              "as a replay.");
    return self.replayOrRefuseRedemption(res, code, fingerprint, respond);
  }

  // The claim's lifetime: the rest of the code's own life and the clock skew
  // every expiry check here allows. After that the code is refused as expired
  // by its own record, so a longer claim would guard nothing.
  private codeClaimTtlMs(record: Json): Json {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.codeClaimTtlMs().");
    const rest = Math.max(0, Number(record.expires || 0) - Date.now());
    log.debug("Leaving OAuth2Server.codeClaimTtlMs().");
    return rest + Number(self.tokenClockSkew() || 0) * 1000;
  }

  // ASYNCHRONOUS, AND THE TWO REASONS ARE THE TWO SLOW THINGS A CLIENT CAN ASK
  // THIS ENDPOINT FOR: an ID Token signed with a post-quantum algorithm it
  // registered, and a `private_key_jwt` client assertion signed with one. Both
  // take SECONDS of pure computation, and until they were moved to the worker
  // pool this service answered nothing at all — not another caller, not the KDC
  // on port 88 — for the length of each. See common/worker.js.
  //
  // It is registered through a wrapper that catches, at the foot of this
  // section: an `async` handler's throw is a rejected promise, which express 4
  // does not see, so without one a defect here would be a request that hangs
  // where it used to be a 500. THE ROLE GATE'S REFUSAL, TURNED INTO AN OAUTH
  // ERROR, and it is done HERE rather than in the route wrapper below because
  // there are TWO registrations of this handler — `/oauth2/token` and
  // `/{as}/oauth2/token` — and only one of them has that wrapper. A refusal
  // that reached the wrapper would be a 500 with `server_error` in it, which is
  // the one answer a client must not get for a decision the service made on
  // purpose.
  //
  // `access_denied` is RFC 6749 section 4.1.2.1's own code for "the resource
  // owner or authorization server denied the request", which is exactly what a
  // policy refusing an issuance is, and 400 is what section 5.2 gives every
  // token endpoint error but `invalid_client`. The `error_description` is the
  // PEP's sentence — it names the application, the roles required and the roles
  // held — because a client that cannot see why is a client whose operator
  // files a bug against this service.
  private async tokenEndpoint(req: Req, res: Res): Promise<Json> {
    const { log, STS, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering the token endpoint's refusal wrapper.");
    try {
      const answered = await self.tokenGrant(req, res);
      log.debug("Leaving the token endpoint's refusal wrapper. Nothing to " +
                "translate.");
      return answered;
    } catch (e) {
      // A DISABLED ACCOUNT (2026-09-17): every grant carrying a person —
      // a code, a refresh token, a password, an assertion, a token exchange,
      // a pre-authorized code — reaches `checkIssuance()`, whose gate refuses
      // it first. RFC 6749 section 5.2's `invalid_grant` ("revoked"), not the
      // policy's `access_denied`: the grant is no longer good, whatever any
      // policy would say.
      if (e && e.name === 'IssuanceRefused' && e.issuance &&
          e.issuance.disabled) {
        log.debug("Leaving the token endpoint's refusal wrapper. The " +
                  "account is disabled.");
        errorCodes.mark(res, 'STS-OAUTH-0551');
        log.debug("Leaving OAuth2Server.tokenEndpoint().");
        return self.oauthError(res, 400, 'invalid_grant', e.message);
      }
      if (e && e.name === 'IssuanceRefused') {
        log.debug("Leaving the token endpoint's refusal wrapper. The " +
                  "issuance " +
                  "policy refused " + e.kind + ".");
        errorCodes.mark(res, 'STS-OAUTH-0191');
        log.debug("Leaving OAuth2Server.tokenEndpoint().");
        return self.oauthError(res, 400, 'access_denied', e.message);
      }
      // #34: one of the two refresh-token sender-constraint settings refused,
      // from inside issue(). 400 for every one of them, which is section 5.2's
      // status for everything but `invalid_client` — and `invalid_client` is
      // what the certificate refusals carry, so they are answered 401.
      if (e && e.name === 'SenderConstraintRefused') {
        log.debug("Leaving the token endpoint's refusal wrapper. A sender " +
                  "constraint refused (" + e.refusal.setting + ").");
        errorCodes.mark(res, e.refusal.errorCode);
        log.debug("Leaving OAuth2Server.tokenEndpoint().");
        // error-code: none — marked above with the refusal's own code, one of
        // STS-OAUTH-0521, 0522 or 0527.
        return self.oauthError(res,
                          e.refusal.error === 'invalid_client' ? 401 : 400,
                          e.refusal.error, e.refusal.description);
      }
      // RFC 9068's refusal at the point of minting — see tokenSet() —
      // answered with the error the plan chose (`invalid_scope` or
      // `invalid_target`), here for the reason above: two registrations, one
      // wrapper.
      if (e && e.name === 'AccessTokenRefused') {
        log.debug("Leaving the token endpoint's refusal wrapper. RFC 9068 " +
                  "refused the audience.");
        errorCodes.mark(res, errorCodes.codeOf(e.refusal) || 'STS-OAUTH-0244');
        log.debug("Leaving OAuth2Server.tokenEndpoint().");
        return self.oauthError(res, 400, e.refusal.error,
                               e.refusal.description);
      }
      log.debug("Leaving the token endpoint's refusal wrapper. Rethrowing.");
      throw e;
    }
  }

  // The Basic challenge an invalid_client answer carries when the client used
  // Basic (RFC 6749 section 5.2). The realm is `oauth2.basicAuthRealm`
  // (2026-09-12), for `scim.authRealm`'s reason: it is what a browser prints in
  // its credential prompt, and a deployment names itself there. Quotes and
  // backslashes are escaped per RFC 7230's quoted-string. One function since
  // 2026-09-13, because three refusals send it now.
  private basicChallenge(): Json {
    const { log, config } = this.deps;
    log.debug("Entering OAuth2Server.basicChallenge().");
    log.debug("Leaving OAuth2Server.basicChallenge().");
    return 'Basic realm="' +
      String(config.value('oauth2.basicAuthRealm') || '').replace(/(["\\])/g,
                                                                  '\\$1') +
      '"';
  }

  // WHICH CLIENT AUTHENTICATION A TOKEN REQUEST CARRIED, read off the request
  // rather than out of `clientFrom()` — which answers with ONE method,
  // preferring a Basic header, and so cannot say that a request carried two.
  // OAuth 2.1 section 2.4 refuses that, and the secret rate limit below counts
  // only requests that carried a secret.
  // EVERY CLIENT IDENTIFIER ONE REQUEST CARRIES (#138, FAPI 1.0 Part 1 section
  // 5.2.2 item 19): the Basic header's user, the body's client_id, and a JWT
  // client assertion's sub. clientFrom() takes the first it finds and ignores
  // the rest, which is right until a profile says two that disagree must be
  // refused.
  private presentedClientIds(req: Req, body: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.presentedClientIds().");
    const out: string[] = [];
    const auth = String(req.headers['authorization'] || '');
    if (/^Basic\s+/i.test(auth)) {
      try {
        const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64')
          .toString('utf8');
        const at = decoded.indexOf(':');
        out.push(decodeURIComponent(at < 0 ? decoded : decoded.slice(0, at)));
      } catch (e) {
        log.debug("Caught in OAuth2Server.presentedClientIds(): " +
                  ((e && e.message) || e));
        // An unreadable header names nothing here; clientFrom() reports it.
      }
    }
    if (body && body.client_id) {
      out.push(String(body.client_id));
    }
    if (body && body.client_assertion &&
        String(body.client_assertion).split('.').length === 3) {
      try {
        const claims = JSON.parse(Buffer.from(
          String(body.client_assertion).split('.')[1], 'base64url')
          .toString('utf8'));
        if (claims && claims.sub) {
          out.push(String(claims.sub));
        }
      } catch (e) {
        log.debug("Caught in OAuth2Server.presentedClientIds(): " +
                  ((e && e.message) || e));
        // Not a JWT this can read; the assertion's own check refuses it.
      }
    }
    log.debug("Leaving OAuth2Server.presentedClientIds(). " + out.length +
              ".");
    return out;
  }

  private presentedClientAuthentication(req: Req, body: Json): Json {
    const { log, clientAuth } = this.deps;
    log.debug("Entering OAuth2Server.presentedClientAuthentication().");
    const presented = {
      basic: /^Basic\s+/i.test(String(req.headers['authorization'] || '')),
      bodySecret: !!(body && body.client_secret),
      assertion: !!(body && body.client_assertion),
      samlAssertion: String((body && body.client_assertion_type) || '') ===
                     clientAuth.SAML_ASSERTION_TYPE
    };
    log.debug("Leaving OAuth2Server.presentedClientAuthentication().");
    return presented;
  }

  // ---------------------------------------------------------------------------
  // A CLIENT SECRET IS NOT CHECKED UNTHROTTLED (2026-09-13). OAuth 2.1 section
  // 2.4.1: "the authorization server MUST protect any endpoint utilizing it
  // against brute force attacks." Applied WHEREVER this service refuses a
  // secret — RFC 9700 mode, OAuth 2.1 mode, product mode — because an
  // unthrottled secret is the same weakness in each; a mode that checks no
  // secret refuses none and counts nothing.
  //
  // THREE DECISIONS, and each is the difference between a limit and a denial of
  // service:
  //
  //   * ONLY A FAILURE IS COUNTED, and a success clears the client's bucket.
  //     This suite, and any real deployment behind one proxy, is one address
  //     making thousands of legitimate token requests.
  //   * THE IDENTITY BUCKET IS THE CLIENT_ID AND THE ADDRESS TOGETHER. Keyed on
  //     the client_id alone, anybody who can reach this port could lock
  //     `sts-admin-console` or `sts-user-portal` out — which is the console's
  //     and the portal's own sign-in — by sending it five wrong secrets a
  //     minute.
  //   * THE REALM IS IN THE BUCKET NAME. The limiter's map is shared by the
  //     process, so without it a client_id failing in one realm would lock the
  //     same name out of every other.
  //
  // `websecurity.js`'s LDAP-bind pattern: `blocked()` before anything is
  // verified, `attempt()` on a refusal, `succeeded(keepAddress)` on success.
  // ---------------------------------------------------------------------------
  private secretLimitKey(req: Req, clientId: Json): Json {
    const { realms, log, websecurity } = this.deps;
    log.debug("Entering OAuth2Server.secretLimitKey().");
    log.debug("Leaving OAuth2Server.secretLimitKey().");
    return { what: 'token-client-secret:' + (realms.currentId() || 'default'),
             identity: String(clientId || '') + '|' +
                       websecurity.addressOf(req) };
  }

  private secretPresented(presented: Json, registered: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.secretPresented().");
    const method = String((registered &&
                           registered.token_endpoint_auth_method) ||
                          '');
    log.debug("Leaving OAuth2Server.secretPresented().");
    return !!(presented.basic || presented.bodySecret ||
              (presented.assertion && method === 'client_secret_jwt'));
  }

  // **COUNTED IN THE CLUSTER'S SHARED WINDOW SINCE 2026-09-14 (#46)**, and
  // returns the count's promise so a caller awaits it before answering: a
  // guesser's next request, on whichever node, then reads a count that includes
  // this failure. `websecurity.attemptShared()` is `attempt()` where no store
  // is shared.
  //
  // **AND IT DECIDES THE ANSWER (2026-09-14, #46 follow-up).** The check before
  // the secret is looked at reads the count; the count is added after — so
  // forty concurrent guesses all read a count under the limit, all had their
  // secrets checked and all were told `invalid_client`: measured 19 to 34 of 40
  // against a limit of 5. The count returned by the one atomic increment is the
  // same number on every node, so a failure whose increment took the bucket
  // PAST the limit is answered with the lockout rather than with "wrong
  // secret": at most `limit` failures per window are ever answered as failures,
  // however many arrive at once and wherever. Resolves to that refusal, or
  // null. `websecurity.failedShared()` argues the rest, including why the check
  // before verification stays (and why a success is not reserved).
  private countSecretFailure(req: Req, clientId: Json, presented: Json,
                             registered: Json): Json {
    const { log, websecurity } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.countSecretFailure().");
    if (!clientId || !self.secretPresented(presented, registered)) {
      log.debug("Leaving OAuth2Server.countSecretFailure(). No secret was " +
                "presented.");
      return Promise.resolve(null);
    }
    const key = self.secretLimitKey(req, clientId);
    log.debug("Leaving OAuth2Server.countSecretFailure().");
    return websecurity.failedShared(key.what, req, key.identity);
  }

  // THE OTHER HALF: a secret that VERIFIED is answered only while the bucket is
  // under the limit, so a right guess racing a burst of wrong ones that already
  // spent the budget is refused exactly like them and teaches nothing.
  // Otherwise the bucket is cleared as before. Resolves to the refusal, or
  // null.
  private settleSecretSuccess(req: Req, clientId: Json, presented: Json,
                              registered: Json): Json {
    const { log, websecurity } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.settleSecretSuccess().");
    if (!clientId || !self.secretPresented(presented, registered)) {
      log.debug("Leaving OAuth2Server.settleSecretSuccess(). No secret was " +
                "presented.");
      return Promise.resolve(null);
    }
    const key = self.secretLimitKey(req, clientId);
    log.debug("Leaving OAuth2Server.settleSecretSuccess().");
    return websecurity.succeededShared(key.what, req, key.identity,
                                       { keepAddress: true,
                                         unlessBlocked: true });
  }

  // The lockout a secret failure or a racing success is answered with — the
  // same 429 the check before verification gives.
  private secretLockout(res: Res, clientId: Json, lockedOut: Json): Json {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.secretLockout().");
    res.set('Retry-After', String(lockedOut.retryAfterS));
    errorCodes.mark(res, 'STS-OAUTH-0284');
    log.debug("Leaving OAuth2Server.secretLockout().");
    return self.oauthError(res, 429, 'invalid_client',
      'Too many failed client authentications for client "' + clientId +
      '" from this address. ' + lockedOut.detail);
  }

  private async tokenGrant(req: Req, res: Res): Promise<Json> {
    const { crypto, stsCrypto, log, logArtifact, STS, b64u, jsonFromB64u,
            parseBody, bodyValues, userFor, dpop, mtls, assertionGrant,
            samlAssertionGrant, mode, authorizationServers, stats, VCI_SCOPE,
            deferredAccessTokens, preAuthorizedCodes, checkTxCode,
            spendPreAuthorizedCode, config, bcp, oauth21, fapi,
            senderConstraints,
            applications, validation, errorCodes, refreshTokenCrypto,
            richAuthorization, delegation, credentials, websecurity,
            clusterClaims, hasScope, authn } = this.deps;
    const self = this;
    log.debug("Entering the token endpoint.");
    const base = self.asBaseOf(req);
    // `checkParsed()` and not `check(req, 'body', ...)`: this service parses
    // every body as raw text, so the parsed object is what a handler holds. See
    // that function's header.
    const posted = validation.checkParsed(parseBody(req), 'body', TOKEN_FORM);
    if (!posted.ok) {
      res.set('Cache-Control', 'no-store');
      log.debug("Leaving the token endpoint. The request is malformed: " +
                posted.code + " on \"" + posted.field + "\".");
      errorCodes.mark(res, 'STS-OAUTH-0196');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, 'invalid_request', posted.detail);
    }
    const body = posted.value;
    const client = self.clientFrom(req, body);
    const grant = String(body.grant_type || '');
    res.set('Cache-Control', 'no-store');
    const presented = self.presentedClientAuthentication(req, body);
    let registeredClient = applications.clientConfigOf(client.client_id);
    // A KEY WRITTEN BY ANOTHER PROCESS A MOMENT AGO (2026-09-23). The console
    // and the portal issue their private_key_jwt key on first use (#138) and
    // then ask for a token over the back channel inside the same request, so
    // the key is on the entry in the process that wrote it and — until the
    // change log reaches this one — not here: in a fresh realm in the
    // single-node suite the sign-in was refused as a client with nothing on
    // file (`sts_hosted_surface_renewal`). A confidential client that presents
    // an assertion and has nothing to check it against is exactly that case,
    // so this process catches up once, proving everything committed before now
    // is applied, and reads the entry again. Nothing else pays for it.
    if (registeredClient && registeredClient.known && body.client_assertion &&
        bcp.isConfidential(registeredClient) &&
        !bcp.credentialOnFile(registeredClient)) {
      try {
        await require('../persistence/persistence').syncNow();
      } catch (e) {
        // A store that cannot be read leaves the entry as this process holds
        // it, and the refusal below says what that is.
        log.debug("Caught in OAuth2Server.tokenGrant(): " +
                  ((e && e.message) || e));
      }
      registeredClient = applications.clientConfigOf(client.client_id);
    }

    // FAPI (#138): one client, however many ways the request names it.
    const identified = fapi.clientIdentifierRefusal(
      self.presentedClientIds(req, body));
    if (identified) {
      if (presented.basic) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      log.debug("Leaving the token endpoint. FAPI: two clients named.");
      errorCodes.mark(res, identified.errorCode || 'STS-OAUTH-0581');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 401, identified.error,
                             identified.description);
    }

    // OAUTH 2.1 — two refusals about the SHAPE of the request, before anything
    // in it is believed: a repeated parameter (sections 3.1 and 3.2) and more
    // than one client authentication method (section 2.4).
    if (oauth21.enabled()) {
      const repeated = oauth21.repeatedParameterRefusal(
          oauth21.repeatedNames(null, typeof req.body === 'string' ? req.body :
                                      ''), 'token request');
      if (repeated) {
        log.debug("Leaving the token endpoint. OAuth 2.1: a repeated " +
                  "parameter.");
        errorCodes.mark(res, repeated.errorCode || 'STS-OAUTH-0285');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, repeated.error, repeated.description);
      }
      const several = oauth21.multipleMethodsRefusal(presented);
      if (several) {
        log.debug("Leaving the token endpoint. OAuth 2.1: several client " +
                  "authentication methods.");
        errorCodes.mark(res, several.errorCode || 'STS-OAUTH-0281');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, several.error, several.description);
      }
    }

    // THE SECRET RATE LIMIT'S FIRST HALF: a client and address past the limit
    // is answered before its secret is looked at. See secretLimitKey().
    if (client.client_id && self.secretPresented(presented, registeredClient)) {
      const key = self.secretLimitKey(req, client.client_id);
      const lockedOut = await websecurity.blockedShared(key.what, req,
                                                        key.identity);
      if (lockedOut) {
        res.set('Retry-After', String(lockedOut.retryAfterS));
        log.debug("Leaving the token endpoint. Too many failed client " +
                  "secrets.");
        errorCodes.mark(res, 'STS-OAUTH-0284');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 429, 'invalid_client',
          'Too many failed client authentications for client "' +
          client.client_id + '" from this address. ' + lockedOut.detail);
      }
    }

    // --- DPoP (RFC 9449 section 5) -------------------------------------------
    // Optional, and checked before any grant is considered so that every grant
    // gets the same treatment: a wallet that sends a proof gets a bound token
    // whether it arrived by authorization code, by pre-authorized code or by
    // refresh. A wallet that sends none gets a Bearer token exactly as before,
    // which is what keeps this switch invisible to the workflows that do not
    // use it.
    let dpopJkt = '';
    if (req.headers['dpop'] !== undefined) {
      const checked = dpop.verifyProof(req.headers['dpop'], {
        htm: req.method, htu: dpop.htuOf(req),
        // The reservation `dpop.proofClaims()` made on arrival (#46).
        req: req
      });
      if (!checked.ok) {
        // Section 8: when the server wants a nonce it does not refuse outright
        // — it ASKS, with a fresh nonce in the header and `use_dpop_nonce` as
        // the error, and the wallet retries once. Answering a plain
        // invalid_dpop_proof here would leave a conforming client with no way
        // forward.
        if (checked.needNonce) {
          res.set('DPoP-Nonce', dpop.issueNonce());
          log.debug("Leaving the token endpoint. Asking the client for a " +
                    "DPoP nonce.");
          errorCodes.mark(res, checked.errorCode || 'STS-OAUTH-0108');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'use_dpop_nonce',
            'Authorization server requires nonce in DPoP proof');
        }
        log.debug("Leaving the token endpoint. The DPoP proof was refused.");
        errorCodes.mark(res, checked.errorCode || 'STS-OAUTH-0118');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_dpop_proof',
                               checked.description);
      }
      dpopJkt = checked.jkt;
      log.debug("This Token Request carries a valid DPoP proof. jkt=" +
                dpopJkt);
    }
    // Nonce mode is not a "DPoP required" mode: it makes proofs FRESHER, not
    // mandatory. A request with no DPoP header is a Bearer request and is
    // answered as one, so turning nonce mode on cannot break the Bearer clients
    // this server also exists to exercise. The settings that DO require a proof
    // (#34) are `sender_constraints.js`'s, asked where a refresh token is
    // minted or redeemed (below) and at the resources.

    // WHAT THIS AUTHORIZATION SERVER SAYS IT GRANTS. Same rule as the
    // authorization endpoint's: the document a client read is the list this
    // endpoint performs.
    const advertisedGrants = self.capabilityFor(req, 'grant_types_supported');
    if (grant && advertisedGrants && advertisedGrants.indexOf(grant) < 0) {
      log.debug("Leaving the token endpoint. " + self.profileOf(req) +
                " does not advertise " + grant + ".");
      errorCodes.mark(res, 'STS-OAUTH-0197');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, 'unsupported_grant_type',
        'The "' + self.profileOf(req) + '" authorization server advertises ' +
                                   'grant_types_supported ' +
        JSON.stringify(advertisedGrants) + ' and this request asks for "' +
                                   grant + '". ' +
        'What its metadata says is what it does.');
    }
    // And which client authentication methods it accepts. A client whose entry
    // declares a method this authorization server does not advertise is refused
    // HERE rather than at the verification, so the message is about the
    // server's capabilities rather than about the credential.
    const advertisedAuth = self.capabilityFor(
      req, 'token_endpoint_auth_methods_supported');
    const declaredMethod = (applications.clientConfigOf(client.client_id) || {})
      .token_endpoint_auth_method;
    if (declaredMethod && advertisedAuth &&
        advertisedAuth.indexOf(String(declaredMethod)) < 0) {
      log.debug("Leaving the token endpoint. " + self.profileOf(req) +
                " does not advertise " + declaredMethod + ".");
      errorCodes.mark(res, 'STS-OAUTH-0198');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, 'invalid_client',
        'The "' + self.profileOf(req) + '" authorization server advertises ' +
        'token_endpoint_auth_methods_supported ' +
        JSON.stringify(advertisedAuth) + ', ' +
        'and this client is configured for ' +
        '"' + declaredMethod + '". A client may use ' +
        'any authorization server here, but only in a way that server offers.');
    }

    // RFC 9700 section 2.4 — the password grant, refused before any grant
    // branch is considered. It is checked here rather than inside that grant's
    // own branch because the answer does not depend on any of the parameters:
    // this server will not perform that grant at all, which is what
    // unsupported_grant_type means and what the metadata says by leaving
    // `password` out.
    const grantCheck = bcp.checkGrantType(grant);
    if (!grantCheck.ok) {
      log.debug("Leaving the token endpoint. RFC 9700 mode refused the grant " +
                "type (" +
                grantCheck.requirement + ").");
      errorCodes.mark(res, grantCheck.errorCode || 'STS-OAUTH-0158');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, grantCheck.error,
                             grantCheck.description);
    }

    // WHAT A CLIENT ASSERTION MAY NAME AS ITS AUDIENCE, decided ONCE for the
    // policy below and the observation after it. They must be handed the same
    // list: `client_auth.js` verifies one document once per request and keeps
    // the answer, so two calls with two lists would have the first silently
    // decide both — which is why the strictness is in that cache's key too.
    //
    // RFC 7523 section 3 says the token endpoint; OpenID Connect Core section 9
    // says the ISSUER, and deployments differ — so both are accepted for the
    // SIGNATURE, rather than one being picked and half the client libraries in
    // the world being refused. OAuth 2.1 mode then requires the issuer as the
    // SOLE value (draft-ietf-oauth-rfc7523bis-11), which `client_auth.js`
    // checks after the signature so that the refusal names the audience.
    const assertionAudiences = [base + '/oauth2/token', self.issuerOf(base),
                                base];
    const strictAudience = (oauth21.strictClientAssertionAudience() ||
                            self.deps.fapi.strictAssertionAudience()) ?
                           self.issuerOf(base) : '';
    // RFC 9700 section 2.5 — the client's credential, checked in that mode (and
    // OAuth 2.1 mode) for a client whose entry declares a confidential method.
    // Above every grant, because a client that cannot authenticate has not
    // authenticated whichever grant it was about to ask for. 401 rather than
    // 400: invalid_client is the one OAuth error RFC 6749 section 5.2 gives
    // that status, and a client_secret_basic caller needs the WWW-Authenticate
    // header to know what to retry with.
    const clientAuth = await bcp.checkClientAuthentication({
      clientId: String(client.client_id || ''),
      clientSecret: client.client_secret,
      assertion: client.assertion,
      assertionType: client.assertionType,
      // The connection, for the two RFC 8705 methods — the certificate that
      // authenticates the client is the one this request arrived with.
      request: req,
      // What a client assertion may name as its audience — see above.
      audiences: assertionAudiences,
      strictAudience: strictAudience,
      registered: registeredClient
    });
    if (!clientAuth.ok) {
      if (/^Basic\s+/i.test(req.headers['authorization'] || '')) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      const overLimit = await self.countSecretFailure(req, client.client_id,
                                                 presented, registeredClient);
      if (overLimit) {
        log.debug("Leaving OAuth2Server.tokenGrant(). Past the secret limit.");
        return self.secretLockout(res, client.client_id, overLimit);
      }
      log.debug("Leaving the token endpoint. RFC 9700 mode refused the " +
                "client (" +
                clientAuth.requirement + ").");
      errorCodes.mark(res, clientAuth.errorCode || 'STS-OAUTH-0137');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 401, clientAuth.error,
                             clientAuth.description);
    }

    // OAUTH 2.1 — THE CLIENT'S ENTRY, before this request is recorded against
    // it: a refusal for being unregistered must not be the thing that creates
    // the entry. SAML client authentication, and a client_id whose entry
    // declares nothing a sighting would not have written.
    const declaration = oauth21.tokenClientDeclarationRefusal({
      grant: grant, clientId: client.client_id, registered: registeredClient,
      presented: presented
    });
    if (declaration) {
      if (presented.basic) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      log.debug("Leaving the token endpoint. OAuth 2.1 refused the client (" +
                declaration.requirement + ").");
      errorCodes.mark(res, declaration.errorCode || 'STS-OAUTH-0278');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 401, declaration.error,
                             declaration.description);
    }

    // #34 (2026-09-15): THE SAME QUESTION FOR THE TWO ASSERTION GRANTS, which
    // the check above leaves alone on purpose — they may arrive with no client
    // at all. One that NAMES a client still has to name one this server knows;
    // one that names none is answered without a refresh token, below.
    const assertionClient = oauth21.assertionClientRefusal({
      grant: grant, clientId: client.client_id, registered: registeredClient
    });
    if (assertionClient) {
      if (presented.basic) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      log.debug("Leaving the token endpoint. OAuth 2.1 refused the client on " +
                "an assertion grant.");
      errorCodes.mark(res, assertionClient.errorCode || 'STS-OAUTH-0299');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      // error-code: none — marked above with the refusal's own code.
      return self.oauthError(res, 401, assertionClient.error,
                        assertionClient.description);
    }

    // The application again, and NOT counted again: redeeming a code is the
    // same transaction the authorization endpoint already recorded. What this
    // adds is the grant type actually used, which is a fact only this endpoint
    // has — and for client_credentials and the pre-authorized code grant it is
    // the FIRST sight of the client, since neither goes near the authorization
    // endpoint.
    if (client.client_id) {
      applications.seen({
        identifier: String(client.client_id),
        kind: 'oauth2-client',
        protocol: 'OAuth 2.0 / OIDC',
        counts: false,
        note: 'presented a Token Request',
        fields: Object.assign(
          { oauthClientId: String(client.client_id), oauthGrantType: grant,
            appAuthorizationServer: self.profileOf(req) },
          // THE SCOPE, WHERE THIS REQUEST CARRIES ONE, and it is recorded here
          // as well as at the authorization endpoint because for three grants
          // this is the ONLY place it is ever seen: client credentials, the
          // password grant and the pre-authorized code grant never go near that
          // endpoint. Without it `oauthScope` on such a client stays empty
          // however often it asks, which reads on /admin/delegation as a
          // delegated permission that has never been requested — a quietly
          // wrong signal about a client that requests it every minute.
          //
          // Conditional, because an `authorization_code` redemption carries no
          // `scope` of its own (the grant does) and writing an empty value
          // would be recording that this client asked for nothing.
          String(body.scope || '').trim()
            ? { oauthScope: String(body.scope).split(/\s+/).filter(Boolean) }
            : {})
      });
    }

    // -------------------------------------------------------------------------
    // RFC 8707 SECTION 2 — `resource` IS READ FOR EVERY GRANT, AND IT USED TO
    // BE READ FOR TWO.
    //
    // Section 2 says the parameter belongs on "a token request", full stop: the
    // grant types it names are the ones RFC 6749 defines and the extensions
    // built on them, not a chosen pair. Until 2026-08-26 only
    // `authorization_code` and `refresh_token` parsed it here — the two that
    // have something to NARROW — and the other four IGNORED it silently. That
    // is the worst shape a parameter can have: a client asking
    // `client_credentials` for a token addressed to
    // `https://apigw1.example.com` got one addressed to `<base>/resource` and
    // no error, so the audience restriction it thought it had was never there.
    // It was found by testing the scope-derived audience above against a
    // request carrying both, and it is a hole in RFC 8707 rather than anything
    // to do with that feature.
    //
    // Parsed ONCE, here, above every grant, for the reason the DPoP check above
    // is where it is: a malformed `resource` is malformed whatever the client
    // is asking for, and six parses is five that agree and a sixth added later
    // that does not. The two RULES stay per grant, because they are the half
    // that depends on what came before:
    //
    //   * `authorization_code` and `refresh_token` may only NARROW what was
    //     already authorized (section 2.2). Both compare this list against what
    //     the code or the refresh token carries, and both refuse
    //     `invalid_target` for anything extra.
    //   * `client_credentials`, `password`, the pre-authorized code grant and
    //     the token exchange have NOTHING to narrow against — no authorization
    //     request preceded any of them — so what is asked for is what is
    //     granted. That is not a relaxation: there is no earlier decision for a
    //     narrowing rule to be about, and inventing one would refuse the only
    //     request those grants can make.
    //
    // **A GRANT THAT NARROWS ITSELF OUT OF THIS SERVICE IS THE CLIENT'S
    // DECISION.** `presentedAccessToken()` in `dpop.ts` refuses a token
    // addressed elsewhere at every protected endpoint here (RFC 9068 section 4,
    // through `jwt_access_token.ts` since 2026-09-13), so `resource` on the
    // pre-authorized code grant produces a token the CREDENTIAL endpoint will
    // not accept, exactly as it does for UserInfo. That was already reachable
    // through the authorization code flow and is what the parameter means; the
    // alternative is a grant that quietly ignores it, which is the bug being
    // fixed.
    // -------------------------------------------------------------------------
    // Through `bodyValues()` and not off `body`, and that is the other half of
    // this hole: `parseBody()` keeps only the LAST value of a repeated
    // parameter, so `resource=a&resource=b` reached here as `b` alone. Section
    // 2 allows the repetition and `parseResourceIndicators()` has handled an
    // array since it was written — nothing could ever hand it one. See
    // `bodyValues()` in helpers.js.
    const askedResources = self.parseResourceIndicators(
        bodyValues(req, body, 'resource'));
    if (askedResources.error) {
      log.debug("Leaving the token endpoint. " + askedResources.error);
      errorCodes.mark(res, 'STS-OAUTH-0154');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, 'invalid_target', askedResources.error);
    }
    const requestedResources = askedResources.resources;
    if (requestedResources.length) {
      logArtifact('RFC 8707 resource indicators', 'on the Token Request',
                  requestedResources);
    }

    // RFC 9396 SECTION 6, once above every grant for the reason the block above
    // is: every grant may carry `authorization_details` — to NARROW what a code
    // or a refresh token authorized, or to ask a direct grant for them
    // outright. The pre-authorized code grant is the exception and reads its
    // own below, because what bounds it is the Credential Offer rather than a
    // grant.
    const askedDetails =
      grant === 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
        ? { details: null }
        : self.parseAuthorizationDetails(body.authorization_details,
            { clientId: (client && client.client_id) || body.client_id,
              req: req });
    if (askedDetails.error) {
      log.debug("Leaving the token endpoint. " + askedDetails.error);
      errorCodes.mark(res, errorCodes.codeOf(askedDetails) || 'STS-OAUTH-0153');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, 'invalid_authorization_details',
                        askedDetails.error);
    }
    const requestedDetails = askedDetails.details;
    if (requestedDetails) {
      logArtifact('RFC 9396 authorization_details', 'on the Token Request',
                  requestedDetails);
    }

    // DELEGATED PERMISSIONS, once above every grant and for the same reason the
    // block above is once above every grant: the four direct grants, the token
    // exchange and a refresh that names a scope all ask for scopes HERE, and a
    // check written into each of them is five that will be right and a sixth
    // added later that will not.
    //
    // IT READS `body.scope` AND NOTHING ELSE, which is what confines it to what
    // the client is ASKING for now. An authorization code carries what was
    // already authorized and was judged at the authorization endpoint; a
    // refresh with no `scope` carries its grant's. Neither is re-judged — see
    // permissionRefusal()'s header, and the row in CLAUDE.md about not
    // re-checking a federated person after the session exists, which is the
    // same rule.
    //
    // Always in product mode; in development a no-op unless
    // `oauth2.delegatedPermissionsEnforced` is on.
    if (body.scope !== undefined && body.scope !== null &&
        String(body.scope) !== '') {
      const permissionProblem = self.permissionRefusal(String(body.scope),
        (client && client.client_id) || body.client_id);
      if (permissionProblem) {
        log.debug("Leaving the token endpoint. An ungranted permission was " +
                  "asked for.");
        errorCodes.mark(res, 'STS-OAUTH-0155');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_scope', permissionProblem);
      }
      // THE SCOPES THIS CLIENT MAY BE ISSUED (#110), on the same reading of
      // `body.scope` and for the same grants. What a grant carries from
      // earlier is narrowed in tokenSet() instead. See scopeRefusal().
      const scopeProblem = self.scopeRefusal(String(body.scope),
        (client && client.client_id) || body.client_id);
      if (scopeProblem) {
        log.debug("Leaving the token endpoint. A scope the client did not " +
                  "declare was asked for.");
        // STS-OAUTH-0577 (protected) or STS-OAUTH-0578 (undeclared).
        errorCodes.mark(res, scopeProblem.code);
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_scope',
                               scopeProblem.description);
      }
    }

    // RFC 9068 SECTION 3, once above every grant and for the block above's
    // reason — and asked BEFORE anything a grant spends: a code redeemed, a
    // refresh token rotated. It reads what the client is asking for NOW, the
    // `scope` and the `resource` values on this request, and nothing a grant
    // carries from earlier; tokenSet() asks the same plan again with the
    // grant's own audience, which is the backstop for that. It is never
    // stricter than the backstop: the resources here are a subset of any
    // grant's.
    //
    // NOT FOR THE TOKEN EXCHANGE, whose audience is RFC 8693's `audience`
    // unioned with the resources and is assembled inside its branch. Nothing
    // that branch does before issuing can be spent, so the backstop is the
    // whole of its check. In every mode.
    if (grant !== 'urn:ietf:params:oauth:grant-type:token-exchange' &&
        (String(body.scope || '') !== '' || requestedResources.length ||
         requestedDetails)) {
      const earlyPlan = self.accessTokenPlan(base, String(body.scope || ''),
        (client && client.client_id) || body.client_id, requestedResources,
        requestedDetails);
      if (earlyPlan.refusal) {
        log.debug("Leaving the token endpoint. RFC 9068 refused the audience.");
        errorCodes.mark(res, errorCodes.codeOf(earlyPlan.refusal) ||
                             'STS-OAUTH-0244');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, earlyPlan.refusal.error,
                          earlyPlan.refusal.description);
      }
    }

    // WHAT THIS REQUEST DEMONSTRATED ABOUT THE CLIENT, observed once and
    // reused.
    //
    // An OBSERVATION rather than a check — `checkClientAuthentication()` above
    // has already applied whatever policy RFC 9700 mode asks for and refused
    // the request if it failed. This is the FACT the role gate needs:
    // ALL_AUTHENTICATED_APPLICATIONS and ALL_UNAUTHENTICATED_APPLICATIONS are
    // about what the client is, which is true whether or not the BCP mode is
    // on. Its header argues why it is not mode-gated.
    //
    // Here rather than inside `issuanceSubjectOf()` because that function is
    // synchronous and this is a signature check; and once rather than per
    // grant, because it is a fact about the REQUEST and six grants recomputing
    // it is five that would agree and a sixth added later that would not.
    // -----------------------------------------------------------------------
    // `token_endpoint_auth_signing_alg`, IN EVERY MODE (#118, OIDC Core
    // section 9 and RFC 7591 section 2): a client that registered one must
    // sign its private_key_jwt or client_secret_jwt assertion with it, and
    // "Servers SHOULD reject tokens signed with any other algorithm". It was
    // never read. Checked on the assertion's header before anything else about
    // it, so development — which does not verify the signature — refuses the
    // wrong algorithm too.
    // -----------------------------------------------------------------------
    const pinnedAlg = String((registeredClient || {})
      .token_endpoint_auth_signing_alg || '');
    if (pinnedAlg && client.assertion) {
      let assertionAlg = '';
      try {
        assertionAlg = String(JSON.parse(Buffer.from(
          String(client.assertion).split('.')[0], 'base64url')
          .toString('utf8')).alg || '');
      } catch (e) {
        log.debug("Caught in OAuth2Server.tokenGrant(): " +
                  ((e && e.message) || e));
        // An unreadable header is refused below as not the registered alg.
        assertionAlg = '';
      }
      if (assertionAlg !== pinnedAlg) {
        log.debug("Leaving the token endpoint. The assertion is not signed " +
                  "with the registered algorithm.");
        errorCodes.mark(res, 'STS-OAUTH-0570');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 401, 'invalid_client',
          'Client "' + (client.client_id || '') + '" registered ' +
          'token_endpoint_auth_signing_alg "' + pinnedAlg + '", and its ' +
          'client_assertion is signed with "' + (assertionAlg || '(none)') +
          '". OIDC Core section 9: an assertion signed with any other ' +
          'algorithm is rejected.');
      }
    }
    const clientObservation = await bcp.observeClientAuthentication({
      clientId: String(client.client_id || ''),
      clientSecret: client.client_secret,
      assertion: client.assertion,
      assertionType: client.assertionType,
      request: req,
      audiences: assertionAudiences,
      strictAudience: strictAudience,
      registered: registeredClient
    });
    // THE SECRET RATE LIMIT'S LAST HALF: a success clears this client's bucket
    // at this address, and leaves the address bucket alone.
    if (clientObservation.authenticated && client.client_id) {
      const racedOut = await self.settleSecretSuccess(req, client.client_id,
                                                 presented, registeredClient);
      if (racedOut) {
        log.debug("Leaving OAuth2Server.tokenGrant(). A verified secret past " +
                  "the limit.");
        return self.secretLockout(res, client.client_id, racedOut);
      }
    }

    // FAPI (#138): a confidential client authenticates with mTLS,
    // private_key_jwt or client_secret_jwt, never a plain secret.
    const fapiAuth = fapi.clientAuthenticationRefusal(
      clientObservation.method);
    if (fapiAuth) {
      if (presented.basic) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      log.debug("Leaving the token endpoint. FAPI refused the client's " +
                "authentication method.");
      errorCodes.mark(res, fapiAuth.errorCode || 'STS-OAUTH-0580');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 401, fapiAuth.error, fapiAuth.description);
    }
    // RFC 7591 SECTION 2 (#120, in every mode, rcbj's decision): a client
    // that REGISTERED its grant_types is held to them. A client_id nobody
    // registered, and a registration naming no list, are not.
    const registeredFlows = client.client_id
      ? applications.registeredFlowsOf(client.client_id) : null;
    if (registeredFlows && registeredFlows.grant_types &&
        registeredFlows.grant_types.indexOf(
          String(body.grant_type || '')) < 0) {
      log.debug("Leaving the token endpoint. A grant type the client did " +
                "not register.");
      errorCodes.mark(res, 'STS-OAUTH-0598');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, 'unauthorized_client',
        'Client "' + client.client_id + '" registered grant_types ' +
        JSON.stringify(registeredFlows.grant_types) + ', and this request ' +
        'is the ' + String(body.grant_type || '') + ' grant (RFC 7591 ' +
        'section 2).');
    }
    // FAPI 1.0 Advanced section 8.6 (#139): a client assertion is signed PS256
    // or ES256, whatever the client registered.
    // FAPI 2.0 section 5.3.2.1 item 13 (#140): a client assertion's iat or
    // nbf more than a minute in the future.
    if (client.assertion) {
      const ahead = fapi.futureTimestampRefusal(
        self.unverifiedClaimsOf(client.assertion), 'the client assertion');
      if (ahead) {
        log.debug("Leaving the token endpoint. FAPI 2.0: a timestamp in the " +
                  "future.");
        errorCodes.mark(res, ahead.errorCode || 'STS-OAUTH-0590');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, ahead.error, ahead.description);
      }
    }
    if (client.assertion) {
      const assertionAlg = self.headerAlgOf(client.assertion);
      const fapiAlg = fapi.signingAlgRefusal(assertionAlg,
                                             'the client assertion');
      if (fapiAlg) {
        log.debug("Leaving the token endpoint. FAPI refused the client " +
                  "assertion's algorithm.");
        errorCodes.mark(res, fapiAlg.errorCode || 'STS-OAUTH-0586');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 401, 'invalid_client',
                               fapiAlg.description);
      }
    }
    // FAPI 1.0 Advanced section 5.2.2 items 5-6 (#139): every access token is
    // sender-constrained — by the client certificate this connection
    // presented, or (unless oauth2.fapiRequireMtls) by the DPoP proof checked
    // above. Refused before any grant is spent.
    const fapiBound = fapi.senderConstraintRefusal({
      dpop: !!dpopJkt, mtls: !!mtls.presentedThumbprint(req) });
    if (fapiBound) {
      log.debug("Leaving the token endpoint. FAPI: the token would be " +
                "unconstrained.");
      errorCodes.mark(res, fapiBound.errorCode || 'STS-OAUTH-0583');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 400, fapiBound.error,
                             fapiBound.description);
    }

    // OAUTH 2.1 — WHAT THE CLIENT PRESENTED. A credential that was included
    // must have verified (section 3.2.2), and the client credentials grant
    // needs an authenticated client (section 4.2).
    const authentication = oauth21.tokenClientAuthenticationRefusal({
      grant: grant, observation: clientObservation, presented: presented
    });
    if (authentication) {
      const overLimit = await self.countSecretFailure(req, client.client_id,
                                                 presented, registeredClient);
      if (overLimit) {
        log.debug("Leaving OAuth2Server.tokenGrant(). Past the secret limit.");
        return self.secretLockout(res, client.client_id, overLimit);
      }
      if (presented.basic) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      log.debug("Leaving the token endpoint. OAuth 2.1 refused the client (" +
                authentication.requirement + ").");
      errorCodes.mark(res, authentication.errorCode ||
                           'STS-OAUTH-0280');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return self.oauthError(res, 401, authentication.error,
                        authentication.description);
    }

    // RFC 8705 — WHAT THE CLIENT DECLARED, IN EVERY MODE (2026-09-13). A client
    // whose entry names a certificate authentication method must have
    // authenticated with it, and one that registered
    // tls_client_certificate_bound_access_tokens must have presented a
    // certificate to bind to. `mtls.declaredRefusal()` argues why these two
    // refusals do not wait for a mode; it reads the observation above, so the
    // certificate is not verified a second time.
    const declared = mtls.declaredRefusal({
      registered: registeredClient, observation: clientObservation, request: req
    });
    if (declared) {
      log.debug("Leaving the token endpoint. RFC 8705: the client's " +
                "declaration was not met.");
      errorCodes.mark(res, declared.errorCode);
      log.debug("Leaving OAuth2Server.tokenGrant().");
      // error-code: none — marked above with mtls.declaredRefusal()'s code
      return self.oauthError(res, declared.status, declared.error,
                        declared.description);
    }

    // ---------------------------------------------------------------------
    // PRODUCT MODE: A CONFIDENTIAL CLIENT AUTHENTICATES. A PUBLIC ONE IS
    // ALLOWED (2026-09-06, narrowed 2026-09-17).
    //
    // The observation above is exactly that — an observation, made in both
    // modes because `/admin/delegation` and the role gate both want to know
    // what the client IS. This is the ENFORCEMENT, and it is the third of the
    // four things product mode requires.
    //
    // **IT SAID "THERE ARE NO PUBLIC CLIENTS" AND REFUSED EVERY CLIENT THAT
    // DID NOT AUTHENTICATE, INCLUDING ONE REGISTERED `none`.** That is the
    // commonest kind of OAuth client there is — a browser or native
    // application that cannot keep a secret — and product mode could not
    // exercise one at all. `bcp.declaredPublic()` is now what this asks, so
    // the refusal falls only on a client whose own registration does NOT say
    // it is public: a `token_endpoint_auth_method` of anything but `none`,
    // INCLUDING a registration that declared none at all, which RFC 7591
    // section 2 reads as `client_secret_basic`. A client that declared `none`
    // presents nothing and that is CORRECT (RFC 6749 section 3.2.1).
    //
    // **IT IS `declaredPublic()` AND NOT `!isConfidential()`**, which is a
    // distinction that cost a real hole in the first version of this block:
    // that function answers "can this server SEE the client to be
    // confidential", which is `false` for a client that declared no method —
    // so a client that never declared itself public would have been let
    // through with no credential. That function's own header says why it must
    // keep answering the way it does for PKCE.
    //
    // **WHAT REPLACES THE SECRET FOR A PUBLIC CLIENT IS NOT NOTHING.** Product
    // mode implies RFC 9700 mode (`mode.enforcesOauthSecurityBcp()`), so a
    // public client here is held to PKCE with S256, an exactly matched
    // redirect URI, a challenge it cannot replay, a refresh token that rotates
    // and no response type that issues a token from the authorization
    // endpoint — and to the grant policy below, which is the other half of
    // what the specifications say instead of "hold a secret".
    //
    // **IT IS HERE AND NOT IN `client_auth.js`** because that module answers
    // "did this credential verify" and this is a different question — "was one
    // required" — which is a property of the deployment rather than of the
    // credential. Putting it there would mean a module that verifies
    // credentials deciding when one is needed, and every caller inheriting that
    // decision whether or not it wanted it.
    //
    // `invalid_client` with a 401, which is RFC 6749 section 5.2's answer for a
    // client that failed to authenticate — not `unauthorized_client`, which is
    // about the GRANT a client may use and would send an author looking at
    // their grant type.
    //
    // **AN ASSERTION GRANT THAT NAMES NO CLIENT IS NOT A CLIENT TO REFUSE**
    // (2026-09-18). RFC 7521 section 4.1 makes client authentication optional
    // there — the signed assertion is the credential, verified against an
    // issuer somebody declared — and #34's block below is written for exactly
    // that request ("they may arrive with no client at all"). This check ran
    // first and read "no client_id" as "an unknown client that must
    // authenticate", so product mode refused every clientless RFC 7523 and
    // RFC 7522 grant: found by sts_jwt_bearer_grant.js run against a
    // product-mode deployment. A grant that NAMES a client is still judged
    // here, known or not.
    const clientlessAssertion = !client.client_id &&
      oauth21.ASSERTION_GRANTS.indexOf(grant) >= 0;
    if (mode.requiresConfidentialClientAuthentication() &&
        !clientlessAssertion &&
        bcp.declaredPublic(registeredClient) === false &&
        !clientObservation.authenticated) {
      log.info('oauth2: product mode refused the token request from "' +
               String(client.client_id || '(unnamed)') + '": ' +
               clientObservation.why);
      const overLimit = await self.countSecretFailure(req, client.client_id,
                                                 presented, registeredClient);
      if (overLimit) {
        log.debug("Leaving OAuth2Server.tokenGrant(). Past the secret limit.");
        return self.secretLockout(res, client.client_id, overLimit);
      }
      // RFC 6749 section 5.2's challenge when the client used Basic, which this
      // refusal did not send until 2026-09-13.
      if (presented.basic) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      errorCodes.mark(res, clientObservation.errorCode || 'STS-OAUTH-0192');
      res.status(401).type('application/json').send(JSON.stringify({
        error: 'invalid_client',
        error_description: oauth21.sanitizeDescription('This service is in ' +
          'product mode, where an application that registered a ' +
          'token_endpoint_auth_method other than "none" must present that ' +
          'credential and it must verify. A client registered ' +
          'token_endpoint_auth_method="none" is public, is allowed, and is ' +
          'held to PKCE instead. ' + clientObservation.why)
      }));
      log.debug("Leaving the token endpoint. Product mode refused an " +
                "unauthenticated client.");
      return;
    }

    // ---------------------------------------------------------------------
    // WHICH GRANTS A PUBLIC CLIENT MAY USE, IN PRODUCT MODE (2026-09-17).
    //
    // The other half of allowing public clients. A public client is allowed to
    // present no credential; it is NOT allowed to use the two grants the
    // specifications define around having one:
    //
    //   * **client_credentials.** RFC 6749 section 4.4 is the grant a client
    //     uses "to obtain an access token using only its client credentials",
    //     and a client with none has nothing to obtain it with — the token
    //     would be minted for anybody who knows the client_id. OAuth 2.1
    //     section 4.2 says it outright: confidential clients only.
    //     `oauth21.registrationRefusal()` already refuses to REGISTER that
    //     combination in OAuth 2.1 mode; this is the same rule at the door
    //     where it matters, because a client can be created through the
    //     console, `/admin-api` or an `ldapmodify` and never meet the
    //     registration endpoint.
    // **THE PASSWORD GRANT IS NOT HERE, AND THAT IS DELIBERATE.** RFC 9700
    // section 2.4 says it MUST NOT be used by ANY client, and
    // `oauth2_bcp.js`'s `no-ropc` rule already refuses it at this endpoint
    // whenever the mode is on — which product mode now makes always. A second
    // refusal here, scoped to public clients, would fire FIRST and answer
    // `unauthorized_client` where every other client gets
    // `unsupported_grant_type`: two errors for one fact, decided by which kind
    // of client asked. The stronger rule is the right one and it is already
    // written.
    //
    // `unauthorized_client` and not `invalid_client`: RFC 6749 section 5.2
    // says this code is for a client "not authorized to use this
    // authorization grant type", which is precisely the fact. The client
    // authenticated (or correctly did not); the GRANT is what is refused.
    if (mode.requiresConfidentialClientAuthentication() &&
        bcp.declaredPublic(registeredClient) &&
        grant === 'client_credentials') {
      log.info('oauth2: product mode refused the client credentials grant ' +
               'to public client "' +
               String(client.client_id || '(unnamed)') + '".');
      errorCodes.mark(res, 'STS-OAUTH-0552');
      res.status(400).type('application/json').send(JSON.stringify({
        error: 'unauthorized_client',
        error_description: oauth21.sanitizeDescription('This client is ' +
          'PUBLIC (token_endpoint_auth_method="none"), and in product mode a ' +
          'public client may use the authorization code and refresh grants ' +
          'only. RFC 6749 section 4.4 defines the client credentials grant ' +
          'for a client that HAS credentials, and OAuth 2.1 section 4.2 ' +
          'limits it to confidential clients outright; a public client using ' +
          'it would mint a token for anybody who knows the client_id. ' +
          'Register this client with a confidential ' +
          'token_endpoint_auth_method and a credential to use it.')
      }));
      log.debug("Leaving the token endpoint. A grant a public client may " +
                "not use.");
      return;
    }

    const respond = function (payload) {
      log.debug("Entering respond().");
      res.status(200).type('application/json').send(JSON.stringify(payload));
      log.debug("Leaving the token endpoint. Issued: " +
                Object.keys(payload).join(', '));
    };

    // Every grant below mints its tokens through THIS rather than calling
    // tokenSet() directly, and the only thing it adds is the request itself.
    // That is what lets RFC 8705 bind a token to the client certificate this
    // connection carried without six call sites having to remember to pass it —
    // and six call sites that must remember is five that will and a sixth added
    // later that will not, which is the reasoning that keeps signJwt() the
    // single counter and refreshToken() the single minter.
    const issue = function (rawOpts) {
      log.debug("Entering issue().");
      // THE CLIENT'S OBSERVED ANSWER IS INJECTED HERE rather than passed by
      // each grant, for the reason the paragraph above about `request: req`
      // gives: every grant mints through this closure, so every grant is
      // decided on the same fact, and a seventh added below inherits it without
      // its author having to know it exists. A grant that already stated it —
      // none does — would win, which is the ordinary Object.assign reading.
      const opts =
          Object.assign({ clientAuthenticated:
                            clientObservation.authenticated },
                        rawOpts);
      // #34 (2026-09-15): an RFC 7523 or RFC 7522 grant that named no client
      // gets no refresh token while OAuth 2.1 mode is on. RECORDED AND NOT
      // REFUSED, because the grant itself is legitimate — the assertion speaks
      // for the subject — and RFC 6749 section 5.1 makes `refresh_token`
      // optional in the response. What would otherwise happen is a chain
      // belonging to nobody, refused at its first redemption for want of a
      // client_id. See `oauth21.js` above `withholdsRefreshToken()`.
      if (opts.withRefresh !== false &&
          oauth21.withholdsRefreshToken({ grant: grant,
                                          clientId: opts.client_id })) {
        log.info(errorCodes.tag('STS-OAUTH-0298') + 'OAuth 2.1 mode: the ' +
                 grant + ' grant arrived with no client, so it is answered ' +
                 'with an access token and no refresh token — a refresh ' +
                 'chain belonging to no client could not be checked against ' +
                 'the client redeeming it.');
        opts.withRefresh = false;
      }
      // RFC 7591 SECTION 2 (#120): a client that registered its grant_types
      // without `refresh_token` gets no refresh token — RECORDED AND NOT
      // REFUSED, for 0298's reason. Issuing one it could never redeem (the
      // grant is refused above, 0598) is the half a token set #34 refuses to
      // hand out.
      if (opts.withRefresh !== false && registeredFlows &&
          registeredFlows.grant_types &&
          registeredFlows.grant_types.indexOf('refresh_token') < 0) {
        log.info(errorCodes.tag('STS-OAUTH-0600') + 'oauth2: "' +
                 client.client_id + '" registered no refresh_token grant, ' +
                 'so the ' + grant + ' grant is answered with no refresh ' +
                 'token.');
        opts.withRefresh = false;
      }
      // THE ROLE GATE, HERE FOR THE REASON THE PARAGRAPH ABOVE GIVES ABOUT THE
      // CLIENT CERTIFICATE. Every grant mints through this closure, so every
      // grant is decided, and a seventh added below inherits the decision
      // without its author having to know it exists. It THROWS on a refusal —
      // see checkIssuance() — which is caught at the foot of this function.
      self.checkIssuance(opts);
      // #34: and the two settings that refuse to hand out a refresh token that
      // is not sender-constrained. Here for the same reason, and reading
      // `withRefresh` — the grant's own answer to "is a refresh token about to
      // be minted" — rather than a list of grants kept beside it.
      if (opts.withRefresh !== false) {
        const constraint = senderConstraints.refreshIssuanceRefusal({
          grant: grant,
          dpopJkt: dpopJkt,
          certificate: !!mtls.peerCertificate(req),
          certificateVerified: mtls.peerVerified(req),
          exempt: senderConstraints.mtlsExemptClient(opts.client_id),
          mtlsAvailable: mtls.available()
        });
        if (constraint) {
          log.debug("Leaving issue(). A sender constraint refused the " +
                    "refresh token.");
          throw new SenderConstraintRefused(log, constraint);
        }
      }
      log.debug("Leaving issue().");
      return self.tokenSet(base, Object.assign({ request: req }, opts));
    };

    // Turn what was authorized into what may be requested: OID4VCI calls these
    // Credential Dataset identifiers, and they are the issuer's own names for
    // "this credential, for this End-User".
    const grantIdentifiers = function (details, user) {
      log.debug("Entering grantIdentifiers().");
      if (!details) {
        log.debug("Leaving grantIdentifiers().");
        return null;
      }
      log.debug("Leaving grantIdentifiers().");
      return details.map(function (d) {
        // A type an application declared is granted as it was asked for:
        // section 7's enrichment is the resource's business, and nothing here
        // knows it.
        if (d.type !== 'openid_credential') {
          return d;
        }
        if (Array.isArray(d.credential_identifiers)) {
          // Already enriched — a refresh token's own copy handed back.
          return d;
        }
        const granted: Json = {
          type: 'openid_credential',
          credential_configuration_id: d.credential_configuration_id,
          credential_identifiers: [
            d.credential_configuration_id + ':' +
            b64u(crypto.createHash('sha256')
              .update(String((user && user.sub) || 'anonymous') + ':' +
                      d.credential_configuration_id)
              .digest()).slice(0, 16)
          ]
        };
        // Echoed back, and it has to be: this is what the credential endpoint
        // reads the selection off (it rides inside the access token), and it is
        // also the only way the wallet learns that the claims it asked for are
        // the claims that were authorized. RFC 9396 section 7 enriches the
        // details it returns rather than replacing them.
        if (d.claims) granted.claims = d.claims;
        return granted;
      });
    };

    if (grant === 'authorization_code') {
      const code = String(body.code || '');
      const fingerprint = self.redemptionFingerprint(client, body, dpopJkt);
      const record = authzCodes.get(code);
      if (!record) {
        // Not necessarily an error: this is also where a second, identical
        // Token Request for a code already redeemed is answered with the tokens
        // it got the first time. See `redeemedCodes` above.
        log.debug("Leaving the token endpoint. No live code by that value; " +
                  "what became of it decides the answer.");
        return self.replayOrRefuseRedemption(res, code, fingerprint, respond);
      }
      if (record.expires < Date.now()) {
        authzCodes.delete(code);
        log.debug("Leaving the token endpoint. The code had expired.");
        errorCodes.mark(res, 'STS-OAUTH-0199');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
          'The authorization code has expired.');
      }
      // NOTHING below consumes the code: every check refuses and leaves it
      // redeemable, so a client that gets one of them can fix what the message
      // names and try the same code again. Burning it here is what used to turn
      // "your code_verifier does not match" into "already-used authorization
      // code" on the very next attempt — the wrong answer at exactly the moment
      // somebody was acting on the right one. The code is consumed at the
      // bottom, where it is actually redeemed. A code belongs to the
      // authorization server that issued it. Checked before anything else about
      // the code, because "that code is not for this server" is a different
      // fact from every other refusal here and reads as one.
      const codeServer = record.authorization_server ||
                         authorizationServers.DEFAULT_ID;
      if (codeServer !== self.profileOf(req)) {
        log.debug("Leaving the token endpoint. The code belongs to " +
                  codeServer + ".");
        errorCodes.mark(res, 'STS-OAUTH-0200');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
          'This authorization code was issued by the "' + codeServer + '" ' +
          'authorization server and is being redeemed at the ' +
          '"' + self.profileOf(req) + '" one. They are separate ' +
          'authorization servers that happen to share a process: they ' +
          'publish different capabilities and a credential does not cross ' +
          'between them. Redeem it at ' +
          (codeServer === authorizationServers.DEFAULT_ID ? '/oauth2/token'
                                                          : '/' + codeServer +
                                                              '/oauth2/token') +
          '.');
      }
      if (body.redirect_uri && body.redirect_uri !== record.redirect_uri) {
        log.debug("Leaving the token endpoint. The grant was refused.");
        errorCodes.mark(res, 'STS-OAUTH-0201');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant', 'redirect_uri does ' +
                                                     'not match the ' +
                                                     'authorization request.');
      }
      // RFC 9700 mode: the PKCE downgrade refusal (section 4.8.2 — a
      // code_verifier for a code that was issued without a challenge), and the
      // two RFC 6749 section 4.1.3 checks that make "bound to the client and
      // the user-agent transaction" true rather than merely intended — the code
      // is redeemed by the client it was issued to, and redirect_uri is PRESENT
      // here rather than only compared when the client volunteered it. Like
      // everything else above, it refuses without consuming the code.
      const bcpCheck = bcp.checkTokenRequest({ record: record, body: body,
                                               client: client });
      if (!bcpCheck.ok) {
        log.debug("Leaving the token endpoint. RFC 9700 mode refused the " +
                  "Token " +
                  "Request (" +
                  bcpCheck.requirement + ").");
        errorCodes.mark(res, bcpCheck.errorCode || 'STS-OAUTH-0158');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, bcpCheck.error, bcpCheck.description);
      }
      // OAUTH 2.1 section 4.1.3: a code with no challenge is refused unless it
      // was issued under the OpenID Connect nonce exemption, and one that was
      // is redeemed only by a client that authenticated on this request.
      const codePkce = oauth21.tokenCodeRefusal({
        record: record, authenticated: clientObservation.authenticated
      });
      if (codePkce) {
        log.debug("Leaving the token endpoint. OAuth 2.1 refused the code (" +
                  codePkce.requirement + ").");
        errorCodes.mark(res, codePkce.errorCode || 'STS-OAUTH-0277');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, codePkce.error, codePkce.description);
      }
      if (record.code_challenge) {
        const verifier = String(body.code_verifier || '');
        if (!verifier) {
          log.debug("Leaving the token endpoint. PKCE was used and no " +
                    "code_verifier came with the code.");
          errorCodes.mark(res, 'STS-OAUTH-0202');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'PKCE was used, so code_verifier is required.');
        }
        const computed = record.code_challenge_method === 'S256'
          ? b64u(crypto.createHash('sha256').update(verifier, 'ascii').digest())
          : verifier;
        if (computed !== record.code_challenge) {
          log.debug("Leaving the token endpoint. The grant was refused.");
          errorCodes.mark(res, 'STS-OAUTH-0203');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant', 'The ' +
                                                       'code_verifier does ' +
                                                       'not match the ' +
                                                       'code_challenge.');
        }
      }
      // RFC 9449 section 10: when the authorization request named a key with
      // `dpop_jkt`, the code is bound to it and only that key may redeem it.
      // This closes the window PKCE does not: an attacker who steals the code
      // AND the code_verifier still cannot use them, because they cannot sign
      // for the key.
      if (record.dpop_jkt) {
        if (!dpopJkt) {
          log.debug("Leaving the token endpoint. The code is DPoP-bound and " +
                    "no proof came with it.");
          errorCodes.mark(res, 'STS-OAUTH-0204');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'The authorization request bound this code to a DPoP key ' +
            '(dpop_jkt), so the Token Request must carry a DPoP proof from ' +
            'that key.');
        }
        if (record.dpop_jkt !== dpopJkt) {
          log.debug("Leaving the token endpoint. The code's dpop_jkt does " +
                    "not match the proof.");
          errorCodes.mark(res, 'STS-OAUTH-0205');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'This authorization code is bound to DPoP key ' + record.dpop_jkt +
            ', but the proof was signed by ' + dpopJkt + '.');
        }
        log.debug("The authorization code's dpop_jkt matches the proof. jkt=" +
                  dpopJkt);
      }
      // RFC 8707 section 2.2: the Token Request may name a resource, and it may
      // only be one the authorization request already asked for. Widening here
      // would let a client award itself an audience the End-User never
      // approved, which is the same escalation the refresh grant's scope check
      // refuses one step later. The parameter itself was read and validated
      // above, for every grant; what is left here is the RULE, which is this
      // grant's alone.
      const granted = record.resources || [];
      const narrowed = requestedResources.filter(function (one) {
        return granted.indexOf(one) >= 0;
      });
      if (requestedResources.length &&
          narrowed.length !== requestedResources.length) {
        const extra = requestedResources.filter(function (one) {
          return granted.indexOf(one) < 0;
        });
        log.debug("Leaving the token endpoint. The Token Request asked for a " +
                  "resource the code does not carry.");
        errorCodes.mark(res, 'STS-OAUTH-0206');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_target',
          'RFC 8707 section 2.2: a Token Request may narrow the resources ' +
          'the authorization request asked for and may not add to them. This ' +
          'authorization code carries ' +
          (granted.length ? granted.join(', ') : 'no resource at all') + ', ' +
          'and the request asks additionally for: ' + extra.join(', ') + '.');
      }
      const forResources = narrowed.length ? narrowed : granted;
      // RFC 9396 section 6: details on the Token Request may narrow what the
      // authorization request authorized and may not add to it.
      const detailsProblem = requestedDetails
        ? richAuthorization.coveredProblem(requestedDetails,
                                           record.authorization_details)
        : '';
      if (detailsProblem) {
        log.debug("Leaving the token endpoint. The Token Request's details " +
                  "are not covered by the code.");
        errorCodes.mark(res, 'STS-OAUTH-0458');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_authorization_details',
                          detailsProblem);
      }
      // SPENT HERE, below every refusal and above the mint — see the block
      // above `refuseConcurrentRedemption()` (#46). The in-memory lookup at the
      // top of this branch stays as the fast refusal; this is the one that
      // holds when two requests found the record at once, on one node or two.
      const codeClaim = await clusterClaims.claim({
        scope: 'oauth.code', value: code, ttlMs: self.codeClaimTtlMs(record)
      });
      if (!codeClaim.ok) {
        log.debug("Leaving OAuth2Server.tokenGrant(). The code's claim was " +
                  "refused.");
        return self.refuseConcurrentRedemption(res, code, fingerprint, respond,
                                          codeClaim);
      }
      // Kept when the response is 2xx; given back otherwise, because a code
      // whose tokens were never issued has not been used.
      clusterClaims.releaseUnlessSucceeded(res, codeClaim.handle);
      const issued = await issue({
        jkt: dpopJkt,
        // One value where there is one, an array where the client asked for the
        // "small set" section 2.3 allows. `aud` takes either, and a
        // single-element array is a shape some libraries read differently from
        // a string — so the ordinary case stays a string.
        audience: forResources.length
          ? (forResources.length === 1 ? forResources[0] : forResources) :
                  undefined,
        // Onto the refresh token as well as into the access token's audience,
        // so that a refresh cannot widen what this grant authorized.
        resources: forResources,
        user: record.user, client_id: record.client_id, scope: record.scope,
        nonce: record.nonce, auth_time: record.auth_time, amr: record.amr,
        acr: record.acr,
        // Off the code, which carried it from the authorization endpoint. This
        // is the ordinary case: most tokens this service issues belong to a
        // sign-on session and only arrive at the console as belonging to one
        // because of this line.
        session_id: record.session_id || '', grant: 'authorization_code',
        // Off the code too, and for the same reason as the line above it: the
        // person is not here and their session cannot be looked up from a
        // back-channel request, so what the role gate is told about them is
        // what was true when the code was minted. `!== false` keeps a code
        // minted by an older process — one whose records have no such field —
        // meaning what it meant, which is that somebody authenticated.
        sessionAuthenticated: record.session_authenticated !== false,
        authorization_details: grantIdentifiers(requestedDetails
          ? richAuthorization.narrow(requestedDetails,
                                     record.authorization_details)
          : record.authorization_details, record.user),
        // The whole grant onto the refresh token, where the request narrowed.
        grantAuthorizationDetails:
          grantIdentifiers(record.authorization_details, record.user),
        // Off the code as well. What the client asked for at the authorization
        // endpoint is what the UserInfo endpoint honours, and the access token
        // is the only thing that reaches it.
        claims: record.claims || null
      });
      // Single use — and remembered as used, with what it bought, so that the
      // same request arriving again gets that answer back instead of a sentence
      // about a code nobody can look up any more.
      authzCodes.delete(code);
      self.rememberRedemption(code, record, fingerprint, issued);
      // The transaction this code_challenge and this nonce belonged to is over,
      // so presenting either of them at the authorization endpoint again is a
      // second transaction reusing a first one's value rather than this one
      // being retried. Told from the CODE's record and not from the request
      // body: what was authorized is the fact, and what a Token Request claims
      // is not.
      bcp.noteRedeemed(record);
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return respond(issued);
    }

    // OID4VCI's pre-authorized code grant (Appendix H.2 / H.3, RFC-registered
    // as urn:ietf:params:oauth:grant-type:pre-authorized_code). No
    // authorization request happened: the End-User was identified out of band
    // and the code in the Credential Offer is the authorization. When the offer
    // said a Transaction Code is required, the wallet must present the one the
    // End-User read off the issuer's screen.
    if (grant === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      const code = String(body['pre-authorized_code'] || '');
      const record = preAuthorizedCodes.get(code);
      if (!record) {
        log.debug("Leaving the token endpoint. The grant was refused.");
        errorCodes.mark(res, 'STS-OAUTH-0207');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
                               'Unknown or already-used ' +
                               'pre-authorized code.');
      }
      if (record.expires < Date.now()) {
        preAuthorizedCodes.delete(code);
        log.debug("Leaving the token endpoint. The grant was refused.");
        errorCodes.mark(res, 'STS-OAUTH-0208');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
                               'The pre-authorized code ' +
                               'has expired.');
      }
      // THE COMPARISON AND THE ATTEMPT COUNT ARE `vc_offers.js`'s (2026-09-12),
      // because that module owns the record they write to: constant time in
      // both modes, and in product the wrong code that reaches
      // `oid4vci.txCodeMaxAttempts` spends the pre-authorized code. What a
      // refusal says stays here, where the response is. ASYNCHRONOUS since
      // 2026-09-14: a wrong code is counted in the cluster claim store (#46).
      const tx = await checkTxCode(code, record, body.tx_code);
      if (!tx.ok) {
        if (tx.store) {
          log.debug("Leaving the token endpoint. The tx_code attempt could " +
                    "not be counted.");
          errorCodes.mark(res, 'STS-VC-0051');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'The Transaction Code could not be checked against this ' +
            'pre-authorized code\'s attempt limit. Try again shortly.');
        }
        if (tx.missing) {
          log.debug("Leaving the token endpoint. The grant was refused: no " +
                    "tx_code.");
          errorCodes.mark(res, 'STS-OAUTH-0209');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'This pre-authorized code requires the Transaction Code shown by ' +
            'the issuer (tx_code).');
        }
        log.debug("Leaving the token endpoint. The grant was refused: the " +
                  "tx_code is wrong.");
        if (tx.spent) {
          errorCodes.mark(res, 'STS-OAUTH-0210');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'The Transaction Code is not correct, and that was the last ' +
            'attempt this pre-authorized code allowed ' +
            '(oid4vci.txCodeMaxAttempts), so the code has been spent. Ask ' +
            'the issuer for a new Credential Offer.');
        }
        errorCodes.mark(res, 'STS-OAUTH-0211');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant', 'The Transaction ' +
                                                     'Code is not correct.' +
          (tx.attemptsLeft !== undefined
            ? ' ' + tx.attemptsLeft + ' attempt(s) remain before this ' +
                                      'pre-authorized code is spent.'
            : ''));
      }
      // Single use, like an authorization code — and across the cluster since
      // 2026-09-14 (#46): the delete is this process's, the claim is every
      // node's. `vc_offers.spendPreAuthorizedCode()` argues it.
      preAuthorizedCodes.delete(code);
      const preAuthSpent = await spendPreAuthorizedCode(code, record);
      if (!preAuthSpent.ok) {
        log.debug("Leaving the token endpoint. The pre-authorized code was " +
                  "refused at its spend.");
        // STS-VC-0049 (redeemed elsewhere) or STS-VC-0051 (the store).
        errorCodes.mark(res, preAuthSpent.errorCode);
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
                               preAuthSpent.description);
      }
      // The End-User was identified out of band, so there is a subject and no
      // sign-on session — and the users page has to be able to say that
      // difference rather than report a missing session as an unknown one.
      stats.recordAuthentication({
        presented: (record.user && record.user.username) || '',
        protocol: 'OpenID4VCI',
        method: 'pre-authorized code' + (record.txCode ? ' ' +
            'with a Transaction Code' : ''),
        sub: (record.user && record.user.sub) || '',
        client_id: client.client_id,
        note: 'Identified out of band when the Credential Offer was made; no ' +
              'browser session exists.'
      });
      // OID4VCI section 6.1.1: the Wallet MAY send authorization_details in the
      // Token Request, in the Pre-Authorized Code Flow as well as the
      // Authorization Code one — and here it is the ONLY place it can, because
      // this flow has no authorization request to have sent them in. That is
      // what lets a cross-device or deferred issuance ask for a subset of the
      // claims.
      const askedFor =
        self.parseAuthorizationDetails(body.authorization_details);
      if (askedFor.error) {
        log.debug("Leaving the token endpoint. " + askedFor.error);
        errorCodes.mark(res, 'STS-OAUTH-0153');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_authorization_details',
                          askedFor.error);
      }
      // What the OFFER was for bounds what the Token Request may ask for: the
      // pre-authorized code authorizes those credentials and no others, so a
      // request naming a different configuration is asking for something nobody
      // ever offered.
      const offered = record.configurationIds || [];
      const notOffered = (askedFor.details || []).filter(function (d) {
        return offered.indexOf(d.credential_configuration_id) === -1;
      });
      if (notOffered.length) {
        log.debug("Leaving the token endpoint. The details name a " +
                  "configuration the offer did not.");
        errorCodes.mark(res, 'STS-OAUTH-0212');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_authorization_details',
          'this Credential Offer is for ' + offered.join(', ') + ', so ' +
          notOffered.map(function (d) {
            return '"' + d.credential_configuration_id + '"';
          }).join(', ') +
          ' cannot be authorized by it.');
      }
      const issued = await issue({
        jkt: dpopJkt,
        user: record.user, client_id: client.client_id, scope: VCI_SCOPE,
        withRefresh: false,
        // RFC 8707 on an OpenID4VCI Token Request, which OID4VCI section 6.1
        // inherits from RFC 6749 along with everything else about this
        // endpoint. A wallet that sends it gets a token the CREDENTIAL endpoint
        // will refuse — `presentedAccessToken()` guards that endpoint too — and
        // that is the parameter working rather than failing: the same is
        // already true of the authorization code flow, and a grant that read
        // the parameter and threw it away would be the bug this closes.
        audience: self.audienceClaim(requestedResources),
        grant: 'pre-authorized code',
        authorization_details: grantIdentifiers(askedFor.details, record.user)
      });
      // Remember which access token belongs to a deferred issuance, so the
      // credential endpoint knows to answer 202 rather than a credential.
      if (record.deferred) {
        deferredAccessTokens.add(issued.access_token);
        log.debug("This access token belongs to a DEFERRED issuance.");
      }
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return respond(issued);
    }

    if (grant === 'refresh_token') {
      let claims;
      try {
        // DECRYPTED FIRST, then verified exactly as it always was. `open()`
        // refuses an unencrypted refresh token outright — this service no
        // longer issues one — and names the condition in its message.
        // Any generation of this realm's key (#42): a refresh token outlives
        // a rotation, and verifies against the key that signed it until that
        // key's grace ends.
        claims = helpers.verifyOwnJws(refreshTokenCrypto.open(
            String(body.refresh_token || '')));
      } catch (e) {
        const refreshCode = errorCodes.codeOf(e) || 'STS-OAUTH-0213';
        log.error(errorCodes.tag(refreshCode) +
                  'the refresh token is not valid: ' + e.message);
        log.debug("Leaving the token endpoint. The grant was refused.");
        errorCodes.mark(res, errorCodes.codeOf(e) || 'STS-OAUTH-0213');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
                               'The refresh token is not ' +
                               'valid: ' + e.message);
      }
      // RFC 9700 section 2.2.2, ABOVE the revocation check and deliberately so.
      // Rotation revokes the token it retires, so a replayed one is also a
      // revoked one — and answering it with "the refresh token was revoked"
      // would be accurate and silent about the fact that a copy of the chain is
      // in circulation. This check knows the difference; the one below cannot.
      //
      // It also covers the two things this grant never checked: that the client
      // presenting the token is the client it was issued to, and that the scope
      // asked for is not wider than the scope granted.
      const refreshCheck = bcp.checkRefreshRequest({
        claims: claims, body: body, clientId: String(client.client_id || '')
      });
      if (!refreshCheck.ok) {
        // The family, revoked HERE rather than inside the check: that module
        // decides and this one acts, and `stats.revoke()` is the one revocation
        // set /oauth2/revoke and the console write to as well. A second set
        // would look correct alone and never see the others.
        (refreshCheck.revoke || []).forEach(function (jti) {
          stats.revoke(jti,
                       'RFC 9700 section 2.2.2: a replayed refresh token ' +
                       'revoked its family');
        });
        // AND BY ID (#46): a child minted on another node in the same instant
        // is in no list here, and is refused at its first use instead.
        if (refreshCheck.family) {
          await bcp.revokeFamily(refreshCheck.family, refreshCheck.clientId);
        }
        log.debug("Leaving the token endpoint. RFC 9700 mode refused the " +
                  "refresh (" +
                  refreshCheck.requirement + ").");
        errorCodes.mark(res, refreshCheck.errorCode || 'STS-OAUTH-0158');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, refreshCheck.error,
                               refreshCheck.description);
      }
      if (stats.isRevoked(claims.jti)) {
        errorCodes.mark(res, 'STS-OAUTH-0214');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
                               'The refresh token was ' +
                               'revoked.');
      }
      // -------------------------------------------------------------------
      // AN ONLINE REFRESH TOKEN ENDS WITH ITS SESSION (#118, OIDC Core
      // section 11). Only `offline_access` asks for access "even when the
      // End-User is not present"; a refresh token granted without it is
      // tied to the sign-on session it came from, and once that session has
      // been signed out of, expired or gone idle it is refused. A refresh
      // token from a grant with no person behind it names no session and is
      // not affected.
      // -------------------------------------------------------------------
      const grantSession = String(claims.sid || '');
      if (grantSession && !hasScope(claims.scope, 'offline_access')) {
        const held = authn.sessionById(grantSession);
        const ended = held ? authn.sessionEnded(held) : 'ended';
        if (ended) {
          log.debug("Leaving the token endpoint. An online refresh token " +
                    "whose session has " + ended + ".");
          errorCodes.mark(res, 'STS-OAUTH-0568');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'This refresh token was granted without offline_access, so it ' +
            'lasts only as long as the sign-on session it came from, and ' +
            'that session has ' + (ended === 'ended' ? 'ended' : ended) +
            '. Ask for offline_access with prompt=consent for access while ' +
            'the person is not signed in (OIDC Core section 11).');
        }
      }
      // RFC 9449 section 5: a bound refresh token may only be redeemed by its
      // own key. Without this the refresh token would be a bearer credential
      // that mints bound access tokens for whoever holds it — which is worse
      // than not binding at all, because the token_type would say `DPoP` and
      // imply a guarantee that was never checked.
      const boundTo = dpop.jktOf(claims);
      if (boundTo) {
        if (!dpopJkt) {
          log.debug("Leaving the token endpoint. The refresh token is bound " +
                    "and no proof came.");
          errorCodes.mark(res, 'STS-OAUTH-0215');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'This refresh token is bound to a DPoP key, so the Token Request ' +
            'must carry a DPoP proof from that key.');
        }
        if (boundTo !== dpopJkt) {
          log.debug("Leaving the token endpoint. The refresh token's cnf.jkt " +
                    "does not match.");
          errorCodes.mark(res, 'STS-OAUTH-0216');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'This refresh token is bound to DPoP key ' + boundTo +
            ', but the proof was signed by ' + dpopJkt + '.');
        }
      }
      // RFC 8705 section 3.1, the same rule for the other constraint: a refresh
      // token bound to a client certificate may only be redeemed on a
      // connection made with it. Without this the long-lived half of a
      // certificate-bound grant would be a bearer credential that mints bound
      // tokens for whoever holds it — worse than not binding at all, because
      // the cnf on what it mints would imply a guarantee nobody checked. `true`
      // because the token's signature was verified two lines above.
      //
      // EXCEPT FOR A CLIENT THAT AUTHENTICATED BY CERTIFICATE ON THIS REQUEST
      // (2026-09-13). RFC 8705 section 7.1: its refresh token is bound through
      // that authentication, so it may present a NEW certificate — the one its
      // old one expired into (section 6.3) — and the tokens minted below bind
      // to the new one. `mtls.refreshBindingApplies()` is the rule.
      const refreshBound = mtls.refreshBindingApplies(
        clientObservation, claims, String(client.client_id || ''));
      const certificateProblem = refreshBound
        ? mtls.checkBinding(claims, req, true, 'refresh token')
        : null;
      if (!refreshBound && mtls.boundThumbprintOf(claims)) {
        log.info('RFC 8705 section 7.1: the refresh token is bound to ' +
                 'certificate ' + mtls.boundThumbprintOf(claims) +
                 ' and client ' +
                 '"' + String(client.client_id || '') + '" authenticated by ' +
                 clientObservation.method + ' on this request, so the ' +
                 'binding is through that authentication and the ' +
                 'certificate on this connection (' +
                 (mtls.presentedThumbprint(req) || 'none') +
                 ') is what the new tokens are bound to.');
      }
      if (certificateProblem) {
        log.debug("Leaving the token endpoint. The refresh token's " +
                  "certificate binding did not hold.");
        errorCodes.mark(res, certificateProblem.errorCode || 'STS-OAUTH-0092');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
                          certificateProblem.description);
      }
      // #34 (2026-09-15): the two settings that ask for MORE than either
      // specification does. The four checks above refuse a BOUND token
      // presented without its key; these refuse an UNBOUND one, which is the
      // case those cannot see — and which is the whole of what an operator
      // turning `oauth2.refreshTokenRequireDpop` or
      // `oauth2.refreshTokenRequireMtls` on is asking about. Neither binds the
      // token here: see the argument above `refreshRedemptionRefusal()`.
      const constraintProblem = senderConstraints.refreshRedemptionRefusal({
        tokenJkt: boundTo,
        provedJkt: dpopJkt,
        tokenThumbprint: mtls.boundThumbprintOf(claims),
        certificate: !!mtls.peerCertificate(req),
        certificateVerified: mtls.peerVerified(req),
        // RFC 8705 section 7.1 again, read off the same decision the binding
        // check above made: `refreshBound` is false exactly when the client
        // authenticated by certificate on this request AND owns this token, and
        // that is the case section 7.1 says is bound through the client id. It
        // passes whether or not the token carries a thumbprint, which is the
        // point of the section — a client whose certificate expired presents
        // the new one.
        section71: !refreshBound,
        exempt: senderConstraints.mtlsExemptClient(client.client_id),
        mtlsAvailable: mtls.available()
      });
      if (constraintProblem) {
        log.debug("Leaving the token endpoint. A sender constraint refused " +
                  "the refresh.");
        errorCodes.mark(res, constraintProblem.errorCode);
        log.debug("Leaving OAuth2Server.tokenGrant().");
        // error-code: none — marked above with the refusal's own code, one of
        // STS-OAUTH-0523 to 0527.
        return self.oauthError(res, 400, constraintProblem.error,
                          constraintProblem.description);
      }
      // RFC 8707 again, one grant later: a refresh may NARROW the resources the
      // original authorization carried and may not add to them. Without this
      // the resource restriction would last exactly one token — which is the
      // same escalation the scope check refuses, and the reason the refresh
      // token carries `resources` at all.
      const grantedResources = Array.isArray(claims.resources) ?
                               claims.resources : [];
      const extraResources = requestedResources.filter(function (one) {
        return grantedResources.indexOf(one) < 0;
      });
      if (extraResources.length) {
        log.debug("Leaving the token endpoint. The refresh asked for a " +
                  "resource the grant does not carry.");
        errorCodes.mark(res, 'STS-OAUTH-0217');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_target',
          'RFC 9700 section 2.2.2: a refresh token is bound to the resource ' +
          'servers its grant was authorized for, and this one carries ' +
          (grantedResources.length ? grantedResources.join(', ') : 'no ' +
              'resource at all') +
          '. The request asks additionally for: ' + extraResources.join(', ') +
          '. A grant cannot widen itself by being renewed.');
      }
      const refreshResources = requestedResources.length
        ? requestedResources : grantedResources;
      // RFC 9396 section 6, one grant later: a refresh may narrow the details
      // the refresh token carries and may not add to them.
      const refreshDetailsProblem = requestedDetails
        ? richAuthorization.coveredProblem(requestedDetails,
                                           claims.authorization_details)
        : '';
      if (refreshDetailsProblem) {
        log.debug("Leaving the token endpoint. The refresh asked for details " +
                  "the grant does not carry.");
        errorCodes.mark(res, 'STS-OAUTH-0458');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_authorization_details',
                          refreshDetailsProblem);
      }

      const refreshedUser = self.refreshedPerson(claims);
      if (!refreshedUser) {
        log.info('oauth2: a refresh for "' + (claims.username || '') + '" ' +
                 'was refused: its subject names nobody in this directory ' +
                 'any more — the person was deleted, or deleted and ' +
                 're-created, which ' +
                 'is a different subject.');
        errorCodes.mark(res, 'STS-OAUTH-0511');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
          'The person this refresh token was issued for is no longer in this ' +
          'service\'s directory.');
      }
      // RFC 9700 section 2.2.2, ONCE ACROSS THE CLUSTER (#46): the presented
      // token is spent through a claim immediately before the mint, below every
      // refusal above, so a refused refresh spends nothing. A claim already
      // held is a replay that `checkRefreshRequest()`'s local mark could not
      // see — another request at the same moment, on this node or another. A
      // no-op while rotation is not required. See `bcp.spendRefreshToken()`.
      const spent = await bcp.spendRefreshToken({ claims: claims, res: res });
      if (!spent.ok) {
        (spent.revoke || []).forEach(function (jti) {
          stats.revoke(jti,
                       'RFC 9700 section 2.2.2: a replayed refresh token ' +
                       'revoked its family');
        });
        if (spent.errorCode === 'STS-OAUTH-0516' && spent.family) {
          await bcp.revokeFamily(spent.family, spent.clientId);
        }
        log.debug("Leaving the token endpoint. RFC 9700 mode refused the " +
                  "refresh at its claim (" + spent.requirement + ").");
        errorCodes.mark(res, spent.errorCode || 'STS-OAUTH-0518');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, spent.status || 400, spent.error,
                          spent.description);
      }
      const refreshed = await issue({
        // The presented token's jti, so the one it mints belongs to the same
        // FAMILY. Only this grant sets it; a root refresh token has none.
        parent_refresh_jti: claims.jti,
        // And the family its own token names, so a node that has not heard of
        // the parent still mints into the right family (#46).
        parent_refresh_family: claims[bcp.FAMILY_CLAIM] || '',
        // Carried forward, and narrowed where the request asked for less. The
        // AUDIENCE of the access token about to be minted comes from the same
        // list, so the two cannot come to describe different resource servers.
        resources: refreshResources,
        audience: refreshResources.length
          ? (refreshResources.length === 1 ? refreshResources[0] :
             refreshResources)
          : undefined,
        // The same reasoning applies to the OID4VCI half of the grant: the
        // credential_identifiers and the claims selection were authorized by
        // the authorization request this refresh token descends from, so an
        // access token that dropped them would refuse the very Credential
        // Request the section 14.5 refresh on step 4 exists to make — naming a
        // credential_identifier "that was not granted".
        authorization_details: requestedDetails
          ? richAuthorization.narrow(requestedDetails,
                                     claims.authorization_details)
          : claims.authorization_details,
        grantAuthorizationDetails: claims.authorization_details,
        // And the same for OIDC Core 5.5's claims request, for exactly the
        // reason above it: it was authorized by the authorization request this
        // refresh token descends from, so an access token that dropped it would
        // make the UserInfo response change under a client that did nothing but
        // renew.
        claims: claims.claims || null,
        // A refresh keeps whatever binding it had: re-binding to the key that
        // happens to have signed this request would let a stolen bound token be
        // laundered into one bound to the thief's key.
        jkt: boundTo || dpopJkt,
        user: refreshedUser, client_id: claims.client_id,
        scope: body.scope ? String(body.scope) : claims.scope,
        // What the PRESENTED refresh token carried, for the refresh token this
        // grant mints: the two values above narrow the access token only. See
        // the paragraph on refreshToken() in tokenSet() — RFC 6749 section 6.
        grantScope: claims.scope || '',
        grantResources: grantedResources,
        // The session the REFRESHED token came from, looked up by the refresh
        // token's own jti. Nothing on the wire carries it — a refresh token
        // names no session — so without this every second-generation token
        // would show as sessionless and a session's token list would stop
        // growing the moment a client refreshed.
        session_id: String(claims.sid || '') ||
                    stats.sessionIdOfJti(claims.jti),
        // Off the REGISTRY, by the same jti the session id comes from, and for
        // the identical reason: a refresh carries no cookie and no session
        // identifier, so what this grant can say about the person is what was
        // recorded when the token it is refreshing was minted. Without this an
        // unauthenticated session's tokens would come back authenticated on
        // their second generation.
        sessionAuthenticated: stats.sessionAuthenticatedOfJti(claims.jti),
        // OIDC Core section 12.2: the renewed ID Token describes the ORIGINAL
        // authentication, which the refresh token carries forward. See
        // refreshToken().
        auth_time: claims.auth_time || undefined,
        amr: Array.isArray(claims.amr) ? claims.amr : undefined,
        acr: claims.acr || undefined,
        grant: 'refresh_token'
      });
      // RFC 9700 section 2.2.2 — ROTATION. The token just redeemed is retired:
      // marked as rotated here (which is what makes a later presentation of it
      // a detectable REPLAY rather than an ordinary revocation) and revoked
      // through the one set every other revocation goes through, so it also
      // reports inactive at /oauth2/introspect.
      //
      // After the new token set exists, not before: a failure between the two
      // would otherwise leave a client with no working refresh token and
      // nothing to show for it. Neither runs while rotation is not required,
      // which is what keeps a refresh token reusable for the whole of its life
      // by default — `oauth2.refreshTokenTtlS`, twenty-four hours unless it has
      // been changed.
      //
      // ASKED OF `rotationRequired()`, NOT `enabled()` (fixed 2026-09-16): with
      // `oauth2.refreshTokenRotation` on and neither mode, this was skipped, so
      // a redeemed token still introspected as active and its replay was never
      // detected as one (STS-OAUTH-0138) — rotation without the half rule 3ao
      // says it is for.
      if (bcp.rotationRequired()) {
        bcp.noteRefreshRotated(claims.jti);
        stats.revoke(claims.jti, 'RFC 9700 section 2.2.2: rotated on use');
      }
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return respond(refreshed);
    }

    if (grant === 'client_credentials') {
      // No user is involved, so no refresh token and no ID token.
      //
      // It is recorded on the users page all the same, flagged as a CLIENT
      // rather than a person. Leaving it out would be tidier and wrong: these
      // tokens have a subject and appear in the tokens table, so a users page
      // that did not know the name would be a second page of one console
      // contradicting the first.
      stats.recordAuthentication({
        presented: client.client_id || 'unknown-client',
        protocol: 'OAuth 2.0', method: 'client_credentials', isClient: true,
        sub: client.client_id || 'unknown-client', client_id: client.client_id,
        // WHAT WAS CHECKED is the observation above, not an assumption: the
        // note said "no secret was checked" in every mode, which product mode
        // (RFC 9700) made false for every confidential client.
        note: 'A client authenticating as itself. No human and no browser is ' +
              'behind this token, and ' +
              (clientObservation.authenticated
                ? 'its credential (' +
                  (clientObservation.method || 'client authentication') +
                  ') was verified.'
                : 'no client credential was verified.')
      });
      // ---------------------------------------------------------------------
      // RFC 9700 section 4.13 — A CLIENT IS NOT A RESOURCE OWNER, and the token
      // has to let a resource server tell them apart.
      //
      // The `sub` of a client_credentials token was the bare client_id while a
      // person's was `urn:sts:user:<name>` (`urn:uuid:<entryUUID>` since
      // 2026-09-14). Different in practice and not by any rule: nothing stopped
      // a client registering an id that looked like a subject, and a resource
      // server keying on `sub` alone had no way to know which kind of thing it
      // was holding. That is the collision the section is about, and the MUST
      // beside it asks for "another mechanism allowing resource servers to
      // distinguish client credentials from resource-owner credentials".
      //
      // There is one such mechanism in each mode, and they are different in
      // kind — `client-subject-separated` in `oauth2_bcp.js` states both:
      //
      //   * WITH THE MODE OFF, `sub` EQUALS `client_id`. True of a
      //     client_credentials token and of nothing else here, and it needs no
      //     invented claim and no convention a resource server has to be told
      //     about — RFC 9700 suggests this comparison itself.
      //   * IN RFC 9700 MODE, A SEPARATE NAMESPACE. `urn:sts:client:<id>`
      //     beside a person's `urn:uuid:<entryUUID>` — two forms that cannot
      //     collide however a client is named, which is what the SHOULD asks
      //     for. `sub` then no longer equals `client_id`, so a resource server
      //     written against the comparison must read the prefix instead.
      //
      // The namespace is mode-gated because it changes the `sub` of every
      // client_credentials token, and a subject identifier is something callers
      // key on.
      // ---------------------------------------------------------------------
      const clientSubject = bcp.enabled()
        ? 'urn:sts:client:' + (client.client_id || 'unknown-client')
        : (client.client_id || 'unknown-client');
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return respond(await issue({
        jkt: dpopJkt,
        sub: clientSubject, username: client.client_id,
        client_id: client.client_id, scope: String(body.scope || ''),
        withRefresh: false,
        // RFC 8707, read above for every grant. Nothing preceded this request,
        // so what was asked for is what is granted — there is no earlier
        // decision for a narrowing rule to be about. No `resources` beside it
        // because this grant issues no refresh token: that field exists so a
        // renewal cannot widen, and nothing here can be renewed.
        audience: self.audienceClaim(requestedResources),
        // RFC 9396: nothing preceded this request either, so the details asked
        // for are the details granted.
        authorization_details: grantIdentifiers(requestedDetails,
                                                userFor(client.client_id)),
        grant: 'client_credentials',
        user: Object.assign(userFor(client.client_id), { sub: clientSubject })
      }));
    }

    if (grant === 'password') {
      const username = String(body.username || '');
      if (!username || !body.password) {
        log.debug("Leaving the token endpoint. The grant was refused.");
        errorCodes.mark(res, 'STS-OAUTH-0218');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_request',
                               'username and password ' +
                                                       'are required.');
      }
      // -----------------------------------------------------------------------
      // THE PASSWORD IS VERIFIED THROUGH `common/credentials.ts` (2026-09-12),
      // AND UNTIL THEN IT WAS NOT VERIFIED AT ALL, IN EITHER MODE.
      //
      // This branch refused the literal string `invalid` and accepted
      // everything else — which was the development-mode contract written out
      // by hand, and product mode inherited it unchanged. So a product
      // deployment that verified every password at the sign-in screen, the LDAP
      // bind, WS-Trust and SCIM Basic handed an access token and a refresh
      // token to ANYBODY who named a person at this endpoint. It was the one
      // door onto an account that `mode.verifiesCredentials()` did not reach.
      //
      // **DEVELOPMENT IS UNCHANGED BY CONSTRUCTION RATHER THAN BY A BRANCH.**
      // `verifyAsync()` refuses the reserved password `invalid` in both modes
      // and answers yes to everything else while nothing is verified, which is
      // exactly what the two lines this replaced did — so there is one
      // statement of "when does this service say no" rather than a second copy
      // here.
      //
      // THE ASYNC DOOR, because this handler already awaits and a scrypt
      // comparison is 68ms on the only thread this process has.
      //
      // THREE PRODUCT-MODE REFUSALS SIT AROUND IT, all behind the predicate
      // that names the question (`verifiesCredentials()`) and none of them
      // reachable in development:
      //
      //   * THE RATE LIMIT the sign-in screen applies, in the SAME bucket,
      //     keyed on the same identity. A limit on the screen and none here
      //     would be a brute-force door that happened to speak JSON.
      //   * A PERSON WHO HOLDS A SECOND FACTOR IS REFUSED. The grant has
      //     nowhere to carry one — RFC 6749 section 4.3 is a username and a
      //     password and nothing else — so issuing would sign them in with one
      //     factor while their account says two, which is `mfaRequired` meaning
      //     nothing at the one endpoint nobody thinks to look at. The refusal
      //     says which door to use instead.
      //   * Every refusal is the ONE protocol answer — `invalid_grant`,
      //     "Authentication failed for user X." — whatever the reason, because
      //     telling a caller that a person exists but the password is wrong is
      //     the account-enumeration answer. The reason goes to the log, which
      //     is `credentials.js`'s own rule about its `detail`.
      // -----------------------------------------------------------------------
      if (mode.verifiesCredentials()) {
        // One budget for the cluster (#46), the sign-in screen's own bucket.
        const allowed = await websecurity.attemptShared('sign-in', req,
                                                        username);
        if (!allowed.ok) {
          log.warn('oauth2: too many password-grant attempts for "' + username +
                   '" (' + allowed.kind + ' bucket). Refusing for ' +
                   allowed.retryAfterS + 's.');
          res.set('Retry-After', String(allowed.retryAfterS));
          log.debug("Leaving the token endpoint. The password grant was rate " +
                    "limited.");
          errorCodes.mark(res, 'STS-OAUTH-0219');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant', allowed.detail);
        }
      }
      const credential = await credentials.verifyAsync(username,
        String(body.password),
        { via: 'the OAuth 2.0 password grant' });
      if (!credential.ok) {
        log.info('oauth2: the password grant for "' + username +
                 '" was refused (' +
                 credential.reason + '): ' + credential.detail);
        log.debug("Leaving the token endpoint. The grant was refused.");
        errorCodes.mark(res, 'STS-OAUTH-0220');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant', 'Authentication ' +
                                                     'failed for ' +
                                                     'user ' + username + '.');
      }
      if (mode.verifiesCredentials()) {
        const held = credentials.mechanismsFor(username);
        if (held.mfaRequired) {
          log.warn('oauth2: the password grant for "' + username + '" was ' +
                   'refused: that person holds a second factor ' +
                   '(' + held.secondFactor + ') ' +
                   'and the password grant cannot carry one.');
          log.debug("Leaving the token endpoint. A second factor is required.");
          errorCodes.mark(res, 'STS-OAUTH-0221');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_grant',
            'Authentication failed for user ' + username + '. This account ' +
            'requires a second factor, which the password grant cannot ' +
            'carry; use the authorization code flow, whose sign-in screen ' +
            'asks for it.');
        }
        await websecurity.succeededShared('sign-in', req, username);
      }
      // A password grant is an authentication: the credential was presented
      // here, to this endpoint, and this is where it succeeded. No session is
      // created — the grant exists for clients that cannot open a browser — so
      // the tokens below belong to a person and to no session, which is a shape
      // the users page shows.
      stats.recordAuthentication({
        presented: username, protocol: 'OAuth 2.0', method: 'password grant ' +
            '(RFC 6749 section 4.3)',
        client_id: client.client_id,
        note: credential.reason === 'verified'
          ? 'The password was verified against the stored userPassword. ' +
            'A password grant creates no browser session.'
          : 'No password is checked here either, except the reserved string ' +
            '"invalid". A password grant creates no browser session.'
      });
      const passwordUser = self.provisionedPerson(username);
      if (!passwordUser) {
        errorCodes.mark(res, 'STS-OAUTH-0510');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant',
                               'There is no directory ' +
          'entry for ' + username +
            ', so there is no subject to issue a token ' +
          'about; the person has to be provisioned first.');
      }
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return respond(await issue({
        jkt: dpopJkt,
        user: passwordUser, client_id: client.client_id,
        scope: String(body.scope || 'openid'),
        // RFC 8707 again. This grant DOES issue a refresh token, so the list
        // goes onto it as well — section 2.2.2's rule that a grant cannot widen
        // itself by being renewed applies here exactly as it does to a code,
        // and the refresh branch above reads `claims.resources` without caring
        // which grant wrote it.
        audience: self.audienceClaim(requestedResources),
        resources: requestedResources,
        authorization_details: grantIdentifiers(requestedDetails,
                                                passwordUser),
        grant: 'password'
      }));
    }

    // -------------------------------------------------------------------------
    // RFC 7521 AND RFC 7523 SECTION 2.1 — THE JWT BEARER AUTHORIZATION GRANT.
    //
    // A trusted party signs a document saying *this person is alice, and I am
    // giving you this so you will issue a token for her*, and this
    // authorization server issues one. There is no browser, no password and no
    // consent step anywhere in it, so the signature is the whole of the grant's
    // security — which is why `assertion_grant.js` refuses an issuer nobody
    // declared and why that refusal is ON by default, alone here with
    // federation's.
    //
    // **THE VERIFICATION IS `assertion_grant.js`'s AND THE RESPONSE IS THIS
    // MODULE'S**, which is the split every library in this directory has: that
    // module never touches `res`, and what a refusal LOOKS like is protocol
    // knowledge that stays where there is a response object.
    // -------------------------------------------------------------------------
    if (grant === assertionGrant.GRANT_TYPE) {
      const checked = await assertionGrant.verify({
        assertion: String(body.assertion || ''),
        scope: String(body.scope || ''),
        // THE CLIENT SECRET, for the symmetric encryption algorithms only. An
        // assertion encrypted `A256KW` or `dir` is encrypted under the one key
        // this service and a client both hold, and there is no other candidate
        // — an RSA-OAEP one is decrypted with this realm's own key and this is
        // ignored. It is `clientConfigOf()`'s value rather than what the
        // request presented: the point is what the CLIENT holds, and a caller
        // that could supply the decryption key would be handing this service a
        // document and the key to read it.
        clientSecret: (applications.clientConfigOf(client.client_id) || {})
          .client_secret,
        // RFC 7521 section 5.2 (5). The same three this service accepts on a
        // client assertion, for the same reason: RFC 7523 section 3 names the
        // token endpoint and OpenID Connect Core section 9 names the ISSUER,
        // and deployments differ — so both are accepted rather than half the
        // client libraries in the world being refused.
        audiences: [base + '/oauth2/token', self.issuerOf(base), base],
        // THE RESPONSE THIS GRANT IS ANSWERED ON, so that the assertion is
        // spent in the used-assertion history only if tokens are issued — a
        // refusal further down this branch releases it. And the client asking,
        // for the history's row.
        request: req,
        requestingClientId: String(client.client_id || '')
      });
      if (!checked.ok) {
        log.debug("Leaving the token endpoint. The assertion was refused.");
        errorCodes.mark(res, checked.errorCode || 'STS-OAUTH-0222');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, checked.error, checked.description);
      }
      // The subject is a PERSON, named by somebody this service trusts, and
      // need not be anybody it has heard of before — recording the
      // authentication creates their entry exactly as typing the name at the
      // sign-in screen does (`provisionedPerson()` below). That is the
      // permissiveness this service keeps everywhere: what is real here is the
      // SIGNATURE, and `assertion_grant.js`'s header says which half is which.
      stats.recordAuthentication({
        presented: checked.subject,
        protocol: 'OAuth 2.0',
        method: 'RFC 7523 JWT bearer assertion' +
                (checked.encrypted ? ' (encrypted)' : ''),
        client_id: client.client_id,
        note: (checked.issuerKind === 'person'
                ? 'This person asserted THEMSELVES, with a signing key pair ' +
                  'this service issued to them. '
                : 'A trusted party asserted this person. ') +
              'The ASSERTION was verified ' +
              'for real — signature, issuer, audience, expiry and a jti that ' +
              'cannot be replayed — against a key registered for "' +
              checked.issuer + '"' +
              (checked.keySource === 'x5c'
                ? ', presented as a certificate chain this service issued'
                : '') + '. No password was checked and no browser was ' +
              'involved: this grant has neither.'
      });
      // THE PERSON, NOW THAT RECORDING THE AUTHENTICATION HAS CREATED THEIR
      // ENTRY (2026-09-14) — and a refusal where the directory declined to.
      const subject = self.provisionedPerson(checked.subject);
      if (!subject) {
        errorCodes.mark(res, 'STS-OAUTH-0510');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant', 'There is no ' +
          'directory entry for the assertion\'s subject, so there is no ' +
          'subject to issue ' +
          'a token about; the person has to be provisioned first.');
      }
      // RFC 7523 section 3 claim 8: an assertion MAY carry other claims. They
      // go onto the token, which is the only useful thing an authorization
      // server can do with a statement a trusted party made about somebody —
      // and the protocol's own claims are stripped first, because an `exp`
      // copied off an assertion would be a token lifetime chosen by whoever
      // signed it.
      const carried = assertionGrant.extraClaimsFrom(checked.claims);
      const issued = await issue({
        jkt: dpopJkt,
        user: subject,
        client_id: client.client_id,
        scope: checked.scope.join(' '),
        // RFC 8707, read above for every grant. Nothing preceded this request —
        // there was no authorization endpoint — so what is asked for is
        // granted, exactly as for the client credentials and password grants.
        audience: self.audienceClaim(requestedResources),
        resources: requestedResources,
        assertionClaims: carried,
        authorization_details: grantIdentifiers(requestedDetails, subject),
        grant: assertionGrant.GRANT_TYPE
      });
      // THE ACT IS RECORDED AS A DELEGATION, because that is exactly what it
      // is: one party asked this service to issue a credential in ANOTHER
      // party's name. It is the third mechanism in that register's OAuth
      // family, beside the two shapes of RFC 8693, and it is drawn on
      // /admin/delegation with them.
      delegation.record({
        protocol: 'OAuth 2.0',
        type: 'oauth-assertion-grant',
        outcome: 'issued',
        initial: {
          presented: checked.subject,
          what: 'the subject of the assertion — the person this token is ' +
                'for. They authenticated at the ASSERTION ISSUER and not ' +
                'here; this service has never seen a credential of theirs.'
        },
        intermediary: {
          presented: checked.issuer,
          application: checked.application || checked.issuer,
          // **A PERSON WHO ASSERTED ABOUT THEMSELVES IS NOT A THIRD PARTY, AND
          // THIS SENTENCE IS THE ONLY PLACE THAT CAN SAY SO.** The register
          // draws one row with an initial, an intermediary and a target; with
          // the two halves being one person, an intermediary described as *the
          // party that signed the assertion* reads as somebody else having
          // vouched for them, which is the opposite of what happened. The row
          // is still drawn — the act IS an issuance somebody asked for — and it
          // says which of the two shapes of this grant it was.
          what: checked.issuerKind === 'person'
            ? 'the person who signed the assertion, which is the same person ' +
              'the token is for. They hold an RFC 7523 signing key pair of ' +
              'their own (stsAssertion* on their entry), and a person\'s key ' +
              'may only assert about that person — so this is somebody ' +
              'presenting themselves rather than one party vouching for ' +
              'another.'
            : (checked.declared
              ? 'the party that signed the assertion, declared on an ' +
                'application entry as oauthAssertionIssuer'
              : 'the party that signed the assertion. No application ' +
                'declares this issuer on oauthAssertionIssuer — it was ' +
                'resolved by its own client_id or identifier, or accepted on ' +
                'a certificate chain this service issued.')
        },
        target: {
          application: String(client.client_id || ''),
          what: client.client_id
            ? 'the client the token was handed to'
            : 'unstated — this request named no client, which RFC 7521 ' +
              'section 6.2 permits when the assertion identifies the party'
        },
        authorizedBy: checked.declared
          ? 'oauthAssertionIssuer on an application entry in this realm, and ' +
            'a signature that verified against a key registered for it. This ' +
            'is one of only two things in this service that refuse by ' +
            'default — an assertion IS the whole authorization, so accepting ' +
            'one from anybody would mean anybody who can reach this port ' +
            'getting a token as anybody.'
          : 'a signature that verified against a key this service holds for "' +
            checked.issuer + '". No application DECLARES that issuer, which ' +
            'means either oauth2.jwtBearerRequireRegisteredIssuer is off or ' +
            'the assertion carried a certificate chain this service issued.',
        consumed: [{
          kind: 'assertion',
          identifier: checked.jti,
          note: 'RFC 7523 section 2.1, signed ' + checked.alg +
                (checked.encrypted
                  ? ' and encrypted ' + checked.encryption.alg + '/' +
                    checked.encryption.enc
                  : '') + '. Its jti is remembered until it expires, so it ' +
                'cannot be presented twice.'
        }],
        produced: [{
          kind: 'access_token',
          identifier: self.jtiOf(issued.access_token),
          note: Object.keys(carried).length
            ? 'carries ' + Object.keys(carried).length +
              ' claim(s) copied off ' +
              'the assertion: ' + Object.keys(carried).join(', ')
            : 'carries nothing from the assertion beyond the subject'
        }],
        // No session, and that is a fact about this grant rather than a gap: a
        // party asserting on somebody's behalf has no browser anywhere in it.
        sessionId: ''
      });
      log.debug("Leaving the token endpoint. An RFC 7523 assertion grant.");
      return respond(issued);
    }

    // -------------------------------------------------------------------------
    // RFC 7521 AND RFC 7522 SECTION 2.1 — THE SAML 2.0 BEARER AUTHORIZATION
    // GRANT.
    //
    // The same shape as the branch above and a DIFFERENT document: a trusted
    // party signs a SAML 2.0 assertion saying *this person is alice, and I am
    // giving you this so you will issue a token for her*. There is no browser,
    // no password and no consent step in it either, so the signature is the
    // whole of the grant's security and `saml_assertion_grant.js` refuses an
    // Issuer nobody declared for the same reason its JWT sibling does.
    //
    // **THE TWO BRANCHES ARE NOT FACTORED TOGETHER AND SHOULD NOT BE.** What
    // they share is this module's half — mint a persona, issue, record a
    // delegation — and what differs is every sentence describing WHY, because
    // the two refusals cite different specifications and the two registers have
    // to say which document was spent. A shared branch would report an RFC 7522
    // grant as an RFC 7523 one on /admin/delegation, which is the one thing
    // that register exists not to do.
    // -------------------------------------------------------------------------
    if (grant === samlAssertionGrant.GRANT_TYPE) {
      const checked = await samlAssertionGrant.verify({
        assertion: String(body.assertion || ''),
        scope: String(body.scope || ''),
        // RFC 7522 section 3 item 2 names the token endpoint URL as an
        // acceptable Audience and item 5 names it as the Recipient. The SAME
        // THREE the JWT profile accepts, because the question — which
        // authorization server was this minted for — has the same three answers
        // here and a deployment that spells it as the issuer is not wrong.
        audiences: [base + '/oauth2/token', self.issuerOf(base), base],
        // As for the JWT profile above: spent only if tokens are issued. NOT
        // `clientId`, which would put this call in RFC 7522 section 2.2.
        request: req,
        requestingClientId: String(client.client_id || '')
      });
      if (!checked.ok) {
        log.debug("Leaving the token endpoint. The SAML assertion was " +
                  "refused.");
        errorCodes.mark(res, checked.errorCode || 'STS-OAUTH-0223');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, checked.error, checked.description);
      }
      // The subject is a PERSON, named by somebody this service trusts, and
      // need not be anybody it has heard of — exactly as for the JWT profile.
      stats.recordAuthentication({
        presented: checked.subject,
        protocol: 'OAuth 2.0',
        method: 'RFC 7522 SAML 2.0 bearer assertion' +
                (checked.encrypted ? ' (encrypted)' : ''),
        client_id: client.client_id,
        note: (checked.issuerKind === 'person'
                ? 'This person asserted THEMSELVES in a SAML 2.0 assertion, ' +
                  'signed with the RFC 7522 key pair on their own entry. '
                : 'A trusted party asserted this person in a SAML 2.0 ' +
                  'assertion. ') +
              'It was verified for real — the XML Signature over the ' +
              '<Assertion> itself, the Issuer, the AudienceRestriction, the ' +
              'bearer SubjectConfirmation and its Recipient, both ' +
              'NotOnOrAfter instants and an ID that cannot be replayed — ' +
              'against a certificate registered for "' + checked.issuer +
              '" under the ' +
              'RFC 7522 attributes. ' +
              (checked.directlyAuthenticated
                ? 'The assertion carries an <AuthnStatement>, so the issuer ' +
                  'is saying it authenticated this person itself (RFC 7522 ' +
                  'section 3 item 7).'
                : 'The assertion carries NO <AuthnStatement>, which section ' +
                  '3 item 7 uses to mean the client is acting autonomously ' +
                  'on this person\'s behalf rather than having watched them ' +
                  'sign in.') +
              ' No password was checked and no browser was involved: this ' +
              'grant has neither.'
      });
      // THE PERSON, NOW THAT RECORDING THE AUTHENTICATION HAS CREATED THEIR
      // ENTRY (2026-09-14) — and a refusal where the directory declined to.
      const subject = self.provisionedPerson(checked.subject);
      if (!subject) {
        errorCodes.mark(res, 'STS-OAUTH-0510');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_grant', 'There is no ' +
          'directory entry for the assertion\'s subject, so there is no ' +
          'subject to issue ' +
          'a token about; the person has to be provisioned first.');
      }
      // RFC 7522 section 3 item 8: other statements MAY be in the assertion.
      // Every attribute goes onto the token, which is the only useful thing an
      // authorization server can do with a statement a trusted party made — the
      // JWT profile's claim 8 treatment of the same thing. A single-valued SAML
      // attribute becomes a string and a multi-valued one stays a list.
      const carried = samlAssertionGrant.extraClaimsFrom(checked.attributes);
      const issued = await issue({
        jkt: dpopJkt,
        user: subject,
        client_id: client.client_id,
        scope: checked.scope.join(' '),
        // RFC 8707. Nothing preceded this request — there was no authorization
        // endpoint — so what is asked for is granted, as for every direct
        // grant.
        audience: self.audienceClaim(requestedResources),
        resources: requestedResources,
        assertionClaims: carried,
        authorization_details: grantIdentifiers(requestedDetails, subject),
        grant: samlAssertionGrant.GRANT_TYPE
      });
      // THE ACT IS RECORDED AS A DELEGATION, for the JWT grant's reason: one
      // party asked this service to issue a credential in ANOTHER party's name.
      // It is the FOURTH mechanism in that register's OAuth family.
      delegation.record({
        protocol: 'OAuth 2.0',
        type: 'oauth-saml-assertion-grant',
        outcome: 'issued',
        initial: {
          presented: checked.subject,
          what: 'the <Subject> of the assertion — the person this token is ' +
                'for. They authenticated at the ASSERTION ISSUER and not ' +
                'here; this service has never seen a credential of theirs.'
        },
        intermediary: {
          presented: checked.issuer,
          application: checked.application || checked.issuer,
          // A person who asserted about themselves is not a third party — the
          // JWT grant's sentence above, for this profile (2026-09-13).
          what: checked.issuerKind === 'person'
            ? 'the person who signed the assertion, which is the same person ' +
              'the token is for. They hold an RFC 7522 signing key pair of ' +
              'their own (stsSamlAssertion* on their entry), and a person\'s ' +
              'key may only assert about that person.'
            : checked.declared
            ? 'the party that signed the assertion, declared on an ' +
              'application entry as oauthSamlAssertionIssuer'
            : 'the party that signed the assertion. No application declares ' +
              'this Issuer on oauthSamlAssertionIssuer — it was resolved by ' +
              'its own client_id or identifier, which means ' +
              'oauth2.saml2BearerRequireRegisteredIssuer is off or the ' +
              'Issuer IS a client_id here.'
        },
        target: {
          application: String(client.client_id || ''),
          what: client.client_id
            ? 'the client the token was handed to'
            : 'unstated — this request named no client, which RFC 7521 ' +
              'section 6.2 permits when the assertion identifies the party'
        },
        authorizedBy: checked.issuerKind === 'person'
          ? 'an XML Signature that verified against the RFC 7522 certificate ' +
            'on "' + checked.person +
              '"\'s own entry, and a <Subject> naming ' +
            'that same person.'
          : checked.declared
          ? 'oauthSamlAssertionIssuer on an application entry in this realm, ' +
            'and an XML Signature that verified against a certificate ' +
            'registered for it under the RFC 7522 attributes. **The RFC 7523 ' +
            'key pair on the same application would not have done**: the two ' +
            'profiles hold separate key pairs and no verifier reads the ' +
            'other\'s.'
          : 'an XML Signature that verified against a certificate this ' +
            'service holds for "' + checked.issuer + '" under the RFC 7522 ' +
            'attributes. No application DECLARES that Issuer, which means ' +
            'either oauth2.saml2BearerRequireRegisteredIssuer is off or the ' +
            'Issuer is a client_id here.',
        consumed: [{
          kind: 'assertion',
          identifier: checked.id,
          note: 'RFC 7522 section 2.1, a SAML 2.0 <Assertion> signed ' +
                (checked.signatureMethod || 'with an XML Signature') +
                (checked.encrypted
                  ? ' and delivered as an <EncryptedAssertion> (' +
                    checked.encryption.algorithm + ')'
                  : '') + '. Its ID is remembered until it expires, so it ' +
                'cannot be presented twice.'
        }],
        produced: [{
          kind: 'access_token',
          identifier: self.jtiOf(issued.access_token),
          note: Object.keys(carried).length
            ? 'carries ' + Object.keys(carried).length + ' claim(s) copied ' +
              'off the assertion\'s AttributeStatement: ' +
              Object.keys(carried).join(', ')
            : 'carries nothing from the assertion beyond the subject'
        }],
        // No session, and that is a fact about this grant rather than a gap.
        sessionId: ''
      });
      log.debug("Leaving the token endpoint. An RFC 7522 assertion grant.");
      return respond(issued);
    }

    if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange') {
      const subjectToken = String(body.subject_token || '');
      if (!subjectToken) {
        errorCodes.mark(res, 'STS-OAUTH-0224');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_request',
                               'subject_token is ' +
                                                       'required.');
      }
      let subject: Json = {};
      // Whether this service is the one that authenticated the subject, or is
      // merely reading a name off somebody else's token. The users page has to
      // say which: a subject that arrived on an unverified token was never
      // authenticated HERE, and a console that listed the two the same way
      // would be claiming an authentication that never happened.
      let subjectVerified = true;
      // A refresh token presented as the subject is ENCRYPTED; open it first so
      // it is verified like any other token this service issued. One that will
      // not open falls to the unverified branch below, and reads as nothing.
      let subjectJws = subjectToken;
      if (refreshTokenCrypto.isEncrypted(subjectToken)) {
        try {
          subjectJws = refreshTokenCrypto.open(subjectToken);
        } catch (e) {
          log.debug("The subject_token is a JWE this realm cannot open: " +
                    e.message);
        }
      }
      // -----------------------------------------------------------------------
      // A TOKEN THAT DOES NOT VERIFY IS NOT EXCHANGED IN PRODUCT (2026-09-21).
      //
      // The subject_token is the WHOLE of what this grant asks for: there is
      // no browser, no password and no consent anywhere in it, so the token
      // that comes out is exactly as good as the check on the one that went
      // in. Development reads a token it cannot verify for its name and
      // exchanges it anyway, which is what lets a client under test drive the
      // grant with a token from any issuer. Product did the SAME until this
      // date — there was no mode check anywhere on the path — so any client
      // that could authenticate could write `{"sub": <anybody>}` into a JWT,
      // sign it with nothing, and be handed a token this realm signed for that
      // person. RFC 8693 section 2.2.2: an invalid subject_token or
      // actor_token is `invalid_request`.
      //
      // `verifyJws()` holds the signature, `exp` and `nbf`; the revocation set
      // is asked here, as the refresh grant asks it, because a verified token
      // this realm has revoked is not one it will exchange either.
      const strictExchange = !mode.exchangesUnverifiedTokens();
      try {
        subject = helpers.verifyOwnJws(subjectJws);
      } catch (e) {
        log.debug("Caught in tokenGrant(): " + ((e && e.message) || e));
        if (strictExchange) {
          log.info('oauth2: product mode refused a token exchange by "' +
                   client.client_id + '": the subject_token did not verify ' +
                   'against this realm\'s signing key (' +
                   ((e && e.message) || e) + ').');
          errorCodes.mark(res, 'STS-OAUTH-0555');
          log.debug("Leaving OAuth2Server.tokenGrant().");
          return self.oauthError(res, 400, 'invalid_request',
                                 'The subject_token is not a token this ' +
                                 'authorization server can verify.');
        }
        // A token from somewhere else: exchange it anyway, but say who it was
        // for as best it can be read.
        subjectVerified = false;
        log.debug("The subject_token was not signed by this server; reading " +
                  "it without verifying.");
        try {
          subject = jsonFromB64u(subjectJws.split('.')[1]) || {};
        } catch (e2) {
          log.error(errorCodes.tag('STS-OAUTH-0225') + 'the subject_token ' +
                                                       'could not be read at ' +
                                                       'all: ' +
                    e2.message);
          subject = {};
        }
      }
      if (subjectVerified && subject.jti && stats.isRevoked(subject.jti)) {
        log.info('oauth2: a token exchange by "' + client.client_id +
                 '" presented a subject_token this realm has revoked.');
        errorCodes.mark(res, 'STS-OAUTH-0557');
        log.debug("Leaving OAuth2Server.tokenGrant().");
        return self.oauthError(res, 400, 'invalid_request',
                               'The subject_token has been revoked.');
      }
      let act;
      if (body.actor_token) {
        // THE ACTOR IS VERIFIED BY THE SAME RULE, for the same reason: `act`
        // is the record, inside the token that comes out, of who acted on the
        // subject's behalf, and a name read out of an unverified token puts a
        // claim there that nobody made. Development still reads it unverified.
        let actorClaims = null;
        if (strictExchange) {
          try {
            actorClaims = helpers.verifyOwnJws(String(body.actor_token));
          } catch (e) {
            log.debug("Caught in tokenGrant(): " + ((e && e.message) || e));
            log.info('oauth2: product mode refused a token exchange by "' +
                     client.client_id + '": the actor_token did not verify ' +
                     'against this realm\'s signing key.');
            errorCodes.mark(res, 'STS-OAUTH-0556');
            log.debug("Leaving OAuth2Server.tokenGrant().");
            return self.oauthError(res, 400, 'invalid_request',
                                   'The actor_token is not a token this ' +
                                   'authorization server can verify.');
          }
          if (actorClaims.jti && stats.isRevoked(actorClaims.jti)) {
            errorCodes.mark(res, 'STS-OAUTH-0557');
            log.debug("Leaving OAuth2Server.tokenGrant().");
            return self.oauthError(res, 400, 'invalid_request',
                                   'The actor_token has been revoked.');
          }
          act = { sub: actorClaims.sub };
        } else {
          try {
            act = { sub: (jsonFromB64u(String(body.actor_token)
              .split('.')[1]) || {}).sub };
          } catch (e) {
            log.error(errorCodes.tag('STS-OAUTH-0226') + 'the actor_token ' +
                                                         'could not be ' +
                                                         'read: ' + e.message);
            act = undefined;
          }
        }
      }
      stats.recordAuthentication({
        presented: subject.username || subject.sub || 'urn:sts:exchanged',
        protocol: 'OAuth 2.0', method: 'token exchange (RFC 8693)',
        sub: subject.sub || '', client_id: client.client_id,
        note: subjectVerified
          ? 'The subject_token was signed by this service and verified, so ' +
            'this subject was authenticated here — earlier, by whatever ' +
            'grant produced that token.'
          : 'The subject_token was NOT signed by this service. The name was ' +
            'read out of it without verifying anything, so this is a subject ' +
            'this service has been TOLD about rather than one it authenticated.'
      });
      // -----------------------------------------------------------------------
      // WHAT THIS EXCHANGE IS FOR, WHICH RFC 8693 SECTION 2.1 SPELLS TWO WAYS.
      //
      // `audience` is "the logical name of the target service" and `resource`
      // is "a URI that indicates the target service or resource" — two ways to
      // name the same kind of thing, both OPTIONAL, both allowed to be
      // repeated, and the section says outright that they MAY BE USED TOGETHER
      // to name several. This used to read `body.audience || body.resource`,
      // which silently DISCARDED the resource whenever both were sent and never
      // validated it at all: a `resource` carrying a fragment, or a repeated
      // one arriving from express as an array, went straight into `aud`.
      //
      // So they are unioned, and the resources are the ones read through
      // `parseResourceIndicators()` above — RFC 8693 section 2.1 cites RFC 8707
      // for that parameter, so it is the same parameter with the same two rules
      // and a malformed one is now refused here as it is everywhere else.
      // `audience` is NOT put through it: a logical name is not required to be
      // a URI and validating it as one would refuse the ordinary case.
      //
      // AUDIENCES FIRST, and that ordering is the one thing here that is a
      // compatibility decision rather than a reading of the RFC. Order means
      // nothing in an `aud` array — but the delegation act below files this
      // exchange against ONE target, and `audience` winning is what it did
      // before. A union that reordered them would quietly move an existing
      // exchange from one box to another in /admin/delegation.
      // -----------------------------------------------------------------------
      // RFC 8693 section 2.1 lets `audience` repeat as well, so it is read the
      // same way. Not through `parseResourceIndicators()` — see the note above.
      const askedAudiences = bodyValues(req, body, 'audience')
        .map(function (one) { return String(one).trim(); })
        .filter(function (one) { return !!one; });
      const exchangeAudiences = askedAudiences.concat(
        requestedResources.filter(function (one) {
          return askedAudiences.indexOf(one) < 0;
        }));
      // -----------------------------------------------------------------------
      // AND WHETHER A REFRESH TOKEN COMES BACK BESIDE IT — RFC 8693 section
      // 2.1's `requested_token_type`, WHICH THIS BRANCH READ NOWHERE UNTIL
      // 2026-09-01.
      //
      // Section 2.2.1 makes `refresh_token` an OPTIONAL member of a token
      // exchange response and says exactly when one is worth having: "in cases
      // where the client of the token exchange needs the ability to access a
      // resource even when the original credential is no longer valid" — the
      // offline case, where there is no longer a person entertaining a session
      // with the client. It is a thing a client ASKS FOR, and the parameter it
      // asks with is `requested_token_type`; section 2.1 leaves the answer
      // entirely to the authorization server when it is absent.
      //
      // So the default is UNCHANGED — an exchange that says nothing gets an
      // access token and nothing else, which is what every caller of this
      // endpoint has ever had — and asking for
      // `urn:ietf:params:oauth:token-type:refresh_token` is what adds one.
      //
      // NOTHING IS REFUSED FOR ASKING FOR SOMETHING ELSE. A
      // `requested_token_type` naming a SAML assertion or a JWT is answered
      // with exactly what this branch has always answered with, because section
      // 2.1's own reading is that the type is a REQUEST rather than an
      // instruction — and refusing one would be this service enforcing
      // something by default, which it keeps for the compliance modes and the
      // few refusals that argue their own case.
      // -----------------------------------------------------------------------
      const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
      const REFRESH_TOKEN_TYPE =
        'urn:ietf:params:oauth:token-type:refresh_token';
      const askedForRefresh =
        String(body.requested_token_type || '').trim() === REFRESH_TOKEN_TYPE;
      // -----------------------------------------------------------------------
      // AND WHAT THIS SERVICE HAS BEEN CONFIGURED TO DO ABOUT THAT ASK.
      //
      // `oauth2.tokenExchangeRefreshToken` is three words rather than a flag,
      // and its row in `config.js` argues why: RFC 8693 section 2.2.1 leaves
      // the decision to the authorization server, real ones differ, and a
      // client written against one of them meets the others. `never` refuses
      // the ask, `when-requested` honours it (the default, and what this
      // endpoint did the day the ask was implemented), `always` hands one to an
      // exchange that never mentioned the parameter.
      //
      // READ THROUGH applications.settingFor() ON THE CLIENT PERFORMING THE
      // EXCHANGE, which is the same call every other per-client OAuth override
      // goes through. The client and not the audience, because the refresh
      // token is handed to the client — it is that party's credential to hold
      // and redeem — and because in the interesting case the subject the
      // exchange is ABOUT has no entry here at all, the whole point of an
      // exchange being a subject_token from somewhere else.
      //
      // AN UNRECOGNISED VALUE IS NOT AN ERROR HERE. `settingFor()` warns naming
      // the entry and falls back to the service-wide setting, and this reads
      // whatever comes back against the three words — so a fourth word behaves
      // as `when-requested` does rather than as `always`, which is the safe end
      // of the range to fall off: the client gets what it asked for and nothing
      // it did not.
      // -----------------------------------------------------------------------
      const refreshPolicy = String(applications.settingFor(
        client.client_id, 'oauth2.tokenExchangeRefreshToken', config) ||
                                   '').trim();
      const wantsRefresh = refreshPolicy === 'always' ||
        (refreshPolicy !== 'never' && askedForRefresh);
      log.debug("Token exchange: oauth2.tokenExchangeRefreshToken is \"" +
                refreshPolicy +
                "\" for " + client.client_id + " and the request " +
                (askedForRefresh ? 'asked for' : 'did not ask for') +
                " a refresh token, so the token set " +
                (wantsRefresh ? 'carries' : 'does not carry') + " one.");
      if (askedForRefresh && refreshPolicy === 'never') {
        // SAID OUT LOUD AND NOT REFUSED. RFC 8693 section 2.1 makes
        // `requested_token_type` a request rather than an instruction and
        // section 2.2.1 makes the member optional, so an exchange that asked
        // and did not get one is a well-formed exchange — the response says
        // what was issued, which is what `issued_token_type` is for. A client
        // that cannot see this line would otherwise have nothing to tell it
        // apart from a service that had never heard of the parameter, which is
        // why it is logged at INFO.
        log.info('oauth2: "' + client.client_id + '" asked for a refresh ' +
                 'token by requested_token_type and ' +
                 'oauth2.tokenExchangeRefreshToken is "never" for it, so the ' +
                 'exchange succeeded without one. Set that to ' +
                 '"when-requested" service-wide, or put ' +
                 'oauthTokenExchangeRefreshToken on this application\'s ' +
                 'entry, to honour the ask.');
      }
      const exchanged = await issue({
        jkt: dpopJkt,
        sub: subject.sub || 'urn:sts:exchanged',
        user: Object.assign(userFor(subject.username),
                            subject.sub ? { sub: subject.sub } : {}),
        client_id: client.client_id,
        scope: String(body.scope || subject.scope || ''),
        audience: self.audienceClaim(exchangeAudiences), act: act,
        // RFC 9396 on an exchange: the details asked for, as for a direct
        // grant. The audience rule is tokenSet()'s backstop, as the header
        // above says.
        authorization_details: grantIdentifiers(requestedDetails,
                                                userFor(subject.username)),
        // Section 2.2.1's `refresh_token` member — and this flag is the ONLY
        // thing this branch decides about it. It is minted by the same
        // refreshToken(), through the same tokenSet(), as the token every other
        // grant here hands back, which is what makes "treat it as any other
        // refresh token" true by construction rather than by six things having
        // been remembered: the same `typ: 'Refresh'`, the same jti in the same
        // revocation set, the same `oauth2.refreshTokenTtlS`, the same RFC 9700
        // family bookkeeping and rotation on redemption, and the same
        // confirmations — an exchange made with a DPoP proof or over a client
        // certificate mints a BOUND refresh token, which is the whole of RFC
        // 9449 section 5 and RFC 8705 section 3 on the long-lived half of a
        // grant.
        withRefresh: wantsRefresh,
        // RFC 8707, reached through RFC 8693 section 2.1, and only relevant now
        // that there is a refresh token to carry it: `resources` is what the
        // refresh grant compares a renewal against, so an exchange addressed to
        // one audience must not be renewable into a token carrying this
        // service's default. A grant cannot widen itself by being renewed, and
        // an exchange is a grant like the rest. The AUDIENCES go on it rather
        // than `requestedResources` alone, because `aud` on the token being
        // minted is the union of both and the two must not come to describe
        // different resource servers.
        resources: wantsRefresh ? exchangeAudiences : undefined,
        grant: 'token exchange'
      });
      // RFC 8693 section 2.2.1: `issued_token_type` describes THE TOKEN IN THE
      // `access_token` MEMBER, and that member holds an access token here
      // whatever was asked for — so it says access token even when a refresh
      // token was requested and came back beside it.
      //
      // The other reading of section 2.1 is that a client asking for a refresh
      // token should be handed one IN `access_token` with `issued_token_type`
      // naming it — the section does say that member is called `access_token`
      // for historical reasons and need not carry one. That is deliberately not
      // what happens here. A client would then hold a `typ: 'Refresh'` JWT
      // under the name every other grant in this service uses for the
      // credential a resource server is presented with, and this service's own
      // protected endpoints would refuse it. The refresh token goes where every
      // other grant puts one, which is what "the same as any other refresh
      // token" means, and the client gets both halves of a grant out of one
      // exchange rather than a credential it has to know not to present.
      exchanged.issued_token_type = ACCESS_TOKEN_TYPE;

      // -----------------------------------------------------------------------
      // THE DELEGATION ACT, for /admin/delegation.
      //
      // RFC 8693 defines TWO of them and section 1.1 is explicit that they are
      // different things, so they are two rows here rather than one with a
      // flag:
      //
      //   * no actor_token — IMPERSONATION. What comes back is a token for the
      //     subject with nothing on it about who exchanged it. The resource
      //     server cannot tell, and neither can anybody reading the token
      //     later, which makes this page the only place it is ever visible.
      //   * an actor_token — DELEGATION (§4.1). What comes back carries `act`
      //     naming the actor, and `act` NESTS: a second hop appears underneath
      //     the first rather than replacing it.
      //
      // The intermediary is deliberately BOTH an identity and an application.
      // The client performing the exchange is the application, always; the
      // actor named in the actor_token is the identity, and only a delegation
      // has one. An impersonation therefore draws a chain whose middle is an
      // application and nobody — which is exactly what happened.
      //
      // The jti is read back off the token that was just signed rather than
      // threaded out of issue(). That is one decode of a string this function
      // already holds, against changing the return type of the one helper every
      // grant here mints through — and jsonFromB64u() is the same reader the
      // actor_token was decoded with twelve lines above.
      const issuedJti = self.jtiOf(exchanged.access_token);
      // AND THE ID TOKEN, WHEN ONE CAME WITH IT. An exchange for a scope
      // carrying `openid` mints two credentials and the act produced BOTH —
      // recording only the access token made the second one an orphan, which
      // /admin/tokens/credential then described as having been issued directly
      // when it had in fact come out of this exchange. A row that says "nothing
      // was exchanged to get this" about a token that was exchanged is worse
      // than a row that says nothing, so both are named here.
      const issuedIdJti = self.jtiOf(exchanged.id_token);
      // AND THE REFRESH TOKEN, when `requested_token_type` asked for one. Named
      // for the id_token's reason and a stronger one: a refresh token is the
      // half of this grant that OUTLIVES the exchange, so an act that did not
      // mention it would describe a delegation as having produced a credential
      // good for an hour when what it actually produced is one good for a day
      // and renewable. /admin/tokens/credential reads these identifiers, and a
      // refresh token with no act behind it reads as having been issued
      // directly.
      const issuedRefreshJti = self.jtiOf(exchanged.refresh_token);
      // The FIRST of them, which is `audience` where one was sent and the
      // resource otherwise — see the ordering note above. A delegation act
      // names one target; an exchange asking for several is drawn against the
      // one it named first, and the raw string is kept in the sentence beside
      // it either way.
      const audience = String(exchangeAudiences[0] || '');
      // ---------------------------------------------------------------------
      // WHICH APPLICATION THAT AUDIENCE IS, when one has registered it.
      //
      // An `audience` names a RESOURCE — `https://esb1.example.com` — and this
      // registry is keyed by the identifier an application presents, which for
      // an OAuth client is its client_id. Recording the raw audience as the
      // target therefore draws a box on /admin/delegation/map that nothing else
      // in the picture mentions: a two-hop chain through a middle tier appears
      // as two unconnected halves, because the URL the first hop reached and
      // the client_id the second hop exchanged AS are the same application
      // under two names. So the audience is looked up on `oauthAudience` and
      // the application's own identifier is what the act is filed under, with
      // the audience that was actually asked for kept in the sentence beside it
      // — the raw string is a fact about the request and must not be lost to a
      // resolution.
      //
      // NOTHING IS REFUSED. An audience nobody registered resolves to null and
      // is recorded verbatim, exactly as it was before this existed. See
      // applications.forAudience(), where the difference between a lookup and a
      // permission is argued.
      // ---------------------------------------------------------------------
      const audienceApplication = audience ?
                                  applications.forAudience(audience) :
                                  null;
      if (audienceApplication) {
        log.debug('the audience "' + audience +
                  '" is registered to application "' +
                  audienceApplication.identifier + '", so the delegation is ' +
                  'recorded against that application rather than against the ' +
                  'URI.');
      }
      delegation.record({
        protocol: 'OAuth 2.0',
        type: act ? 'oauth-delegation' : 'oauth-impersonation',
        outcome: 'issued',
        initial: {
          presented: subject.username || subject.sub || 'urn:sts:exchanged',
          what: subjectVerified
            ? 'the subject of the token presented, which this service signed ' +
              'and verified — so they were authenticated here, earlier, by ' +
              'whatever grant produced it'
            : 'the subject named in a token this service did NOT sign. The ' +
              'name was read without verifying anything, so this is somebody ' +
              'this service has been TOLD about rather than one it ' +
              'authenticated'
        },
        intermediary: {
          presented: act ? String(act.sub || '') : '',
          application: client.client_id,
          what: act
            ? 'the actor named in the actor_token, exchanging through client ' +
              client.client_id
            : 'the client performing the exchange. No actor_token was sent, ' +
              'so no identity is named — the client is the whole of the ' +
              'middle here'
        },
        target: {
          application: audienceApplication ? audienceApplication.identifier :
                       audience,
          what: audience
            ? (audienceApplication
                ? 'the application registered for the audience "' + audience +
                  '", which is what the exchanged token is addressed to. The ' +
                  'request named the audience; this registry named the ' +
                  'application'
                : 'the audience or resource the exchanged token is for. No ' +
                  'application here has registered it on `oauthAudience`, so ' +
                  'it is recorded exactly as it was asked for')
            : 'unstated — neither `audience` nor `resource` was sent, so the ' +
              'token that came back is not addressed to anything in particular'
        },
        authorizedBy: 'nothing. RFC 8693 leaves the policy to the ' +
                      'authorization server and this one has none: any ' +
                      'client may exchange any token for a token about ' +
                      'anybody. The `may_act` claim is the mechanism a real ' +
                      'deployment would use, and this service neither issues ' +
                      'nor reads it.',
        consumed: ([{
          kind: 'subject_token',
          identifier: String(subject.jti || ''),
          note: subjectVerified
            ? 'signed by this service and verified'
            : 'NOT signed by this service; read without verifying'
        }] as Json[]).concat(act ? [{
          kind: 'actor_token',
          note: 'read without verifying — only its `sub` is taken, which is ' +
                'what goes into the `act` claim'
        }] : []),
        produced: [{
          kind: 'access_token',
          identifier: issuedJti,
          note: act ?
                'carries an `act` claim naming ' + String(act.sub || '(nobody)')
                    : 'carries nothing about the client that exchanged it'
        }].concat(exchanged.id_token ? [{
          kind: 'id_token',
          identifier: issuedIdJti,
          note: 'minted alongside because the requested scope carries ' +
                '`openid`. RFC 8693 returns ONE token — the `access_token` ' +
                'member above is what `issued_token_type` describes — and ' +
                'this one rides along because every grant here mints a ' +
                'token SET.'
        }] : []).concat(exchanged.refresh_token ? [{
          kind: 'refresh_token',
          identifier: issuedRefreshJti,
          note: 'RFC 8693 section 2.2.1\'s optional `refresh_token`, minted ' +
                'because oauth2.tokenExchangeRefreshToken is "' +
                  refreshPolicy +
                '" for this client and the request ' +
                (askedForRefresh ? 'asked for one with requested_token_type'
                                 : 'did not ask for one') + '. It is an ' +
                'ordinary refresh token of this service: redeemable at the ' +
                'refresh grant, revocable, and bound to the same key or ' +
                'certificate as the access token above. It OUTLIVES the ' +
                'exchange, which is the point of asking — the client can go ' +
                'on reaching the audience after the subject_token it was ' +
                'exchanged for has expired.'
        }] : []),
        // No session, and that is a fact about token exchange rather than a
        // gap: a service exchanging a token on somebody's behalf has no browser
        // anywhere in it. issue() records the same emptiness on the token
        // itself.
        sessionId: ''
      });
      log.debug("Leaving OAuth2Server.tokenGrant().");
      return respond(exchanged);
    }

    log.debug("Leaving the token endpoint.");
    log.debug("Leaving the token endpoint. The grant type is not supported.");
    errorCodes.mark(res, 'STS-OAUTH-0227');
    log.debug("Leaving OAuth2Server.tokenGrant().");
    return self.oauthError(res, 400, 'unsupported_grant_type',
                      'grant_type "' + grant + '" ' +
        'is not supported.');
  }

// logArtifact STS baseUrlOf b64u jsonFromB64u nowSec randomId xmlEscape
// parseBody bodyValues plainOauthError signJwt signJwtAs allSigningKeys
// allSigningKeysAsync signJwtAsAsync userFor hasScope signingKeyFor
// certificateHeaderFor publishedKidFor nameForSubject hasSubjectResolver
// LEGACY_SUBJECT_PREFIX requestObjectKeysFor dpop joseKid mtls clientAuth
// assertionGrant softwareStatement samlAssertionGrant mode authorizationServers
// stats VCI_CONFIGS VCI_CONFIG_ID VCI_SCOPE vciFormatOf vcClaims
// deferredAccessTokens issuerStates preAuthorizedCodes checkTxCode
// spendPreAuthorizedCode config authn sessionOf endSession bcp oauth21
// senderConstraints frontchannel applications validation errorCodes
// refreshTokenCrypto jwtAccessToken introspectionJwt stepUp requestObject
// richAuthorization par oauthMonitor delegation consent consentScreen
// claimAttributes gate debuggerAccess credentials websecurity clusterClaims
// clusterBarrier capabilities

  private parEndpoint(req: Req, res: Res): Json {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering the pushed authorization request endpoint.");
    self.parRequest(req, res).catch(function (e) {
      log.error(errorCodes.tag('STS-OAUTH-0420') + 'the pushed authorization ' +
                'request endpoint failed: ' + (e && e.stack ? e.stack : e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-OAUTH-0420');
        self.oauthError(res, 500, 'server_error',
                        String((e && e.message) || e));
      }
    });
    log.debug("Leaving the pushed authorization request endpoint.");
  }

  // Section 2's endpoint "accepts HTTP POST requests"; section 2.3's 405 for
  // every other method, with the Allow header RFC 9110 section 15.5.6 requires.
  private parMethodNotAllowed(req: Req, res: Res): Json {
    const { log, errorCodes, oauthMonitor } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.parMethodNotAllowed(). method=" +
              req.method);
    res.set('Allow', 'POST');
    res.set('Cache-Control', 'no-store');
    errorCodes.mark(res, 'STS-OAUTH-0401');
    oauthMonitor.record(String((req.query || {}).client_id || ''),
                        'par.refused', { error: 'method_not_allowed' });
    log.debug("Leaving OAuth2Server.parMethodNotAllowed().");
    return self.oauthError(res, 405, 'invalid_request',
      'The pushed authorization request endpoint accepts POST only (RFC 9126 ' +
      'section 2), with the authorization request in an ' +
      'application/x-www-form-urlencoded body.');
  }

  private async parRequest(req: Req, res: Res): Promise<Json> {
    const { realms, jwt, log, STS, parseBody, bodyValues,
            hasScope, dpop, mtls, mode, config, bcp, oauth21, fapi,
            applications, validation, errorCodes, requestObject,
            par, oauthMonitor, websecurity } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.parRequest().");
    res.set('Cache-Control', 'no-store');
    const base = self.asBaseOf(req);
    let countedClient = '';
    // One refusal shape for the whole endpoint: marked, counted and answered.
    const refuse = function (status: number, error: string,
                             description: string, code: string,
                             headers?: Json) {
      log.debug("Entering refuse(). " + code);
      Object.keys(headers || {}).forEach(function (name) {
        res.set(name, headers[name]);
      });
      errorCodes.mark(res, code);
      oauthMonitor.record(countedClient, 'par.refused', { error: error });
      log.info('par: a push from "' + (countedClient || '(no client_id)') +
               '" was refused ' + status + ' ' + error + ': ' + description);
      log.debug("Leaving refuse().");
      // error-code: none — every caller of refuse() passes its own code
      return self.oauthError(res, status, error, description);
    };

    // --- 1. WHAT KIND OF REQUEST ---------------------------------------------
    if (!config.value('oauth2.pushedAuthorizationRequests')) {
      log.debug("Leaving OAuth2Server.parRequest(). Switched off.");
      return refuse(404, 'invalid_request', 'This authorization server does ' +
        'not offer pushed authorization requests ' +
        '(oauth2.pushedAuthorizationRequests is off), and its metadata ' +
        'carries no pushed_authorization_request_endpoint. Send the ' +
        'authorization request ' +
        'to the authorization endpoint instead.', 'STS-OAUTH-0400');
    }
    const raw = typeof req.body === 'string' ? req.body : '';
    const maxBytes = Number(config.value('oauth2.parMaxBodyBytes'));
    if (isFinite(maxBytes) && Buffer.byteLength(raw, 'utf8') > maxBytes) {
      log.debug("Leaving OAuth2Server.parRequest(). Too large.");
      return refuse(413, 'invalid_request', 'The pushed authorization ' +
        'request is ' + Buffer.byteLength(raw, 'utf8') + ' bytes, and this ' +
        'authorization server accepts at most ' + maxBytes + ' ' +
        '(oauth2.parMaxBodyBytes; RFC 9126 section 2.3).', 'STS-OAUTH-0402');
    }
    const type = String(req.headers['content-type'] || '').split(';')[0].trim()
      .toLowerCase();
    if (type !== 'application/x-www-form-urlencoded') {
      log.debug("Leaving OAuth2Server.parRequest(). Not a form.");
      return refuse(400, 'invalid_request', 'A pushed authorization request ' +
        'is sent as application/x-www-form-urlencoded (RFC 9126 section 2), ' +
        'and ' +
        'this one is "' + (type || '(no Content-Type)') + '".',
        'STS-OAUTH-0403');
    }
    const posted = validation.checkParsed(parseBody(req), 'body', PAR_FORM);
    if (!posted.ok) {
      log.debug("Leaving OAuth2Server.parRequest(). Malformed: " +
                posted.code + " on \"" +
                posted.field + "\".");
      return refuse(400, 'invalid_request', posted.detail, 'STS-OAUTH-0403');
    }
    const body = posted.value;

    // --- 2. WHOSE REQUEST
    // -----------------------------------------------------
    const presented = self.presentedClientAuthentication(req, body);
    const client = self.clientFrom(req, body);
    const clientId = String(client.client_id || '');
    countedClient = clientId || String(body.client_id || '');
    if (body.client_id && clientId && String(body.client_id) !== clientId) {
      log.debug("Leaving OAuth2Server.parRequest(). Two client_ids.");
      return refuse(400, 'invalid_request', 'The pushed request names ' +
        'client_id "' + body.client_id + '" and its client authentication ' +
        'names "' + clientId + '". A pushed authorization request is bound ' +
        'to the client that authenticated (RFC 9126 section 2.2), so the two ' +
        'must ' +
        'be the same client.', 'STS-OAUTH-0406');
    }
    if (!clientId) {
      log.debug("Leaving OAuth2Server.parRequest(). No client_id.");
      return refuse(400, 'invalid_request', 'A pushed authorization request ' +
        'requires client_id (RFC 9126 section 2.1: "as a required ' +
        'authorization request parameter, it is similarly required in a ' +
        'pushed authorization request"), and this one carries none — no ' +
        'client_id ' +
        'parameter, no Authorization: Basic header and no client assertion.',
        'STS-OAUTH-0405');
    }
    const registered = applications.clientConfigOf(clientId);

    // FAPI (#138): one client, however many ways the request names it.
    const identified = fapi.clientIdentifierRefusal(
      self.presentedClientIds(req, body));
    if (identified) {
      log.debug("Leaving OAuth2Server.parRequest(). FAPI: two clients " +
                "named.");
      return refuse(401, identified.error, identified.description,
                    identified.errorCode,
                    presented.basic ?
                      { 'WWW-Authenticate': self.basicChallenge() } : null);
    }

    // OAuth 2.1's two refusals about the SHAPE, as at the token endpoint.
    const repeatedInBody = oauth21.repeatedNames(null, raw);
    if (oauth21.enabled()) {
      const several = oauth21.multipleMethodsRefusal(presented);
      if (several) {
        log.debug("Leaving OAuth2Server.parRequest(). OAuth 2.1: several " +
                  "methods.");
        return refuse(400, several.error, several.description,
                      several.errorCode || 'STS-OAUTH-0281');
      }
    }
    // A parameter other than the two repeatable ones given twice is refused in
    // every mode, as the authorization endpoint's schema refuses one: a pushed
    // request is read into one object, and "the last value wins" would be this
    // server choosing between two answers on the client's behalf.
    const repeatedHere = repeatedInBody.filter(function (name) {
      return PAR_REPEATABLE.indexOf(name) < 0;
    });
    if (repeatedHere.length) {
      log.debug("Leaving OAuth2Server.parRequest(). A repeated parameter.");
      return refuse(400, 'invalid_request', 'This pushed authorization ' +
        'request repeats ' + repeatedHere.join(', ') + '. Only resource ' +
        '(RFC 8707) and claim may be given more than once.', 'STS-OAUTH-0403');
    }

    // THE PUSH LIMIT, section 2.3's 429: every push is counted, successful or
    // not, because every one that succeeds holds a row. Per client_id and
    // address, in the limiter every other door here uses; the address bucket is
    // ten times the client's so one address serving several clients is not one
    // client's allowance.
    const perClient = Math.max(1, Math.floor(Number(
      config.value('oauth2.parRequestsPerMinute')) || 1));
    const limited = await websecurity.attemptShared(
      'par-push:' + (realms.currentId() || 'default'), req,
      clientId + '|' + websecurity.addressOf(req),
      { identity: perClient, address: perClient * 10 });
    if (!limited.ok) {
      log.debug("Leaving OAuth2Server.parRequest(). Too many pushes.");
      return refuse(429, 'invalid_request', 'Too many pushed authorization ' +
        'requests from client "' + clientId + '" at this address ' +
        '(oauth2.parRequestsPerMinute; RFC 9126 section 2.3). ' +
        limited.detail,
        'STS-OAUTH-0407', { 'Retry-After': String(limited.retryAfterS) });
    }
    if (self.secretPresented(presented, registered)) {
      const key = self.secretLimitKey(req, clientId);
      const lockedOut = await websecurity.blockedShared(key.what, req,
                                                        key.identity);
      if (lockedOut) {
        log.debug("Leaving OAuth2Server.parRequest(). Too many failed client " +
                  "secrets.");
        return refuse(429, 'invalid_client', 'Too many failed client ' +
          'authentications for client "' + clientId + '" from this address. ' +
          lockedOut.detail, 'STS-OAUTH-0284',
          { 'Retry-After': String(lockedOut.retryAfterS) });
      }
    }

    // --- 3. A DPoP PROOF
    // ------------------------------------------------------ RFC 9449 section
    // 10.1: a proof sent with the push binds the authorization code to its key
    // exactly as `dpop_jkt` does, and where both are sent they must name the
    // same key. Checked against THIS endpoint's URL and method.
    let dpopJkt = '';
    if (req.headers['dpop'] !== undefined) {
      const checked = dpop.verifyProof(req.headers['dpop'], {
        htm: req.method, htu: dpop.htuOf(req),
        // The reservation `dpop.proofClaims()` made on arrival (#46).
        req: req
      });
      if (!checked.ok) {
        if (checked.needNonce) {
          log.debug("Leaving OAuth2Server.parRequest(). Asking for a DPoP " +
                    "nonce.");
          return refuse(400, 'use_dpop_nonce', 'Authorization server ' +
            'requires nonce in DPoP proof',
            checked.errorCode || 'STS-OAUTH-0416',
            { 'DPoP-Nonce': dpop.issueNonce() });
        }
        log.debug("Leaving OAuth2Server.parRequest(). The DPoP proof was " +
                  "refused.");
        return refuse(400, 'invalid_dpop_proof', checked.description,
                      checked.errorCode || 'STS-OAUTH-0416');
      }
      dpopJkt = checked.jkt;
    }

    // --- 4. CLIENT AUTHENTICATION, AS AT THE TOKEN ENDPOINT
    // -------------------
    const advertisedAuth = self.capabilityFor(
      req, 'token_endpoint_auth_methods_supported');
    const declaredMethod = String(registered.token_endpoint_auth_method || '');
    if (declaredMethod && advertisedAuth &&
        advertisedAuth.indexOf(declaredMethod) < 0) {
      log.debug("Leaving OAuth2Server.parRequest(). " + self.profileOf(req) +
                " does not " +
                "advertise " + declaredMethod + ".");
      return refuse(400, 'invalid_client', 'The "' + self.profileOf(req) +
        '" ' +
        'authorization server advertises ' +
        'token_endpoint_auth_methods_supported ' +
        JSON.stringify(advertisedAuth) +
                       ', and this client is configured for "' +
        declaredMethod + '". The pushed authorization request endpoint ' +
        'authenticates a client as the token endpoint does (RFC 9126 section ' +
        '2).', 'STS-OAUTH-0421');
    }
    // Section 2: the authorization server "MUST accept its issuer identifier,
    // token endpoint URL, or pushed authorization request endpoint URL" as a
    // client assertion's audience. OAuth 2.1 mode's sole-issuer rule still wins
    // where that mode is on, as at the token endpoint.
    const assertionAudiences = [self.issuerOf(base), base + '/oauth2/token',
                                base + '/oauth2/par', base];
    const strictAudience = (oauth21.strictClientAssertionAudience() ||
                            self.deps.fapi.strictAssertionAudience()) ?
                           self.issuerOf(base) : '';
    const authentication = {
      clientId: clientId,
      clientSecret: client.client_secret,
      assertion: client.assertion,
      assertionType: client.assertionType,
      request: req,
      audiences: assertionAudiences,
      strictAudience: strictAudience,
      registered: registered
    };
    const policy = await bcp.checkClientAuthentication(authentication);
    if (!policy.ok) {
      const overLimit = await self.countSecretFailure(req, clientId, presented,
                                                 registered);
      if (overLimit) {
        log.debug("Leaving OAuth2Server.parRequest(). Past the secret limit.");
        return refuse(429, 'invalid_client', 'Too many failed client ' +
          'authentications for client "' + clientId + '" from this address. ' +
          overLimit.detail, 'STS-OAUTH-0284',
          { 'Retry-After': String(overLimit.retryAfterS) });
      }
      log.debug("Leaving OAuth2Server.parRequest(). RFC 9700 mode refused " +
                "the client.");
      return refuse(401, policy.error, policy.description,
                    policy.errorCode || 'STS-OAUTH-0422',
                    presented.basic ?
                      { 'WWW-Authenticate': self.basicChallenge() } : null);
    }
    const declaration = oauth21.tokenClientDeclarationRefusal({
      grant: 'authorization_code', clientId: clientId, registered: registered,
      presented: presented
    });
    if (declaration) {
      log.debug("Leaving OAuth2Server.parRequest(). OAuth 2.1 refused the " +
                "client.");
      return refuse(401, declaration.error, declaration.description,
                    declaration.errorCode || 'STS-OAUTH-0278',
                    presented.basic ?
                      { 'WWW-Authenticate': self.basicChallenge() } : null);
    }
    const observation = await bcp.observeClientAuthentication(authentication);
    // FAPI (#138): the confidential client authentication methods it allows.
    const fapiAuth = fapi.clientAuthenticationRefusal(observation.method);
    if (fapiAuth) {
      log.debug("Leaving OAuth2Server.parRequest(). FAPI refused the " +
                "client's authentication method.");
      return refuse(401, fapiAuth.error, fapiAuth.description,
                    fapiAuth.errorCode,
                    presented.basic ?
                      { 'WWW-Authenticate': self.basicChallenge() } : null);
    }
    // FAPI 2.0 section 5.3.2.2 item 4 (#140): a push authenticates its client.
    const fapiPushed = fapi.parAuthenticationRefusal(
      !!observation.authenticated);
    if (fapiPushed) {
      log.debug("Leaving OAuth2Server.parRequest(). FAPI 2.0: an " +
                "unauthenticated push.");
      return refuse(401, fapiPushed.error, fapiPushed.description,
                    fapiPushed.errorCode, null);
    }
    // FAPI 2.0 section 5.3.2.1 item 13 (#140): the client assertion's iat or
    // nbf more than a minute ahead.
    if (body.client_assertion) {
      const ahead = fapi.futureTimestampRefusal(
        self.unverifiedClaimsOf(body.client_assertion),
        'the client assertion');
      if (ahead) {
        log.debug("Leaving OAuth2Server.parRequest(). FAPI 2.0: a " +
                  "timestamp in the future.");
        return refuse(400, ahead.error, ahead.description, ahead.errorCode,
                      null);
      }
    }
    if (observation.authenticated) {
      const racedOut = await self.settleSecretSuccess(req, clientId, presented,
                                                 registered);
      if (racedOut) {
        log.debug("Leaving OAuth2Server.parRequest(). A verified secret past " +
                  "the limit.");
        return refuse(429, 'invalid_client', 'Too many failed client ' +
          'authentications for client "' + clientId + '" from this address. ' +
          racedOut.detail, 'STS-OAUTH-0284',
          { 'Retry-After': String(racedOut.retryAfterS) });
      }
    }
    const presentedRefusal = oauth21.tokenClientAuthenticationRefusal({
      grant: 'authorization_code', observation: observation,
      presented: presented
    });
    if (presentedRefusal) {
      const overLimit = await self.countSecretFailure(req, clientId, presented,
                                                 registered);
      if (overLimit) {
        log.debug("Leaving OAuth2Server.parRequest(). Past the secret limit.");
        return refuse(429, 'invalid_client', 'Too many failed client ' +
          'authentications for client "' + clientId + '" from this address. ' +
          overLimit.detail, 'STS-OAUTH-0284',
          { 'Retry-After': String(overLimit.retryAfterS) });
      }
      log.debug("Leaving OAuth2Server.parRequest(). OAuth 2.1 refused the " +
                "credential.");
      return refuse(401, presentedRefusal.error, presentedRefusal.description,
                    presentedRefusal.errorCode || 'STS-OAUTH-0280',
                    presented.basic ?
                      { 'WWW-Authenticate': self.basicChallenge() } : null);
    }
    // RFC 8705 — a declared certificate method, in every mode, as at the token
    // endpoint (RFC 9126 section 2 authenticates a client as that endpoint
    // does). The bound-tokens half is the token endpoint's: nothing is issued
    // here.
    const declared = mtls.declaredRefusal({
      registered: registered, observation: observation, request: req
    });
    if (declared && declared.error === 'invalid_client') {
      log.debug("Leaving OAuth2Server.parRequest(). RFC 8705: the declared " +
                "method did not authenticate.");
      return refuse(401, declared.error, declared.description,
                    declared.errorCode, null);
    }
    // The token endpoint's rule, at the endpoint RFC 9126 section 2 says
    // authenticates a client as that one does — a CONFIDENTIAL client only
    // since 2026-09-17, so a public client may push a request here as it may
    // redeem a code there.
    if (mode.requiresConfidentialClientAuthentication() &&
        bcp.declaredPublic(registered) === false && !observation.authenticated) {
      const overLimit = await self.countSecretFailure(req, clientId, presented,
                                                 registered);
      if (overLimit) {
        log.debug("Leaving OAuth2Server.parRequest(). Past the secret limit.");
        return refuse(429, 'invalid_client', 'Too many failed client ' +
          'authentications for client "' + clientId + '" from this address. ' +
          overLimit.detail, 'STS-OAUTH-0284',
          { 'Retry-After': String(overLimit.retryAfterS) });
      }
      log.debug("Leaving OAuth2Server.parRequest(). Product mode refused a " +
                "public client.");
      return refuse(401, 'invalid_client', 'This service is in product mode, ' +
        'where an application that registered a confidential ' +
        'token_endpoint_auth_method must authenticate — at the pushed ' +
        'authorization request endpoint as at the token endpoint (RFC 9126 ' +
        'section 2). A public client may push without one. ' +
        (observation.why || ''),
        observation.errorCode || 'STS-OAUTH-0423',
        presented.basic ? { 'WWW-Authenticate': self.basicChallenge() } : null);
    }

    // --- 5. request_uri REFUSED; A request OBJECT VERIFIED
    // --------------------
    if (body.request_uri !== undefined && String(body.request_uri) !== '') {
      log.debug("Leaving OAuth2Server.parRequest(). A request_uri in a push.");
      return refuse(400, 'invalid_request', 'A pushed authorization request ' +
        'may not carry request_uri (RFC 9126 section 2.1: "it MUST NOT be ' +
        'provided") — the request_uri is what this endpoint answers with.',
        'STS-OAUTH-0404');
    }
    const profile = self.authorizationProfileOf(req);
    let params: Json = {};
    let source = 'form';
    let objectAlg = '';
    let objectEncrypted = '';
    // What a pushed request object is remembered by (#35), spent in step 7.
    let pushedOnce: Json = null;
    if (body.request !== undefined && String(body.request) !== '') {
      // Section 3: the form carries the client's authentication and `request`,
      // and "all other request parameters ... MUST appear as claims of the
      // JWT".
      const outside = Object.keys(body).filter(function (name) {
        return ['request', 'client_id'].concat(PAR_NOT_PARAMETERS)
          .indexOf(name) < 0;
      });
      if (outside.length) {
        log.debug("Leaving OAuth2Server.parRequest(). Parameters beside a " +
                  "request object.");
        return refuse(400, 'invalid_request', 'This push carries a request ' +
          'object and also ' + outside.join(', ') + '. RFC 9126 section 3: ' +
          'beside `request`, the form body holds only what client ' +
          'authentication needs, and every authorization request parameter ' +
          'MUST be a claim of the request object.', 'STS-OAUTH-0409');
      }
      const verified = await requestObject.verifyObject({
        jwt: String(body.request), client: registered, clientId: clientId,
        issuer: self.issuerOf(base), asBase: base, profile: profile, keySet: STS
      });
      if (!verified.ok) {
        log.debug("Leaving OAuth2Server.parRequest(). The request object is " +
                  "refused.");
        return refuse(400, verified.error, verified.description,
                      errorCodes.codeOf(verified) || 'STS-OAUTH-0409');
      }
      // Section 3 step 3: a client with credentials established must be the
      // client the object names. `verifyObject()` has refused a `client_id`
      // claim naming anybody else; one with NO client_id claim is refused here,
      // because "does not match the client_id claim" cannot be satisfied by an
      // object that makes no claim.
      if (observation.authenticated && verified.claims &&
          verified.claims.client_id === undefined) {
        log.debug("Leaving OAuth2Server.parRequest(). No client_id claim.");
        return refuse(400, 'invalid_request_object', 'The pushed request ' +
          'object carries no client_id claim, and client "' + clientId + '" ' +
          'authenticated: RFC 9126 section 3 requires the authenticated ' +
          'client_id to match the client_id claim of the request object.',
          'STS-OAUTH-0424');
      }
      params = Object.assign({}, verified.params);
      pushedOnce = verified.once || null;
      source = 'request';
      objectAlg = String(verified.alg || '');
      objectEncrypted = String(verified.encrypted || '');
    } else {
      if (requestObject.signedRequired(registered, profile)) {
        log.debug("Leaving OAuth2Server.parRequest(). A signed request " +
                  "object is required.");
        return refuse(400, 'invalid_request', 'This push carries plain ' +
          'parameters, and a signed request object is required here (RFC ' +
          '9101 section 10.5 — oauth2.requireSignedRequestObject, this ' +
          'client\'s require_signed_request_object or this authorization ' +
          'server\'s metadata). RFC 9126 section 2.3: such a client "MUST" ' +
          'push a ' +
          '`request` object.', 'STS-OAUTH-0415');
      }
      Object.keys(body).forEach(function (name) {
        if (PAR_NOT_PARAMETERS.indexOf(name) < 0 && name !== 'request') {
          params[name] = body[name];
        }
      });
      // The two parameters that may repeat, read off the raw body — the parsed
      // object kept only the last of each.
      PAR_REPEATABLE.forEach(function (name) {
        const values = bodyValues(req, body, name);
        if (values.length > 1) {
          params[name] = values;
        }
      });
    }
    PAR_PRIVATE_FIELDS.forEach(function (name) {
      delete params[name];
    });
    params.client_id = clientId;
    if (dpopJkt) {
      if (params.dpop_jkt !== undefined && String(params.dpop_jkt) !== '' &&
          String(params.dpop_jkt) !== dpopJkt) {
        log.debug("Leaving OAuth2Server.parRequest(). dpop_jkt names another " +
                  "key.");
        return refuse(400, 'invalid_dpop_proof', 'The push carries a DPoP ' +
          'proof for the key ' + dpopJkt + ' and dpop_jkt "' + params.dpop_jkt +
          '". RFC 9449 section 10.1: where both are sent they must name the ' +
          'same key.', 'STS-OAUTH-0417');
      }
      params.dpop_jkt = dpopJkt;
    }

    // --- 6. VALIDATED AS AN AUTHORIZATION REQUEST
    // -----------------------------
    const allowRelaxed = !!(observation.authenticated &&
      config.value('oauth2.parAllowUnregisteredRedirectUris'));
    const vetted = self.vetAuthorizationRequest(req, {
      input: params, where: 'body', repeated: repeatedInBody,
      what: 'pushed authorization request', relaxRedirect: allowRelaxed
    });
    if (!vetted.ok) {
      log.debug("Leaving OAuth2Server.parRequest(). The authorization " +
                "request is refused (" + vetted.code + ").");
      return refuse(400, vetted.error, vetted.description, vetted.code);
    }
    const q = vetted.q;
    const scope = String(q.scope || 'openid');
    // RFC 9396's client and profile narrowing, when that parser takes them.
    const details = self.parseAuthorizationDetails(q.authorization_details,
                                              { clientId: clientId, req: req });
    if (details.error) {
      log.debug("Leaving OAuth2Server.parRequest(). authorization_details.");
      return refuse(400, 'invalid_authorization_details', details.error,
                    errorCodes.codeOf(details) || 'STS-OAUTH-0153');
    }
    const resources = self.parseResourceIndicators(q.resource);
    if (resources.error) {
      log.debug("Leaving OAuth2Server.parRequest(). resource.");
      return refuse(400, 'invalid_target', resources.error, 'STS-OAUTH-0154');
    }
    const permissionProblem = self.permissionRefusal(scope, clientId);
    if (permissionProblem) {
      log.debug("Leaving OAuth2Server.parRequest(). An ungranted permission.");
      return refuse(400, 'invalid_scope', permissionProblem, 'STS-OAUTH-0155');
    }
    // #110: the scopes this client may be issued, refused at the push for
    // the authorization endpoint's reason. See scopeRefusal().
    const scopeProblem = self.scopeRefusal(scope, clientId);
    if (scopeProblem) {
      log.debug("Leaving OAuth2Server.parRequest(). An undeclared scope.");
      // STS-OAUTH-0577 (protected) or STS-OAUTH-0578 (undeclared).
      return refuse(400, 'invalid_scope', scopeProblem.description,
                    scopeProblem.code);
    }
    // RFC 9396: details whose type belongs to one API beside a scope or
    // resource naming another are refused here, at the push, rather than when
    // the request_uri is used.
    const plan = self.accessTokenPlan(base, scope, clientId,
                                      resources.resources, details.details);
    if (plan.refusal) {
      log.debug("Leaving OAuth2Server.parRequest(). RFC 9068 refused the " +
                "audience.");
      return refuse(400, plan.refusal.error, plan.refusal.description,
                    errorCodes.codeOf(plan.refusal) || 'STS-OAUTH-0244');
    }
    const claimsProblem = self.parseClaimsRequest(q.claims);
    if (claimsProblem.error) {
      log.debug("Leaving OAuth2Server.parRequest(). The claims request.");
      return refuse(400, 'invalid_request', claimsProblem.error,
                    'STS-OAUTH-0157');
    }

    // --- 7. KEPT, AND ANSWERED
    // ------------------------------------------------
    // A PUSHED REQUEST OBJECT'S `jti` IS SPENT HERE (#35): the push is the
    // object's one use, and the URN answered below resolves to the kept
    // parameters without reading the object again. Below every refusal, so a
    // push refused for anything spends nothing, and bound to this response —
    // the 201 keeps it, a store refusal below releases it.
    if (pushedOnce) {
      const spent = await requestObject.spend({
        once: pushedOnce, request: req, clientId: clientId
      });
      if (!spent.ok) {
        log.debug("Leaving OAuth2Server.parRequest(). The request object's " +
                  "jti was not spent.");
        return refuse(spent.status || 400, spent.error, spent.description,
                      errorCodes.codeOf(spent) || 'STS-OAUTH-0374');
      }
    }
    const kept = par.push({
      clientId: clientId,
      authorizationServer: self.profileOf(req),
      params: q,
      clientAuthenticated: !!observation.authenticated,
      method: observation.authenticated ? String(observation.method || '') : '',
      source: source,
      alg: objectAlg,
      encrypted: objectEncrypted,
      dpopJkt: dpopJkt,
      redirectRelaxed: !!vetted.relaxed
    });
    if (!kept.ok) {
      log.debug("Leaving OAuth2Server.parRequest(). The store refused it.");
      return refuse(503, kept.error, kept.description,
                    errorCodes.codeOf(kept) || 'STS-OAUTH-0408');
    }
    applications.seen({
      identifier: clientId,
      kind: hasScope(scope, 'openid') ? 'oidc-relying-party' : 'oauth2-client',
      protocol: 'OAuth 2.0 / OIDC',
      counts: false,
      note: 'pushed an authorization request',
      fields: { oauthClientId: clientId,
                appAuthorizationServer: self.profileOf(req) }
    });
    res.status(201).type('application/json').send(JSON.stringify({
      request_uri: kept.requestUri,
      expires_in: kept.expiresIn
    }));
    log.debug("Leaving OAuth2Server.parRequest(). Pushed, " + kept.expiresIn +
              "s.");
    return undefined;
  }

  // --- introspection (RFC 7662, and RFC 9701's JWT response)
  // -------------------
  // ---------------------------------------------------------------------------
  // WHAT THE INTROSPECTION ENDPOINT DOES SINCE 2026-09-13, WHICH IS TWO THINGS.
  //
  // **RFC 7662 AS IT WAS**: a JSON object saying whether the token is active
  // and, if it is, what its claims are. Development answers anybody who holds
  // the token string, as it always did — every suite and client under test
  // introspects that way. PRODUCT MODE requires the caller to authenticate as a
  // client (`mode.opensIntrospection()`), which RFC 7662 section 2.1's "MUST
  // require some form of authorization" reads as, and answers one that does not
  // with section 2.3's 401 invalid_client.
  //
  // **RFC 9701 WHEN IT IS ASKED FOR**: a request whose Accept header names
  // `application/token-introspection+jwt` gets the same answer as a signed JWT,
  // addressed to the resource server that asked. That caller must authenticate
  // IN EVERY MODE, and is refused 400 when it does not — section 5's own
  // status, deliberately not RFC 6749's 401 — because a response whose `aud` is
  // "whoever sent this" is a signed statement addressed to nobody. The mode
  // does not move it: it is not a hardening on top of the feature, it is what
  // the feature is.
  //
  // **ONE AUTHENTICATION, THE TOKEN ENDPOINT'S.**
  // `bcp.observeClientAuthentication()` is the fact the token endpoint's role
  // gate already uses — all six methods, the used-assertion history, the
  // revocation check on a certificate — and the secret rate limit is the same
  // bucket, so a secret cannot be guessed at this endpoint that is throttled at
  // that one. A credential presented to a mode that does not require one is NOT
  // checked, which is what development did before.
  //
  // **A PROMISE CHAIN BEHIND A SYNCHRONOUS HANDLER**, for the UserInfo
  // response's reason: express 4 does not look at what a handler returns, and
  // both routes — `/oauth2/introspect` and `/:as/oauth2/introspect` through
  // `forProfile()` — call `introspectEndpoint()`, so the catch is here once
  // rather than on one of the two.
  // ---------------------------------------------------------------------------
  private introspectEndpoint(req: Req, res: Res): Json {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering the introspection endpoint.");
    self.introspectRequest(req, res).catch(function (e) {
      log.error(errorCodes.tag('STS-OAUTH-0294') +
                'the introspection endpoint ' +
                'failed: ' + (e && e.stack ? e.stack : e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-OAUTH-0294');
        self.oauthError(res, 500, 'server_error',
                        String((e && e.message) || e));
      }
    });
    log.debug("Leaving OAuth2Server.introspectEndpoint().");
  }

  // The RFC 7662 answer for one token, as the object the response carries.
  // `{ active: false }` and nothing else for a token that is not active — which
  // RFC 7662 section 2.2 permits and RFC 9701 section 5 REQUIRES of the JWT, so
  // the one function serves both shapes of response.
  private introspectionOf(token: Json): Json {
    const { stsCrypto, log, STS, dpop, stats, refreshTokenCrypto } = this.deps;
    log.debug("Entering OAuth2Server.introspectionOf().");
    const inactive = { active: false };
    if (!token) {
      log.debug("Leaving OAuth2Server.introspectionOf(). No token.");
      return inactive;
    }
    // An encrypted token is a refresh token: opened first, then verified like
    // everything else. One that will not open is simply not active — RFC 7662
    // section 2.2 says nothing more than that to anybody.
    let jws = token;
    if (refreshTokenCrypto.isEncrypted(token)) {
      try {
        jws = refreshTokenCrypto.open(token);
      } catch (e) {
        log.debug("Caught in OAuth2Server.introspectionOf(): the token does " +
                  "not open (" + e.message + "), so it is inactive.");
        log.debug("Leaving OAuth2Server.introspectionOf().");
        return inactive;
      }
    }
    let claims;
    try {
      claims = helpers.verifyOwnJws(jws);
    } catch (e) {
      // Expired, forged, or simply not one of ours.
      log.debug("Caught in OAuth2Server.introspectionOf(): the token does " +
                "not verify (" + e.message + "), so it is inactive.");
      log.debug("Leaving OAuth2Server.introspectionOf().");
      return inactive;
    }
    // AN UNENCRYPTED REFRESH TOKEN IS NOT ACTIVE, and neither is a JWE that
    // opened to anything but one: the refresh grant refuses both, and an
    // introspection that called one active would contradict the grant.
    if ((claims.typ === 'Refresh') !== (jws !== token)) {
      log.debug("Leaving OAuth2Server.introspectionOf(). A refresh token " +
                "that is not encrypted, or a JWE that is not a refresh token.");
      return inactive;
    }
    if (stats.isRevoked(claims.jti)) {
      log.debug("Leaving OAuth2Server.introspectionOf(). Revoked.");
      return inactive;
    }
    // JSON drops the members that are undefined, exactly as the response always
    // did; the JWT's claims are serialised the same way, so both shapes carry
    // the same members.
    const answer = JSON.parse(JSON.stringify({
      active: true,
      scope: claims.scope || '',
      client_id: claims.client_id,
      username: claims.username,
      // A bound token is not a Bearer token, and an introspection response that
      // says otherwise invites the caller to accept it as one.
      token_type: claims.typ === 'Refresh' ? 'refresh_token'
                                          : (dpop.jktOf(claims) ? 'DPoP' :
                                             'Bearer'),
      // RFC 9449 section 6.1 / RFC 7662: the confirmation travels to the
      // resource server so it can check the binding itself.
      cnf: claims.cnf,
      // RFC 9396 section 9.2: the resource server learns what the token
      // authorizes in detail the same way it learns its scope.
      authorization_details: claims.authorization_details,
      // RFC 9470 section 6.2: WHEN the person behind the token authenticated
      // and to what level, so a resource server that introspects rather than
      // reading a JWT can make the same step-up decision. Absent where the
      // token has no authentication behind it, for RFC 9068 section 2.2.1's
      // reason.
      acr: claims.acr, auth_time: claims.auth_time,
      exp: claims.exp, iat: claims.iat, nbf: claims.nbf,
      sub: claims.sub, aud: claims.aud, iss: claims.iss, jti: claims.jti
    }));
    log.debug("Leaving OAuth2Server.introspectionOf(). Active.");
    return answer;
  }

  // ---------------------------------------------------------------------------
  // WHO IS CALLING AN ENDPOINT THAT IS NOT THE TOKEN ENDPOINT (#102,
  // 2026-09-22), for the two that authenticate their caller as a client:
  // introspection (RFC 7662 section 2.1, RFC 9701 section 5) and revocation
  // (RFC 7009 section 2.1). It was introspection's own block until revocation
  // needed the same thing, and one copy is the point — a secret throttled at
  // one endpoint must not be guessable at the other, and a method advertised
  // for one must be verified the same way at the other.
  //
  // **WHAT IT DOES, IN ORDER.** The secret rate limit, the token endpoint's
  // bucket, before any secret is looked at; the advertised-method check
  // against the member `opts.capability` names, so a client declaring a
  // method the selected authorization server does not list is refused before
  // its credential is read; `bcp.observeClientAuthentication()`, all six
  // methods, with assertion audiences of this endpoint, the token endpoint,
  // the issuer and the base; and the failure counted, or the success settled.
  //
  // **A PUBLIC CLIENT IS THE ONE DIFFERENCE BETWEEN THE CALLERS.** RFC 7009
  // section 2.1 validates "the client credentials (in case of a confidential
  // client)", and section 5 expects a public client to revoke its own tokens
  // — so where `opts.allowPublic` is set, an entry declaring `none` is
  // IDENTIFIED by its registered client_id and let through as such. RFC 9701
  // needs a resource server it can address a signed answer to, so
  // introspection passes false and a public client is refused there as
  // before.
  //
  // **`opts.lenient`** is development's revocation with a credential (see
  // `mode.opensRevocation()`): a credential that FAILS is refused exactly as
  // in product, but one with nothing to check it against — an unknown
  // client_id, an entry with nothing on file, an entry declaring no method —
  // is not a failure, and the caller goes on unidentified, as it would have
  // with no credential at all.
  //
  // Resolves `{ ok: true, clientId, method, identified }` — `identified`
  // false only on the lenient path — or `{ ok: false }` with the refusal
  // already sent: `opts.refusal(observed, why)` says which code, status and
  // sentence, and whether a Basic caller gets the challenge.
  // ---------------------------------------------------------------------------
  private async authenticateEndpointCaller(req: Req, res: Res, body: Json,
                                           opts: Json): Promise<Json> {
    const { log, bcp, oauth21, applications, errorCodes,
            websecurity } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.authenticateEndpointCaller(). " +
              opts.endpoint);
    const client = self.clientFrom(req, body);
    const clientId = String(client.client_id || '');
    const registered = applications.clientConfigOf(clientId);
    const presented = self.presentedClientAuthentication(req, body);
    // THE SECRET RATE LIMIT, the token endpoint's bucket: a client and address
    // past the limit is answered before its secret is looked at.
    if (clientId && self.secretPresented(presented, registered)) {
      const key = self.secretLimitKey(req, clientId);
      const lockedOut = await websecurity.blockedShared(key.what, req,
                                                        key.identity);
      if (lockedOut) {
        res.set('Retry-After', String(lockedOut.retryAfterS));
        log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). Too " +
                  "many failed client secrets.");
        errorCodes.mark(res, 'STS-OAUTH-0284');
        self.oauthError(res, 429, 'invalid_client',
          'Too many failed client authentications for client "' + clientId +
          '" from this address. ' + lockedOut.detail);
        return { ok: false };
      }
    }
    // WHAT THIS AUTHORIZATION SERVER SAYS IT ACCEPTS, the token endpoint's
    // rule: a client whose entry declares a method the selected server does
    // not advertise is refused before its credential is read, so the sentence
    // is about the server's capabilities rather than about the credential. A
    // removed member means the check does not run.
    const advertisedAuth = self.capabilityFor(req, opts.capability);
    const declaredMethod = String(registered.token_endpoint_auth_method ||
                                  '');
    if (declaredMethod && advertisedAuth &&
        advertisedAuth.indexOf(declaredMethod) < 0) {
      log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). " +
                self.profileOf(req) + " does not advertise " +
                declaredMethod + " for " + opts.endpoint + ".");
      errorCodes.mark(res, opts.advertisedCode);
      // error-code: none — marked on the line above, with the caller's code.
      self.oauthError(res, opts.advertisedStatus, 'invalid_client',
        'The "' + self.profileOf(req) + '" authorization server advertises ' +
        opts.capability + ' ' + JSON.stringify(advertisedAuth) + ', and ' +
        'this client is configured for "' + declaredMethod + '". A client ' +
        'may use any authorization server here, but only in a way that ' +
        'server offers.');
      return { ok: false };
    }
    const base = self.asBaseOf(req);
    // What a client assertion may name as its audience: this endpoint, and
    // what the token endpoint accepts — the token endpoint URL, the issuer and
    // the base — because RFC 7523 section 3 says "the authorization server"
    // and a client library signs one assertion shape for every endpoint.
    const observed = await bcp.observeClientAuthentication({
      clientId: clientId,
      clientSecret: client.client_secret,
      assertion: client.assertion,
      assertionType: client.assertionType,
      request: req,
      audiences: [base + opts.path, base + '/oauth2/token',
                  self.issuerOf(base), base],
      strictAudience: (oauth21.strictClientAssertionAudience() ||
                       self.deps.fapi.strictAssertionAudience()) ?
                      self.issuerOf(base) : '',
      registered: registered
    });
    if (!observed.authenticated) {
      // A PUBLIC CLIENT, identified by the client_id its entry was registered
      // under. `STS-OAUTH-0194` is the observation that says exactly that and
      // nothing else: a known entry declaring `none`.
      if (opts.allowPublic && observed.errorCode === 'STS-OAUTH-0194') {
        log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). " +
                  "Public client " + clientId + ", identified by its " +
                  "client_id.");
        return { ok: true, clientId: clientId, method: 'none',
                 identified: true };
      }
      // Development's "nothing to check it against" — see the header.
      if (opts.lenient &&
          ['STS-OAUTH-0193', 'STS-OAUTH-0195',
           'STS-OAUTH-0553'].indexOf(String(observed.errorCode)) >= 0) {
        log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). " +
                  "Development: nothing to verify the credential against (" +
                  observed.errorCode + "), so the caller is unidentified.");
        return { ok: true, clientId: '', method: '', identified: false };
      }
      const overLimit = await self.countSecretFailure(req, clientId,
                                                      presented, registered);
      if (overLimit) {
        log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). Past " +
                  "the secret limit.");
        self.secretLockout(res, clientId, overLimit);
        return { ok: false };
      }
      const why = clientId ? observed.why
        : 'the request carried no client credential — no Authorization: ' +
          'Basic header, no client_id and client_secret, and no client ' +
          'assertion.';
      const refusal = opts.refusal(observed, why);
      log.info(errorCodes.tag(refusal.code) + opts.endpoint + ': client "' +
               (clientId || '(none)') + '" did not authenticate (' +
               (observed.errorCode || 'no credential') + '): ' + why);
      if (refusal.challenge && presented.basic) {
        res.set('WWW-Authenticate', self.basicChallenge());
      }
      log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). " +
                "Refused (" + refusal.code + ").");
      errorCodes.mark(res, refusal.code);
      // error-code: none — marked on the line above, with the caller's code.
      self.oauthError(res, refusal.status, 'invalid_client',
                      refusal.description);
      return { ok: false };
    }
    const racedOut = await self.settleSecretSuccess(req, clientId, presented,
                                                    registered);
    if (racedOut) {
      log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). A " +
                "verified secret past the limit.");
      self.secretLockout(res, clientId, racedOut);
      return { ok: false };
    }
    log.debug("Leaving OAuth2Server.authenticateEndpointCaller(). Client " +
              clientId + " authenticated with " + observed.method + " at " +
              opts.endpoint + ".");
    return { ok: true, clientId: clientId, method: observed.method,
             identified: true };
  }

  private async introspectRequest(req: Req, res: Res): Promise<Json> {
    const { log, baseUrlOf, parseBody, mode, oauth21,
            applications, validation, errorCodes,
            introspectionJwt } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.introspectRequest().");
    const posted = validation.checkParsed(parseBody(req), 'body',
                                          TOKEN_QUERY_FORM);
    res.set('Cache-Control', 'no-store');
    // The answer depends on the Accept header, so a cache that ignored it would
    // hand one resource server's JWT to a JSON client. `no-store` already keeps
    // shared caches out; this says why the two answers differ.
    res.set('Vary', 'Accept');
    if (!posted.ok) {
      log.debug("Leaving OAuth2Server.introspectRequest(). The request is " +
                "malformed.");
      errorCodes.mark(res, 'STS-OAUTH-0229');
      return self.oauthError(res, 400, 'invalid_request', posted.detail);
    }
    const body = posted.value;
    const wantsJwt = introspectionJwt.wantsJwt(req.headers['accept']);
    const client = self.clientFrom(req, body);
    let clientId = String(client.client_id || '');
    const registered = applications.clientConfigOf(clientId);
    const presented = self.presentedClientAuthentication(req, body);

    // OAUTH 2.1 SECTION 2.4 — "The client MUST NOT use more than one
    // authentication method in each request" — is a rule about a REQUEST, and
    // it was asked at the token endpoint alone. Asked here before anything is
    // verified, and whether or not this request had to authenticate: a request
    // carrying two credentials is malformed whichever of them would be read.
    const several = oauth21.multipleMethodsRefusal(presented);
    if (several) {
      log.debug("Leaving OAuth2Server.introspectRequest(). OAuth 2.1: " +
                "several client authentication methods.");
      errorCodes.mark(res, several.errorCode || 'STS-OAUTH-0281');
      return self.oauthError(res, 400, several.error, several.description);
    }

    // Whether the caller PROVED who it is, which is what section 5's "intended
    // for the resource server" rule is then asked of. False for a development
    // JSON request, which authenticates nobody and so cannot be compared.
    let authenticated = false;
    if (wantsJwt || !mode.opensIntrospection()) {
      const caller = await self.authenticateEndpointCaller(req, res, body, {
        endpoint: 'introspection',
        path: '/oauth2/introspect',
        capability: 'introspection_endpoint_auth_methods_supported',
        advertisedCode: 'STS-OAUTH-0295',
        advertisedStatus: wantsJwt ? 400 : 401,
        allowPublic: false,
        refusal: function (observed: Json, why: string): Json {
          if (!wantsJwt) {
            // RFC 7662 section 2.3 answers as RFC 6749 section 5.2 does, and
            // a client_secret_basic caller needs the challenge to know what
            // to retry.
            return { code: 'STS-OAUTH-0292', status: 401, challenge: true,
                     description: 'This realm is in product mode, where ' +
                       'introspection requires the caller to authenticate ' +
                       'as a client (RFC 7662 section 2.1) — and ' + why };
          }
          return { code: 'STS-OAUTH-0291', status: 400, challenge: false,
                   description: 'RFC 9701 section 5: a JWT introspection ' +
                     'response is addressed to the resource server that ' +
                     'asks for it, so the caller must authenticate as a ' +
                     'client — and ' + why };
        }
      });
      if (!caller.ok) {
        log.debug("Leaving OAuth2Server.introspectRequest(). The caller " +
                  "did not authenticate.");
        return undefined;
      }
      clientId = caller.clientId;
      authenticated = true;
    }

    // SECTION 5's "not intended to be introspected by the resource server",
    // asked of every caller that authenticated — see `intendedFor()` for the
    // rule rcbj chose. A token that is not the caller's is answered exactly as
    // an invalid one, so the two cannot be told apart.
    let answer = self.introspectionOf(String(body.token || ''));
    if (authenticated && answer.active === true &&
        !introspectionJwt.intendedFor(answer, clientId, baseUrlOf(req))) {
      log.info('introspection: client "' + clientId + '" asked about a token ' +
               'not intended for it (client_id ' + answer.client_id + ', aud ' +
               JSON.stringify(answer.aud) + '), answered as inactive.');
      answer = { active: false };
    }
    if (!wantsJwt) {
      res.status(200).type('application/json').send(JSON.stringify(answer));
      log.debug("Leaving OAuth2Server.introspectRequest(). JSON, active=" +
                answer.active +
                ".");
      return undefined;
    }
    // WHAT THE SELECTED AUTHORIZATION SERVER PUBLISHES, which a profile may
    // narrow (`authorization_servers.ts`). A registration outside it is the
    // client's refusal, answered before anything is signed; one this service
    // cannot honour at all is the 500 below.
    const resourceServer = Object.assign({}, registered,
                                         { client_id: clientId });
    const advertised = {
      signing: self.capabilityFor(req,
        'introspection_signing_alg_values_supported'),
      encryption: self.capabilityFor(req,
        'introspection_encryption_alg_values_supported'),
      enc: self.capabilityFor(req,
        'introspection_encryption_enc_values_supported')
    };
    const protection = introspectionJwt.protectionFor(resourceServer,
                                                      advertised);
    if (!protection.ok && protection.notAdvertised) {
      log.debug("Leaving OAuth2Server.introspectRequest(). " +
                self.profileOf(req) + " does not " +
                "advertise what this client registered.");
      errorCodes.mark(res, errorCodes.codeOf(protection) || 'STS-OAUTH-0296');
      return self.oauthError(res, 400, 'invalid_client',
                             protection.description);
    }
    let out;
    try {
      out = await introspectionJwt.respond({
        introspection: answer,
        issuer: self.issuerOf(self.asBaseOf(req)),
        client: resourceServer,
        advertised: advertised
      });
    } catch (e) {
      // Every sentence respond() rejects with is about what this client
      // registered, so it goes back as the description — the UserInfo
      // response's reasoning, and its 500: the registration was accepted, or an
      // ldapmodify wrote it, and it cannot now be honoured.
      log.error(errorCodes.tag('STS-OAUTH-0293') + 'introspection: the JWT ' +
                'response registered by client "' + clientId + '" could not ' +
                'be produced: ' + e.message);
      errorCodes.mark(res, 'STS-OAUTH-0293');
      log.debug("Leaving OAuth2Server.introspectRequest(). The JWT could not " +
                "be produced.");
      return self.oauthError(res, 500, 'server_error', e.message);
    }
    // A BUFFER, so express sends the media type exactly as section 5 names it
    // rather than appending a charset parameter to a type that has none.
    res.status(200).set('Content-Type', out.contentType)
       .send(Buffer.from(out.body, 'utf8'));
    log.debug("Leaving OAuth2Server.introspectRequest(). JWT for " +
              clientId + ", alg=" +
              out.alg + (out.enc ? ', encrypted ' + out.enc : '') +
              ", active=" + answer.active + ".");
    return undefined;
  }

  // --- revocation (RFC 7009)
  // ---------------------------------------------------------------------------
  // WHAT THE REVOCATION ENDPOINT DOES SINCE #102 (2026-09-22). Until then it
  // revoked the jti of ANY JWS this realm had signed, for anybody who held
  // the string, answered 200 to a request with no token at all, and left the
  // rest of a refresh token's grant alive. RFC 7009, section by section:
  //
  //   * **SECTION 2.1's `token` IS REQUIRED**: a request without one is 400
  //     `invalid_request` (`STS-OAUTH-0608`), in both modes.
  //   * **THE CLIENT FIRST.** "The authorization server first validates the
  //     client credentials (in case of a confidential client) and then
  //     verifies whether the token was issued to the client making the
  //     revocation request." In product (`mode.opensRevocation()`) every
  //     request is asked: a confidential client presents a credential that
  //     verifies (`STS-OAUTH-0609`), a public one names its registered
  //     client_id (`STS-OAUTH-0610` when it names nothing registered).
  //     Development asks only a caller that PRESENTED a credential — and holds
  //     that one to the same refusals, so a client under test that
  //     authenticates meets them. `authenticateEndpointCaller()` is shared
  //     with introspection, rate limit and all.
  //   * **SECTION 2.2's 200 FOR AN INVALID TOKEN**, unchanged: one that does
  //     not open or verify, or a refresh token that is not the JWE this realm
  //     issues, is answered 200 with nothing revoked.
  //   * **SECTION 2.2.1's `unsupported_token_type` FOR ANYTHING THAT IS NOT AN
  //     ACCESS OR A REFRESH TOKEN** (`STS-OAUTH-0611`) — an ID Token, a
  //     logout token, a SET: valid tokens this realm signed, of a type this
  //     server does not revoke. Chosen over section 2.2's quiet 200, which is
  //     for an INVALID token "since the client cannot handle such an error in
  //     a reasonable way"; an ID Token is not invalid, and section 2.2.1
  //     defines this error for exactly the case of a server "not supporting
  //     [the revocation of] the presented token type". A 200 would tell the
  //     client something was revoked when nothing was, and the ID Token
  //     cannot be withdrawn anyway — nothing presents it back here.
  //   * **ANOTHER CLIENT'S TOKEN IS REFUSED `invalid_grant`** (`STS-OAUTH-
  //     0606`), which is RFC 6749 section 5.2's word for a grant "issued to
  //     another client", and nothing is revoked. Section 2.1 says the request
  //     "is refused and the client is informed of the error"; answering 200
  //     would have been the refusal pretending to be a success. The caller
  //     already holds the token string, so the refusal teaches it nothing it
  //     did not know. The row on the audit log names both clients.
  //   * **A REFRESH TOKEN TAKES ITS GRANT WITH IT.** Section 2.1: revoking a
  //     refresh token SHOULD also invalidate the access tokens "based on the
  //     same authorization grant", and here it does — every refresh token of
  //     its family and every access token minted beside one
  //     (`bcp.grantMembersOf()`), through `stats.revoke()`, and the family by
  //     id for every node (`bcp.revokeFamily()`). **This is NOT
  //     `oauth2_bcp.js`'s replay rule**, which deliberately leaves the access
  //     tokens alone: a replay is this server DETECTING a copied chain and
  //     keeping the evidence of what it was used for, while a revocation is
  //     the CLIENT saying it is finished with the grant. An access token keeps
  //     the section's MAY unexercised: revoking one revokes that token alone.
  //
  // **A PROMISE CHAIN BEHIND A SYNCHRONOUS HANDLER**, for
  // `introspectEndpoint()`'s reason: both routes call this, so the catch is
  // here once.
  // ---------------------------------------------------------------------------
  private revokeEndpoint(req: Req, res: Res): Json {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.revokeEndpoint().");
    self.revokeRequest(req, res).catch(function (e) {
      log.error(errorCodes.tag('STS-OAUTH-0614') +
                'the revocation endpoint failed: ' +
                (e && e.stack ? e.stack : e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-OAUTH-0614');
        self.oauthError(res, 500, 'server_error',
                        String((e && e.message) || e));
      }
    });
    log.debug("Leaving OAuth2Server.revokeEndpoint().");
  }

  // Which kind of token RFC 7009 was handed, once it has opened and verified:
  // 'access', 'refresh', or 'other' for a token this realm signed that is
  // neither. An access token is RFC 9068's `at+jwt` by its protected header,
  // or this service's own `typ: Bearer` claim, which every access token here
  // has carried beside it; a refresh token is the `Refresh` JWS this realm
  // seals as a JWE — and one that arrived unsealed is not one it issued,
  // which is `null`: an invalid token, answered as section 2.2 says.
  private revocableKindOf(jws: string, claims: Json,
                          sealed: boolean): string | null {
    const { log, jwtAccessToken } = this.deps;
    log.debug("Entering OAuth2Server.revocableKindOf().");
    if (claims.typ === 'Refresh' || sealed) {
      log.debug("Leaving OAuth2Server.revocableKindOf(). " +
                ((claims.typ === 'Refresh') === sealed ? "A refresh token."
                  : "A refresh token not sealed, or a JWE that is not one."));
      return (claims.typ === 'Refresh') === sealed ? 'refresh' : null;
    }
    const access =
      jwtAccessToken.isAccessTokenType(jwtAccessToken.typOf(jws)) ||
      claims.typ === 'Bearer';
    log.debug("Leaving OAuth2Server.revocableKindOf(). " +
              (access ? "An access token." : "Neither."));
    return access ? 'access' : 'other';
  }

  private async revokeRequest(req: Req, res: Res): Promise<Json> {
    const { log, parseBody, stats, validation, errorCodes, mode, bcp, oauth21,
            refreshTokenCrypto, audit } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.revokeRequest().");
    // Every answer this endpoint gives, the refusals included, is about a
    // credential — so none of them is cached.
    res.set('Cache-Control', 'no-store');
    const posted = validation.checkParsed(parseBody(req), 'body',
                                          REVOCATION_FORM);
    if (!posted.ok) {
      log.debug("Leaving OAuth2Server.revokeRequest(). The request is " +
                "malformed.");
      errorCodes.mark(res, 'STS-OAUTH-0230');
      return self.oauthError(res, 400, 'invalid_request', posted.detail);
    }
    const body = posted.value;
    const token = String(body.token || '');
    if (!token) {
      log.debug("Leaving OAuth2Server.revokeRequest(). No token.");
      errorCodes.mark(res, 'STS-OAUTH-0608');
      return self.oauthError(res, 400, 'invalid_request',
        'RFC 7009 section 2.1: the token parameter is REQUIRED — the ' +
        'request names nothing to revoke.');
    }
    // OAuth 2.1 section 2.4, introspection's reason: a request carrying two
    // credentials is malformed whichever of them would be read.
    const presented = self.presentedClientAuthentication(req, body);
    const several = oauth21.multipleMethodsRefusal(presented);
    if (several) {
      log.debug("Leaving OAuth2Server.revokeRequest(). OAuth 2.1: several " +
                "client authentication methods.");
      errorCodes.mark(res, several.errorCode || 'STS-OAUTH-0281');
      return self.oauthError(res, 400, several.error, several.description);
    }

    // THE CLIENT. A certificate is not counted as "presented" in development:
    // the main port asks every connection for one, so a browser that happens
    // to hold one would otherwise be authenticated on a request it never
    // meant to authenticate. Product asks every request, certificates
    // included.
    const credentialPresented = !!(presented.basic || presented.bodySecret ||
                                   presented.assertion);
    let caller: Json = { ok: true, clientId: '', method: '',
                         identified: false };
    if (!mode.opensRevocation() || credentialPresented) {
      caller = await self.authenticateEndpointCaller(req, res, body, {
        endpoint: 'revocation',
        path: '/oauth2/revoke',
        capability: 'revocation_endpoint_auth_methods_supported',
        advertisedCode: 'STS-OAUTH-0613',
        advertisedStatus: 401,
        allowPublic: true,
        lenient: mode.opensRevocation(),
        refusal: function (observed: Json, why: string): Json {
          const unknown = observed.errorCode === 'STS-OAUTH-0193';
          return { code: unknown ? 'STS-OAUTH-0610' : 'STS-OAUTH-0609',
                   status: 401, challenge: true,
                   description: 'RFC 7009 section 2.1: the revocation ' +
                     'endpoint validates the client before the token' +
                     (mode.opensRevocation() ? ', and a credential was ' +
                       'presented'
                       : ' — this realm is in product mode, where every ' +
                         'revocation request comes from a client') +
                     ' — and ' + why };
        }
      });
      if (!caller.ok) {
        log.debug("Leaving OAuth2Server.revokeRequest(). The caller was " +
                  "refused.");
        return undefined;
      }
    }

    // THE TOKEN. An encrypted refresh token is opened first; `open()` throws
    // for one this realm cannot open, which RFC 7009 answers exactly as an
    // invalid token.
    const sealed = refreshTokenCrypto.isEncrypted(token);
    let jws = token;
    let claims: Json = null;
    try {
      jws = sealed ? refreshTokenCrypto.open(token) : token;
      claims = helpers.verifyOwnJws(jws);
    } catch (e) {
      log.debug("Caught in OAuth2Server.revokeRequest(): the token does not " +
                "verify (" + ((e && e.message) || e) + ").");
      claims = null;
    }
    const kind = claims ? self.revocableKindOf(jws, claims, sealed) : null;
    if (!kind) {
      // SECTION 2.2: "invalid tokens do not cause an error response".
      res.status(200).end();
      log.debug("Leaving OAuth2Server.revokeRequest(). An invalid token; " +
                "nothing to revoke.");
      return undefined;
    }
    if (kind === 'other') {
      log.debug("Leaving OAuth2Server.revokeRequest(). Not an access or a " +
                "refresh token (typ " + (claims.typ || '(none)') + ").");
      errorCodes.mark(res, 'STS-OAUTH-0611');
      return self.oauthError(res, 400, 'unsupported_token_type',
        'RFC 7009 section 2.2.1: this authorization server revokes access ' +
        'tokens and refresh tokens, and the token presented is neither' +
        (claims.typ ? ' (typ "' + claims.typ + '")' : '') + ' — an ID ' +
        'Token, for one, is not revocable here. Nothing was revoked.');
    }
    const owner = String(claims.client_id || claims.azp || '');
    if (caller.identified && owner !== caller.clientId) {
      audit.record({
        action: 'oauth.token.revoke', actor: caller.clientId,
        target: owner || '(no client)', protocol: 'OAuth 2.0 / OIDC',
        channel: 'http', outcome: 'refused', errorCode: 'STS-OAUTH-0612',
        detail: 'client "' + caller.clientId + '" asked to revoke a ' + kind +
                ' token issued to "' + (owner || '(no client)') + '", jti ' +
                (claims.jti || '(none)')
      });
      log.info(errorCodes.tag('STS-OAUTH-0612') + 'revocation: client "' +
               caller.clientId + '" asked to revoke a ' + kind + ' token ' +
               'issued to "' + (owner || '(no client)') + '". Refused; ' +
               'nothing was revoked.');
      log.debug("Leaving OAuth2Server.revokeRequest(). Another client's " +
                "token.");
      errorCodes.mark(res, 'STS-OAUTH-0612');
      return self.oauthError(res, 400, 'invalid_grant',
        'RFC 7009 section 2.1: this token was issued to another client, and ' +
        'a client may revoke only its own. Nothing was revoked.');
    }

    const via = 'the RFC 7009 revocation endpoint';
    const revoked: string[] = [];
    if (claims.jti && stats.revoke(claims.jti, via)) {
      revoked.push(String(claims.jti));
    }
    if (kind === 'refresh') {
      // THE GRANT: every refresh token of the family and every access token
      // minted beside one, as the header above argues; and the family BY ID,
      // so a member minted on another node at this moment is refused at its
      // first use.
      const family = bcp.familyOfRefresh(claims);
      bcp.grantMembersOf(family, claims.jti).forEach(function (jti: string) {
        if (stats.revoke(jti, via + ', with the refresh token of its grant')) {
          revoked.push(jti);
        }
      });
      if (family) {
        await bcp.revokeFamily(family, owner);
      }
    }
    audit.record({
      action: 'oauth.token.revoke', actor: caller.clientId || '',
      target: owner || '(no client)', protocol: 'OAuth 2.0 / OIDC',
      channel: 'http', outcome: 'success',
      detail: (caller.identified ? 'client "' + caller.clientId + '"'
                                 : 'an unidentified caller (development)') +
              ' revoked a ' + kind + ' token issued to "' +
              (owner || '(no client)') + '"; ' + revoked.length +
              ' jti(s) newly revoked'
    });
    res.status(200).end();
    log.debug("Leaving OAuth2Server.revokeRequest(). A " + kind + " token; " +
              revoked.length + " jti(s) newly revoked, " +
              stats.revokedCount() + " revoked so far.");
    return undefined;
  }

  // --- dynamic client registration (RFC 7591) + management (RFC 7592)
  // ----------
  // ---------------------------------------------------------------------------
  // IS RFC 7591 REGISTRATION OPEN TO ANYBODY WHO CAN REACH THIS PORT?
  //
  // In development, always: it is how a client under test registers itself, and
  // it is on `mode.js`'s list of test controls by name. In a product realm only
  // when `oauth2.openRegistration` says so, because an open registration
  // endpoint is a door through which anybody mints a CONFIDENTIAL client of
  // this authorization server — and product mode's third requirement is that
  // every application holds a secret somebody administering the service gave
  // it. RFC 7591 section 3 anticipates exactly this with the initial access
  // token; this service issues none, so the product-mode answer is the setting,
  // and the way to create an application there is the console or /admin-api.
  //
  // One function, read by the endpoint AND by the metadata, so the two cannot
  // disagree about whether the endpoint exists.
  // ---------------------------------------------------------------------------
  registrationOpen(): Json {
    const { log, mode, config } = this.deps;
    log.debug("Entering OAuth2Server.registrationOpen().");
    log.debug("Leaving OAuth2Server.registrationOpen().");
    return mode.opensTestControls() ||
           config.value('oauth2.openRegistration') === true;
  }

  // ---------------------------------------------------------------------------
  // MAY ANYBODY REGISTER AT ALL? Open, or closed with a door a trusted software
  // statement goes through (`oauth2.softwareStatementOpensRegistration`). The
  // discovery documents read THIS, so an endpoint that admits a client carrying
  // a statement is still advertised — RFC 7591 section 3 is exactly that client
  // finding the endpoint in the metadata and bringing its statement.
  // ---------------------------------------------------------------------------
  registrationReachable(): Json {
    const { log, softwareStatement } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.registrationReachable().");
    log.debug("Leaving OAuth2Server.registrationReachable().");
    return self.registrationOpen() || softwareStatement.opensRegistration();
  }

  // The lifetime `client_secret_expires_at` publishes, as an absolute time or
  // 0. RFC 7591 section 3.2.1: 0 means the secret does not expire, which is the
  // default and what this service always said.
  private registeredSecretExpiry(issuedAt: Json): Json {
    const { log, config } = this.deps;
    log.debug("Entering OAuth2Server.registeredSecretExpiry().");
    const seconds = Number(config.value('oauth2.registeredSecretLifetimeS'));
    log.debug("Leaving OAuth2Server.registeredSecretExpiry().");
    return isFinite(seconds) && seconds > 0 ?
      issuedAt + Math.floor(seconds) : 0;
  }

  private clientRecord(base: Json, metadata: Json, clientId: Json,
                       secret: Json, token: Json): Json {
    const { log, nowSec } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.clientRecord(). client_id=" + clientId);
    const issuedAt = nowSec();
    const record = Object.assign({}, self.withRegistrationDefaults(metadata), {
      client_id: clientId,
      client_id_issued_at: issuedAt,
      client_secret: secret,
      // `oauth2.registeredSecretLifetimeS`; 0 = never, the default.
      client_secret_expires_at: self.registeredSecretExpiry(issuedAt),
      registration_access_token: token,
      registration_client_uri: base + '/oauth2/register/' + clientId
    });
    // A PUBLIC CLIENT IS ISSUED NO SECRET (#120): `none` authenticates with
    // nothing, and a secret it holds is a credential nobody checks.
    if (record.token_endpoint_auth_method === 'none') {
      delete record.client_secret;
      delete record.client_secret_expires_at;
    }
    log.debug("Leaving OAuth2Server.clientRecord().");
    return record;
  }

  // -------------------------------------------------------------------------
  // Every client a request NAMES, read unverified, for the key prefetch
  // above (#120): `client_id` in the query or a form body, the Basic user, a
  // client assertion's `sub`, and the `client_id` claim of a presented access
  // token (UserInfo has no other). Chooses what is fetched and nothing else.
  // -------------------------------------------------------------------------
  presentedClientIdsOf(req: Req): string[] {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.presentedClientIdsOf().");
    const ids: string[] = [];
    const add = function (value: any): void {
      const id = typeof value === 'string' ? value : '';
      if (id && id.length <= 512 && ids.indexOf(id) < 0) {
        ids.push(id);
      }
    };
    const payloadOf = function (jwt: any): any {
      try {
        return JSON.parse(Buffer.from(String(jwt || '').split('.')[1] || '',
                                      'base64url').toString('utf8'));
      } catch (e) {
        log.debug("Caught in OAuth2Server.presentedClientIdsOf(): " +
                  ((e && e.message) || e));
        // Not a JWT: it names nobody.
        return null;
      }
    };
    const query = req.query || {};
    add(query.client_id);
    const type = String((req.headers || {})['content-type'] || '');
    if (/^application\/x-www-form-urlencoded/i.test(type) &&
        typeof req.body === 'string') {
      const form = new URLSearchParams(req.body);
      add(form.get('client_id'));
      const assertion = payloadOf(form.get('client_assertion'));
      add(assertion && assertion.sub);
      const token = payloadOf(form.get('access_token'));
      add(token && token.client_id);
    }
    const authorization = String((req.headers || {}).authorization || '');
    const basic = /^Basic\s+(\S+)$/i.exec(authorization);
    if (basic) {
      const user = Buffer.from(basic[1], 'base64').toString('utf8')
        .split(':')[0];
      try {
        add(decodeURIComponent(user));
      } catch (e) {
        log.debug("Caught in OAuth2Server.presentedClientIdsOf(): " +
                  ((e && e.message) || e));
        // Not form-encoded: taken as it is.
        add(user);
      }
    }
    const bearer = /^(?:Bearer|DPoP)\s+(\S+)$/i.exec(authorization);
    if (bearer) {
      const token = payloadOf(bearer[1]);
      add(token && token.client_id);
    }
    log.debug("Leaving OAuth2Server.presentedClientIdsOf(). " + ids.length +
              " client(s).");
    return ids;
  }

  // -------------------------------------------------------------------------
  // THE ENCRYPTION-KEY READERS ARE SYNCHRONOUS (#120), so a registration whose
  // keys are at a `jwks_uri` and which asks for an encrypted response (the ID
  // Token, UserInfo, RFC 9701 introspection, JARM) has the set fetched here,
  // before the key checks read `client_jwks.js`'s cache. Only an https URI:
  // anything else is refused by `oidcRegistrationProblem()` below and is not
  // dialled first. A failed fetch refuses nothing by itself — the key check
  // that needed it does, naming the fetch.
  // -------------------------------------------------------------------------
  async prefetchRegisteredKeys(metadata: Json): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering OAuth2Server.prefetchRegisteredKeys().");
    const m = metadata || {};
    const wantsKey = ['id_token_encrypted_response_alg',
                      'userinfo_encrypted_response_alg',
                      'introspection_encrypted_response_alg',
                      'authorization_encrypted_response_alg']
      .some(function (member: string): boolean {
        return !!m[member];
      });
    if (!wantsKey || m.jwks || typeof m.jwks_uri !== 'string' ||
        !/^https:\/\//i.test(m.jwks_uri)) {
      log.debug("Leaving OAuth2Server.prefetchRegisteredKeys(). Nothing to " +
                "fetch.");
      return;
    }
    await clientJwks.ensure(m.jwks_uri, '');
    log.debug("Leaving OAuth2Server.prefetchRegisteredKeys().");
  }

  // -------------------------------------------------------------------------
  // RFC 7591 SECTION 3.2.1 (#120): "the authorization server MUST return all
  // registered metadata about the client, including any fields provisioned by
  // the authorization server itself" — so the defaults section 2 and OpenID
  // Connect Registration section 2 name are APPLIED, stored and returned:
  // `token_endpoint_auth_method` client_secret_basic, `grant_types`
  // authorization_code, `response_types` code, `application_type` web. The
  // grant and response types are what the endpoints then hold the client to.
  // -------------------------------------------------------------------------
  withRegistrationDefaults(metadata: Json): Json {
    const { log, applications } = this.deps;
    log.debug("Entering OAuth2Server.withRegistrationDefaults().");
    const lists = applications.grantsAndResponseTypesOf(metadata);
    const out = Object.assign({}, metadata, {
      token_endpoint_auth_method:
        String((metadata || {}).token_endpoint_auth_method ||
               'client_secret_basic'),
      grant_types: lists.grant_types,
      response_types: lists.response_types,
      application_type: String((metadata || {}).application_type || 'web')
    });
    log.debug("Leaving OAuth2Server.withRegistrationDefaults().");
    return out;
  }

  // THE WRAPPER, because the endpoint below is asynchronous since software
  // statements (2026-09-13) — verifying one may consult a foreign OCSP
  // responder — and both routes, `/oauth2/register` and `/:as/oauth2/register`,
  // call a function that returns nothing. The token endpoint's arrangement.
  private registerEndpoint(req: Req, res: Res): Json {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.registerEndpoint().");
    self.registerClient(req, res).catch(function (e) {
      log.error(errorCodes.tag('STS-OAUTH-0228') +
                'the registration endpoint ' +
                'failed: ' + (e && e.stack ? e.stack : e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-OAUTH-0228');
        self.oauthError(res, 500, 'server_error', e.message);
      }
    });
    log.debug("Leaving OAuth2Server.registerEndpoint().");
  }

  // RFC 8705 SECTION 3.4 AT REGISTRATION (2026-09-13): a client asking for
  // certificate-bound access tokens from a service whose main port is not TLS
  // is asking for something this server will refuse at every token request —
  // the declaration is held to in every mode (`mtls.declaredRefusal()`) and
  // there is no certificate to bind to — so it is refused here, where section
  // 3.2.2 can still say so, and `tls_client_certificate_bound_access_tokens` is
  // `false` in the metadata it read. 3f's mirror rule. The grammar of the
  // member is `applications.mtlsMetadataProblem()`'s; this knows the port.
  private mtlsRegistrationProblem(metadata: Json): Json {
    const { log, mtls } = this.deps;
    log.debug("Entering OAuth2Server.mtlsRegistrationProblem().");
    if ((metadata || {}).tls_client_certificate_bound_access_tokens === true &&
        !mtls.available()) {
      log.debug("Leaving OAuth2Server.mtlsRegistrationProblem(). No TLS " +
                "listener to bind on.");
      return { errorCode: 'STS-REG-0133', error: 'invalid_client_metadata',
               description: 'tls_client_certificate_bound_access_tokens is ' +
                 'true, and this authorization server\'s token endpoint is ' +
                 'not on a TLS listener (global.https is off), so there is ' +
                 'no client certificate to bind a token to. Its metadata ' +
                 'advertises tls_client_certificate_bound_access_tokens: ' +
                 'false.' };
    }
    log.debug("Leaving OAuth2Server.mtlsRegistrationProblem().");
    return null;
  }

  // ---------------------------------------------------------------------------
  // RFC 7591 SECTION 2's `scope` AT REGISTRATION (#110, 2026-09-22). The member
  // is written to `oauthAllowedScope` — the list the client may be issued —
  // so a registration naming this service's own protected scopes would be a
  // client granting itself Admin Write, SCIM or Shared Signals. Section 2
  // lets the server refuse or replace what it will not accept; refused
  // (`invalid_client_metadata`, section 3.2.2), so the client is told rather
  // than holding a registration that says something this server will never
  // issue. An RFC 7592 update may KEEP a protected scope an administrator
  // already declared on the entry — `existing` — and may not add one.
  // ---------------------------------------------------------------------------
  private registeredScopeProblem(metadata: Json, existing?: string): Json {
    const { log, scopePolicy, applications } = this.deps;
    log.debug("Entering OAuth2Server.registeredScopeProblem().");
    const raw = (metadata || {}).scope;
    if (raw === undefined || raw === null) {
      log.debug("Leaving OAuth2Server.registeredScopeProblem(). No scope.");
      return null;
    }
    if (typeof raw !== 'string') {
      log.debug("Leaving OAuth2Server.registeredScopeProblem(). Not a string.");
      return { errorCode: 'STS-REG-0173', error: 'invalid_client_metadata',
               description: 'scope must be a string of space-separated ' +
                 'scope values (RFC 7591 section 2).' };
    }
    const held = existing ? (applications.allowedScopesOf(existing) || []) :
      [];
    const refused = scopePolicy.split(raw).filter(function (one) {
      return scopePolicy.isProtected(one) && held.indexOf(one) < 0;
    });
    if (refused.length) {
      log.debug("Leaving OAuth2Server.registeredScopeProblem(). Protected.");
      return { errorCode: 'STS-REG-0173', error: 'invalid_client_metadata',
               description: 'scope names ' + refused.map(function (one) {
                 return '"' + one + '"';
               }).join(', ') + ', and ' +
                 (refused.length === 1 ? 'that is' : 'those are') + ' this ' +
                 'service\'s own protected ' +
                 (refused.length === 1 ? 'scope' : 'scopes') + ': a client ' +
                 'is issued one only when an administrator declares it in ' +
                 'the client\'s oauthAllowedScope, on the console or ' +
                 'through POST /admin-api/applications/add. Register ' +
                 'without it.' };
    }
    log.debug("Leaving OAuth2Server.registeredScopeProblem().");
    return null;
  }

  // A refusal `software_statement.ts` decided, answered. Both of RFC 7591
  // section 3.2.2's statement errors are a 400.
  private statementRefused(res: Res, refusal: Json): Json {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.statementRefused(). code=" +
              refusal.errorCode);
    errorCodes.mark(res, refusal.errorCode || 'STS-OAUTH-0309');
    log.debug("Leaving OAuth2Server.statementRefused().");
    return self.oauthError(res, 400, refusal.error, refusal.description);
  }

  private async registerClient(req: Req, res: Res): Promise<Json> {
    const { log, baseUrlOf, randomId, parseBody,
            softwareStatement, config, bcp, applications,
            validation, errorCodes, idTokenEncryption,
            pairwiseSubjects } = this.deps;
    const self = this;
    log.debug("Entering the client registration endpoint.");
    const base = baseUrlOf(req);
    const open = self.registrationOpen();
    if (!open && !softwareStatement.opensRegistration()) {
      log.warn('oauth2: a dynamic client registration was refused — this ' +
               'realm is in product mode and oauth2.openRegistration is off.');
      log.debug("Leaving the client registration endpoint. Registration is " +
                "closed.");
      errorCodes.mark(res, 'STS-OAUTH-0231');
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.oauthError(res, 403, 'access_denied',
        'Dynamic client registration is closed: this realm is in product ' +
        'mode, where an application is created by an administrator — on ' +
        '/admin/applications/new or with POST ' +
        '/admin-api/applications/create. Set oauth2.openRegistration to let ' +
        'anybody who can reach this ' +
        'endpoint register a client.');
    }
    // ---------------------------------------------------------------------
    // `checkDocument()` AND NOT A SCHEMA, AND THIS IS THE ENDPOINT THAT
    // ARGUMENT WAS WRITTEN FOR.
    //
    // RFC 7591 section 2 lets a client register ANY metadata it likes, and
    // `applications.js` keeps the whole document verbatim in
    // `appRegistrationJson` precisely because no fixed attribute set can
    // represent it. So the shape is not this service's to decide: the very
    // next line expects `redirect_uris` to be an ARRAY, and `jwks` is a
    // nested object. Running the scalar-enforcing `checkParsed()` over this
    // would refuse every conforming client registration in existence.
    //
    // What IS checked is what is true of any JSON this service accepts: no
    // `__proto__` at any depth, a bounded nesting and a bounded key count.
    // The pollution case is real rather than theoretical here — this
    // document is stored and later rebuilt into a client record with
    // attributes merged over it.
    // ---------------------------------------------------------------------
    const document = validation.checkDocument(parseBody(req), 'registration');
    if (!document.ok) {
      log.debug("Leaving the client registration endpoint. The document is " +
                "refused: " +
                document.code + ".");
      errorCodes.mark(res, 'STS-OAUTH-0232');
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.oauthError(res, 400, 'invalid_client_metadata',
                             document.detail);
    }
    // ---------------------------------------------------------------------
    // THE SOFTWARE STATEMENT, BEFORE ANY OTHER CHECK OF THE METADATA, because
    // a TRUSTED one decides what the metadata IS (RFC 7591 section 3.1.1: its
    // claims take precedence) — every check below runs on the merged document,
    // so a statement cannot fix a `javascript:` redirect URI or a grant RFC
    // 9700 mode refuses any more than the JSON can.
    //
    // AND IT IS THE SECOND DOOR THROUGH A CLOSED ENDPOINT. Where registration
    // is not open to everybody, only a statement this realm TRUSTS admits the
    // client; an untrusted one — accepted unverified with the issuer refusal
    // off — does not, and neither does none.
    // ---------------------------------------------------------------------
    const resolved = await softwareStatement.resolve(document.value,
                                                     { base: base });
    if (!open && !(resolved.ok && resolved.statement &&
                   resolved.statement.trusted)) {
      if (!resolved.ok && document.value.software_statement !== undefined) {
        log.debug("Leaving the client registration endpoint. Closed, and the " +
                  "statement that could have opened it was refused.");
        log.debug("Leaving OAuth2Server.registerClient().");
        return self.statementRefused(res, resolved);
      }
      log.warn('oauth2: a dynamic client registration was refused — this ' +
               'realm is in product mode, oauth2.openRegistration is off, ' +
               'and the ' +
               'registration carried no trusted software statement.');
      errorCodes.mark(res, 'STS-OAUTH-0231');
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.oauthError(res, 403, 'access_denied',
        'Dynamic client registration is closed to a registration without a ' +
        'trusted software statement: this realm is in product mode, where an ' +
        'application is created by an administrator — on ' +
        '/admin/applications/new or with POST /admin-api/applications/create ' +
        '— or registers with a software statement this realm trusts (RFC ' +
        '7591 section 2.3). Set oauth2.openRegistration to let anybody who ' +
        'can ' +
        'reach this endpoint register a client.');
    }
    if (!resolved.ok) {
      log.debug("Leaving the client registration endpoint. The software " +
                "statement was refused.");
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.statementRefused(res, resolved);
    }
    const metadata = resolved.metadata;
    if (metadata.redirect_uris && !Array.isArray(metadata.redirect_uris)) {
      errorCodes.mark(res, 'STS-OAUTH-0233');
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.oauthError(res, 400, 'invalid_redirect_uri',
                             'redirect_uris must be an array.');
    }
    // THE ADDRESSES, IN EVERY MODE (2026-09-13). Until this date the elements
    // of redirect_uris were never looked at, and neither were
    // post_logout_redirect_uris or frontchannel_logout_uri — so `javascript:`
    // registered in all three, and the last is framed on the sign-out page
    // (`backchannel_logout_uri` joined them on 2026-09-17, #36). The
    // rule is the application register's, asked here so the answer is RFC 7591
    // section 3.2.2's error rather than a registration that silently did not
    // store. RFC 9701 section 6's three members are checked beside the
    // addresses, for the same reason: a registration naming an algorithm this
    // service cannot sign or encrypt with would be accepted and then fail at
    // every JWT introspection response, which is the client finding out at the
    // wrong endpoint.
    // A `jwks_uri` whose keys an encrypted response would need is fetched
    // now (#120), so the key checks below find them in the cache.
    await self.prefetchRegisteredKeys(metadata);
    const addressProblem =
      applications.registrationUriProblem(metadata) ||
      applications.introspectionResponseProblem(metadata) ||
      applications.idTokenEncryptionMetadataProblem(metadata) ||
      idTokenEncryption.registrationKeyProblem(metadata) ||
      applications.jarmMetadataProblem(metadata) ||
      self.deps.jarm.registrationKeyProblem(metadata) ||
      applications.requestObjectMetadataProblem(metadata) ||
      applications.pushedAuthorizationMetadataProblem(metadata) ||
      applications.oidcSubjectMetadataProblem(metadata) ||
      applications.oidcRegistrationProblem(metadata) ||
      applications.mtlsMetadataProblem(metadata) ||
      self.mtlsRegistrationProblem(metadata) ||
      applications.authorizationDetailsMetadataProblem(metadata) ||
      self.registeredScopeProblem(metadata);
    if (addressProblem) {
      log.debug("Leaving the client registration endpoint. An unusable " +
                "address or introspection response algorithm.");
      errorCodes.mark(res, addressProblem.errorCode || 'STS-REG-0070');
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.oauthError(res, 400, addressProblem.error,
                        addressProblem.description);
    }
    // OIDC CORE SECTION 8.1 (#118): a sector_identifier_uri is FETCHED and must
    // list every redirect URI — the one outbound request registration makes.
    // See `pairwise_subjects.ts`.
    const sectorProblem = await pairwiseSubjects.sectorIdentifierProblem(
      metadata);
    if (sectorProblem) {
      log.debug("Leaving the client registration endpoint. The " +
                "sector_identifier_uri was refused.");
      errorCodes.mark(res, sectorProblem.errorCode || 'STS-REG-0169');
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.oauthError(res, 400, sectorProblem.error,
                             sectorProblem.description);
    }
    // RFC 9700 mode: this endpoint will not register a client for something the
    // other endpoints refuse. A registration is a document the client keeps and
    // acts on, so recording `grant_types: ["password"]` for a server that
    // answers that grant with unsupported_grant_type would be the discovery
    // document's promise broken in the other direction — and the client would
    // find out at the first token request rather than here.
    const registrationCheck = bcp.checkClientRegistration(metadata);
    if (!registrationCheck.ok) {
      log.debug("Leaving the client registration endpoint. RFC 9700 mode " +
                "refused the metadata (" +
                registrationCheck.requirement + ").");
      errorCodes.mark(res, registrationCheck.errorCode || 'STS-OAUTH-0158');
      log.debug("Leaving OAuth2Server.registerClient().");
      return self.oauthError(res, 400, registrationCheck.error,
                        registrationCheck.description);
    }
    // The prefix and both sizes are settings since 2026-09-12; the defaults are
    // the literals that were here. The secret and the registration access token
    // share a size because both ARE secrets and neither is weaker than the
    // other.
    const secretBytes = Number(config.value('oauth2.registeredSecretBytes')) ||
                        24;
    const clientId = String(config.value('oauth2.registeredClientIdPrefix') ||
                            '') +
                     randomId(Number(
                       config.value('oauth2.registeredClientIdBytes')) || 8);
    // The management URI names the authorization server the client
    // registered at (#120): `/{id}/oauth2/register/{client_id}` for a named
    // one, which is where its RFC 7592 routes are.
    const record = self.clientRecord(self.asBaseOf(req), metadata, clientId,
                                     randomId(secretBytes),
                                     randomId(secretBytes));
    // Into the directory, under ou=applications. The response below is composed
    // from `record` rather than read back, because the two are the same object
    // and a read-back would only be able to differ.
    applications.register(clientId, record,
                          { softwareStatement: resolved.statement });
    res.status(201).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(record, null, 2));
    log.debug("Leaving the client registration endpoint. Registered " +
              clientId +
              ".");
    log.debug("Leaving OAuth2Server.registerClient().");
  }

  private withRegisteredClient(req: Req, res: Res, handler: Json): Json {
    const { stsCrypto, log, applications, validation, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.withRegisteredClient().");
    // A PATH parameter, and it is checked like any other value from outside. An
    // express route parameter cannot be an array or a nested object the way a
    // query parameter can, so what this catches is a control character and a
    // length — a client_id is an identifier and 8kb of one is not.
    const named = validation.checkParsed({ client_id: req.params.client_id },
                                         'params', REGISTERED_CLIENT_PARAMS);
    if (!named.ok) {
      log.debug("Leaving OAuth2Server.withRegisteredClient(). The client_id " +
                "is malformed.");
      errorCodes.mark(res, 'STS-OAUTH-0234');
      log.debug("Leaving OAuth2Server.withRegisteredClient().");
      return self.oauthError(res, 400, 'invalid_request', named.detail);
    }
    log.debug("Entering OAuth2Server.withRegisteredClient(). client_id=" +
              named.value.client_id);
    const record = applications.registrationOf(named.value.client_id);
    const auth = (req.headers['authorization'] || '')
      .replace(/^Bearer\s+/i, '');
    // RFC 7592 SECTION 2 (#120): an unknown client is a 401, not a 404 — so
    // the answer does not say which client_ids exist — and the token used
    // "SHOULD be immediately revoked", being another client's.
    if (!record) {
      applications.revokeRegistrationAccessToken(auth);
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"');
      log.debug("Leaving OAuth2Server.withRegisteredClient(). No such client.");
      errorCodes.mark(res, 'STS-OAUTH-0235');
      log.debug("Leaving OAuth2Server.withRegisteredClient().");
      return self.oauthError(res, 401, 'invalid_token',
                             'The registration access token does not match.');
    }
    // CONSTANT TIME, AND NEVER AGAINST AN EMPTY TOKEN (2026-09-12, in every
    // mode). This was `auth !== record.registration_access_token`: a comparison
    // whose running time leaks how much of a guess was right, and — the sharper
    // half — one that matched an ABSENT header against a record whose token was
    // absent too, which is what an entry edited by `ldapmodify` or carried
    // across from an older build can hold. An RFC 7592 read hands back the
    // client secret, so both are refusals of a credential disclosure rather
    // than tidiness.
    const expected = String(record.registration_access_token || '');
    if (!expected || !stsCrypto.constantTimeEquals(auth, expected)) {
      res.set('WWW-Authenticate', 'Bearer');
      log.debug("Leaving OAuth2Server.withRegisteredClient(). The " +
                "registration access token did not match.");
      errorCodes.mark(res, 'STS-OAUTH-0236');
      log.debug("Leaving OAuth2Server.withRegisteredClient().");
      return self.oauthError(res, 401, 'invalid_token',
                             'The registration access token does not match.');
    }
    const result = handler(record);
    log.debug("Leaving OAuth2Server.withRegisteredClient().");
    return result;
  }

  // RFC 7592 section 2.2, after the registration access token has matched.
  private async updateClient(req: Req, res: Res, record: Json): Promise<Json> {
    const { log, baseUrlOf, parseBody, softwareStatement, bcp,
            applications, validation, errorCodes,
            idTokenEncryption, pairwiseSubjects } = this.deps;
    const self = this;
    log.debug("Entering OAuth2Server.updateClient(). client_id=" +
              record.client_id);
    // THE SAME CHECKS THE POST MAKES (2026-09-13). An update is a registration
    // too — RFC 7592 section 2.2 replaces the whole document — and it went
    // straight to the directory: no pollution check, no address check, and not
    // RFC 9700 mode's refusal of what the other endpoints refuse, so a client
    // registered clean could PUT the password grant or a `javascript:` URI
    // onto itself. `oauth-oidc/CLAUDE.md` 3f's rule — a refusal at an
    // endpoint needs the matching refusal at registration — had a second door.
    const parsed = validation.checkDocument(parseBody(req), 'registration');
    if (!parsed.ok) {
      log.debug("Leaving the client update endpoint. The document is " +
                "refused: " + parsed.code + ".");
      errorCodes.mark(res, 'STS-OAUTH-0232');
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.oauthError(res, 400, 'invalid_client_metadata',
                             parsed.detail);
    }
    // THE STATEMENT, as the POST applies it — and the one rule the POST does
    // not have: a client let in by a trusted statement where nobody else may
    // register cannot PUT away what that statement fixed.
    const resolved = await softwareStatement.resolve(parsed.value,
                                                     { base: baseUrlOf(req) });
    if (!resolved.ok) {
      log.debug("Leaving the client update endpoint. The software " +
                "statement was refused.");
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.statementRefused(res, resolved);
    }
    const bound = softwareStatement.updateProblem(
      applications.softwareStatementFactsOf(record.client_id), resolved,
      self.registrationOpen());
    if (bound) {
      log.debug("Leaving the client update endpoint. The statement that " +
                "admitted this client is not vouched for again.");
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.statementRefused(res, bound);
    }
    const metadata = resolved.metadata;
    // RFC 7592 SECTION 2.2 (#120): the update carries the client's own
    // client_id, and a client_secret only if it is the one issued — either
    // was overwritten silently until this date.
    if (String(metadata.client_id || '') !== String(record.client_id)) {
      log.debug("Leaving the client update endpoint. The client_id does not " +
                "match.");
      errorCodes.mark(res, 'STS-OAUTH-0595');
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.oauthError(res, 400, 'invalid_request',
        'RFC 7592 section 2.2: the update must carry client_id, and it must ' +
        'be "' + record.client_id + '".');
    }
    if (metadata.client_secret !== undefined &&
        String(metadata.client_secret) !== String(record.client_secret || '')) {
      log.debug("Leaving the client update endpoint. The client_secret does " +
                "not match.");
      errorCodes.mark(res, 'STS-OAUTH-0595');
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.oauthError(res, 400, 'invalid_request',
        'RFC 7592 section 2.2: a client_secret in the update must be the one ' +
        'this server issued.');
    }
    if (metadata.redirect_uris && !Array.isArray(metadata.redirect_uris)) {
      log.debug("Leaving the client update endpoint. redirect_uris is not an " +
                "array.");
      errorCodes.mark(res, 'STS-OAUTH-0233');
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.oauthError(res, 400, 'invalid_redirect_uri',
                        'redirect_uris must be an array.');
    }
    // A `jwks_uri` whose keys an encrypted response would need is fetched
    // now (#120), so the key checks below find them in the cache.
    await self.prefetchRegisteredKeys(metadata);
    const addressProblem =
      applications.registrationUriProblem(metadata) ||
      applications.introspectionResponseProblem(metadata) ||
      applications.idTokenEncryptionMetadataProblem(metadata) ||
      idTokenEncryption.registrationKeyProblem(metadata) ||
      applications.requestObjectMetadataProblem(metadata) ||
      applications.pushedAuthorizationMetadataProblem(metadata) ||
      applications.oidcSubjectMetadataProblem(metadata) ||
      applications.oidcRegistrationProblem(metadata) ||
      applications.mtlsMetadataProblem(metadata) ||
      self.mtlsRegistrationProblem(metadata) ||
      applications.authorizationDetailsMetadataProblem(metadata) ||
      self.registeredScopeProblem(metadata, record.client_id);
    if (addressProblem) {
      log.debug("Leaving the client update endpoint. An unusable address.");
      errorCodes.mark(res, addressProblem.errorCode || 'STS-REG-0070');
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.oauthError(res, 400, addressProblem.error,
                        addressProblem.description);
    }
    // OIDC Core section 8.1, as at registration (#118).
    const sectorProblem = await pairwiseSubjects.sectorIdentifierProblem(
      metadata);
    if (sectorProblem) {
      log.debug("Leaving the client update endpoint. The " +
                "sector_identifier_uri was refused.");
      errorCodes.mark(res, sectorProblem.errorCode || 'STS-REG-0169');
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.oauthError(res, 400, sectorProblem.error,
                             sectorProblem.description);
    }
    const registrationCheck = bcp.checkClientRegistration(metadata);
    if (!registrationCheck.ok) {
      log.debug("Leaving the client update endpoint. RFC 9700 mode refused " +
                "the metadata (" + registrationCheck.requirement + ").");
      errorCodes.mark(res, registrationCheck.errorCode || 'STS-OAUTH-0158');
      log.debug("Leaving OAuth2Server.updateClient().");
      return self.oauthError(res, 400, registrationCheck.error,
                        registrationCheck.description);
    }
    const updated = Object.assign({}, self.withRegistrationDefaults(metadata), {
      client_id: record.client_id,
      client_id_issued_at: record.client_id_issued_at,
      client_secret: record.client_secret,
      client_secret_expires_at: record.client_secret_expires_at,
      registration_access_token: record.registration_access_token,
      registration_client_uri: record.registration_client_uri
    });
    applications.updateRegistration(record.client_id, updated,
                                    { softwareStatement: resolved.statement });
    res.status(200)
       .type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(updated, null, 2));
    log.debug("Leaving OAuth2Server.updateClient().");
  }

  // RFC 7592's three operations, as methods so that `/oauth2/register/...`
  // and `/{id}/oauth2/register/...` (#120) are the same handlers.
  private registrationRead(req: Req, res: Res): void {
    const { log } = this.deps;
    log.debug("Entering the client read endpoint.");
    this.withRegisteredClient(req, res, function (record) {
      // `no-store`: the document carries the client_secret and the
      // registration access token (RFC 7592 section 2.1), which the POST that
      // minted them already sent with this header and these two did not until
      // 2026-09-13.
      res.status(200)
         .type('application/json')
         .set('Cache-Control', 'no-store')
         .send(JSON.stringify(record, null, 2));
    });
    log.debug("Leaving the client read endpoint.");
  }

  private registrationUpdate(req: Req, res: Res): void {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering the client update endpoint.");
    self.withRegisteredClient(req, res, function (record) {
      self.updateClient(req, res, record).catch(function (e) {
        log.error(errorCodes.tag('STS-OAUTH-0228') + 'the client update ' +
                  'endpoint failed: ' + (e && e.stack ? e.stack : e));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-OAUTH-0228');
          self.oauthError(res, 500, 'server_error', e.message);
        }
      });
    });
    log.debug("Leaving the client update endpoint.");
  }

  private registrationDelete(req: Req, res: Res): void {
    const { log, applications } = this.deps;
    log.debug("Entering the client delete endpoint.");
    this.withRegisteredClient(req, res, function (record) {
      // The REGISTRATION goes and the application entry stays, with
      // appRegistered FALSE and the credentials stripped off it. See
      // forgetRegistration(): this registry records what this service has
      // seen, and losing that an application was ever here because its
      // registration was withdrawn would be losing the fact rather than the
      // configuration.
      applications.forgetRegistration(record.client_id);
      res.status(204).end();
    });
    log.debug("Leaving the client delete endpoint.");
  }

  // -------------------------------------------------------------------------
  // EVERY ROUTE AND MIDDLEWARE THIS MODULE REGISTERS, IN THE ORDER THE OLD FILE
  // REGISTERED THEM (rule 1: the order of `common/protocol_stack.ts`'s
  // `register()` calls is the route order, and within a module the
  // registration order is).
  // -------------------------------------------------------------------------
  registerRoutes(app: any): void {
    const self = this;
    const { crypto, realms, forge, jwt, stsCrypto, log, logArtifact, STS,
            baseUrlOf, b64u, jsonFromB64u, nowSec, randomId, xmlEscape,
            parseBody, bodyValues, plainOauthError, signJwt, signJwtAs,
            allSigningKeys, allSigningKeysAsync, signJwtAsAsync, userFor,
            hasScope, signingKeyFor, certificateHeaderFor, publishedKidFor,
            nameForSubject, hasSubjectResolver, LEGACY_SUBJECT_PREFIX,
            requestObjectKeysFor, dpop, joseKid, mtls, clientAuth,
            assertionGrant, softwareStatement, samlAssertionGrant, mode,
            authorizationServers, stats, VCI_CONFIGS, VCI_CONFIG_ID, VCI_SCOPE,
            vciFormatOf, vcClaims, deferredAccessTokens, issuerStates,
            preAuthorizedCodes, checkTxCode, spendPreAuthorizedCode, config,
            authn, sessionOf, endSession, bcp, oauth21, senderConstraints,
            frontchannel, applications, validation, errorCodes,
            refreshTokenCrypto, jwtAccessToken, introspectionJwt, stepUp,
            requestObject, richAuthorization, par, oauthMonitor, delegation,
            consent, consentScreen, claimAttributes, gate, debuggerAccess,
            credentials, websecurity, clusterClaims, clusterBarrier,
            capabilities } = this.deps;
    log.debug("Entering OAuth2Server.registerRoutes().");
    // -------------------------------------------------------------------------
    // A DPoP PROOF'S `jti`, RESERVED ACROSS THE CLUSTER ON ARRIVAL (2026-09-14,
    // #46). `dpop.ts` registers nothing (rule 3), so the middleware it builds
    // is registered HERE, above this module's first route — and so above every
    // route that verifies a proof: the token endpoint, the PAR endpoint,
    // UserInfo and the step-up stand-in below, and the credential endpoints,
    // SCIM and Shared Signals, all registered after this module (rule 1:
    // middleware applies only to routes added after it). Nothing required above
    // this module reads a DPoP header. It does nothing for a request without
    // one. Why the reservation is made on arrival rather than inside
    // `verifyProof()` is argued above `PROOF_CLAIM` in `dpop.ts`.
    // -------------------------------------------------------------------------
    app.use(dpop.proofClaims());

    // -------------------------------------------------------------------------
    // A CLIENT'S `jwks_uri`, FETCHED BEFORE AN ENDPOINT THAT MAY ENCRYPT TO IT
    // (#120). The key readers behind an encrypted ID Token, UserInfo response,
    // RFC 9701 introspection response and JARM response are synchronous, so
    // the five endpoints that produce them wait here for `client_jwks.js` to
    // hold the set — which dials nothing for a client that registered `jwks`,
    // no `jwks_uri`, or no encrypted response. The client ids are read
    // UNVERIFIED and choose only what is fetched; nothing is decided on them.
    // Never refuses: a failed fetch is refused, by name, where the key was
    // needed.
    // -------------------------------------------------------------------------
    app.use(['/oauth2/authorize', '/oauth2/token', '/oauth2/par',
             '/oauth2/userinfo', '/oauth2/introspect',
             '/:as/oauth2/authorize', '/:as/oauth2/token', '/:as/oauth2/par',
             '/:as/oauth2/userinfo', '/:as/oauth2/introspect'],
            function (req: Req, res: Res, next: () => void): void {
      log.debug("Entering the client key prefetch.");
      Promise.all(self.presentedClientIdsOf(req).map(function (id: string) {
        return clientJwks.ensureFor(id, '');
      })).then(function () {
        log.debug("Leaving the client key prefetch.");
        next();
      }, function (e: any) {
        log.debug("Caught in the client key prefetch: " +
                  ((e && e.message) || e));
        // ensureFor() never rejects; the request goes on regardless.
        next();
      });
    });

    app.get('/.well-known/oauth-authorization-server',
            self.sendAsMetadata.bind(self));

    // Issuer-with-path form, e.g.
    // /.well-known/oauth-authorization-server/tenant1 — and that path component
    // now names the PROFILE as well as the issuer.
    app.get('/.well-known/oauth-authorization-server/*',
            function (req, res, next) {
      // `[realm/<id>][/<server>]` (#119) — see issuerPathTarget().
      self.discoveryForPath(req, res, next, req.params[0],
                            self.sendAsMetadata.bind(self));
    });

    // WebFinger (#119): at the host root, answering for every realm.
    app.get('/.well-known/webfinger', self.webfingerEndpoint.bind(self));

    app.get('/.well-known/openid-configuration', function (req, res) {
      log.debug("Entering the OpenID Connect Discovery endpoint.");
      self.sendOidcMetadata(req, res);
      log.debug("Leaving the OpenID Connect Discovery endpoint.");
    });

    // -------------------------------------------------------------------------
    // An issuer identifier with a path component, which the two specifications
    // resolve to two DIFFERENT URLs — the single most common reason a discovery
    // fetch 404s, so both are served.
    //
    //   OpenID Connect Discovery 1.0 section 4  APPENDS:  https://host/tenant1/.well-known/openid-configuration
    //   RFC 8414 section 3.1                    INSERTS:  https://host/.well-known/openid-configuration/tenant1
    //
    // The appended form gets the issuer it was asked for, built back up from
    // the path the request arrived on: that shape exists precisely so a
    // multi-tenant server can answer for one tenant, and a document at
    // /tenant1/... claiming to be issued by https://host is one a conforming
    // client MUST reject (the issuer has to match the one the URL was built
    // from). The endpoints inside it stay where they really are, since nothing
    // requires them to live under the issuer.
    //
    // The inserted form is the RFC 8414 shape and is answered the way the
    // oauth-authorization-server route above answers it — with the request's
    // base URL as the issuer — so the two behave alike.
    // -------------------------------------------------------------------------
    app.get('/.well-known/openid-configuration/*', function (req, res, next) {
      log.debug("Entering the OpenID Connect Discovery endpoint (RFC 8414 " +
                "inserted-path form).");
      // `[realm/<id>][/<server>]` (#119) — see issuerPathTarget().
      self.discoveryForPath(req, res, next, req.params[0], function (q, r) {
        self.sendOidcMetadata(q, r);
      });
      log.debug("Leaving the OpenID Connect Discovery endpoint (RFC 8414 " +
                "inserted-path form).");
    });

    app.get('/*/.well-known/openid-configuration', function (req, res, next) {
      log.debug("Entering the OpenID Connect Discovery endpoint (issuer-path " +
                "form).");
      // req.params[0] is everything before /.well-known that the realm
      // prefix left — the server's segment. `app.js` has entered a realm the
      // path named; one it could not find leaves `realm/<id>` here, and
      // issuerPathTarget() refuses that and any second segment (#119).
      const path = String(req.params[0] || '').replace(/^\/+|\/+$/g, '');
      const target = self.issuerPathTarget(path);
      if (!target || path.split('/')[0] === 'realm') {
        errorCodes.mark(res, 'STS-OAUTH-0594');
        log.debug("Leaving the OpenID Connect Discovery endpoint (issuer-" +
                  "path form). Names nothing.");
        next();
        return;
      }
      req.__asProfile = self.profileFromPath(target.server);
      self.sendOidcMetadata(req, res,
                            baseUrlOf(req) + (path ? '/' + path : ''));
      log.debug("Leaving the OpenID Connect Discovery endpoint (issuer-path " +
                "form). path=" + path);
    });

    app.get('/oauth2/jwks', self.jwksEndpoint.bind(self));

    app.get('/oauth2/autopost.js', function (req, res) {
      log.debug("Entering the authorization form-post script.");
      res.set('Content-Security-Policy',
              app.contentSecurityPolicy({ 'style-src': null,
                                                                     'img-src':
                                                                       null }));
      res.status(200)
         .type('application/javascript')
         .set('Cache-Control', 'no-store')
         .send(AUTOPOST_SCRIPT);
      log.debug("Leaving the authorization form-post script.");
    });

    // -------------------------------------------------------------------------
    // OPENID CONNECT SESSION MANAGEMENT 1.0 section 3.2: THE OP IFRAME (#121).
    //
    // THE ONE PAGE HERE THAT MAY BE FRAMED — by the realm's registered
    // relying parties and nobody else (`app.framedContentSecurityPolicy()`
    // narrows `frame-ancestors` to their redirect-URI origins; with none it is
    // still 'none'), and X-Frame-Options, which can only say DENY or
    // SAMEORIGIN, is removed so it cannot overrule the narrower CSP.
    //
    // THE NINTH SCRIPTED PAGE, argued from scratch (the root CLAUDE.md's
    // table): the iframe's whole job is to ANSWER A `postMessage`, and no
    // markup can, so there is no submit button to fall back on — with script
    // off it answers nothing, and a relying party's `postMessage` goes
    // unanswered, which the specification already treats as the iframe
    // being unusable. `script-src 'self'` naming the one sibling resource.
    //
    // Off (the default), both paths answer a 404 of their own that names the
    // setting — NOT Express's `Cannot GET`, which is how
    // tests/vendored/sts_metadata.js tells a path nobody routed from an
    // endpoint answering 404.
    // -------------------------------------------------------------------------
    app.get(sessionManagement.IFRAME_PATH, function (req, res) {
      log.debug("Entering the OP iframe.");
      if (!sessionManagement.enabled()) {
        errorCodes.mark(res, 'STS-OAUTH-0601');
        log.debug("Leaving the OP iframe. Session Management is off.");
        return self.sessionManagementOff(res);
      }
      res.set('Content-Security-Policy',
              app.framedContentSecurityPolicy(
                sessionManagement.frameAncestors(),
                { 'script-src': "'self'", 'style-src': null }));
      res.removeHeader('X-Frame-Options');
      res.status(200).type('text/html').set('Cache-Control', 'no-store')
         .send(sessionManagement.iframePage());
      log.debug("Leaving the OP iframe.");
      return undefined;
    });

    app.get(sessionManagement.SCRIPT_PATH, function (req, res) {
      log.debug("Entering the OP iframe's script.");
      if (!sessionManagement.enabled()) {
        errorCodes.mark(res, 'STS-OAUTH-0601');
        log.debug("Leaving the OP iframe's script. Session Management is off.");
        return self.sessionManagementOff(res);
      }
      res.set('Content-Security-Policy',
              app.contentSecurityPolicy({ 'style-src': null,
                                          'img-src': null }));
      res.status(200).type('application/javascript')
         .set('Cache-Control', 'no-store')
         .send(sessionManagement.IFRAME_SCRIPT);
      log.debug("Leaving the OP iframe's script.");
      return undefined;
    });

    app.get('/oauth2/authorize', self.authorizeEndpoint.bind(self));
    // OIDC Core section 3.1.2.1: GET and POST (#118).
    app.post('/oauth2/authorize', self.authorizeEndpoint.bind(self));

    // -------------------------------------------------------------------------
    // GET /oauth2/rfc9700 — what this mode is, and whether it is on.
    //
    // NON-SPEC. RFC 9700 defines no discovery member and no endpoint, and there
    // is no way for a client to find out from the protocol whether the server
    // it is talking to enforces it — the metadata narrowing above is a
    // consequence of the mode rather than an announcement of it. So this says
    // so directly, and it says the uncomfortable half too: which requirements
    // are enforced, which are only DETECTED because they are the client's to
    // keep, and the one that is not enforced at all with the reason attached.
    //
    // It is a report and not a switch. The mode is configuration —
    // oauth2.rfc9700 — so it is turned on at /admin/config or through POST
    // /admin-api/config like every other setting, which is what gives it a
    // console control, a management API operation and an audit row without a
    // line being written for any of the three. /dpop/nonce-mode is a switch as
    // well, and a test control: it writes the setting
    // `oauth2.dpopNonceRequired` for the realm it is reached in (see its header
    // below).
    //
    // Read-only, so there is no console control here and therefore nothing for
    // rule 7 in CLAUDE.md to require of the management API.
    // -------------------------------------------------------------------------
    // OAuth 2.1 mode's report, beside RFC 9700 mode's and for its reasons: what
    // the mode enforces is published rather than left to be read out of the
    // code, and a test reads `enabled` rather than inferring the mode from a
    // refusal. The rows cite draft-ietf-oauth-v2-1-16 by revision, and the
    // report says the draft is a draft.
    app.get('/oauth2/oauth21', function (req, res) {
      log.debug("Entering the OAuth 2.1 mode report.");
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(oauth21.state(), null, 2));
      log.debug("Leaving the OAuth 2.1 mode report. enabled=" +
                oauth21.enabled());
    });

    // THE FAPI PROFILE IN FORCE (#138), for the realm here and for a named
    // authorization server at /{id}/oauth2/fapi (in the table below, so it is
    // answered inside that server's own profile).
    app.get('/oauth2/fapi', self.fapiReport.bind(self));

    app.get('/oauth2/rfc9700', function (req, res) {
      log.debug("Entering the RFC 9700 mode report.");
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
         .send(JSON.stringify(bcp.state(), null, 2));
      log.debug("Leaving the RFC 9700 mode report. enabled=" + bcp.enabled());
    });

    app.get('/oauth2/logout', self.logoutEndpoint.bind(self));
    // RP-Initiated Logout 1.0 section 2: GET and POST (#124).
    app.post('/oauth2/logout', self.logoutEndpoint.bind(self));

    app.get('/oauth2/userinfo', self.userinfoResponse.bind(self));

    app.post('/oauth2/userinfo', self.userinfoResponse.bind(self));

    app.get('/oauth2/step-up/resource/:application',
            self.stepUpResource.bind(self));

    app.post('/oauth2/step-up/resource/:application',
             self.stepUpResource.bind(self));

    // --- token endpoint
    // ---------------------------------------------------------
    // -------------------------------------------------------------------------
    // NON-SPEC: the DPoP nonce switch.
    //
    // RFC 9449 sections 8 and 9 let a server demand a server-supplied nonce in
    // every proof, which turns the first request of a session into a 401/retry
    // handshake. Whether to do that is a deployment's choice, and both answers
    // are worth being able to try — a wallet that handles the happy path but
    // not the handshake is a wallet that works until it meets a server that
    // asks.
    //
    // So it is a runtime switch: a test, or somebody reading the page, can turn
    // it on, watch the retry, and turn it off again without restarting the
    // service. GET reports; POST {"required": true|false} sets — the runtime
    // setting `oauth2.dpopNonceRequired` since 2026-09-12 (below). Listed on
    // /admin/sts-metadata as non-spec, because it is.
    // -------------------------------------------------------------------------
    app.get('/dpop/nonce-mode', function (req, res) {
      log.debug("Entering the DPoP nonce-mode endpoint (read).");
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
        .send(JSON.stringify(dpop.state(), null, 2));
      log.debug("Leaving the DPoP nonce-mode endpoint (read).");
    });

    // -------------------------------------------------------------------------
    // TWO THINGS CHANGED ABOUT THE WRITE ON 2026-09-12.
    //
    // **IT IS PER TRUST REALM.** It set one switch for the whole process, so a
    // test turning nonces on at /realm/acme/dpop/nonce-mode demanded them of
    // every client of every other realm. It writes `oauth2.dpopNonceRequired`
    // now, which lands on the realm it is reached in — see
    // `dpop.setNonceMode()`.
    //
    // **IT IS A TEST CONTROL AND PRODUCT MODE REFUSES IT.** Anybody who can
    // reach the port could change a security policy of the authorization server
    // and empty its replay cache in the same call. In product the setting is
    // still changeable, through the two doors that already require a credential
    // — /admin/oauth2 and POST /admin-api/config/set — and this endpoint says
    // so. The READ above stays open in both modes: it reports a policy a client
    // needs to know to talk to this server at all.
    // -------------------------------------------------------------------------
    app.post('/dpop/nonce-mode', function (req, res) {
      log.debug("Entering the DPoP nonce-mode endpoint (write).");
      if (!mode.opensTestControls()) {
        log.warn('oauth2: POST /dpop/nonce-mode was refused — product mode ' +
                 'does not open test controls.');
        log.debug("Leaving the DPoP nonce-mode endpoint. Refused in product " +
                  "mode.");
        errorCodes.mark(res, 'STS-OAUTH-0178');
        return self.oauthError(res, 403, 'access_denied',
          'POST /dpop/nonce-mode is a test control and this realm is in ' +
          'product mode, where test controls are closed. Set ' +
          'oauth2.dpopNonceRequired instead — on /admin/oauth2 or with POST ' +
          '/admin-api/config/set, both ' +
          'of which require a credential.');
      }
      const body = parseBody(req);
      // Only an explicit boolean, so a typo cannot silently leave the switch in
      // a state nobody chose: a test that means to turn nonces OFF and leaves
      // them on makes every later section in the run fail for an invisible
      // reason.
      const wanted = body.required;
      if (wanted !== true && wanted !== false && wanted !== 'true' &&
          wanted !== 'false') {
        log.debug("Leaving the DPoP nonce-mode endpoint. Refused.");
        errorCodes.mark(res, 'STS-OAUTH-0179');
        return self.oauthError(res, 400, 'invalid_request',
          'Send {"required": true} or {"required": false}.');
      }
      try {
        dpop.setNonceMode(wanted === true || wanted === 'true');
      } catch (e) {
        log.error(errorCodes.tag('STS-OAUTH-0180') + 'oauth2: the DPoP nonce ' +
                                                     'switch could not be ' +
                                                     'written: ' +
                  e.message);
        log.debug("Leaving the DPoP nonce-mode endpoint. The setting " +
                  "refused it.");
        errorCodes.mark(res, 'STS-OAUTH-0180');
        return self.oauthError(res, 500, 'server_error', e.message);
      }
      // A change of policy invalidates nothing already issued, but the replay
      // cache holds this realm's proofs and a test that has just been refusing
      // proofs on purpose wants a clean slate for the next section.
      dpop.forgetProofs();
      res.status(200).type('application/json').set('Cache-Control', 'no-store')
        .send(JSON.stringify(dpop.state(), null, 2));
      log.debug("Leaving the DPoP nonce-mode endpoint (write). required=" +
                dpop.nonceModeOn());
    });

    // -------------------------------------------------------------------------
    // THE WRAPPER, AND IT IS NOT CEREMONY.
    //
    // `tokenEndpoint` is an `async function` (see its header). Express 4 does
    // not look at what a handler returns, so a promise that rejects — from a
    // defect anywhere in the token endpoint, from a worker process that died
    // mid-signature — would be an unhandled rejection and a request that never
    // gets an answer, where the same throw used to be a 500 with the reason in
    // it. This puts that back, and puts it back for the asynchronous half as
    // well.
    //
    // `oauthError` and not `res.status(500).send()`: a token endpoint's
    // failures are OAuth errors all the way down, and a client that gets HTML
    // back from this URL has to guess.
    app.post('/oauth2/token', function (req, res) {
      log.debug("Entering the token endpoint wrapper.");
      self.tokenEndpoint(req, res).catch(function (e) {
        log.error(errorCodes.tag('STS-OAUTH-0228') +
                  'the token endpoint failed: ' +
                  (e && e.stack ? e.stack : e));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-OAUTH-0228');
          self.oauthError(res, 500, 'server_error', e.message);
        }
      });
      log.debug("Leaving the token endpoint wrapper.");
    });

    app.post('/oauth2/par', self.parEndpoint.bind(self));

    // SECTION 2.3's 405 IS MIDDLEWARE AND NOT A ROUTE, for
    // /admin/sts-metadata's reason: that page lists the methods the ROUTER
    // holds for a path, and `tests/vendored/sts_metadata.js` calls every one
    // and fails on a 405 — so an `app.all()` would advertise ACL, PROPFIND and
    // the rest as methods this endpoint has, which is the opposite of what the
    // 405 says. A path-mounted middleware answers every method but POST at
    // exactly these two paths (and not at anything beneath them) and lists
    // nothing. It sits after the POST route, which has already answered a POST,
    // and it is the one handler here the router reading cannot see — named in
    // the ENDPOINTS row's own sentence instead.
    app.use(['/oauth2/par', '/:as/oauth2/par'], function (req, res, next) {
      if (req.method === 'POST' || (req.path !== '/' && req.path !== '')) {
        return next();
      }
      return self.parMethodNotAllowed(req, res);
    });

    // -------------------------------------------------------------------------
    // THE SAME ENDPOINTS, UNDER EVERY AUTHORIZATION SERVER'S OWN NAME.
    //
    // Registered here, in one block, so that the set cannot drift from the set
    // above — an endpoint that existed at `/oauth2/x` and not at
    // `/{id}/oauth2/x` would be one a named authorization server advertises and
    // does not have.
    //
    // The route order rule (rule 1 in CLAUDE.md) is why they are AFTER the
    // unprefixed ones: `/:as/oauth2/authorize` cannot match `/oauth2/authorize`
    // (three segments against two), so the two sets do not overlap and the
    // order is a matter of reading rather than of behaviour — but the block
    // being one block is what makes a missing member visible.
    [
      ['get', '/:as/oauth2/authorize', self.authorizeEndpoint.bind(self)],
      ['post', '/:as/oauth2/authorize', self.authorizeEndpoint.bind(self)],
      ['post', '/:as/oauth2/token', self.tokenEndpoint.bind(self)],
      ['post', '/:as/oauth2/par', self.parEndpoint.bind(self)],
      ['get', '/:as/oauth2/logout', self.logoutEndpoint.bind(self)],
      ['post', '/:as/oauth2/logout', self.logoutEndpoint.bind(self)],
      ['get', '/:as/oauth2/userinfo', self.userinfoResponse.bind(self)],
      ['post', '/:as/oauth2/userinfo', self.userinfoResponse.bind(self)],
      ['post', '/:as/oauth2/introspect', self.introspectEndpoint.bind(self)],
      ['post', '/:as/oauth2/revoke', self.revokeEndpoint.bind(self)],
      ['post', '/:as/oauth2/register', self.registerEndpoint.bind(self)],
      // RFC 7592 at a named server (#120): where its registration_client_uri
      // points.
      ['get', '/:as/oauth2/register/:client_id',
       self.registrationRead.bind(self)],
      ['put', '/:as/oauth2/register/:client_id',
       self.registrationUpdate.bind(self)],
      ['delete', '/:as/oauth2/register/:client_id',
       self.registrationDelete.bind(self)],
      ['get', '/:as/oauth2/jwks', self.jwksEndpoint.bind(self)],
      ['get', '/:as/oauth2/fapi', self.fapiReport.bind(self)]
    ].forEach(function (route) {
      app[route[0]](route[1], self.forProfile(route[2]));
    });

    app.post('/oauth2/introspect', self.introspectEndpoint.bind(self));

    app.post('/oauth2/revoke', self.revokeEndpoint.bind(self));

    app.post('/oauth2/register', self.registerEndpoint.bind(self));

    app.get('/oauth2/register/:client_id',
            self.registrationRead.bind(self));
    app.put('/oauth2/register/:client_id',
            self.registrationUpdate.bind(self));
    app.delete('/oauth2/register/:client_id',
               self.registrationDelete.bind(self));

    // --- the documents the metadata links to --------------------------------
    app.get('/docs', function (req, res) {
      log.debug("Entering the service documentation endpoint.");
      res.type('text/plain').send(
        'Mock authorization server (service_documentation).\n\n' +
        'Every endpoint in ' + baseUrlOf(req) +
        '/.well-known/oauth-authorization-server ' +
        'answers.\nTokens are RS256 JWTs signed with the key ' +
        'at ' + baseUrlOf(req) + '/oauth2/jwks.\nNo ' +
        'credential is ever verified: this server exists to exercise a ' +
        'client.\n');
      log.debug("Leaving the service documentation endpoint.");
    });

    app.get('/policy', function (req, res) {
      log.debug("Entering the policy document endpoint.");
      res.type('text/plain').send('Mock authorization server policy ' +
                                  '(op_policy_uri). Test data only.\n');
      log.debug("Leaving the policy document endpoint.");
    });

    app.get('/tos', function (req, res) {
      log.debug("Entering the terms of service endpoint.");
      res.type('text/plain').send('Mock authorization server terms of ' +
                                  'service (op_tos_uri). Test data only.\n');
      log.debug("Leaving the terms of service endpoint.");
    });

    // #46: an authorization code and a PAR request_uri are spent through a
    // claim (`refuseConcurrentRedemption()`, `issueAuthorizationResponse()`).
    // At require time — see cluster/CLAUDE.md on why a capability is the code.

    log.debug("Leaving OAuth2Server.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<OAuth2Server>(
  'oauth-oidc/oauth2',
  () => new OAuth2Server(OAuth2Server.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

capabilities.provide('oauth.codes-once');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  OAuth2Server: OAuth2Server,
  installInstance: (instance: OAuth2Server): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  asMetadata: slot.forward('asMetadata'),
  // THE TWO ADVERTISED SIGNING LISTS, for `admin-ui/crypto_metadata.ts`.
  // They are already in the discovery document, so exporting them
  // publishes nothing new; what it buys is that the crypto page reports the
  // list this module ENFORCES rather than a copy of it.
  // `ID_TOKEN_SIGNING_ALGS` is the shared table itself and
  // `USERINFO_SIGNING_ALGS` is not — it adds the HMAC family, which is
  // signed with the client's own secret, and `none` — and a page that
  // showed one where it meant the other would be wrong in the direction
  // nobody checks.
  ID_TOKEN_SIGNING_ALGS: ID_TOKEN_SIGNING_ALGS,
  USERINFO_SIGNING_ALGS: USERINFO_SIGNING_ALGS,
  accessToken: slot.forward('accessToken'),
  tokenSet: slot.forward('tokenSet'),
  // THE TWO SCOPE POLICIES (#110), for `tests/scope_policy.js`: which scopes
  // a client may be issued, and whether it holds a delegated permission.
  scopeRefusal: slot.forward('scopeRefusal'),
  permissionRefusal: slot.forward('permissionRefusal'),
  protectedScopes: slot.forward('protectedScopes'),
  // THE ID TOKEN BUILDER, for GNAP (2026-09-12). RFC 9635 section 3.4.1
  // lets a grant response carry an OpenID Connect ID Token as a SUBJECT
  // ASSERTION, and a second builder in `gnap/` would be a second answer to
  // what an ID Token from this realm contains — claims layers, persona
  // values, the directory's facts, the registered signing algorithm — that
  // would disagree with this one the first time either grew a claim.
  // `gnap/gnap.ts` is required long after this module, so the require runs
  // in the ordinary direction.
  idToken: slot.forward('idToken'),
  // The outstanding authorization codes, for the protocol-independent
  // logout. Functions rather than the Map, and both stores behind them —
  // see the block above outstandingCodesFor(). `logout/logout.ts` requires
  // this module in the ordinary direction: `common/protocol_stack.ts` loads
  // it long before that one, so the require moves no route and closes no
  // cycle.
  outstandingCodesFor: slot.forward('outstandingCodesFor'),
  dropCode: slot.forward('dropCode'),
  // Which issuer identifier a sign-out should put in a front-channel
  // notification's `iss`. This process runs several named authorization
  // servers and an RP is expecting the one that issued ITS tokens, so the
  // caller has to be able to ask rather than assume the default.
  issuerOf: slot.forward('issuerOf'),
  // ----------------------------------------------------------------------
  // OIDC Core section 5.5, for the CONSOLE — /admin/userinfo-claims
  // previews what a claims request would return, and it does it by calling
  // the two functions the UserInfo endpoint itself calls rather than by
  // reimplementing them. That is the rule every other preview in this
  // service follows (see claim_attributes.js's previewFor()) and it exists
  // for the same reason: a preview that agreed with the page and disagreed
  // with the endpoint would be worse than no preview at all.
  //
  // They are exported rather than moved to a library because they are
  // PROTOCOL knowledge — what section 5.5 says a request looks like, and
  // what this server does with one — and this is the module that owns it.
  // admin.js is required after this one (rule 5), so the require runs in
  // the ordinary direction and closes no cycle.
  // ----------------------------------------------------------------------
  parseClaimsRequest: slot.forward('parseClaimsRequest'),
  requestedClaimsOf: slot.forward('requestedClaimsOf'),
  requestedClaimNames: slot.forward('requestedClaimNames'),
  CLAIMS_REQUEST_MEMBERS: CLAIMS_REQUEST_MEMBERS,
  // A GETTER, so a reader holding this module sees
  // `oauth2.maxRequestedClaims` as it is now rather than the default it was
  // at require time.
  get MAX_REQUESTED_CLAIMS() {
    helpers.log.debug("Entering MAX_REQUESTED_CLAIMS().");
    helpers.log.debug("Leaving MAX_REQUESTED_CLAIMS().");
    return slot.get().maxRequestedClaims();
  },
  PERSONA_CLAIMS: PERSONA_CLAIMS,
  // The RFC 8414 `signed_metadata` signer, for the OID4VCI issuer
  // metadata's copy of the same construct. See its header.
  signPublishedDocument: slot.forward('signPublishedDocument'),
  authCodeTtlMs: slot.forward('authCodeTtlMs'),
  registrationOpen: slot.forward('registrationOpen'),
  registrationReachable: slot.forward('registrationReachable')
  // `registeredClients` used to be exported from here. It is not a Map in
  // this module any more — the registrations are entries under
  // ou=applications, and `applications.registrationOf()` is how anything
  // reads one. Re-exporting a second name for that would be the
  // two-stores problem with extra steps. The browser session used to be
  // exported from here, because this module owned the login flow it came
  // out of. It does not any more: `authn.js` does, and wsfed.ts and
  // admin.js take it from there. Re-exporting it would leave two names for
  // one store and a reader no way to tell which is the real one.
};
