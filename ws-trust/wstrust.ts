// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: wstrust.ts
//
// ---------------------------------------------------------------------------
// WS-Trust 1.4 (and 1.0-1.3, which differ only in the namespace and action
// URIs): the SOAP RequestSecurityToken endpoint and everything that reads or
// writes one.
//
// It accepts an RST and dispatches on wst:RequestType:
//
//   Issue    -> RSTR Collection with a freshly minted, STS-signed SAML 2.0
//               assertion (or a JWT, when TokenType asks for one), a
//               Lifetime, and an attached reference.
//   Renew    -> RSTR with a fresh token for the supplied RenewTarget.
//   Validate -> RSTR with wst:Status/wst:Code valid|invalid.
//   Cancel   -> RSTR with wst:RequestedTokenCancelled.
//
// Authentication: a WS-Security UsernameToken is accepted when username and
// password are both present (and the password is not the literal "invalid",
// which lets a negative test force an auth failure). A SAML assertion in the
// security header is accepted as a credential too, and a request carrying an
// OnBehalfOf/ActAs token (delegation) is accepted on top of either. It does not
// verify request signatures or enforce delegation policy.
//
// **THAT PARAGRAPH IS DEVELOPMENT MODE, AND PRODUCT MODE IS DIFFERENT IN FIVE
// PLACES (2026-09-12)** — every one of them asked through
// `mode.verifiesCredentials()`, because each is the question "is a presented
// credential actually checked":
//
//   * a UsernameToken's password is verified against the stored
//     `userPassword` (`common/credentials.ts`), not only against "invalid";
//   * a request with NO credential is refused, where development issues a token
//     for the literal subject `anonymous` (and a Renew for whoever its
//     RenewTarget names);
//   * a SAML assertion presented AS the credential must carry a signature that
//     verifies against THIS REALM'S OWN signing certificate and be inside its
//     Conditions — the smallest real answer to "which issuer is trusted",
//     because it is the one key this service already holds and publishes at
//     /sts/cert, and it covers the case WS-Trust exists for here: exchanging or
//     renewing a token this STS issued. There is no configured list of foreign
//     issuers yet, and saying so is better than accepting any;
//   * an OnBehalfOf / ActAs is refused without a requester credential of the
//     requester's own, and the token inside it must be such an assertion too;
//   * no subject is invented: `saml-subject` and `delegated-subject` are
//     development's words for an assertion with no NameID, and product refuses.
//
// The token lifetime a request asks for is CLAMPED in both modes
// (`wstrust.maxTokenLifetimeMin`), because an STS that honours any requested
// lifetime is wrong in every mode — see handleRst().
//
// EVERY accepted credential is put through stats.recordAuthentication(), on
// every one of the four operations, and that matters beyond the counter it
// increments: it is this service's single authentication funnel, so it is also
// what writes the audit log's `authentication` row and what makes the embedded
// LDAP directory grow a `uid=<name>,ou=users` entry for the person. Three
// things here used to miss it, and each one produced somebody who had
// authenticated through WS-Trust and had no directory object:
//
//   * Validate and Cancel answered before authenticate() was ever called.
//   * a request with BOTH a UsernameToken and an OnBehalfOf recorded only the
//     delegated subject — the requester, the one party that presented a
//     credential, was dropped.
//   * a Renew with no security header read the assertion out of its own
//     RenewTarget and recorded THAT as the credential; the token was talking,
//     not the requester.
//
// The SAML assertion itself is built and protected by saml2.ts: WS-Trust
// carries tokens, it does not define them.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `WsTrust` takes every module of this service it reads — and each
// name it used to destructure from `helpers.js` and `saml/saml2` — through
// its constructor as `WsTrustDeps`, and its three endpoints are registered by
// `registerRoutes(app)`; xmldom is a library and is used directly. The module
// still exports `handleRst()`, `issuerDisagreement()`, `checkedAssertion()`,
// `buildToken()` and `soapFault()`, for the modules and tests that require it
// by them. It registers NOTHING at load (#50, R1): the module exports
// `registerRoutes(app)`, and `common/protocol_stack.ts` calls it at the point
// in the route order where requiring this module always registered them
// (rule 1). Since R2 that root also builds the instance and installs it, and
// the exported functions are FACADES that forward to it. `WsTrust.wire()`
// logs the startup issuer check, as the module did — when the root installs
// the instance, still before the routes are registered rather than after;
// a process without the root builds a default instance and logs it at load.
// ---------------------------------------------------------------------------

// One signer and one verifier for the whole service since 2026-08-27.
import stsCrypto = require('../common/crypto');
import xmldom = require('@xmldom/xmldom');
import app = require('../common/app');
// firstByLocal/textByLocal were written here and now live in helpers.js:
// WS-Federation reads the same shapes (a `wreq` RST, and a `wresult` at its
// mock relying party), and a second copy of a reader that has to cope with
// four trust namespaces is a second copy that gets one of them wrong.
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// The input validator. A LEAF (rule 3): it registers no route and requires only
// `config`, `error_codes`, bunyan, zod, zlib and @xmldom/xmldom, so it closes
// no cycle.
import validation = require('../common/validation');
// wstrust.issuer. A SAML token requested THROUGH WS-Trust is built by the
// SAML modules and carries saml.issuer instead; the two are separate
// settings for that reason, and unset both are the SAML entityID (#494).
import config = require('../common/config');
// #480: the names this service signs under, in one place (a library).
import IssuerNames = require('../common/issuer_names');
import saml2 = require('../saml/saml2');
// #487: the SAML 1.1 assertion builder SAML 1.1 SSO uses. A library.
import saml11 = require('../saml/saml11');
import stats = require('../common/admin_stats');
// The application registry (ou=applications in the embedded directory). A
// library that registers no route, so it cannot move anything in the require
// order this module sits in.
import applications = require('../common/applications');
// THE ROLE GATE. A LEAF (rule 3) requiring only `helpers`, `config` and
// `error_codes`, so a require from here moves no route and closes no cycle.
// See `common/issuance_gate.js`; an unfilled decider answers "allowed".
import gate = require('../common/issuance_gate');
// #485: the OAuth 2.0 scope policy a WS-Trust JWT's configured scopes are
// judged by. A LIBRARY (rule 3) whose requires are libraries this module
// or the issuance gate already loads, so it closes no cycle.
import scopePolicy = require('../common/scope_policy');
// The delegation register (/admin/delegation). Two of the eight mechanisms that
// page knows are this module's — OnBehalfOf and ActAs — and they are the two
// where nothing is checked at all, which is a fact the page states beside the
// Kerberos rows where something is. A library like the two above: it registers
// no route.
import delegation = require('../common/delegation');
// WHO MAY ACT FOR WHOM (#108, 2026-09-23): the policy `OnBehalfOf` and
// `ActAs` are now decided by. A library (rule 3) requiring only libraries.
import delegationPolicy = require('../common/delegation_policy');
// THE SESSION STORE. A plain require in the ordinary direction, and it is why
// this module moved BELOW authn.js in the require order on 2026-09-05 rather
// than keeping its old place — see the note on its line in
// common/protocol_stack.ts. Requiring it from above would have dragged every
// /authn route to the front of the router (rule 1) until #50's R1; since
// then requiring it registers nothing, and `common/protocol_stack.ts`
// registers the /authn routes ahead of this module's in its own order.
// `authn.js` does not require this module, so no cycle closes either way.
import authn = require('../authn/authn');
// The credential verifier and the mode. Libraries that register no route and
// never require this module: `mode.js` is a leaf, and `credentials.js`
// requires only other libraries.
import credentials = require('../common/credentials');
import mode = require('../common/mode');
// The one reading of how a requester authenticated, in SAML 2.0's vocabulary,
// so an assertion this STS issues says what the credential was rather than
// calling everything a password. A leaf in `saml/` that registers nothing.
import authnContext = require('../saml/authn_context');
// The error codes (common/error_codes.js). A LEAF that requires nothing. A
// refusal decided below handleRst() travels out on the result's `errorCode` and
// is marked on the response by the route; it never reaches the SOAP body.
import errorCodes = require('../common/error_codes');
// WHERE A REQUEST IS SERVED IN A SERVICE DEPLOYED AS CELLS (#98 D10): at the
// home of the person it names. Libraries that register no route.
import cells = require('../common/cells');
import cellPlacement = require('../common/cell_placement');
// A DELEGATED SUBJECT'S ATTRIBUTES FROM THEIR HOME (#98 section 5): required
// at load, not lazily, because loading it is what registers the
// `fetch-attributes` operation this cell answers as somebody's home.
import cellAttributes = require('../common/cell_attributes');

const { DOMParser, XMLSerializer } = xmldom;

type Helpers = typeof helpers;
type Saml2 = typeof saml2;

// Everything this module reads of the rest of the service. The helpers and the
// two SAML 2.0 builders are named one by one, as the module destructured them.
interface WsTrustDeps {
  stsCrypto: typeof stsCrypto;
  config: typeof config;
  validation: typeof validation;
  buildSamlAssertion: Saml2['buildSamlAssertion'];
  buildSaml11Assertion: (opts: any) => string;
  encryptAssertion: Saml2['encryptAssertion'];
  stats: typeof stats;
  applications: typeof applications;
  gate: typeof gate;
  delegation: typeof delegation;
  delegationPolicy: typeof delegationPolicy;
  authn: typeof authn;
  credentials: typeof credentials;
  mode: typeof mode;
  authnContext: typeof authnContext;
  errorCodes: typeof errorCodes;
  log: Helpers['log'];
  logArtifact: Helpers['logArtifact'];
  STS: Helpers['STS'];
  xmlEscape: Helpers['xmlEscape'];
  iso: Helpers['iso'];
  randomId: Helpers['randomId'];
  signJwtAs: Helpers['signJwtAs'];
  firstByLocal: Helpers['firstByLocal'];
  textByLocal: Helpers['textByLocal'];
  subjectForName: Helpers['subjectForName'];
  hasSubjectResolver: Helpers['hasSubjectResolver'];
  userFor: Helpers['userFor'];
  scopePolicy: typeof scopePolicy;
}

// The express app's registration methods, as `registerRoutes()` uses them.
interface RouteRegistrar {
  get(path: string, ...handlers: any[]): unknown;
  post(path: string, ...handlers: any[]): unknown;
}

const WST_NS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';

// THE MAY 2004 MEMBER SUBMISSION'S NAMESPACE (#188, 2026-09-24). The answer
// echoes the request's trust namespace, and three of the elements this
// endpoint answered with are not in that version's schema
// (schemas.xmlsoap.org/ws/2004/04/trust/ws-trust.xsd): its
// RequestSecurityTokenResponseCollection holds AT LEAST TWO responses, so an
// Issue is answered with the RSTR itself; the reference to the issued token
// is `RequestedTokenReference` (2005/02 renamed it
// `RequestedAttachedReference`); and there is no Cancel at all — no
// CancelTarget and no RequestedTokenCancelled — so a Cancel is refused with
// the version's own InvalidRequest fault rather than answered in elements
// the version does not have. tests/vendored/sts_xml_schema_validation.js
// validates each version's answers against its own published schema.
const WST_2004_04_NS = 'http://schemas.xmlsoap.org/ws/2004/04/trust';

const SOAP12_NS = 'http://www.w3.org/2003/05/soap-envelope';

const SOAP11_NS = 'http://schemas.xmlsoap.org/soap/envelope/';

const SAML2_TOKEN_TYPE =
    'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0';

const JWT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

// SAML 1.1 (#487): the WS-Security SAML Token Profile 1.1's URI, and the
// assertion namespace an older client names the type by. Both ask for the
// same token; the answer names the first.
const SAML11_TOKEN_TYPE =
    'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1';
const SAML11_TOKEN_TYPE_ALIAS = 'urn:oasis:names:tc:SAML:1.0:assertion';
// The SAML Token Profile's reference to a SAML 1.1 assertion by its
// AssertionID (section 3.4.3).
const SAML11_ASSERTION_ID_REF = 'http://docs.oasis-open.org/wss/' +
    'oasis-wss-saml-token-profile-1.0#SAMLAssertionID';

const STATUS_TOKEN_TYPE = WST_NS + '/RSTR/Status';

const STATUS_VALID = WST_NS + '/status/valid';

const STATUS_INVALID = WST_NS + '/status/invalid';

// The elements of a WS-Trust request that hold SOMEBODY ELSE'S token. A
// UsernameToken or an Assertion inside one of these is not the requester's
// credential and must never be read as one.
const NOT_A_CREDENTIAL = ['OnBehalfOf', 'ActAs', 'RenewTarget',
                          'ValidateTarget', 'CancelTarget'];

/**
 * WS-Trust 1.0 to 1.4: the SOAP RequestSecurityToken endpoint at `/sts`,
 * dispatching on the request type (Issue, Renew, Validate, Cancel), and
 * everything that reads or writes an RST.
 */
class WsTrust {
  /**
   * Builds an instance over what it depends on.
   *
   * @param deps - the helpers, settings, crypto, the assertion builders, the
   * registers, the issuance gate and the delegation policy, among others
   */
  constructor(private readonly deps: WsTrustDeps) {
    deps.log.debug("Entering WsTrust.constructor().");
    deps.log.debug("Leaving WsTrust.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): WsTrustDeps {
    helpers.log.debug("Entering WsTrust.defaultDeps().");
    helpers.log.debug("Leaving WsTrust.defaultDeps().");
    return {
      stsCrypto: stsCrypto,
      config: config,
      validation: validation,
      buildSamlAssertion: saml2.buildSamlAssertion,
      buildSaml11Assertion: saml11.buildSaml11Assertion,
      encryptAssertion: saml2.encryptAssertion,
      stats: stats,
      applications: applications,
      gate: gate,
      delegation: delegation,
      delegationPolicy: delegationPolicy,
      authn: authn,
      credentials: credentials,
      mode: mode,
      authnContext: authnContext,
      errorCodes: errorCodes,
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      STS: helpers.STS,
      xmlEscape: helpers.xmlEscape,
      iso: helpers.iso,
      randomId: helpers.randomId,
      signJwtAs: helpers.signJwtAs,
      firstByLocal: helpers.firstByLocal,
      textByLocal: helpers.textByLocal,
      subjectForName: helpers.subjectForName,
      hasSubjectResolver: helpers.hasSubjectResolver,
      userFor: helpers.userFor,
      scopePolicy: scopePolicy
    };
  }

  // The work loading this module did with its own instance before R2,
  // run once for whichever instance is installed.
  /**
   * Runs the startup check once for the installed instance: whether the two
   * issuer names agree.
   *
   * @param instance - the instance being installed
   */
  static wire(instance: WsTrust): void {
    helpers.log.debug("Entering WsTrust.wire().");
    instance.warnAtStartup();
    helpers.log.debug("Leaving WsTrust.wire().");
  }

  // -------------------------------------------------------------------------
  // THE ROUTES, in the order this module has always registered them.
  // -------------------------------------------------------------------------
  /**
   * Registers `GET /sts/cert`, `GET /sts` and `POST /sts`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: RouteRegistrar): void {
    const { log } = this.deps;
    log.debug("Entering WsTrust.registerRoutes().");
    // GET /sts/cert
    app.get('/sts/cert', (req, res) => {
      return this.stsCertEndpoint(req, res);
    });
    // GET /sts
    app.get('/sts', (req, res) => {
      return this.stsDescriptionEndpoint(req, res);
    });
    // POST /sts
    app.post('/sts', (req, res) => {
      return this.stsEndpoint(req, res);
    });
    log.debug("Leaving WsTrust.registerRoutes().");
  }

  private soapNsFor(version) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.soapNsFor().");
    log.debug("Leaving WsTrust.soapNsFor().");
    return version === '1.1' ? SOAP11_NS : SOAP12_NS;
  }

  // ---------------------------------------------------------------------------
  // THE JWT, and three things changed on 2026-09-12.
  //
  //   * THE ALGORITHM is `wstrust.jwtAlgorithm` rather than the literal RS256,
  //     signed through `helpers.signJwtAs()` with this realm's key for that
  //     algorithm — so the header now carries the `kid` /oauth2/jwks publishes
  //     it under, which the old direct signature over STS.privateKey never did.
  //   * A `jti`. Every other token this service issues carries one and the
  //     token register keys on it; this one had none, which made it the one
  //     token here that could not be named — on /admin/delegation a WS-Trust
  //     JWT's produced identifier was an empty cell explained by a sentence. It
  //     is still not put through helpers.signJwt()'s register: that funnel is
  //     RS256 by construction, and a jti a caller can quote is the half that
  //     was missing.
  //   * THE LIFETIME is whatever handleRst() decided, which is now bounded.
  //
  // `iat`, `exp`, `iss` and `aud` are set explicitly rather than by
  // jsonwebtoken's options, because signJwtAs() takes a payload and nothing
  // else.
  //
  // AND ITS STRUCTURE AND CLAIMS FOLLOW RFC 9068 AND RFC 8693 (#476, rcbj:
  // "follow RFC-9068 and OAuth2 Token Exchange spec for claims in the JWT"
  // — and ONLY for the JWT: the RST, the AppliesTo, the requester's
  // authentication and the RSTR stay WS-Trust's, and a SAML assertion is
  // untouched). What changed, and the reasoned exceptions:
  //
  //   * `typ: "at+jwt"` in the protected header (RFC 9068 section 2.1). The
  //     token is the bearer credential the AppliesTo's service accepts, which
  //     is what an access token is (RFC 6749 section 1.4), and the header is
  //     what keeps it from being mistaken for an ID Token. The RSTR's
  //     wst:TokenType stays `urn:ietf:params:oauth:token-type:jwt`, which is
  //     what the RST asked for and WS-Trust's to answer.
  //   * `client_id` (RFC 9068 section 2.2, RFC 8693 section 4.3): the
  //     APPLICATION the requester authenticated as — the client_id it
  //     registers, else its identifier, as `may_act` names one — found the
  //     way the delegation register finds it (`applications.get()`, then
  //     `forClientId()`). EXCEPTION: a person asking for a token about
  //     themselves with their own UsernameToken has no client, so the claim
  //     is LEFT OUT rather than filled with a name that is not one.
  //   * `act` (RFC 8693 section 4.1): the current actor outermost, prior ones
  //     nested, as before (#186) — and each entry now in the shape this
  //     service's OAuth tokens give it: `iss`, this token's own issuer, in
  //     every entry (#471; the token-chaining profile's "a sub claim ... and
  //     an iss claim identifying the AS"), and an application named by its
  //     client subject in the mode — `urn:sts:client:<client_id>` in RFC
  //     9700 mode, the bare client_id otherwise (#471,
  //     `OAuth2Server.clientActorSubject()`). RFC 8693 permits both and
  //     requires neither. A person who acted (delegation.actorRole) is named
  //     by their `urn:uuid:` subject, as a person is everywhere else. Every
  //     entry is this realm's: each prior delegate came from a token this
  //     STS issued (verified in product), so this issuer is the one vouching
  //     for all of them. #443's ORIGINAL CLIENT needs no rule here: the
  //     first application in a WS-Trust chain is in it because it made the
  //     first ActAs itself.
  //   * EXCEPTIONS with no WS-Trust source: `scope` (an RST asks for none),
  //     and `auth_time` / `acr` / `amr`, which RFC 9068 section 2.2.1 makes
  //     optional and which a delegated JWT could only copy from a token it
  //     cannot see the authentication of. `iss` is `wstrust.issuer`, the
  //     STS's own name, because a WS-Trust issuer publishes no OAuth
  //     authorization server metadata for RFC 9068 section 4 to compare it
  //     with. `exp` is the lifetime the RSTR's wst:Lifetime states, so the
  //     two cannot disagree.
  // ---------------------------------------------------------------------------
  private buildJwt(subject, audience, lifetimeMin, delegates?, requester?,
                   application?, jwtIssuer?) {
    const {
      config, log, logArtifact, randomId, signJwtAs, subjectForName,
      delegationPolicy
    } = this.deps;
    const self = this;
    log.debug("Entering WsTrust.buildJwt().");
    const alg = String(config.value('wstrust.jwtAlgorithm') || 'RS256');
    const now = Math.floor(Date.now() / 1000);
    // THE REALM'S OAUTH ISSUER (#480, rcbj): the identifier
    // /.well-known/oauth-authorization-server publishes, in every mode, so
    // RFC 9068 section 4's check of `iss` against the authorization server's
    // metadata holds — the key that signs this JWT is that server's, at its
    // `jwks_uri`. It was `wstrust.issuer` until #480. Every `act` entry below
    // carries the same issuer (#471).
    const issuer = String(jwtIssuer || this.oauthIssuer(''));
    const claims: any = {
      iss: issuer,
      // THE PERSON'S SUBJECT (2026-09-14) — `urn:uuid:<entryUUID>`, as every
      // other token here. The bare name is left only for a process with no
      // directory, where nobody has a subject; with one, a person the directory
      // does not hold is refused before this is reached (`STS-WSTRUST-0017`),
      // because a bare name would be a `sub` a relying party links on and a
      // person created later under that name would inherit.
      sub: subjectForName(subject) || subject,
      name: subject,
      iat: now,
      exp: now +
           (lifetimeMin > 0 ? lifetimeMin :
            Number(config.value('wstrust.tokenLifetimeMin'))) * 60,
      jti: randomId(18)
    };
    // An empty-string audience is not an audience — only set it when present.
    if (audience) claims.aud = audience;
    const clientId = this.clientIdOf(requester);
    if (clientId) {
      claims.client_id = clientId;
    }
    // THE APPLICATION'S CONFIGURED SCOPES (#485, `wstrustJwtScope`), in
    // RFC 9068 section 2.2.3's `scope`, judged as an OAuth access token's
    // are — `scopePolicy.narrow()`, the token endpoint's own backstop, with
    // the application as the client: its `oauthAllowedScope`, the protected
    // scopes and the issuance policy's per-scope question, and one audit
    // row (STS-OAUTH-0579) naming what was left off. None configured, or
    // none left: no `scope` at all.
    const scope = this.configuredScope(application);
    if (scope) {
      claims.scope = scope;
    }
    // #186: the parties that acted, as RFC 8693 section 4.1's `act` — the
    // most recent outermost, each earlier one nested beneath it — which is
    // the same chain an assertion carries as Delegation Restriction. #476:
    // each entry named as its party is named here, with this issuer.
    const namespaced = this.clientSubjectsNamespaced();
    let act = null;
    (delegates || []).forEach(function (one) {
      const next: any = { sub: self.actorSubjectOf(String(one.nameId),
                                                   namespaced) };
      if (issuer) {
        next.iss = String(issuer);
      }
      if (act) {
        next.act = act;
      }
      act = next;
    });
    if (act) {
      claims.act = act;
    }
    // And RFC 8693 section 4.4's `may_act`, from the person's own choice
    // (`stsMayAct`) — the same claim an access token about them carries.
    const mayAct = delegationPolicy.mayActClaimFor(claims.sub);
    if (mayAct) {
      claims.may_act = mayAct;
    }
    // THE APPLICATION'S CLAIMS (#483, #484): the groups claim, the roles
    // claim, directory-attribute claims and the custom access-token claims —
    // `stats.jwtClaims('access_token', …)`, the one function an OAuth access
    // token's come from, with the context it is handed there
    // (`OAuth2Server.customClaimContext()`'s members). They describe the
    // SUBJECT, so an OnBehalfOf / ActAs token carries the person's and
    // nothing of the requester's. The settings are the APPLIES-TO's
    // application's (`application`), which is the relying party this token
    // is for, as a SAML assertion's are its service provider's; an OAuth
    // access token's are its client's, which is the same role. The
    // protocol's own claims are assigned OVER them, as at the token
    // endpoint, so none of them can replace `sub`, `act` or `exp`.
    const custom = this.applicationClaims(subject, claims, audience,
                                          application);
    const payload = Object.assign(custom, claims);
    const header = { typ: 'at+jwt' };
    logArtifact('WS-Trust JWT', 'before signing',
                { header: Object.assign({ alg: alg }, header),
                  payload: payload });
    // `wstrust.jwtCertificateHeader` decides the `x5c` / `x5u`.
    const signed = signJwtAs(payload, alg, null,
                             { certificateHeader: 'wstrust-jwt',
                               header: header });
    logArtifact('WS-Trust JWT', 'after signing', signed);
    log.debug("Leaving WsTrust.buildJwt(). " + alg + ", jti=" + claims.jti +
              ".");
    return { token: signed, jti: claims.jti };
  }

  // The access-token claims an application's settings put in a token about
  // `subject` (#483, #484): `stats.jwtClaims()` with the members
  // `OAuth2Server.customClaimContext()` gives it — the person's username and
  // subject, their profile where the mode has one, the token's client_id
  // and audience — and `application`, the entry whose settings govern.
  private applicationClaims(subject, claims, audience, application) {
    const { stats, userFor, log } = this.deps;
    log.debug("Entering WsTrust.applicationClaims().");
    const user: any = subject && subject !== 'anonymous'
      ? (userFor(subject) || {}) : {};
    const out = stats.jwtClaims('access_token', {
      username: subject === 'anonymous' ? '' : String(subject || ''),
      sub: claims.sub || '',
      email: user.email || '',
      name: user.name || '',
      given_name: user.given_name || '',
      family_name: user.family_name || '',
      client_id: claims.client_id || '',
      audience: String(audience || ''),
      application: String(application || '')
    }) || {};
    log.debug("Leaving WsTrust.applicationClaims(). " +
              Object.keys(out).length + " claim(s).");
    return out;
  }

  // `wstrustJwtScope` on the application, narrowed by the scope policy
  // (#485). '' when nothing is configured or nothing survives.
  private configuredScope(application) {
    const { applications, scopePolicy, log } = this.deps;
    log.debug("Entering WsTrust.configuredScope().");
    const app: any = application ? applications.get(application) : null;
    const held = app && app.fields
      ? [].concat(app.fields.wstrustJwtScope || []).map(String)
        .map(function (one) { return one.trim(); })
        .filter(function (one) { return !!one; })
      : [];
    if (!held.length) {
      log.debug("Leaving WsTrust.configuredScope(). None configured.");
      return '';
    }
    const kept = scopePolicy.narrow(held.join(' '),
                                    this.clientIdOf(application),
                                    { grant: 'wstrust' });
    log.debug("Leaving WsTrust.configuredScope(). \"" + kept + "\".");
    return String(kept || '').trim();
  }

  // THE APPLICATION A TOKEN IS FOR (#483): the one registered for the
  // AppliesTo, found the way the register finds it (`forAppliesTo()`,
  // which skips the entry `seen()` files under the address itself), and
  // only then the entry of that very identifier. '' for none.
  private appliesToApplication(audience) {
    const { applications, log } = this.deps;
    log.debug("Entering WsTrust.appliesToApplication().");
    const wanted = String(audience || '').trim();
    const found: any = wanted
      ? (applications.forAppliesTo(wanted) || applications.get(wanted))
      : null;
    log.debug("Leaving WsTrust.appliesToApplication(). " +
              (found ? found.identifier : 'None.'));
    return found ? String(found.identifier) : '';
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION A TOKEN IS FOR MUST BE A REGISTERED ONE, IN PRODUCT (#496).
  //
  // rcbj, 2026-10-06: in product an application nobody registered gets
  // nothing but its protocol's own "unknown application" error. "Registered"
  // is #494's word, `IssuerNames.registeredApplication()`: `appRegisteredBy`
  // set on the entry the AppliesTo resolves to — found the way the token
  // will be named, appliesToApplication(), so the application this refuses
  // and the one whose entityID an issued assertion would carry are one. An
  // entry `seen()` filed in development is a sighting, not a registration,
  // and is refused like no entry at all; a realm switched from development
  // keeps none of what development learnt.
  //
  // AN RST WITH NO AppliesTo IS REFUSED TOO (rcbj's decision on #496). It
  // names no application, and the token it would be answered with carries
  // no audience restriction — one any relying party would be entitled to
  // accept.
  //
  // THE FAULTS ARE WS-TRUST 1.4 SECTION 11's. An AppliesTo is, in 1.3's
  // section 4.1, "the scope for which this security token is desired", so
  // an AppliesTo this STS serves nobody under is `wst:InvalidScope` ("The
  // request scope is invalid") — the exact sentence, where
  // `wst:InvalidRequest` would also have been true and said less. A request
  // with no AppliesTo LACKS what it needs to be answered, which is the
  // table's InvalidRequest row.
  //
  // Every token type (SAML 2.0, SAML 1.1, JWT) and OnBehalfOf / ActAs alike:
  // the question is asked before the token type or the delegation is read.
  // The delegation policy's own `unregistered-target` / `no-target` refusal
  // (STS-WSTRUST-0024) is therefore not reached for a delegation in product;
  // it still decides the targets a REGISTERED AppliesTo allows, and still
  // writes development's "would have refused" note.
  //
  // Development answers null: the token is issued under the shared name and
  // `seen()` files the application, as it always was.
  // ---------------------------------------------------------------------------
  private unregisteredApplication(op: string, audience: string,
                                  stated: boolean) {
    const { mode, log } = this.deps;
    log.debug("Entering WsTrust.unregisteredApplication(). op=" + op);
    if (op === 'validate' || op === 'cancel') {
      log.debug("Leaving WsTrust.unregisteredApplication(). " +
                "Issues nothing.");
      return null;
    }
    if (mode.issuesToUnregisteredApplications()) {
      log.debug("Leaving WsTrust.unregisteredApplication(). Development.");
      return null;
    }
    const wanted = String(audience || '').trim();
    if (!wanted) {
      log.debug("Leaving WsTrust.unregisteredApplication(). No AppliesTo.");
      return {
        errorCode: 'STS-WSTRUST-0031', trustFault: 'InvalidRequest',
        why: 'The request carries ' + (stated ? 'an empty' : 'no') +
             ' <wsp:AppliesTo>, so it names no application a token could ' +
             'be issued for. In product mode a token is issued only for a ' +
             'registered application, and never without an audience.'
      };
    }
    if (IssuerNames.registeredApplication(
      this.appliesToApplication(wanted))) {
      log.debug("Leaving WsTrust.unregisteredApplication(). Registered.");
      return null;
    }
    log.debug("Leaving WsTrust.unregisteredApplication(). Not registered.");
    return {
      errorCode: 'STS-WSTRUST-0030', trustFault: 'InvalidScope',
      why: 'The AppliesTo "' + wanted + '" is not a registered application ' +
           'in this realm. In product mode a token is issued only for an ' +
           'application registered ahead of time (the console, ' +
           '/admin-api, RFC 7591 or an LDAP add under ou=applications); ' +
           'one that was only seen is not registered.'
    };
  }

  // WHAT THE ISSUED TOKEN SAYS ABOUT WHO ACTED, for the act's note (#478).
  // It said, until #478, that nothing in an ActAs token carried the
  // composite fact, "a gap in the mock" — true until #186 and wrong since:
  // an ActAs assertion names every party that acted in its SAML V2.0
  // Condition for Delegation Restriction, and since #476 a JWT names them in
  // RFC 8693's nested `act`. The note now says what the token issued
  // carries, in the token's own vocabulary.
  private actNote(via, tokenType) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.actNote(). " + via);
    const jwt = tokenType === JWT_TOKEN_TYPE;
    let out;
    if (tokenType === SAML11_TOKEN_TYPE) {
      // #487: SAML 1.1 has no element to say who acted — see
      // buildSaml11Token().
      out = (via === 'ActAs'
        ? 'ActAs is COMPOSITE (WS-Trust 1.4 section 9.3), but a SAML 1.1 ' +
          'assertion has no element to say so: the Delegation Restriction ' +
          'is a SAML V2.0 condition. The assertion names the subject alone; ' +
          'this register is the record of who acted.'
        : 'OnBehalfOf is IMPERSONATION (WS-Trust 1.3 section 9.2): the SAML ' +
          '1.1 assertion names the subject and adds nobody for this ' +
          'requester, so the relying party sees an ordinary sign-in.');
      log.debug("Leaving WsTrust.actNote(). SAML 1.1.");
      return out;
    }
    if (via === 'ActAs') {
      out = 'ActAs is COMPOSITE (WS-Trust 1.4 section 9.3): the far end ' +
        'can see that a middle tier is acting, and the token issued says ' +
        'so. ' + (jwt
        ? 'The JWT names every party that acted in RFC 8693 section 4.1\'s ' +
          'nested `act` claim, this requester outermost.'
        : 'The assertion names every party that acted in its SAML V2.0 ' +
          'Condition for Delegation Restriction, one <del:Delegate> each, ' +
          'least to most recent, this requester last.');
    } else {
      out = 'OnBehalfOf is IMPERSONATION (WS-Trust 1.3 section 9.2): the ' +
        (jwt ? 'JWT' : 'assertion') + ' names the subject and adds ' +
        'nobody for this requester, so the relying party sees an ordinary ' +
        'sign-in. A chain the presented token already carried is kept as it ' +
        'was (' + (jwt ? 'its `act`' : 'its Delegation Restriction') + ').';
    }
    log.debug("Leaving WsTrust.actNote().");
    return out;
  }

  // WHAT WAS CHECKED OF THE TOKEN A DELEGATION CONSUMED, for the act's row
  // (#479). It said "Its signature and Conditions are not checked" in every
  // mode, which is development's sentence: product verifies an assertion
  // inside OnBehalfOf / ActAs against this realm's own certificate and its
  // Conditions (`checkedAssertion()`), and a JWT against this realm's key,
  // its issuer and its `exp` (#477), and refuses one that fails. The note
  // now follows the mode and the kind of token. The identifier is read in
  // either, so the lineage can be followed back through it.
  private consumedNote(via, tokenKind) {
    const { mode, log } = this.deps;
    log.debug("Entering WsTrust.consumedNote(). " + tokenKind);
    const jwt = tokenKind === 'JWT';
    const lead = 'the token inside <wst:' + via + '>, which is what this ' +
      'request is delegating WITH';
    const lineage = '; its identifier is read so that the lineage of what ' +
      'came out can be followed back through it';
    let out;
    if (!mode.verifiesCredentials()) {
      out = lead + '. In development mode it is NOT verified: its ' +
        'signature and ' + (jwt ? 'expiry' : 'Conditions') + ' are not ' +
        'checked' + lineage;
    } else if (jwt) {
      out = lead + ': a JWT, VERIFIED with this realm\'s own key, its ' +
        'issuer this security token service\'s and its exp not passed' +
        lineage;
    } else {
      out = lead + ': a SAML assertion, VERIFIED against this realm\'s ' +
        'own signing certificate, inside its Conditions' + lineage;
    }
    log.debug("Leaving WsTrust.consumedNote().");
    return out;
  }

  // The application a party authenticated as, by the name it presented:
  // the entry of that identifier, else the one registering it as a
  // client_id. Null for a person, or a name nothing registers.
  private applicationOf(name) {
    const { applications, log } = this.deps;
    log.debug("Entering WsTrust.applicationOf().");
    const wanted = String(name || '').trim();
    const found = wanted
      ? (applications.get(wanted) || applications.forClientId(wanted) || null)
      : null;
    log.debug("Leaving WsTrust.applicationOf(). " +
              (found ? found.identifier : 'None.'));
    return found;
  }

  // RFC 9068's `client_id` for a token the requester `name` asked for: the
  // client_id its application registers, else the application's
  // identifier (`delegationPolicy.mayActClaimFor()`'s rule). '' when the
  // requester is no application — see buildJwt(), the first exception.
  private clientIdOf(name) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.clientIdOf().");
    const app: any = this.applicationOf(name);
    if (!app) {
      log.debug("Leaving WsTrust.clientIdOf(). Not an application.");
      return '';
    }
    const registered = app.fields && app.fields.oauthClientId;
    const first = Array.isArray(registered) ? registered[0] : registered;
    log.debug("Leaving WsTrust.clientIdOf().");
    return String(first || app.identifier);
  }

  // The `sub` of one `act` entry (#476): an application by its client
  // subject in the mode (#471's one form), a person by their subject, and
  // anything else as it was named.
  private actorSubjectOf(name, namespaced) {
    const { subjectForName, log } = this.deps;
    log.debug("Entering WsTrust.actorSubjectOf().");
    const clientId = this.clientIdOf(name);
    if (clientId) {
      log.debug("Leaving WsTrust.actorSubjectOf(). A client.");
      return namespaced ? 'urn:sts:client:' + clientId : clientId;
    }
    const person = subjectForName(name);
    log.debug("Leaving WsTrust.actorSubjectOf(). " +
              (person ? "A person." : "As named."));
    return person || String(name);
  }

  // Whether a client's subject is `urn:sts:client:<id>` here: RFC 9700 mode
  // (`oauth2_bcp.enabled()`, which product implies), the predicate the
  // token endpoint asks for the same question (#471). Asked of the module
  // LAZILY, `common/consent.ts`'s arrangement: it is loaded with the
  // authorization server, and a require at load would pull the OAuth
  // modules in ahead of this one.
  private clientSubjectsNamespaced(): boolean {
    const { log } = this.deps;
    log.debug("Entering WsTrust.clientSubjectsNamespaced().");
    let on = false;
    try {
      on = !!require('../oauth-oidc/oauth2_bcp').enabled();
    } catch (e) {
      // A process without the authorization server (a unit test of this
      // module alone) has no RFC 9700 mode to be in.
      log.debug("Caught in WsTrust.clientSubjectsNamespaced(): " +
                ((e && e.message) || e));
      on = false;
    }
    log.debug("Leaving WsTrust.clientSubjectsNamespaced(). " + on);
    return on;
  }

  // Build the token element (what goes inside wst:RequestedSecurityToken).
  // `authnContextClassRef` is how the REQUESTER authenticated — see
  // authnContextOf() — and is written into a SAML assertion's AuthnStatement.
  // It is optional so an existing caller of this export gets `unspecified`,
  // which is the builder's default and overstates nothing.
  /**
   * Builds the token that goes inside `wst:RequestedSecurityToken`: a signed
   * SAML 2.0 assertion, or a JWT in a BinarySecurityToken when the token type
   * asks for one.
   *
   * @param tokenType - the requested token type
   * @param subject - the subject
   * @param audience - the audience
   * @param lifetimeMin - the lifetime in minutes
   * @param authnContextClassRef - how the requester authenticated; unspecified
   * when absent
   * @param delegates - #186: the parties that acted for the subject, least
   * to most recent; none when absent
   * @param requester - #476: the name the requester authenticated as, whose
   * application is a JWT's `client_id`; none when absent
   * @param application - #483: the application the token is for, whose
   * claim settings govern; the AppliesTo's when absent
   * @param jwtIssuer - #480: a JWT's `iss`, the realm's OAuth issuer at the
   * request's base; the process's base when absent
   * @returns the token's XML, its reference, its token type and its id
   */
  buildToken(tokenType, subject, audience, lifetimeMin,
                      authnContextClassRef, delegates?, requester?,
                      application?, jwtIssuer?) {
    const { buildSamlAssertion, authnContext, log, xmlEscape } = this.deps;
    log.debug("Entering WsTrust.buildToken(). tokenType=" + tokenType + ", " +
        "subject=" +
              subject);
    if (tokenType === JWT_TOKEN_TYPE) {
      const forApp = application || this.appliesToApplication(audience);
      const built = this.buildJwt(subject, audience, lifetimeMin,
                                  delegates, requester, forApp, jwtIssuer);
      const token = { xml: '<wsse:BinarySecurityToken ' +
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ' +
        'ValueType="urn:ietf:params:oauth:token-type:jwt">' + built.token +
        '</wsse:BinarySecurityToken>',
        ref: '', tokenType: JWT_TOKEN_TYPE, id: built.jti };
      log.debug("Leaving WsTrust.buildToken(). Issued a JWT.");
      return token;
    }
    if (tokenType === SAML11_TOKEN_TYPE) {
      const built11 = this.buildSaml11Token(subject, audience, lifetimeMin,
                                            authnContextClassRef, application);
      log.debug("Leaving WsTrust.buildToken(). Issued a SAML 1.1 assertion.");
      return built11;
    }
    // #186: an ActAs token NAMES the parties that acted — the SAML V2.0
    // Condition for Delegation Restriction, least to most recent.
    // #483: the AppliesTo's application, so its own claim settings (the
    // groups claim's, its custom attributes) govern the assertion as a
    // service provider's govern a SAML SSO one.
    const samlApp = application || this.appliesToApplication(audience);
    // #480, #494: the Issuer is `saml.issuer` where somebody set it, and
    // otherwise, in either mode, the SAML 2.0 entityID — a REGISTERED
    // application's own where `saml2.perApplicationEntityId` is on, the name
    // SAML SSO and WS-Federation give the same application; the shared one
    // for an AppliesTo nobody registered (`common/issuer_names.ts`).
    const assertion = buildSamlAssertion(subject, audience, lifetimeMin,
      { authnContextClassRef: authnContextClassRef ||
                              authnContext.AC_UNSPECIFIED,
        delegates: delegates || [],
        application: samlApp,
        issuer: IssuerNames.samlIssuer(samlApp) });
    const idm = assertion.match(/\bID="([^"]+)"/);
    const id = idm ? idm[1] : '';
    const ref = '<wst:RequestedAttachedReference>' +
      '<wsse:SecurityTokenReference ' +
      'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
      '<wsse:KeyIdentifier ' +
      'ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">' +
      xmlEscape(id) +
      '</wsse:KeyIdentifier></wsse:SecurityTokenReference>' +
      '</wst:RequestedAttachedReference>';
    log.debug("Leaving WsTrust.buildToken(). Issued a SAML 2.0 assertion " +
              "with ID " + id +
              ".");
    // `id` is carried out because /admin/delegation quotes the identifier of
    // what a delegated request PRODUCED: the AssertionID for this branch and,
    // since 2026-09-12, the `jti` for the JWT branch above, which had no
    // identifier at all until then. The JWT is still not in the tokens register
    // — what puts a token there is helpers.signJwt(), and this one is signed
    // through signJwtAs() for its configurable algorithm.
    return { xml: assertion, ref: ref, tokenType: SAML2_TOKEN_TYPE, id: id };
  }

  // ---------------------------------------------------------------------------
  // A SAML 1.1 ASSERTION (#487), built by `saml/saml11.ts`'s builder — the
  // one SAML 1.1 SSO and WS-Federation use — so the application's SAML 1.1
  // settings govern it as they govern those: its groups and roles claims,
  // `saml11CustomAttributes` and directory-sourced attributes, through the
  // `application` member #483 added (`stats.samlAttributes('saml11', …)`).
  // The subject, the AudienceRestrictionCondition for the AppliesTo, and an
  // AuthenticationStatement whose method is the SAML 1.1 reading of how the
  // requester authenticated (`authnContextOf()`'s class, mapped).
  //
  // **NO DELEGATE CHAIN, AND THAT IS AN EXCEPTION.** SAML 1.1 has no
  // Delegation Restriction: the SAML V2.0 Condition for Delegation
  // Restriction (sstc-saml-delegation-cs-01) is a SAML 2.0 condition type,
  // derived from SAML 2.0's ConditionAbstractType, and cannot appear in a
  // SAML 1.1 <saml:Conditions>. SAML 1.1 has no standard element for "this
  // party acted". WS-Trust 1.4 section 9.3 says what an ActAs token is
  // EXPECTED to contain (the identity acted as), and names no representation
  // of the requester. So an ActAs in SAML 1.1 is issued about the subject,
  // as the profile allows, and names nobody else. The register is where the
  // chain is, and the act's note says so. A chain a presented token carried
  // cannot be written into SAML 1.1 either, and is not.
  // ---------------------------------------------------------------------------
  private buildSaml11Token(subject, audience, lifetimeMin,
                           authnContextClassRef, application) {
    const { buildSaml11Assertion, authnContext, log, xmlEscape } = this.deps;
    log.debug("Entering WsTrust.buildSaml11Token().");
    const samlApp = application || this.appliesToApplication(audience);
    const method = authnContextClassRef === authnContext.AC_PASSWORD_PROTECTED
      ? authnContext.AM_PASSWORD : authnContext.AM_UNSPECIFIED;
    const assertion = buildSaml11Assertion({
      subject: subject, audience: audience, lifetimeMin: lifetimeMin,
      authnMethod: method, application: samlApp,
      // #480, #494: the same Issuer a SAML 2.0 WS-Trust assertion carries —
      // per application for a registered AppliesTo, as SAML SSO names it.
      issuer: IssuerNames.samlIssuer(samlApp) });
    const idm = assertion.match(/\bAssertionID="([^"]+)"/);
    const id = idm ? idm[1] : '';
    const ref = '<wst:RequestedAttachedReference>' +
      '<wsse:SecurityTokenReference xmlns:wsse="' +
      'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-' +
      'secext-1.0.xsd"><wsse:KeyIdentifier ValueType="' +
      SAML11_ASSERTION_ID_REF + '">' + xmlEscape(id) +
      '</wsse:KeyIdentifier></wsse:SecurityTokenReference>' +
      '</wst:RequestedAttachedReference>';
    log.debug("Leaving WsTrust.buildSaml11Token(). AssertionID " + id + ".");
    return { xml: assertion, ref: ref, tokenType: SAML11_TOKEN_TYPE, id: id };
  }

  private envelope(version, action, bodyInner) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.envelope(). version=" + version +
              ", action=" + action);
    const soapNs = this.soapNsFor(version);
    const header = action
      ? '<soap:Header><wsa:Action ' +
        'xmlns:wsa="http://www.w3.org/2005/08/addressing">' + action +
        '</wsa:Action></soap:Header>'
      : '';
    log.debug("Leaving WsTrust.envelope().");
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="' + soapNs + '">' + header +
      '<soap:Body>' + bodyInner + '</soap:Body></soap:Envelope>';
  }

  // `trustFault` (#108, every refusal since #183): one of WS-Trust 1.4
  // section 11's fault codes, and `trustNs` the trust namespace to qualify it
  // with, which is the request's own. Section 11: "The tables below are
  // defined in terms of SOAP 1.1. For SOAP 1.2, the Fault/Code/Value is
  // env:Sender ... and the Fault/Code/Subcode/Value is the faultcode below."
  // So on 1.1 it REPLACES `soap:Client` as the faultcode, and on 1.2 it is
  // the Subcode under `soap:Sender`. Every refusal here names one at the
  // place it refuses — `ws-trust/CLAUDE.md` has the table, and why each —
  // and a call without one is the generic Client/Sender fault no refusal
  // sends any more.
  /**
   * Builds a SOAP Fault for the request's SOAP version, qualified with a
   * WS-Trust 1.4 section 11 fault code when one is given.
   *
   * @param version - the SOAP version, `1.1` or `1.2`
   * @param reason - the fault's reason
   * @param trustFault - a WS-Trust fault code, such as `RequestFailed`
   * @param trustNs - the trust namespace to qualify it with, the request's own
   * @returns the SOAP envelope
   */
  // error-code: none — the definition of the helper, not a call to it
  soapFault(version, reason, trustFault?, trustNs?) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering WsTrust.soapFault(). version=" + version + ", " +
        "reason=" + reason);
    const soapNs = this.soapNsFor(version);
    const wstDecl = trustFault
      ? ' xmlns:wst="' + xmlEscape(trustNs || WST_NS) + '"' : '';
    const body = version === '1.1'
      ? '<soap:Fault><faultcode' + wstDecl + '>' +
        (trustFault ? 'wst:' + trustFault : 'soap:Client') +
        '</faultcode><faultstring>' +
        xmlEscape(reason) + '</faultstring></soap:Fault>'
      : '<soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value>' +
        (trustFault
          ? '<soap:Subcode><soap:Value' + wstDecl + '>wst:' + trustFault +
            '</soap:Value></soap:Subcode>'
          : '') +
        '</soap:Code><soap:Reason><soap:Text ' +
        'xml:lang="en">' + xmlEscape(reason) +
        '</soap:Text></soap:Reason></soap:Fault>';
    log.debug("Leaving WsTrust.soapFault().");
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="' + soapNs + '">' + '<soap:Body>' + body +
      '</soap:Body></soap:Envelope>';
  }

  // THE ONE FAULT THAT IS NOT A REFUSAL (#183): this service failing, which
  // section 11 has no code for — every one of its codes is a Sender fault,
  // something wrong with the REQUEST. SOAP 1.1 section 4.4.1 calls this
  // `Server` and SOAP 1.2 Part 1 section 5.4.6 `Receiver`, "the message
  // could not be processed for reasons attributable to the processing of the
  // message rather than to the contents of the message itself".
  /**
   * Builds the SOAP Fault for a failure of this service rather than of the
   * request: `soap:Server` on SOAP 1.1, `soap:Receiver` on SOAP 1.2.
   *
   * @param version - the SOAP version, `1.1` or `1.2`
   * @param reason - the fault's reason
   * @returns the SOAP envelope
   */
  // error-code: none — the definition of the helper, not a call to it
  receiverFault(version, reason) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering WsTrust.receiverFault(). version=" + version);
    const body = version === '1.1'
      ? '<soap:Fault><faultcode>soap:Server</faultcode><faultstring>' +
        xmlEscape(reason) + '</faultstring></soap:Fault>'
      : '<soap:Fault><soap:Code><soap:Value>soap:Receiver</soap:Value>' +
        '</soap:Code><soap:Reason><soap:Text xml:lang="en">' +
        xmlEscape(reason) + '</soap:Text></soap:Reason></soap:Fault>';
    log.debug("Leaving WsTrust.receiverFault().");
    return '<?xml version="1.0" encoding="UTF-8"?>' +
      '<soap:Envelope xmlns:soap="' + this.soapNsFor(version) + '">' +
      '<soap:Body>' + body + '</soap:Body></soap:Envelope>';
  }

  // --- request handling ------------------------------------------------------
  private detectSoapVersion(doc, contentType) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.detectSoapVersion().");
    const root = doc && doc.documentElement;
    log.debug("Leaving WsTrust.detectSoapVersion().");
    if (root && root.namespaceURI === SOAP11_NS) {
      log.debug("Leaving WsTrust.detectSoapVersion().");
      return '1.1';
    }
    if (root && root.namespaceURI === SOAP12_NS) {
      log.debug("Leaving WsTrust.detectSoapVersion().");
      return '1.2';
    }
    log.debug("Leaving WsTrust.detectSoapVersion().");
    return /text\/xml/i.test(contentType || '') ? '1.1' : '1.2';
  }

  // The request's own trust namespace, for a fault raised before
  // handleRst() has read it (#183); 1.3's when there is none.
  private trustNsOf(doc): string {
    const { log, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.trustNsOf().");
    const rst = doc ? firstByLocal(doc, 'RequestSecurityToken') : null;
    log.debug("Leaving WsTrust.trustNsOf().");
    return (rst && rst.namespaceURI) || WST_NS;
  }

  // Is `node` inside one of them?
  private insideAnotherPartysToken(node) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.insideAnotherPartysToken().");
    let current = node && node.parentNode;
    while (current) {
      const name = current.localName || current.nodeName || '';
      if (NOT_A_CREDENTIAL.indexOf(String(name).split(':').pop()) >= 0) {
        log.debug("Leaving WsTrust.insideAnotherPartysToken(). It is inside " +
                  name + ".");
        return true;
      }
      current = current.parentNode;
    }
    log.debug("Leaving WsTrust.insideAnotherPartysToken(). It is not.");
    return false;
  }

  // The first element of that local name under `root` that is the REQUESTER'S
  // own, skipping any that belongs to somebody else.
  //
  // This exists because a WS-Trust request routinely carries several
  // identities: the requester's UsernameToken in the security header, the
  // subject named in `wst:OnBehalfOf` or `wst:ActAs`, and the token being
  // renewed, validated or cancelled in `wst:RenewTarget` /
  // `wst:ValidateTarget`. All of them are `wsse:UsernameToken` or
  // `saml:Assertion` elements, so a plain search over the document answers
  // "which comes first in DOCUMENT ORDER", which is not the question being
  // asked.
  //
  // That is not hypothetical: a Renew whose RenewTarget held the expiring
  // assertion, sent with no security header at all, used to authenticate as
  // that assertion's NameID. It was the TOKEN talking, not the requester.
  private firstOwnedByRequester(root, name) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.firstOwnedByRequester(). name=" + name);
    const found = root.getElementsByTagNameNS('*', name);
    for (let i = 0; found && i < found.length; i++) {
      if (!this.insideAnotherPartysToken(found[i])) {
        log.debug("Leaving WsTrust.firstOwnedByRequester(). Found one at " +
                  "index " + i +
                  ".");
        return found[i];
      }
    }
    log.debug("Leaving WsTrust.firstOwnedByRequester(). There is none.");
    return null;
  }

  // The element a REQUESTER's own credential may be read from: `wsse:Security`
  // when the request has one, and the whole document when it has none. The
  // fallback is deliberately lenient — a UsernameToken put somewhere other than
  // the security header is still read — and it is safe because
  // firstOwnedByRequester() below is what does the looking.
  private credentialScope(doc) {
    const { log, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.credentialScope().");
    const security = firstByLocal(doc, 'Security');
    if (security) {
      log.debug("Leaving WsTrust.credentialScope(). The security header is " +
                "the scope.");
      return security;
    }
    log.debug("Leaving WsTrust.credentialScope(). There is no security " +
              "header, so the whole document is the scope.");
    return doc;
  }

  // ---------------------------------------------------------------------------
  // A SAML ASSERTION SOMEBODY PRESENTED, CHECKED THE WAY PRODUCT MODE CHECKS
  // ONE (2026-09-12).
  //
  // Development reads the NameID off an assertion and believes it — the posture
  // the credential note below has always stated. In product that is a
  // credential anybody can type, so this is the check that replaces believing
  // it, used for the requester's own assertion AND for the token inside an
  // OnBehalfOf/ActAs:
  //
  //   1. THE SIGNATURE, over THIS assertion element and no other, against THIS
  //      REALM'S OWN signing certificate. The element is serialised on its own
  //      first, because the SOAP document can hold several assertions — the
  //      requester's and the delegated one — and a verifier asked about "the
  //      assertion in this document" would be answered about whichever came
  //      first. Exclusive canonicalization is what makes a standalone
  //      serialisation of an embedded element verify, and it is the only one
  //      this service signs with.
  //   2. THE CONDITIONS, NotBefore and NotOnOrAfter, with `oauth2.clockSkewS`
  //      of tolerance — the reading tolerance `federation_sp.ts` applies to an
  //      inbound assertion, for the reason it gives: a deployment decides once
  //      how far out the clocks it reads may be.
  //   3. A SUBJECT. An assertion naming nobody names nobody; development's
  //      `saml-subject` fallback is not a person.
  //
  // WHY THIS REALM'S CERTIFICATE AND NOTHING ELSE: it is the smallest real
  // answer. It is the key this STS already holds and publishes at /sts/cert,
  // and it covers what an assertion is presented here FOR — renewing,
  // validating or exchanging a token this STS issued. Trusting a foreign issuer
  // needs a register of which certificate may assert which subjects, and
  // accepting any certificate in the document's own KeyInfo would be accepting
  // any assertion at all.
  // ---------------------------------------------------------------------------
  /**
   * Checks a SAML assertion presented to this STS, as a credential or inside
   * OnBehalfOf or ActAs: its signature against this realm's own signing
   * certificate, its conditions within `oauth2.clockSkewS`, and a subject.
   *
   * @param assertion - the assertion element
   * @param what - what it was presented as, for the refusal
   * @returns `{ ok, subject }`, or `{ ok: false, errorCode, … }` — with
   * `trustFault: 'ExpiredData'` on an expired one, the one refusal here whose
   * section 11 code does not depend on the seat it was presented in
   */
  checkedAssertion(assertion, what) {
    const { stsCrypto, config, log, STS, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.checkedAssertion(). what=" + what);
    const nameId = firstByLocal(assertion, 'NameID') ||
                   firstByLocal(assertion, 'NameIdentifier');
    const named = nameId ? (nameId.textContent || '').trim() : '';
    const xml = new XMLSerializer().serializeToString(assertion);
    // Any generation of this realm's XML key (#42): helpers.verifyOwnXml().
    const signature = helpers.verifyOwnXml(xml, { element: 'Assertion' });
    if (!signature.ok) {
      log.debug("Leaving WsTrust.checkedAssertion(). The signature did not " +
                "verify.");
      return { ok: false, errorCode: 'STS-WSTRUST-0004',
               reason: 'The ' + what + ' is a SAML assertion whose signature ' +
                       'does not verify against this security token ' +
                       'service\'s ' +
                       'own certificate (' +
                       (signature.why || 'unsigned') + '). In product mode ' +
                       'an assertion is accepted only if this STS issued it.' };
    }
    const conditions = firstByLocal(assertion, 'Conditions');
    const skewMs =
      Math.max(0, Number(config.value('oauth2.clockSkewS'))) * 1000;
    const now = Date.now();
    const notBefore = conditions ?
                      Date.parse(conditions.getAttribute('NotBefore') || '') :
                      NaN;
    const notOnOrAfter = conditions ?
                         Date.parse(conditions.getAttribute('NotOnOrAfter') ||
                                    '') : NaN;
    if (!isNaN(notBefore) && notBefore - skewMs > now) {
      log.debug("Leaving WsTrust.checkedAssertion(). Not yet valid.");
      return { ok: false, errorCode: 'STS-WSTRUST-0005',
               reason: 'The ' + what + ' is not valid until ' +
                 conditions.getAttribute('NotBefore') + '.' };
    }
    if (!isNaN(notOnOrAfter) && notOnOrAfter + skewMs <= now) {
      log.debug("Leaving WsTrust.checkedAssertion(). Expired.");
      return { ok: false, errorCode: 'STS-WSTRUST-0006',
               trustFault: 'ExpiredData',
               reason: 'The ' + what + ' expired at ' +
                 conditions.getAttribute('NotOnOrAfter') + '.' };
    }
    if (!named) {
      log.debug("Leaving WsTrust.checkedAssertion(). It names nobody.");
      return { ok: false, errorCode: 'STS-WSTRUST-0007',
               reason: 'The ' + what + ' carries no NameID, so it names ' +
                                  'nobody. Product mode does not invent a ' +
                                  'subject for it.' };
    }
    log.debug("Leaving WsTrust.checkedAssertion(). Verified, for " + named +
              ".");
    return { ok: true, subject: named };
  }

  // The requester's own credential, read from that scope. It returns null when
  // nothing was presented, which is a different answer from a credential that
  // was presented and refused.
  //
  // EVERY REFUSAL HERE IS `wst:FailedAuthentication` (#183) — section 11's
  // "Authentication failed", which is what each of them is: the requester's
  // credential was incomplete, wrong, or an assertion that did not verify —
  // except an EXPIRED assertion, which is `wst:ExpiredData`, "The request
  // data is out-of-date", the more exact of the two. The same fault for a
  // wrong password and an unknown user is the enumeration rule below.
  private requesterCredential(doc) {
    const { credentials, mode, log, firstByLocal, textByLocal } = this.deps;
    log.debug("Entering WsTrust.requesterCredential().");
    const scope = this.credentialScope(doc);
    const ut = this.firstOwnedByRequester(scope, 'UsernameToken');
    if (ut) {
      const user = textByLocal(ut, 'Username');
      const pass = textByLocal(ut, 'Password');
      if (!user || !pass) {
        log.debug("Leaving WsTrust.requesterCredential(). Incomplete " +
                  "UsernameToken.");
        return { ok: false, errorCode: 'STS-WSTRUST-0002',
                 trustFault: 'FailedAuthentication',
                 reason: 'UsernameToken requires a username and password.' };
      }
      // THE CREDENTIAL (2026-09-06). One call, both modes — `credentials.js`
      // still refuses the reserved string `invalid` in development, which is
      // what this branch used to do on its own, and verifies against the hashed
      // `userPassword` in product mode.
      //
      // **THE FAULT SAYS THE SAME THING WHATEVER FAILED.** A SOAP Fault that
      // distinguished "no such user" from "wrong password" would be the account
      // enumeration answer over a protocol whose whole audience is machines;
      // the reason goes to the log instead.
      // `door: 'wstrust'` (#101): a password-only door, so in product a
      // person with a second factor is refused their password here — with
      // this same fault — and an app password scoped to `wstrust` is
      // accepted instead.
      const checked = credentials.verify(user, pass, {
        via: 'a WS-Security UsernameToken', door: 'wstrust'
      });
      if (!checked.ok) {
        log.info('wstrust: the UsernameToken for "' + user + '" was refused (' +
                 checked.reason + '): ' + checked.detail);
        log.debug("Leaving WsTrust.requesterCredential(). The credential was " +
                  "refused.");
        return { ok: false, errorCode: 'STS-WSTRUST-0003',
                 trustFault: 'FailedAuthentication',
                 reason: 'Authentication failed for user ' + user + '.' };
      }
      log.debug("Leaving WsTrust.requesterCredential(). A UsernameToken " +
                "for " + user + ".");
      // AN APP PASSWORD IS SAID SO (#101): one factor, and the row names it.
      const viaApp = checked.reason === 'app-password' && checked.appPassword;
      return { ok: true, subject: user,
               method: viaApp ? 'WS-Security UsernameToken (app password)'
                 : 'WS-Security UsernameToken',
               kind: 'password',
               note: viaApp
                 ? 'An app password scoped to WS-Trust ("' +
                   checked.appPassword.name + '") was verified.'
                 : mode.verifiesCredentials()
                 ? 'The password was verified against the stored userPassword.'
                 : 'The password is not checked in development mode, except ' +
                   'for the reserved string "invalid".' };
    }
    // A SAML assertion presented directly as the credential.
    const assertion = this.firstOwnedByRequester(scope, 'Assertion');
    if (assertion) {
      // PRODUCT: verified, or refused. See checkedAssertion().
      if (mode.verifiesCredentials()) {
        const checked = this.checkedAssertion(assertion, 'requester\'s ' +
            'credential');
        if (!checked.ok) {
          log.info('wstrust: a SAML assertion presented as a credential was ' +
                   'refused: ' +
                   checked.reason);
          log.debug("Leaving WsTrust.requesterCredential(). The assertion " +
                    "was refused.");
          return { ok: false, reason: checked.reason,
                   errorCode: checked.errorCode,
                   trustFault: checked.trustFault || 'FailedAuthentication' };
        }
        log.debug("Leaving WsTrust.requesterCredential(). A verified SAML " +
                  "assertion for " +
                  checked.subject + ".");
        return { ok: true, subject: checked.subject, kind: 'assertion',
                 method: 'a SAML assertion as the credential',
                 note: 'The assertion\'s signature was verified against this ' +
                       'STS\'s own certificate and its Conditions were ' +
                       'checked.' };
      }
      const nameId = firstByLocal(assertion, 'NameID') ||
        firstByLocal(assertion, 'NameIdentifier');
      const named = (nameId && (nameId.textContent || '').trim()) ||
        'saml-subject';
      log.debug("Leaving WsTrust.requesterCredential(). A SAML assertion " +
                "for " + named +
                ".");
      return { ok: true, subject: named, kind: 'assertion',
               method: 'a SAML assertion as the credential',
               note: 'The assertion\'s signature and Conditions are not ' +
                     'checked in development mode; the NameID is read and ' +
                     'believed.' };
    }
    log.debug("Leaving WsTrust.requesterCredential(). Nothing was presented.");
    return null;
  }

  // The subject named in `wst:OnBehalfOf` or `wst:ActAs`, and WHICH OF THE TWO
  // it was. `{ subject: '', element: '' }` when the request delegates nothing.
  //
  // The two used to be collapsed with a `||`, which was right for everything
  // that reads this — the token issued is identical either way, because this
  // service polices nothing — and wrong for /admin/delegation, which is where
  // the difference is the whole point. They are not two spellings of one thing:
  //
  //   * `wst:OnBehalfOf` (1.3 §9.2) asks for a token ABOUT somebody. The
  //     relying party is handed an ordinary sign-in and cannot tell a middle
  //     tier was involved. IMPERSONATION.
  //   * `wst14:ActAs` (1.4 §9.3) is composite by definition: the token is about
  //     the named subject AND says the requester is acting. DELEGATION, and the
  //     element to reach for when the far end must be able to tell.
  //
  // A request carrying BOTH takes OnBehalfOf, which is the order the `||`
  // always had; the row says which one it attributed the act to, so the choice
  // is visible rather than silently made.
  //
  // AND THE IDENTIFIER OF THE TOKEN THAT WAS HANDED IN, which is the one thing
  // here that /admin/tokens/credential cannot do without. That page walks a
  // lineage by joining what an act PRODUCED to what the next act CONSUMED, on
  // the identifier and on nothing else (see credential_graph.js). A chain of
  // OnBehalfOf hops — the assertion one call issues is the assertion the next
  // call delegates with — is exactly the shape it exists to draw, and it was
  // invisible to it until this was read: the act's `consumed` named the
  // requester's WS-Security credential, which this service never issued and
  // cannot name, so every trail stopped one generation in at a wall.
  //
  // Three spellings, because three things can legitimately be inside one of
  // these elements: a SAML 2.0 assertion (`ID`), a SAML 1.1 one
  // (`AssertionID`), and a <wsse:SecurityTokenReference> naming a token by
  // KeyIdentifier rather than carrying it. An element holding none of them
  // yields '', which is not an error — it is the honest "this act consumed
  // something this register cannot name", and the lineage page prints that as a
  // reason rather than as an origin.
  private delegatedTokenId(element) {
    const { log, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.delegatedTokenId().");
    const assertion = firstByLocal(element, 'Assertion');
    if (assertion) {
      const id = assertion.getAttribute('ID') ||
        assertion.getAttribute('AssertionID') || '';
      if (String(id).trim()) {
        log.debug("Leaving WsTrust.delegatedTokenId(). An assertion, " + id +
                  ".");
        return String(id).trim();
      }
    }
    const keyIdentifier = firstByLocal(element, 'KeyIdentifier');
    if (keyIdentifier) {
      const named = (keyIdentifier.textContent || '').trim();
      if (named) {
        log.debug("Leaving WsTrust.delegatedTokenId(). A reference to " +
                  named + ".");
        return named;
      }
    }
    log.debug("Leaving WsTrust.delegatedTokenId(). Nothing here carries an " +
              "identifier.");
    return '';
  }

  private delegatedSubject(doc, jwtIssuer?) {
    const { mode, log, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.delegatedSubject().");
    const oboEl = firstByLocal(doc, 'OnBehalfOf');
    const actAsEl = firstByLocal(doc, 'ActAs');
    const obo = oboEl || actAsEl;
    if (!obo) {
      log.debug("Leaving WsTrust.delegatedSubject(). Nothing is delegated.");
      return { subject: '', element: '', tokenId: '' };
    }
    const element = oboEl ? 'OnBehalfOf' : 'ActAs';
    // A JWT THIS STS ISSUED, in the BinarySecurityToken its own RSTR carries
    // it in (#477). WS-Trust 1.3 section 9.2 and 1.4 section 9.3 put a
    // security token in either element and name no kind, so a JWT is read
    // the way an assertion is — see delegatedJwt(). An assertion inside
    // wins where an element somehow carries both, as it always did.
    const jwtEl = firstByLocal(obo, 'Assertion') ? null
      : this.delegatedJwtElement(obo);
    if (jwtEl) {
      const fromJwt = this.delegatedJwt(jwtEl, element, jwtIssuer);
      fromJwt.both = !!(oboEl && actAsEl);
      log.debug("Leaving WsTrust.delegatedSubject(). A JWT via " + element +
                ".");
      return fromJwt;
    }
    // PRODUCT: the token being delegated WITH must be an assertion this STS
    // issued and that is still valid — a bare UsernameToken or an unsigned
    // assertion inside <wst:OnBehalfOf> is a name anybody can type, and the
    // token this request asks for would be ABOUT that name. See
    // checkedAssertion().
    if (mode.verifiesCredentials()) {
      const inner = firstByLocal(obo, 'Assertion');
      if (!inner) {
        log.debug("Leaving WsTrust.delegatedSubject(). Product: no assertion " +
                  "to delegate with.");
        return { subject: '', element: element, tokenId: '',
                 errorCode: 'STS-WSTRUST-0008',
                 trustFault: 'InvalidRequest',
                 refused: 'The <wst:' + element + '> carries no SAML ' +
                          'assertion. In product mode a delegated subject ' +
                          'must be carried in an assertion this security ' +
                          'token service issued, because a name alone is not ' +
                          'evidence of anybody.' };
      }
      const checked = this.checkedAssertion(inner,
                                       'token inside <wst:' + element + '>');
      if (!checked.ok) {
        log.debug("Leaving WsTrust.delegatedSubject(). Product: the " +
                  "delegated token was refused.");
        // The requester authenticated; what is wrong is a token the
        // REQUEST carries, so `wst:InvalidRequest` rather than
        // FailedAuthentication — and `wst:ExpiredData` for an expired one
        // (#183).
        return { subject: '', element: element, tokenId: '',
                 refused: checked.reason,
                 errorCode: checked.errorCode,
                 trustFault: checked.trustFault || 'InvalidRequest' };
      }
      log.debug("Leaving WsTrust.delegatedSubject(). Product: " +
                checked.subject + " via " + element + ".");
      return { subject: checked.subject, element: element,
               both: !!(oboEl && actAsEl),
               tokenId: this.delegatedTokenId(obo), tokenKind: 'assertion',
               audiences: this.delegatedAudiences(obo),
               delegates: this.delegatedDelegates(obo) };
    }
    const nameId = firstByLocal(obo, 'NameID') ||
      firstByLocal(obo, 'NameIdentifier');
    const named = (nameId && (nameId.textContent || '').trim()) ||
      'delegated-subject';
    const tokenId = this.delegatedTokenId(obo);
    log.debug("Leaving WsTrust.delegatedSubject(). " + named + " via " +
              element + ".");
    return { subject: named, element: element, both: !!(oboEl && actAsEl),
             tokenId: tokenId, tokenKind: 'assertion',
             audiences: this.delegatedAudiences(obo),
             delegates: this.delegatedDelegates(obo) };
  }

  // ---------------------------------------------------------------------------
  // A JWT INSIDE OnBehalfOf OR ActAs (#477, 2026-10-06).
  //
  // WS-Trust names no kind of token for either element: 1.3 section 9.2's
  // OnBehalfOf and 1.4 section 9.3's ActAs each hold "a security token or
  // wsse:SecurityTokenReference". Until #477 only a SAML assertion was read
  // there, so a chain whose response tokens were JWTs stopped at its first
  // hop: product refused the JWT (`STS-WSTRUST-0008`, "no SAML assertion"),
  // and development read no NameID and delegated for `delegated-subject`.
  //
  // THE SAME FOOTING AS AN ASSERTION (`checkedAssertion()`), for the same
  // reason: the smallest real answer to "which issuer is trusted" is this
  // STS. So the token is the `wsse:BinarySecurityToken` this STS's own RSTR
  // carries a JWT in (ValueType `urn:ietf:params:oauth:token-type:jwt`),
  // and in PRODUCT it must verify with this realm's own key, be inside its
  // own `exp` / `nbf` (`oauth2.clockSkewS`, via `verifyJws()`), carry this
  // STS's issuer (`wstrust.issuer`) — an OAuth access token from this realm
  // is signed with the same key and is not a token this STS issued — and
  // name a person this directory holds by its `urn:uuid:` subject.
  // Development reads it unverified and believes it, as it believes a
  // NameID. What the rest of the request needs is read off it as an
  // assertion's is: the subject, S (its `aud`), the prior delegates (its
  // `act`, innermost first: least to most recent) and the identifier the
  // act consumed (its `jti`). Nothing about the decision or the token issued
  // changes; WS-Trust's processing reads one more kind of token.
  // ---------------------------------------------------------------------------
  private delegatedJwtElement(element) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.delegatedJwtElement().");
    const all = element && element.getElementsByTagNameNS
      ? element.getElementsByTagNameNS('*', 'BinarySecurityToken') : [];
    for (let i = 0; i < all.length; i += 1) {
      if (String(all[i].getAttribute('ValueType') || '') === JWT_TOKEN_TYPE) {
        log.debug("Leaving WsTrust.delegatedJwtElement(). Found.");
        return all[i];
      }
    }
    log.debug("Leaving WsTrust.delegatedJwtElement(). None.");
    return null;
  }

  private delegatedJwt(jwtEl, element, jwtIssuer?): any {
    const { mode, config, log } = this.deps;
    log.debug("Entering WsTrust.delegatedJwt(). " + element);
    const token = String(jwtEl.textContent || '').trim();
    const what = 'JWT inside <wst:' + element + '>';
    const refused = function (code, why, fault?) {
      log.debug("Entering refused(). " + code);
      log.debug("Leaving refused().");
      return { subject: '', element: element, tokenId: '', errorCode: code,
               trustFault: fault || 'InvalidRequest', refused: why };
    };
    let claims: any = null;
    if (mode.verifiesCredentials()) {
      try {
        claims = helpers.verifyOwnJws(token);
      } catch (e) {
        log.debug("Caught in WsTrust.delegatedJwt(): " +
                  ((e && e.message) || e));
        const message = String((e && e.message) || e);
        log.debug("Leaving WsTrust.delegatedJwt(). Product: it did not " +
                  "verify.");
        if (/expired/i.test(message)) {
          return refused('STS-WSTRUST-0027', 'The ' + what + ' has ' +
                         'expired (' + message + ').', 'ExpiredData');
        }
        return refused('STS-WSTRUST-0026', 'The ' + what + ' does not ' +
                       'verify with this security token service\'s own key (' +
                       message + '). In product mode a delegated JWT is ' +
                       'accepted only if this STS issued it.');
      }
      // The issuer this STS's JWTs carry since #480: the realm's OAuth
      // issuer. An access token the authorization server issued carries it
      // too, under the same key — the realm is one issuer.
      const issuer = String(jwtIssuer || this.oauthIssuer(''));
      if (!claims || String(claims.iss || '') !== issuer) {
        log.debug("Leaving WsTrust.delegatedJwt(). Product: another issuer.");
        return refused('STS-WSTRUST-0026', 'The ' + what + ' was issued by "' +
                       String(claims && claims.iss) + '", not by this ' +
                       'security token service ("' + issuer + '").');
      }
    } else {
      try {
        claims = JSON.parse(Buffer.from(token.split('.')[1] || '',
                                        'base64url').toString('utf8'));
      } catch (e) {
        log.debug("Caught in WsTrust.delegatedJwt(): " +
                  ((e && e.message) || e));
        // Development reads what it can; a JWT it cannot read names nobody.
        claims = {};
      }
    }
    const subject = this.nameOfSubject(String(claims.sub || '')) ||
      (mode.verifiesCredentials() ? '' : String(claims.name || ''));
    if (!subject) {
      log.debug("Leaving WsTrust.delegatedJwt(). It names nobody.");
      if (mode.verifiesCredentials()) {
        return refused('STS-WSTRUST-0028', 'The ' + what + '\'s sub "' +
                       String(claims.sub || '') + '" names nobody this ' +
                       'directory holds.');
      }
    }
    const audiences = [].concat(claims.aud === undefined ? [] : claims.aud)
      .map(String).filter(function (one) { return !!one; });
    log.debug("Leaving WsTrust.delegatedJwt(). " + (subject ||
              'delegated-subject') + ".");
    return { subject: subject || 'delegated-subject', element: element,
             tokenKind: 'JWT',
             tokenId: String(claims.jti || ''), audiences: audiences,
             delegates: this.delegatesInAct(claims.act) };
  }

  // A person's username from the `urn:uuid:` subject this service gave them.
  private nameOfSubject(sub) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.nameOfSubject().");
    const name = helpers.nameForSubject(sub);
    log.debug("Leaving WsTrust.nameOfSubject().");
    return name;
  }

  // An RFC 8693 `act` chain as the delegates list an assertion's Delegation
  // Restriction gives (least to most recent): innermost first, each `sub`
  // read back to the name the rest of this module uses — an application's
  // identifier for a client subject (`urn:sts:client:<client_id>` or the
  // bare client_id, #476), a person's username for a `urn:uuid:` one.
  private delegatesInAct(act) {
    const { applications, log } = this.deps;
    log.debug("Entering WsTrust.delegatesInAct().");
    const chain = [];
    let level = act;
    // Bounded, as `OAuth2Server.priorActChain()` is: RFC 8693 bounds the
    // nesting by nothing.
    for (let depth = 0; level && typeof level === 'object' && depth < 64;
         depth += 1) {
      chain.unshift(String(level.sub || ''));
      level = level.act;
    }
    const out = chain.filter(function (one) { return !!one; })
      .map((sub) => {
        const clientId = /^urn:sts:client:./.test(sub)
          ? sub.slice('urn:sts:client:'.length) : sub;
        const app: any = applications.get(clientId) ||
          applications.forClientId(clientId);
        if (app) {
          return { nameId: String(app.identifier), format: '', instant: '' };
        }
        const person = this.nameOfSubject(sub);
        return { nameId: person || sub,
                 format: person ? 'urn:oasis:names:tc:SAML:1.1:nameid-' +
                                  'format:unspecified' : '',
                 instant: '' };
      });
    log.debug("Leaving WsTrust.delegatesInAct(). " + out.length);
    return out;
  }

  // #186: the parties the delegated assertion already says ACTED — its SAML
  // V2.0 Delegation Restriction's <del:Delegate> NameIDs, least to most
  // recent, as that profile orders them — so an ActAs of an ActAs token
  // keeps the chain, as RFC 8693's `act` nests.
  private delegatedDelegates(element) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.delegatedDelegates().");
    const out = [];
    const all = element && element.getElementsByTagNameNS
      ? element.getElementsByTagNameNS(
        'urn:oasis:names:tc:SAML:2.0:conditions:delegation', 'Delegate')
      : [];
    for (let i = 0; i < all.length; i += 1) {
      const nameIds = all[i].getElementsByTagNameNS('*', 'NameID');
      const nameId = nameIds.length
        ? String(nameIds[0].textContent || '').trim() : '';
      if (nameId) {
        out.push({ nameId: nameId,
                   format: String(nameIds[0].getAttribute('Format') || ''),
                   instant: String(all[i].getAttribute('DelegationInstant') ||
                                   '') });
      }
    }
    log.debug("Leaving WsTrust.delegatedDelegates(). " + out.length);
    return out;
  }

  // #186: the audiences the delegated assertion is restricted to — SAML 2.0's
  // <saml:Audience> and SAML 1.1's <saml:Audience> under
  // AudienceRestrictionCondition alike — which is S, the application the
  // assertion was issued for. Empty when it names none.
  private delegatedAudiences(element) {
    const { log } = this.deps;
    log.debug("Entering WsTrust.delegatedAudiences().");
    const out = [];
    const all = element && element.getElementsByTagNameNS
      ? element.getElementsByTagNameNS('*', 'Audience') : [];
    for (let i = 0; i < all.length; i += 1) {
      const text = String(all[i].textContent || '').trim();
      if (text && out.indexOf(text) < 0) {
        out.push(text);
      }
    }
    log.debug("Leaving WsTrust.delegatedAudiences(). " + out.length);
    return out;
  }

  // Who this request is from, who the token it asks for is about, and whether
  // the credential presented was accepted.
  //
  // TWO identities can be in one request and BOTH are recorded, which is the
  // part that used to be wrong: a request carrying a UsernameToken AND an
  // OnBehalfOf returned at the delegation branch before it had looked at the
  // UsernameToken, so the requester — the one party here that actually
  // presented a credential — was recorded nowhere and grew no directory entry.
  // The delegated subject is still what the token is ABOUT, and is still what
  // this returns as the subject.
  //
  // Every accepted credential goes through stats.recordAuthentication(), which
  // is this service's single authentication funnel: it is what the admin
  // console's users page counts, what the audit log writes an `authentication`
  // row from, and what the embedded LDAP directory grows a
  // `uid=<name>,ou=users` entry from. A path that accepts a credential without
  // calling it is a person who authenticated here and is in none of the three.
  private authenticate(doc, jwtIssuer?) {
    const { stats, delegation, mode, log } = this.deps;
    log.debug("Entering WsTrust.authenticate().");
    const credential = this.requesterCredential(doc);
    if (credential && !credential.ok) {
      log.debug("Leaving WsTrust.authenticate(). The credential was refused.");
      return { ok: false, reason: credential.reason,
               errorCode: credential.errorCode,
               trustFault: credential.trustFault };
    }
    if (credential) {
      stats.recordAuthentication({
        presented: credential.subject, protocol: 'WS-Trust',
        method: credential.method, note: credential.note
      });
    }
    const delegatedBy = this.delegatedSubject(doc, jwtIssuer);
    if (delegatedBy.refused) {
      log.debug("Leaving WsTrust.authenticate(). The delegated token was " +
                "refused.");
      return { ok: false, reason: delegatedBy.refused,
               errorCode: delegatedBy.errorCode,
               trustFault: delegatedBy.trustFault };
    }
    const delegated = delegatedBy.subject;
    // PRODUCT: A DELEGATION NEEDS A REQUESTER. Development issues a token about
    // somebody for a request that presented no credential of its own — the gap
    // the delegation register draws on purpose. In product the requester is the
    // one party a delegation must be attributable to, so a request with nobody
    // in that seat is refused before anything is recorded.
    if (delegated && !credential && mode.verifiesCredentials()) {
      log.debug("Leaving WsTrust.authenticate(). Product: a delegation with " +
                "no requester credential.");
      return { ok: false, errorCode: 'STS-WSTRUST-0009',
               trustFault: 'FailedAuthentication',
               reason: 'This request delegates (<wst:' + delegatedBy.element +
                       '>) and presents no credential of its own. In product ' +
                       'mode the requester must authenticate — a WS-Security ' +
                       'UsernameToken, or a SAML assertion this security ' +
                       'token service issued — before a token about somebody ' +
                       'else is issued to it.' };
    }
    if (delegated) {
      // THE DELEGATED SUBJECT IS NOT RECORDED HERE (#183). It used to be,
      // on this line, which is above the delegation policy — so a refused
      // OnBehalfOf or ActAs still put its subject on /admin/users as
      // somebody seen, for an act the policy had said no to.
      // handleRst() records them once the policy has allowed the act (see
      // recordDelegatedSubject()); the requester's own row, above, stays
      // here, because the requester DID authenticate whatever is decided
      // after.
      log.debug("Leaving WsTrust.authenticate(). Delegated request " +
                "(OnBehalfOf/ActAs).");
      // `delegation` carries what /admin/delegation needs and nothing else
      // reads: WHICH element it was, and WHO presented a credential of their
      // own — the requester, who is the intermediary of the chain and is the
      // one party this function's `subject` deliberately does not name.
      // handleRst() records the act once the token exists; recording it here
      // would claim a credential that a later failure would have meant nobody
      // held.
      return {
        ok: true, subject: delegated, kind: 'delegated',
        delegation: {
          element: delegatedBy.element,
          both: !!delegatedBy.both,
          requester: credential ? credential.subject : '',
          requesterMethod: credential ? credential.method : '',
          // The identifier of the token that was delegated WITH, where it
          // carried one. handleRst() records it as what the act consumed, which
          // is what lets /admin/tokens/credential walk a chain of these hops
          // back to the sign-in that started it. See delegatedTokenId().
          tokenId: delegatedBy.tokenId || '',
          // #479: an assertion or a JWT, for the act's consumed-token note.
          tokenKind: delegatedBy.tokenKind || '',
          // #186: S — the audiences the delegated assertion is restricted
          // to, the application it was issued for.
          audiences: delegatedBy.audiences || [],
          // #186: the parties the delegated assertion says already acted.
          delegates: delegatedBy.delegates || []
        }
      };
    }
    if (credential) {
      log.debug("Leaving WsTrust.authenticate(). Accepted for " +
                credential.subject + ".");
      return { ok: true, subject: credential.subject, kind: credential.kind };
    }
    // PRODUCT: NO CREDENTIAL, NO TOKEN (2026-09-12). Everything below this line
    // is development's — and it is also what made a Renew with no credential
    // issue a token for whoever its RenewTarget named, because that branch in
    // handleRst() starts from the `anonymous` this returns. Refusing here
    // closes both, and Validate and Cancel with them: every operation
    // authenticates above the branch on the operation, which is this file's
    // rule.
    if (mode.verifiesCredentials()) {
      log.debug("Leaving WsTrust.authenticate(). Product: no credential was " +
                "presented.");
      return { ok: false, errorCode: 'STS-WSTRUST-0010',
               trustFault: 'FailedAuthentication',
               reason: 'No credential was presented. In product mode every ' +
                       'WS-Trust operation requires one in the wsse:Security ' +
                       'header — a WS-Security UsernameToken verified ' +
                       'against the directory, or a SAML assertion this ' +
                       'security token service issued.' };
    }
    // No credential — lenient (anonymous), so a "None" credential still issues.
    //
    // Deliberately NOT recorded as an authentication: no userid was presented,
    // so there is nothing to record. The assertion this issues names
    // `anonymous`, and the users page picks that up from the assertion instead
    // — as a subject something was issued to and who never authenticated, which
    // is exactly what happened.
    log.debug("Leaving WsTrust.authenticate(). No credential was presented; " +
              "treating as anonymous.");
    return { ok: true, subject: 'anonymous', kind: 'none' };
  }

  // ---------------------------------------------------------------------------
  // HOW THE REQUESTER AUTHENTICATED, AS THE SAML 2.0 CLASS THE ASSERTION STATES
  // (2026-09-12).
  //
  // The assertion this STS issued used to carry PasswordProtectedTransport for
  // every request — the builder's default, and nobody passed anything else — so
  // an ANONYMOUS request, a delegation and an exchanged assertion were all
  // signed as a password sign-in. That is wrong in every mode. Now:
  //
  //   UsernameToken    PasswordProtectedTransport, exactly as before
  //   SAML assertion   PreviousSession — "authenticated to an authentication
  //                    authority at some point in the past", which is precisely
  //                    what an assertion presented as a credential proves
  //   OnBehalfOf/ActAs unspecified: the subject presented nothing here
  //   nothing          unspecified
  // ---------------------------------------------------------------------------
  private authnContextOf(auth) {
    const { authnContext, log } = this.deps;
    log.debug("Entering WsTrust.authnContextOf().");
    if (auth && auth.kind === 'password') {
      log.debug("Leaving WsTrust.authnContextOf().");
      return authnContext.AC_PASSWORD_PROTECTED;
    }
    if (auth && auth.kind === 'assertion') {
      log.debug("Leaving WsTrust.authnContextOf().");
      return 'urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession';
    }
    log.debug("Leaving WsTrust.authnContextOf().");
    return authnContext.AC_UNSPECIFIED;
  }

  // THE DELEGATED SUBJECT ON /admin/users (#183), once the delegation policy
  // has allowed the act — or, in development, said only that it WOULD have
  // refused it. With what it is said plainly: the subject named in an
  // OnBehalfOf presented no credential of their own here; something else
  // asked for a token about them. The users page prints the method, so the
  // row is not mistaken for a sign-in.
  //
  // It still goes ahead of the role gate and the JWT-subject check, because
  // in development this funnel is what grows their directory entry
  // (`ldap.autocreateUsers`) and both of those read it. Product creates
  // nobody here, so in product the order only decides whether a refusal
  // leaves a row — and the delegation policy's, the one this was about,
  // no longer does.
  private recordDelegatedSubject(subject: string): void {
    const { stats, log } = this.deps;
    log.debug("Entering WsTrust.recordDelegatedSubject().");
    stats.recordAuthentication({
      presented: subject, protocol: 'WS-Trust',
      method: 'OnBehalfOf / ActAs (delegated)',
      note: 'The requester named this subject; the subject presented ' +
            'nothing. The delegation policy allowed the requester to act ' +
            'for them, or — in development — said it would have refused ' +
            'and was not enforced (#108, #186).'
    });
    log.debug("Leaving WsTrust.recordDelegatedSubject().");
  }

  /**
   * Handles one RequestSecurityToken: parses the SOAP body, authenticates the
   * requester, decides delegation and issuance, and answers the RSTR or a SOAP
   * Fault. Never throws on a malformed body.
   *
   * @param rawBody - the request body
   * @param contentType - the request's content type
   * @param options - `encrypt`, to encrypt an issued assertion
   * @returns the HTTP status, the SOAP version, the envelope body and, where
   * issued, the sign-in to record
   */
  handleRst(rawBody, contentType, options) {
    const {
      config, validation, encryptAssertion, applications, gate, delegation,
      mode, errorCodes, log, xmlEscape, iso, firstByLocal, textByLocal,
      subjectForName, hasSubjectResolver, delegationPolicy
    } = this.deps;
    log.debug("Entering WsTrust.handleRst().");
    options = options || {};
    // ---------------------------------------------------------------------
    // **THIS PARSE ANSWERED 500 UNTIL 2026-09-06, TO AN EMPTY BODY AMONG OTHER
    // THINGS**, and the reason is a library change rather than carelessness.
    // `@xmldom/xmldom` used to report a malformed document by calling a handler
    // whose default wrote to the console and carried on, so a bare parse
    // returned a partial tree; in 0.9.10 the default handler THROWS a
    // ParseError. The bare parse here was outside any try/catch, so
    // `POST /sts` with `<a><b></a>` — or with nothing at all — took the request
    // down with an uncaught exception rather than answering a Fault.
    //
    // `validation.parseXml()` never throws; it answers a refusal, and this
    // endpoint renders it as the SOAP Fault it should always have been. The
    // version is detected from the CONTENT TYPE alone here, because there is no
    // document to read a namespace off.
    // ---------------------------------------------------------------------
    const read = validation.parseXml(rawBody, 'request');
    if (!read.ok) {
      log.debug("Leaving WsTrust.handleRst(). The request is not well-formed " +
                "XML.");
      // `wst:InvalidRequest`, "The request was invalid or malformed" (#183),
      // qualified with 1.3's namespace: there is no document to read the
      // request's own off.
      return { status: 400, errorCode: 'STS-WSTRUST-0001',
               version: this.detectSoapVersion(null, contentType),
               body: this.soapFault(this.detectSoapVersion(null, contentType),
                               read.detail, 'InvalidRequest', WST_NS) };
    }
    const doc = read.value;
    const version = this.detectSoapVersion(doc, contentType);
    const requestType = textByLocal(doc, 'RequestType');
    // Operation from the LAST path segment of RequestType, so any WS-Trust
    // version's namespace works (2004/04, 2005/02, or ws-sx 200512).
    const op = requestType.split('/').pop().toLowerCase();
    // Echo the request's trust namespace in the response (whatever version the
    // client used); fall back to 200512.
    const rstEl = firstByLocal(doc, 'RequestSecurityToken');
    const trustNs = (rstEl && rstEl.namespaceURI) || WST_NS;
    const statusTokenType = trustNs + '/RSTR/Status';
    const statusValid = trustNs + '/status/valid';
    const statusInvalid = trustNs + '/status/invalid';
    const keyTypeReq = textByLocal(doc, 'KeyType') || (trustNs + '/Bearer');

    const tokenTypeReq = textByLocal(doc, 'TokenType');
    const appliesToEl = firstByLocal(doc, 'AppliesTo');
    const audience = appliesToEl ?
                     (textByLocal(appliesToEl, 'Address') ||
                      (appliesToEl.textContent || '').trim()) : '';
    // THE LIFETIME (2026-09-12). The default was the literal 60 and is
    // `wstrust.tokenLifetimeMin`. A requested wst:Lifetime REPLACED it with no
    // bound at all, so a caller could ask for a token valid for a year and get
    // one — and WS-Trust 1.4 section 4.1 is explicit that the requestor's
    // Lifetime is a REQUEST and the issued one is the STS's decision, returned
    // in the RSTR. That makes an unbounded honour a defect in every mode rather
    // than a mock's leniency, so the clamp to `wstrust.maxTokenLifetimeMin`
    // applies in development too. What went out is what the RSTR's own
    // wst:Lifetime says below, so a client can see it was shortened.
    const lifetimeEl = firstByLocal(doc, 'Lifetime');
    const maxLifetimeMin = Number(config.value('wstrust.maxTokenLifetimeMin'));
    let lifetimeMin = Math.min(Number(config.value('wstrust.tokenLifetimeMin')),
                               maxLifetimeMin);
    if (lifetimeEl) {
      const created = textByLocal(lifetimeEl, 'Created');
      const expires = textByLocal(lifetimeEl, 'Expires');
      if (created && expires) {
        const diff = (Date.parse(expires) - Date.parse(created)) / 60000;
        if (diff > 0) {
          lifetimeMin = Math.max(1, Math.round(diff));
          if (lifetimeMin > maxLifetimeMin) {
            log.info('wstrust: the request asked for a ' + lifetimeMin +
                     '-minute ' +
                     'token; it is issued for ' +
                     'wstrust.maxTokenLifetimeMin, ' + maxLifetimeMin + ' ' +
                         'minutes.');
            lifetimeMin = maxLifetimeMin;
          }
        }
      }
    }

    // AN APPLICATION NOBODY REGISTERED GETS NOTHING IN PRODUCT (#496). Asked
    // ABOVE authenticate(), because that is where the requester's
    // `recordAuthentication()` row is written, and rcbj's rule is that a
    // refused request leaves no trace of the caller: no /admin/users row, no
    // `seen()` sighting, nothing issued. Validate and Cancel issue nothing
    // and are not asked. See unregisteredApplication().
    const unregistered = this.unregisteredApplication(op, audience,
                                                      !!appliesToEl);
    if (unregistered) {
      log.info('wstrust: refused an RST in product mode — ' +
               unregistered.why);
      log.debug("Leaving WsTrust.handleRst(). No registered application.");
      return { status: 500, version: version,
               errorCode: unregistered.errorCode,
               // error-code: none — decided in unregisteredApplication(), carried on errorCode above
               body: this.soapFault(version, unregistered.why,
                                    unregistered.trustFault, trustNs) };
    }

    // EVERY operation authenticates, and it happens here — above the four
    // branches rather than inside two of them.
    //
    // Validate and Cancel used to return before this line was reached, so a
    // UsernameToken presented to either was accepted (the operation answered
    // 200) and recorded nowhere: the requester appeared in neither the admin
    // console's users page, nor the audit log, nor the embedded LDAP directory,
    // which grows its `uid=<name>,ou=users` entry off the same funnel. Half of
    // this endpoint's operations authenticated nobody.
    //
    // It also means the reserved password "invalid" now refuses a Validate and
    // a Cancel the way it already refused an Issue and a Renew, which is the
    // answer a client should get: a credential this service rejects does not
    // become acceptable because of what was asked with it.
    // #480: the realm's OAuth issuer at this request's base, which a JWT
    // this STS issues carries and a JWT presented to it must carry.
    const jwtIssuer = this.oauthIssuer(String(options.base || ''));
    // AUTHENTICATED AT THE DOOR ALREADY (#499): the route authenticates an
    // Issue or a Renew that delegates nothing before calling this, so that
    // the sign-in can be assessed for risk between the credential and the
    // decision (doorAssessment()). It hands the answer in rather than have
    // the credential verified twice — a second verification would count a
    // refused password twice and spend a nonce twice.
    const auth: any = options.preAuthenticated ||
      this.authenticate(doc, jwtIssuer);
    if (!auth.ok) {
      log.debug("Leaving WsTrust.handleRst(). Authentication failed, " +
                "answering with a SOAP Fault.");
      // error-code: none — the code was decided where authenticate() refused, and rides out on auth.errorCode
      return { status: 500, version: version, errorCode: auth.errorCode,
               body: this.soapFault(version,
                               auth.reason || 'Authentication failed.',
                               auth.trustFault || 'FailedAuthentication',
                               trustNs) };
    }

    if (op === 'validate') {
      const target = firstByLocal(doc, 'ValidateTarget');
      const hasToken = target &&
                       (firstByLocal(target, 'Assertion') ||
                        firstByLocal(target, 'BinarySecurityToken') ||
                        (target.textContent || '').trim());
      const code = hasToken ? statusValid : statusInvalid;
      // A wst:Status of invalid is this operation's refusal, delivered in a
      // 200.
      const invalidCode = hasToken ? '' : 'STS-WSTRUST-0014';
      const reason = hasToken ? 'The token is valid.' : 'No token to validate.';
      const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs +
                   '"><wst:TokenType>' + statusTokenType +
                   '</wst:TokenType><wst:Status><wst:Code>' + code +
                   '</wst:Code><wst:Reason>' + xmlEscape(reason) +
                   '</wst:Reason></wst:Status>' +
                   '</wst:RequestSecurityTokenResponse>';
      log.debug("Leaving WsTrust.handleRst(). Validate answered with " +
                "wst:Status.");
      return { status: 200, version: version, errorCode: invalidCode,
               body: this.envelope(version, trustNs + '/RSTR/ValidateFinal',
                                   rstr) };
    }

    if (op === 'cancel' && trustNs === WST_2004_04_NS) {
      log.debug("Leaving WsTrust.handleRst(). Cancel is not in WS-Trust " +
                "2004/04.");
      return { status: 500, version: version, errorCode: 'STS-WSTRUST-0021',
               body: this.soapFault(version, 'WS-Trust 2004/04 defines no ' +
                                    'Cancel binding (no CancelTarget and no ' +
                                    'RequestedTokenCancelled); it was ' +
                                    'added in the 2005/02 version.',
                                    'InvalidRequest', trustNs) };
    }

    if (op === 'cancel') {
      const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs +
                   '"><wst:RequestedTokenCancelled/>' +
                   '</wst:RequestSecurityTokenResponse>';
      log.debug("Leaving WsTrust.handleRst(). Cancel answered with " +
                "wst:RequestedTokenCancelled.");
      return { status: 200, version: version,
               body: this.envelope(version, trustNs + '/RSTR/CancelFinal',
                                   rstr) };
    }

    // -------------------------------------------------------------------------
    // WHO MAY ACT FOR WHOM, AND AS WHAT (#186). WS-Trust puts no authorization
    // on `OnBehalfOf` (1.3 section 9.2) or `ActAs` (1.4 section 9.3) — "a real
    // STS decides this from policy that has no place in the message" — and
    // the issuance policy is that policy, the same rules the RFC 8693 token
    // exchange and Kerberos S4U are decided by, through
    // `common/delegation_policy.ts`. The ELEMENT is the request's choice of
    // semantics: OnBehalfOf asks for IMPERSONATION, ActAs for DELEGATION, and
    // the entries' allowed semantics still decide. The actor is the
    // REQUESTER; S is the delegated assertion's audience; R the AppliesTo.
    // A person may be the requester when they hold delegation.actorRole.
    //
    // A REQUEST CARRYING BOTH ELEMENTS asks for two contradictory things and is
    // refused in every mode (wst:InvalidRequest).
    //
    // ENFORCED IN PRODUCT — the policy's answer says whether a refusal is
    // enforced — as a SOAP Fault with WS-Trust 1.4 section 11's
    // `wst:RequestFailed`; development issues and writes "would have been
    // refused" on the act's row. Here rather than in authenticate(), because
    // this is the only place that knows the AppliesTo, which is the TARGET.
    //
    // AND AHEAD OF THE ROLE GATE AND THE JWT-SUBJECT CHECK SINCE #183, so
    // that the delegated subject is recorded on /admin/users only once it
    // has been allowed (recordDelegatedSubject()), and still before those two
    // read the entry that record may create. Validate and Cancel have
    // returned above: neither issues anything about anybody, so neither asks.
    // -------------------------------------------------------------------------
    let delegationDecision = null;
    if (auth.delegation && auth.delegation.both) {
      const why = 'The request carries both <wst:OnBehalfOf> (impersonation) ' +
        'and <wst14:ActAs> (delegation); send one.';
      log.info('wstrust: refused a request carrying both OnBehalfOf and ' +
               'ActAs.');
      log.debug("Leaving the RST handler. Both delegation elements.");
      return { status: 500, version: version, errorCode: 'STS-WSTRUST-0025',
               body: this.soapFault(version, why, 'InvalidRequest',
                                    trustNs) };
    }
    if (auth.delegation) {
      const via = auth.delegation.element;
      const requester = String(auth.delegation.requester || '');
      delegationDecision = delegationPolicy.decide({
        protocol: 'WS-Trust',
        requested: via === 'ActAs' ? 'delegation' : 'impersonation',
        actor: requester,
        subject: String(auth.subject || ''),
        source: auth.delegation.audiences || [],
        targets: audience ? [audience] : [],
        targetKind: 'appliesTo'
      });
      if (!delegationDecision.allowed && delegationDecision.enforced) {
        const CODES = {
          'intermediary': 'STS-WSTRUST-0019',
          'policy': 'STS-WSTRUST-0020',
          'semantics': 'STS-WSTRUST-0022',
          'authority': 'STS-WSTRUST-0023',
          'no-target': 'STS-WSTRUST-0024',
          'unregistered-target': 'STS-WSTRUST-0024',
          'targets': 'STS-WSTRUST-0024'
        };
        const code = CODES[delegationDecision.refusal] || 'STS-WSTRUST-0018';
        const why = delegationDecision.why;
        const refusedTarget = delegationDecision.targets[0] ||
          { asked: '', application: '' };
        delegation.record({
          protocol: 'WS-Trust',
          type: via === 'ActAs' ? 'wstrust-actas' : 'wstrust-onbehalfof',
          outcome: 'refused',
          initial: { presented: auth.subject,
                     what: 'the subject named in <wst:' + via + '>' },
          intermediary: { presented: requester,
                          application: delegationDecision.intermediary,
                          what: 'the requester, authenticated by ' +
                                String(auth.delegation.requesterMethod ||
                                       'nothing') },
          target: { application: refusedTarget.application ||
                                 refusedTarget.asked,
                    what: audience
                      ? 'the AppliesTo "' + audience + '"'
                      : 'unstated — the RST carried no AppliesTo' },
          authorizedBy: 'refused by the issuance policy: ' + why,
          reason: why,
          consumed: auth.delegation.tokenId
            ? [{ kind: 'delegated token',
                 identifier: auth.delegation.tokenId,
                 note: 'the token inside <wst:' + via + '>' }]
            : [],
          produced: []
        });
        log.info('wstrust: the issuance policy refused <wst:' + via +
                 '> by "' + requester + '" for "' + String(auth.subject) +
                 '" to "' + audience + '": ' + why);
        log.debug("Leaving the RST handler. The issuance policy refused " +
                  "it.");
        // error-code: none — `code` rides out on the answer
        return { status: 500, version: version, errorCode: code,
                 body: this.soapFault(version, why, 'RequestFailed',
                                      trustNs) };
      }
    }

    if (auth.delegation) {
      this.recordDelegatedSubject(String(auth.subject || ''));
    }

    // Issue / Renew both mint (or re-mint) a token, for whoever authenticate()
    // above says this request is about.
    //
    // The one thing that answer does not cover is a Renew sent with NO
    // credential at all: the requester is anonymous, but the token being
    // renewed names somebody, and a renewal that came back about `anonymous`
    // would have thrown away the only subject in the exchange. So the
    // RenewTarget's own NameID is read for the SUBJECT — and only for the
    // subject. It is not an authentication and is not recorded as one: the
    // token said it, nobody presented it. A Renew that DID authenticate keeps
    // its own subject, which is what a service renewing a token in its own name
    // should get.
    let subject = auth.subject;
    if (op === 'renew' && subject === 'anonymous') {
      const renewTarget = firstByLocal(doc, 'RenewTarget');
      const renewNameId = renewTarget && (firstByLocal(renewTarget, 'NameID') ||
        firstByLocal(renewTarget, 'NameIdentifier'));
      const renewNamed = renewNameId ?
        (renewNameId.textContent || '').trim() : '';
      if (renewNamed) {
        log.debug("An unauthenticated Renew; the subject is the one the " +
                  "RenewTarget names, " + renewNamed + ".");
        subject = renewNamed;
      }
    }
    // THE ROLE GATE, and this is the one issuance site here where the
    // application may be ABSENT and that is not an error. AppliesTo is optional
    // in an RST, and a token with no audience restriction is a state this
    // service deliberately allows IN DEVELOPMENT (product refused it above,
    // #496, with an AppliesTo nobody registered) — so there is no
    // application to have a requirement, and `issuance_gate.check()` answers
    // "allowed" for a call that names none. Its header says why that is the
    // honest answer rather than a hole: this service issues nothing to
    // nobody, so a call with no application is a caller that does not know
    // who it is serving.
    //
    // THE SUBJECT MAY BE `anonymous`, which is this protocol's own word and not
    // a missing value — a Renew with no credential is renewing somebody else's
    // token. `authenticated` follows the credential and not the name, so an
    // anonymous Renew is decided as an unauthenticated subject and can be
    // refused by ALL_UNAUTHENTICATED_USERS, which is the one place in this
    // service besides the sign-in screen where that role means anything.
    //
    // A REFUSAL IS A SOAP FAULT, because that is the only answer this protocol
    // has: an RST is answered with an RSTR or with a Fault, and an RSTR
    // carrying no token would be a success that issued nothing.
    // THE SIGN-IN'S OWN RISK (#499): where the route assessed this very
    // sign-in at the door, the policy decides on that assessment — not on
    // the person's standing from an earlier one, which is what a request
    // that delegates, or one handed in with no door, is still decided on
    // (the gate finds it: `riskFactsOf()`).
    const doorRisk = options.doorRisk &&
      String(options.doorRisk.username) === String(subject || '')
      ? { risk: options.doorRisk.facts } : {};
    const roleAnswer = gate.check(Object.assign({
      application: audience,
      kind: gate.ISSUANCE.WSTRUST_TOKEN,
      subject: { kind: 'user', name: String(subject || ''),
                 authenticated: subject !== 'anonymous' },
      claims: null
    }, doorRisk));
    if (typeof options.onIssuanceAnswer === 'function') {
      options.onIssuanceAnswer(roleAnswer);
    }
    if (!roleAnswer.allowed) {
      log.info('wstrust: the issuance policy refused a token for "' +
               String(subject) + '" to "' + audience + '". ' + roleAnswer.why);
      log.debug("Leaving the RST handler. The issuance policy refused it.");
      // A realm being removed (#262) is its own code. Both are
      // `wst:RequestFailed` (#183): the request was understood and the
      // requester authenticated, and the policy said no.
      return { status: 403, version: version,
               errorCode: roleAnswer.retiring ? 'STS-CORE-0121'
                                              : 'STS-WSTRUST-0011',
               body: this.soapFault(version, roleAnswer.why, 'RequestFailed',
                                    trustNs) };
    }

    // #487: SAML 1.1 by either of its two names; anything else that is not
    // the JWT's is answered with SAML 2.0, as it always was.
    const tokenType = (tokenTypeReq === JWT_TOKEN_TYPE) ? JWT_TOKEN_TYPE :
      (tokenTypeReq === SAML11_TOKEN_TYPE ||
       tokenTypeReq === SAML11_TOKEN_TYPE_ALIAS) ? SAML11_TOKEN_TYPE :
        SAML2_TOKEN_TYPE;
    // A JWT'S `sub` IS A SUBJECT, AND THERE IS NONE WITHOUT AN ENTRY — the rule
    // the OAuth 2.0 grants follow (`STS-OAUTH-0510`). An `anonymous` Renew
    // names nobody by design and is left to the paragraph above.
    if (tokenType === JWT_TOKEN_TYPE && subject !== 'anonymous' &&
        hasSubjectResolver() && !subjectForName(subject)) {
      log.info('wstrust: refused a JWT for "' + String(subject) + '": the ' +
               'directory holds no entry for them, so there is no subject to ' +
               'issue it about.');
      log.debug("Leaving the RST handler. No subject for the JWT.");
      return { status: 400, version: version, errorCode: 'STS-WSTRUST-0017',
               body: this.soapFault(version, 'There is no directory entry ' +
                                             'for "' +
                               String(subject) + '", so no JWT can be issued ' +
                               'about them.', 'RequestFailed', trustNs) };
    }
    // #186: WHO ACTED, carried into the token. A delegation (ActAs) adds the
    // requester after whoever the delegated assertion already named; an
    // impersonation keeps that chain and adds nobody — a prior delegation is
    // never laundered into an ordinary token; a self act adds nobody.
    const priorDelegates = (auth.delegation && auth.delegation.delegates) ||
      [];
    const delegates = delegationDecision &&
      delegationDecision.semantics === 'delegation'
      ? priorDelegates.concat([{
        nameId: String(delegationDecision.intermediary ||
                       auth.delegation.requester || ''),
        instant: new Date().toISOString() }])
      : priorDelegates;
    // #476: who ASKED, for a JWT's `client_id` — the requester of a
    // delegation, or whoever authenticated for a token about themselves.
    // An anonymous request (development) asked as nobody.
    const requester = auth.delegation
      ? String(auth.delegation.requester || '')
      : (auth.kind === 'none' ? '' : String(auth.subject || ''));
    // NO NAME TO SIGN A SAML ASSERTION UNDER (#494): product with
    // `saml2.entityId` empty and `saml.issuer` unset. SAML SSO refuses the
    // same state (STS-SAML-0004); an assertion whose Issuer is empty matches
    // no metadata a relying party could be configured from. A JWT is not
    // affected: its `iss` is the realm's OAuth issuer.
    const issuerProblem = tokenType === JWT_TOKEN_TYPE ? ''
      : IssuerNames.problem('saml.issuer');
    if (issuerProblem) {
      log.debug("Leaving the RST handler. No name to sign under.");
      return { status: 500, version: version, errorCode: 'STS-WSTRUST-0029',
               body: this.soapFault(version, issuerProblem, 'RequestFailed',
                                    trustNs) };
    }
    const tok = this.buildToken(tokenType, subject, audience, lifetimeMin,
                           this.authnContextOf(auth), delegates, requester,
                           undefined, jwtIssuer);

    // Optional encryption (?encrypt=1): encrypt the SAML assertion to the
    // recipient certificate carried in the request's WS-Security signature
    // (X509Data).
    //
    // TWO CHANGES ON 2026-09-12. The algorithms are `saml2.encryptionAlgorithm`
    // and `saml2.keyTransportAlgorithm`, answered for the AppliesTo as
    // `/saml2` answers them for a service provider — they were passed nowhere
    // and the cipher's own defaults decided, so the settings a console page
    // said were in force did nothing to a WS-Trust assertion. And a FAILURE is
    // a refusal in product mode: development returns the plaintext and logs it,
    // because a mock that stopped issuing when a certificate was missing is
    // useless while somebody sets this up; product returns a SOAP Fault
    // instead, because an assertion the caller asked to have encrypted crossing
    // the wire readable is the one outcome the flag exists to prevent. The
    // predicate is `sendsWeakerThanAsked()`: what a response may lose on the
    // way out, which is the question here, rather than who may drive a test
    // control.
    if (options.encrypt && tok.tokenType === SAML2_TOKEN_TYPE) {
      const x509 = firstByLocal(doc, 'X509Certificate');
      const recipB64 = x509 ? (x509.textContent || '').replace(/\s+/g, '') : '';
      let failure = '';
      if (recipB64) {
        const recipPem = '-----BEGIN CERTIFICATE-----\n' +
            (recipB64.match(/.{1,64}/g) || []).join('\n') + '\n-----END ' +
            'CERTIFICATE-----\n';
        const how = {
          algorithm: String(applications.settingFor(audience || '',
                                                    'saml2.encryptionAlgorithm',
                                                    config) || ''),
          keyTransport: String(applications.settingFor(
            audience || '', 'saml2.keyTransportAlgorithm', config) || '')
        };
        try {
          tok.xml = encryptAssertion(tok.xml, recipPem, how);
          tok.ref = '';
        } catch (e) {
          failure = 'the assertion could not be encrypted to the certificate ' +
                    'in the request: ' +
                    e.message;
        }
      } else {
        failure = '?encrypt=1 was requested and the request carries no ' +
                  'recipient certificate (no X509Certificate in its ' +
                  'WS-Security signature)';
      }
      if (failure) {
        if (!mode.sendsWeakerThanAsked()) {
          log.info('wstrust: refused to return a plaintext assertion — ' +
                   failure + '.');
          log.debug("Leaving WsTrust.handleRst(). Encryption was required " +
                    "and did not happen.");
          // No recipient certificate is the REQUEST lacking what it asked
          // to be answered with, `wst:InvalidRequest`; a certificate that
          // could not be encrypted to is `wst:RequestFailed` (#183).
          return { status: 500, version: version,
                   errorCode: recipB64 ? 'STS-WSTRUST-0013'
                                       : 'STS-WSTRUST-0012',
                   body: this.soapFault(version,
                                   'Encryption was requested and ' + failure +
                                            '. In product mode the assertion ' +
                                            'is not returned in clear ' +
                                            'instead.',
                                   recipB64 ? 'RequestFailed'
                                            : 'InvalidRequest', trustNs) };
        }
        log.error(errorCodes.tag(recipB64 ? 'STS-WSTRUST-0013' :
                                 'STS-WSTRUST-0012') +
                  failure + '; returning plaintext.');
      }
    }
    // THE RELYING PARTY. AppliesTo is WS-Trust's name for the service a token
    // is being issued FOR, and this is where one is about to be. It is optional
    // in an RST — a token with no AppliesTo has no audience restriction, which
    // is a state this service deliberately allows in development — so an
    // absent one records nothing rather than an empty application. In product
    // only a REGISTERED AppliesTo reaches here (#496), and a sighting of an
    // entry that does not exist creates nothing there anyway.
    //
    // The SECOND kind is the mirror of wsfed.ts's: where the token issued is a
    // SAML 2.0 assertion, this AppliesTo is also its audience, which is exactly
    // what `saml2-service-provider` is defined as in KINDS. Recording only the
    // WS-Trust kind left that one reachable through WS-Federation alone, so the
    // console's filter answered "no SAML 2.0 service providers" for a service
    // that had just issued one. A JWT gets no second kind — there is no row for
    // it, and inventing a spelling here is how one application comes to be
    // listed under two.
    if (audience) {
      applications.seen({
        identifier: audience,
        kind: tok.tokenType === SAML2_TOKEN_TYPE
          ? ['wstrust-relying-party', 'saml2-service-provider']
          : 'wstrust-relying-party',
        protocol: 'WS-Trust',
        user: subject || '',
        note: 'a token was issued for this AppliesTo',
        fields: { wstrustAppliesTo: audience, samlEntityId: audience }
      });
    }

    // -------------------------------------------------------------------------
    // THE DELEGATION ACT, for /admin/delegation.
    //
    // Recorded here rather than in authenticate() for the reason the KDC
    // records its own at the bottom of handleTgsReq(): this is the first line
    // at which the token EXISTS, and an act recorded where the decision was
    // made would name a credential nobody ever held. It is also the only place
    // that knows the AppliesTo, which is the TARGET of the chain —
    // authenticate() reads the security header and never sees it.
    //
    // Nothing about this is a check. This service accepts any delegation from
    // anybody about anybody, and the row says so in the column where a Kerberos
    // row names an attribute. That asymmetry is the most useful thing on the
    // page: the same picture, policed at one end and not at the other.
    // -------------------------------------------------------------------------
    if (auth.delegation) {
      const via = auth.delegation.element;
      // -----------------------------------------------------------------------
      // WHICH APPLICATION THE AppliesTo IS, when one has registered it.
      //
      // The same resolution the token endpoint performs for an RFC 8693
      // `audience`, arriving through a different protocol, and it is here for
      // the same reason: this string names a SERVICE —
      // `https://esb.example.com` — and the register is keyed by the identifier
      // an application PRESENTS. An act filed under the URI draws a box on
      // /admin/delegation/map that nothing else in the picture mentions, so a
      // two-hop chain through a middle tier comes out as two unconnected
      // halves: the AppliesTo the first hop asked for and the name the second
      // hop authenticated AS are one application under two names.
      //
      // NOTHING IS REFUSED. An AppliesTo nobody registered resolves to null and
      // is recorded verbatim, exactly as it was before this existed — and the
      // raw string stays in the sentence beside the target either way, because
      // what was asked for is a fact about the request and must not be lost to
      // a resolution. See applications.forAppliesTo().
      // -----------------------------------------------------------------------
      const targetApplication = audience ? applications.forAppliesTo(audience)
                                         : null;
      if (targetApplication) {
        log.debug('the AppliesTo "' + audience + '" is registered to ' +
                  'application "' + targetApplication.identifier + '" on ' +
                  targetApplication.matchedAttribute + ', so the delegation ' +
                  'is recorded against that application rather than against ' +
                  'the URI.');
      }
      // AND WHETHER THE REQUESTER IS ONE TOO. The middle tier of a WS-Trust
      // chain authenticates with a credential rather than by naming an
      // application, so `presented` is where it belongs and is what the picture
      // keys the box on. But an ESB asking for a token to reach a back end IS
      // an application, and where this registry already holds an entry under
      // that name the act says so: the box then links to the entry and is drawn
      // as a service rather than as a person. A LOOKUP and not a claim — an
      // unknown name leaves the slot empty, exactly as before.
      const requesterApplication = auth.delegation.requester
        ? applications.get(auth.delegation.requester) : null;
      delegation.record({
        protocol: 'WS-Trust',
        type: via === 'ActAs' ? 'wstrust-actas' : 'wstrust-onbehalfof',
        outcome: 'issued',
        initial: {
          presented: subject,
          what: 'the subject named in <wst:' + via + '>, who presented ' +
                                                     'nothing here'
        },
        intermediary: {
          // Empty where the request presented no credential of its own, which
          // is allowed here and is worth seeing: an ANONYMOUS requester asked
          // for a token about somebody else and got one. The page draws that as
          // a gap in the chain rather than as a missing value.
          presented: auth.delegation.requester,
          application: requesterApplication ? requesterApplication.identifier :
                       '',
          what: auth.delegation.requester
            ? 'the requester, authenticated by ' +
              auth.delegation.requesterMethod +
              (requesterApplication
                ? ', and an application in this registry'
                : '')
            : 'nobody — the request presented no credential of its own, and ' +
              'this service issued the token anyway'
        },
        target: {
          application: targetApplication ? targetApplication.identifier :
                       audience,
          what: audience
            ? (targetApplication
                ? 'the application registered for the AppliesTo "' + audience +
                  '" on ' + targetApplication.matchedAttribute + ', which is ' +
                  'also the assertion\'s audience. The request named the ' +
                  'service; this registry named the application'
                : 'the AppliesTo, which is also the assertion\'s audience. ' +
                  'No application here has registered it, so it is recorded ' +
                  'exactly as it was asked for')
            : 'unstated — the RST carried no AppliesTo, so the token issued ' +
              'has no audience restriction at all'
        },
        // WHAT ALLOWED IT (#108), the way a Kerberos row names an attribute
        // — or, in development, what WOULD have refused it.
        authorizedBy: delegationDecision
          ? delegationPolicy.rowText(delegationDecision)
          : 'nothing: no delegation was decided',
        consumed: (auth.delegation.requester
          ? [{ kind: 'WS-Security credential',
               note: auth.delegation.requesterMethod }]
          : [] as any[]).concat(auth.delegation.tokenId
          ? [{ kind: 'delegated token',
               identifier: auth.delegation.tokenId,
               note: this.consumedNote(via, auth.delegation.tokenKind) }]
          : []),
        produced: [{
          kind: tok.tokenType === SAML11_TOKEN_TYPE ? 'SAML 1.1 assertion'
            : tok.tokenType === SAML2_TOKEN_TYPE ? 'SAML 2.0 assertion'
                                                   : 'JWT',
          identifier: tok.id || '',
          note: tok.id
            ? (tok.tokenType === JWT_TOKEN_TYPE ? 'jti' : 'AssertionID')
            : 'this token carries no identifier'
        }],
        note: auth.delegation.both
          ? 'The request carried BOTH <wst:OnBehalfOf> and <wst14:ActAs>. ' +
            'OnBehalfOf is what this act is attributed to, which is the ' +
            'order this service has always read them in.'
          : this.actNote(via, tok.tokenType)
      });
    }

    const appliesToOut = audience
      ? '<wsp:AppliesTo ' +
        'xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" ' +
        'xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
        '<wsa:EndpointReference><wsa:Address>' +
        xmlEscape(audience) +
        '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>'
      : '';
    const rstrInner =
      '<wst:TokenType>' + tok.tokenType + '</wst:TokenType>' +
      '<wst:RequestedSecurityToken>' + tok.xml +
      '</wst:RequestedSecurityToken>' +
      appliesToOut +
      '<wst:Lifetime ' +
      'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
      '<wsu:Created>' + iso(0) + '</wsu:Created><wsu:Expires>' +
      iso(lifetimeMin) + '</wsu:Expires></wst:Lifetime><wst:KeyType>' +
      keyTypeReq + '</wst:KeyType>' +
      // 2004/04 spells the reference RequestedTokenReference (#188).
      (trustNs === WST_2004_04_NS
        ? tok.ref.split('wst:RequestedAttachedReference')
            .join('wst:RequestedTokenReference')
        : tok.ref);

    // ---------------------------------------------------------------------
    // WHAT THIS EXCHANGE SIGNED IN, for the caller to act on (2026-09-05).
    //
    // **AN ISSUED CREDENTIAL IMPLIES A SESSION THIS SERVICE TRACKS**, and until
    // this day WS-Trust was the one family here that issued one and tracked
    // nothing: `startSession()` was called zero times in this file. What that
    // cost was not visible from inside this endpoint — it answered correctly
    // and always had — but from `/admin/sessions` and from a global sign-out,
    // where an assertion this service had minted for somebody five minutes ago
    // belonged to nobody who was signed in. An identity provider that cannot
    // say "this is live" cannot say "I have ended it" either, which is the
    // whole of what a sign-out is.
    //
    // IT IS RETURNED RATHER THAN DONE HERE, and that is deliberate: this
    // function has no `res` and must not acquire one. It is called by the route
    // below AND directly by callers that hand it a body and read a body back,
    // so a cookie written from inside it would be a side effect on an object
    // half its callers do not have. The route starts the session; this says
    // who.
    //
    // ONLY ON AN ISSUE THAT AUTHENTICATED. A Renew whose requester was
    // anonymous is signing nobody in — its subject came off the RenewTarget,
    // which the token said and nobody presented — and Validate and Cancel issue
    // nothing at all. Each of those returns above this line.
    //
    // AND NEVER ON A DELEGATION (2026-09-12). `auth.subject` on an OnBehalfOf /
    // ActAs request is the DELEGATED subject — the person who presented nothing
    // — so this used to start a browser session in the name of somebody who was
    // not there, with amr ["pwd"], on the response to whoever asked. That is
    // wrong in every mode: the requester authenticated and the subject did not,
    // and a session is a statement that its subject signed in. The requester is
    // not signed in either — the token is about somebody else — so nothing is.
    //
    // THE AMR SAYS WHICH CREDENTIAL IT WAS. `pwd` for a UsernameToken, as
    // before; nothing for a SAML assertion, which is evidence of an earlier
    // sign-in elsewhere rather than of a password presented now.
    const signIn = auth.subject && auth.subject !== 'anonymous' &&
                   auth.kind !== 'delegated'
      ? { username: auth.subject, method: auth.method || 'WS-Trust',
          via: 'WS-Trust ' + op,
          amr: auth.kind === 'assertion' ? [] : ['pwd'] }
      : null;

    if (op === 'renew') {
      const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs +
                   '">' + rstrInner + '</wst:RequestSecurityTokenResponse>';
      log.debug("Leaving WsTrust.handleRst(). Renew answered with a fresh " +
                "token.");
      return { status: 200, version: version, signIn: signIn,
               body: this.envelope(version, trustNs + '/RSTR/RenewFinal',
                                   rstr) };
    }

    // Issue -> RSTR Collection (WS-Trust 1.3+; pre-OASIS clients tolerate it
    // too) — except in 2004/04, whose collection holds at least two
    // responses, so an Issue there is answered with the one RSTR (#188).
    if (trustNs === WST_2004_04_NS) {
      const rstr = '<wst:RequestSecurityTokenResponse xmlns:wst="' + trustNs +
                   '">' + rstrInner + '</wst:RequestSecurityTokenResponse>';
      log.debug("Leaving WsTrust.handleRst(). Issue answered with an RSTR " +
                "(2004/04).");
      return { status: 200, version: version, signIn: signIn,
               body: this.envelope(version, trustNs + '/RSTR/Issue', rstr) };
    }
    const rstrc = '<wst:RequestSecurityTokenResponseCollection xmlns:wst="' +
                  trustNs + '"><wst:RequestSecurityTokenResponse>' + rstrInner +
                  '</wst:RequestSecurityTokenResponse>' +
                  '</wst:RequestSecurityTokenResponseCollection>';
    log.debug("Leaving WsTrust.handleRst(). Issue answered with an RSTR " +
              "Collection.");
    return { status: 200, version: version, signIn: signIn,
             body: this.envelope(version, trustNs + '/RSTRC/IssueFinal',
                                 rstrc) };
  }

  // **`no-store`, LIKE EVERY OTHER DOCUMENT HERE THAT DESCRIBES A KEY.** In
  // development mode this certificate is made when the process starts and is
  // thrown away when it stops — the root CLAUDE.md's *Signing keys, and any
  // document that publishes one* — so a cached copy outlives the key it names,
  // and a client that re-read it from a proxy would be checking this service's
  // signatures against the certificate of a service that is no longer running.
  // It was the ONE metadata document in this service served without the header,
  // which tests/vendored/sts_metadata_anonymous.js found by asking the same
  // question of all nineteen of them at once.
  private stsCertEndpoint(req, res) {
    const { log, STS } = this.deps;
    log.debug("Entering the STS certificate endpoint.");
    // The XML signing key's certificate (#42, D2): what signs the SAML
    // assertions this STS issues — a PINNED key's where the realm signs with
    // one (#263).
    const signer = STS.xmlSigner;
    res.type('text/plain').set('Cache-Control', 'no-store')
       .send(signer && signer.pinned ? signer.certPem : STS.xml.certPem);
    log.debug("Leaving the STS certificate endpoint.");
  }

  // ---------------------------------------------------------------------------
  // THE TWO NAMES THIS STS SIGNS UNDER, AND WHETHER THEY AGREE (2026-09-12).
  //
  // A JWT from this endpoint is issued by `wstrust.issuer`; a SAML assertion
  // from it is issued by `saml.issuer`, because the SAML builder reads that.
  // The split is deliberate (config.js argues it) and the two default to one
  // string — but a relying party configured with one and handed a token under
  // the other refuses it as coming from an unknown issuer, and nothing said the
  // two had drifted. So GET /sts says so for the realm it is asked in, and the
  // process logs it once at startup for the process-wide values. It is reported
  // rather than reconciled, because making one follow the other would take away
  // the split.
  // ---------------------------------------------------------------------------
  /**
   * Reports whether the two names this STS signs under disagree:
   * `wstrust.issuer` for a JWT and `saml.issuer` for a SAML assertion.
   *
   * @returns the sentence saying they disagree, or '' when they agree
   */
  issuerDisagreement() {
    const { log } = this.deps;
    log.debug("Entering WsTrust.issuerDisagreement().");
    // #480: the STS's published name and the shared SAML Issuer, as signed.
    // A JWT's `iss` is neither since #480 — it is the realm's OAuth issuer,
    // named on its own line of GET /sts.
    const stsName = String(IssuerNames.wstrustIssuer() || '');
    const samlIssuer = String(IssuerNames.samlIssuer() || '');
    if (stsName === samlIssuer) {
      log.debug("Leaving WsTrust.issuerDisagreement().");
      return '';
    }
    log.debug("Leaving WsTrust.issuerDisagreement().");
    return 'wstrust.issuer ("' + stsName + '") and saml.issuer ("' +
           samlIssuer + '") differ: this STS publishes the first as its name ' +
           'and a SAML assertion from it names the second as its Issuer, so ' +
           'a relying party configured from the name will refuse the ' +
           'assertion.';
  }

  // THE REALM'S OAUTH ISSUER at a base URL (#480): what
  // /.well-known/oauth-authorization-server publishes for the realm's
  // authorization server there, through `oauth2.issuerOf()` — asked LAZILY,
  // `federation_slo.ts`'s arrangement, because the authorization server is
  // loaded after this module. With no request (a caller handing handleRst()
  // a body), the base is the process's own, with the ambient realm's prefix.
  private oauthIssuer(base: string): string {
    const { log } = this.deps;
    log.debug("Entering WsTrust.oauthIssuer().");
    let at = String(base || '');
    if (!at) {
      at = String(config.managementApiBaseUrl() || '')
        .replace(/\/admin-api$/, '') +
        String(require('../common/realms').currentPrefix() || '');
    }
    // Where `oauth-oidc` is advertised (#472), whichever base asked.
    at = helpers.rebaseTo(at, 'oauth-oidc');
    let out = at;
    try {
      out = String(require('../oauth-oidc/oauth2').issuerOf(at) || at);
    } catch (e) {
      // No authorization server loaded (this module tested on its own): the
      // base is what it would have answered with no pinned issuer.
      log.debug("Caught in WsTrust.oauthIssuer(): " + ((e && e.message) || e));
      out = at;
    }
    log.debug("Leaving WsTrust.oauthIssuer(). " + out);
    return out;
  }

  private stsDescriptionEndpoint(req, res) {
    const { config, log } = this.deps;
    log.debug("Entering the STS description endpoint.");
    const disagreement = this.issuerDisagreement();
    // #480: the STS's name (`wstrust.issuer`; in product the SAML 2.0
    // entityID where nobody set it), and on a line of its own the `iss` its
    // JWTs carry, the realm's OAuth issuer.
    res.type('text/plain').send('WS-Trust STS mock. POST a SOAP ' +
                                'RequestSecurityToken here.\nIssuer: ' +
                                IssuerNames.wstrustIssuer() + '\n' +
                                'JWT issuer: ' +
                                this.oauthIssuer(helpers.baseUrlOf(req)) +
                                '\n' +
                                (disagreement ?
                                 'WARNING: ' + disagreement + '\n' : ''));
    log.debug("Leaving the STS description endpoint.");
  }

  // -------------------------------------------------------------------------
  // THE PERSON'S RISK STANDING, READ BEFORE THE EXCHANGE (#62 P3). An RST
  // rests on no session, so the issuance policy's risk facts are the
  // person's standing — and `handleRst()` asks the gate synchronously, so the
  // standing is read from the store HERE, first, for the name the request
  // CLAIMS (a UsernameToken's Username). Nothing is authenticated by it and
  // nothing is decided: a name that turns out not to authenticate simply
  // left a standing in this process's cache. Never rejects; a store that
  // cannot answer leaves the decision to roles alone.
  // -------------------------------------------------------------------------
  private stsEndpoint(req, res) {
    const { log, validation, textByLocal } = this.deps;
    log.debug("Entering WsTrust.stsEndpoint().");
    const self = this;
    let claimed = '';
    const read = validation.parseXml(req.body || '', 'request');
    if (read.ok) {
      claimed = textByLocal(read.value, 'Username');
    }
    // THE PERSON'S HOME CELL (#98 D10), before anything is read, verified,
    // recorded or spent: see homeNameOf(). Single-cell mode goes straight
    // on, as it always did.
    const home = read.ok && cells.isMulti() && !req.stsCellRelay
      ? this.homeNameOf(read.value) : '';
    // THE DELEGATED SUBJECT, when it is somebody other than the person the
    // request is served for: see delegatedHere().
    const delegated = read.ok && cells.isMulti()
      ? this.delegatedNameOf(read.value, home) : '';
    if (home) {
      log.debug("Leaving WsTrust.stsEndpoint(). Finding the home cell.");
      return cellPlacement.relayToHome(req, res,
        require('../common/realms').currentId(), 'name', home,
        'a WS-Trust request').then(function (relayed: boolean): unknown {
          return relayed ? undefined
            : self.stsEndpointHere(req, res, claimed, delegated,
                                   read.value);
        });
    }
    log.debug("Leaving WsTrust.stsEndpoint().");
    return this.stsEndpointHere(req, res, claimed, delegated,
                                read.ok ? read.value : null);
  }

  // The subject of an OnBehalfOf / ActAs, when the request is served for
  // somebody ELSE — its requester, whose home this is (homeNameOf()). ''
  // when nothing is delegated, or the delegated subject is the one the
  // request was placed by.
  private delegatedNameOf(doc, placedBy: string): string {
    const { firstByLocal, log } = this.deps;
    log.debug("Entering WsTrust.delegatedNameOf().");
    const obo = firstByLocal(doc, 'OnBehalfOf') || firstByLocal(doc, 'ActAs');
    const named = obo ? firstByLocal(obo, 'NameID') ||
                        firstByLocal(obo, 'NameIdentifier') : null;
    const name = named ? String(named.textContent || '').trim() : '';
    log.debug("Leaving WsTrust.delegatedNameOf().");
    return name && name.toLowerCase() !== String(placedBy || '').toLowerCase()
      ? name : '';
  }

  // ---------------------------------------------------------------------------
  // A DELEGATED SUBJECT HOMED IN ANOTHER CELL (#98 section 5,
  // `fetch-attributes`). The request is served at its REQUESTER's home, whose
  // directory does not hold the person the token is about — so the token's
  // subject, its configured attributes, the delegation policy's flags on
  // their entry and the issuance policy's roles would be made from nothing.
  // Their home is asked for their credential-free attributes
  // (`common/cell_attributes.ts`), which it releases only where the transfer
  // policy says, and the exchange runs with them held in this process's
  // directory for exactly its own synchronous duration.
  //
  // FAIL-CLOSED (D6): home refusing to release them, or not reachable, is a
  // refused issuance — a Fault naming which, never a token about somebody
  // this cell cannot describe. A person already held here as a projection is
  // read as they are; one unknown to every cell is served as a name nobody
  // knows always was.
  // ---------------------------------------------------------------------------
  private delegatedHere(req, res, delegated: string, doc): unknown {
    const { errorCodes, log } = this.deps;
    log.debug("Entering WsTrust.delegatedHere().");
    const self = this;
    const realms = require('../common/realms');
    const realmId = realms.currentId();
    if (require('../common/cell_sessions').isProjected(realmId, 'name',
                                                       delegated)) {
      log.debug("Leaving WsTrust.delegatedHere(). Held here already.");
      return this.stsEndpointNow(req, res);
    }
    log.debug("Leaving WsTrust.delegatedHere(). Asking where they live.");
    return require('../common/cell_routing').homeOf(realmId, 'name', delegated)
      .then(function (home: string): unknown {
        if (!home || home === cells.id() || !cells.get(home)) {
          return self.stsEndpointNow(req, res);
        }
        return cellAttributes.fetch(realmId, delegated, home)
          .then(function (got: any): unknown {
            if (!got.ok) {
              const version = self.detectSoapVersion(doc,
                req.headers['content-type'] || '');
              errorCodes.mark(res, got.code);
              res.status(got.code === 'STS-CELL-0125' ? 503 : 403)
                 .type(version === '1.1' ? 'text/xml; charset=utf-8'
                                         : 'application/soap+xml; ' +
                                           'charset=utf-8')
                 .send(self.soapFault(version, 'The subject of this ' +
                   'request\'s delegation is held in another part of this ' +
                   'service, which ' + (got.code === 'STS-CELL-0125'
                     ? 'could not be reached'
                     : 'did not release what a token about them needs') +
                   ', so no token is issued about them.', 'RequestFailed',
                   self.trustNsOf(doc)));
              return undefined;
            }
            return cellAttributes.withPerson(realmId, got.projection,
              function () {
                return self.stsEndpointNow(req, res);
              });
          });
      });
  }

  // ---------------------------------------------------------------------------
  // WHICH PERSON'S HOME SERVES AN RST (#98 D10). A request is served where the
  // person whose CREDENTIAL it presents is homed, because that is the one
  // cell that can verify it — a UsernameToken's password is checked against
  // a `userPassword` only the home cell holds, and a person's second factor,
  // lockout and app passwords are there too. In order:
  //
  //   1. the requester's UsernameToken, by its Username;
  //   2. the requester's own SAML assertion, by its NameID. **An assertion
  //      this realm signed would VERIFY in any cell** — the signing keys are
  //      the global tier's (D8) — and it is relayed anyway, because what
  //      follows the verification is the person's: the authentication is
  //      recorded against their entry, the issuance policy and the risk
  //      standing read it, the token's attributes are its attributes, and a
  //      browser session may be started for them. None of that exists
  //      outside their home;
  //   3. with no requester credential (development's delegation with nobody
  //      in the requester's seat), the subject of the OnBehalfOf / ActAs.
  //
  // **A DELEGATION ACROSS CELLS IS SERVED AT THE REQUESTER'S HOME**, which
  // does not hold the delegated subject's entry when that person is homed
  // elsewhere; the token about them then carries what that cell knows of
  // them, which is nothing beyond the name. Fetching a subject's attributes
  // from its home is the design's `fetch-attributes` operation (#98 section
  // 5), not built yet — recorded in `ws-trust/CLAUDE.md`.
  //
  // A NameID that is not a login name (an email address, a pairwise value)
  // is unknown to the routing index, and the request is served where it
  // arrived — the answer it always had.
  // ---------------------------------------------------------------------------
  private homeNameOf(doc): string {
    const { firstByLocal, log, textByLocal } = this.deps;
    log.debug("Entering WsTrust.homeNameOf().");
    const nameOf = function (el): string {
      log.debug("Entering nameOf().");
      const named = el ? firstByLocal(el, 'NameID') ||
                         firstByLocal(el, 'NameIdentifier') : null;
      log.debug("Leaving nameOf().");
      return named ? String(named.textContent || '').trim() : '';
    };
    const scope = this.credentialScope(doc);
    const ut = this.firstOwnedByRequester(scope, 'UsernameToken');
    if (ut) {
      log.debug("Leaving WsTrust.homeNameOf(). A UsernameToken.");
      return String(textByLocal(ut, 'Username') || '').trim();
    }
    const assertion = this.firstOwnedByRequester(scope, 'Assertion');
    if (assertion) {
      log.debug("Leaving WsTrust.homeNameOf(). The requester's assertion.");
      return nameOf(assertion);
    }
    log.debug("Leaving WsTrust.homeNameOf(). The delegated subject.");
    return nameOf(firstByLocal(doc, 'OnBehalfOf') ||
                  firstByLocal(doc, 'ActAs'));
  }

  // ---------------------------------------------------------------------------
  // The endpoint, once the request is known to be served HERE.
  //
  // THE STANDINGS, READ FIRST (#62 P3): the requester's, and — new with
  // #499 — the subject of an OnBehalfOf / ActAs, whose standing is what a
  // delegated hop is decided on and which a node that did not see their
  // sign-in holds only from the store. Then THE SIGN-IN ITSELF IS ASSESSED
  // AT THE DOOR (doorAssessment(), #499), and the exchange is decided on
  // that assessment rather than on the standing an earlier one left —
  // which is what risk/CLAUDE.md's door table always said WS-Trust did.
  // ---------------------------------------------------------------------------
  private stsEndpointHere(req, res, claimed, delegated?: string, doc?) {
    const { log, subjectForName, firstByLocal } = this.deps;
    log.debug("Entering WsTrust.stsEndpointHere().");
    const self = this;
    const names: string[] = [];
    if (claimed) {
      names.push(String(claimed));
    }
    const obo = doc ? firstByLocal(doc, 'OnBehalfOf') ||
                      firstByLocal(doc, 'ActAs') : null;
    const oboNamed = obo ? firstByLocal(obo, 'NameID') ||
                           firstByLocal(obo, 'NameIdentifier') : null;
    const oboName = oboNamed ? String(oboNamed.textContent || '').trim() : '';
    if (oboName && names.indexOf(oboName) < 0) {
      names.push(oboName);
    }
    const preloads = names.map(function (name: string): Promise<unknown> {
      try {
        const sub = String(subjectForName(name) || '');
        return sub ? require('../risk/risk_engine').loadStanding(
          require('../common/realms').currentId(), name, sub)
          : Promise.resolve(null);
      } catch (e) {
        log.debug("Caught in WsTrust.stsEndpointHere(): " +
                  ((e && e.message) || e));
        // No risk engine in this process: nothing to read, and the roles
        // decide.
        return Promise.resolve(null);
      }
    });
    const serve = function (door: any): unknown {
      log.debug("Entering serve().");
      log.debug("Leaving serve().");
      return delegated ? self.delegatedHere(req, res, delegated, doc)
                       : self.stsEndpointNow(req, res, door);
    };
    log.debug("Leaving WsTrust.stsEndpointHere().");
    return Promise.all(preloads).then(function (): Promise<unknown> {
      return delegated ? Promise.resolve(null)
                       : self.doorAssessment(req, doc);
    }).then(serve, function (e: any): unknown {
      log.debug("Caught in WsTrust.stsEndpointHere(): " +
                ((e && e.message) || e));
      // loadStanding() and doorAssessment() never reject; this is their
      // belt and braces. Served as before #499: authenticated inside the
      // exchange and decided on the standing.
      return serve(null);
    });
  }

  // ---------------------------------------------------------------------------
  // THE SIGN-IN, ASSESSED AT THE DOOR (#499; rcbj's decision 2 on the
  // ticket). An Issue or a Renew that delegates nothing signs its requester
  // in, so it is authenticated HERE, before the exchange, and — when it
  // authenticated a person — assessed with `authn.assessSignIn()`, the same
  // call every other door makes between the credential and the decision.
  // The assessment is RECORDED (it moves the person's history and standing,
  // as every sign-in's does) and the exchange is decided on it, so a person
  // held at MEDIUM by an earlier sign-in is let through the moment this one
  // scores lower, and refused the moment it scores higher.
  //
  // Answers `{ auth, username, assessment, facts }`, `{ auth }` for a
  // credential that did not authenticate a person (handleRst() answers its
  // Fault without verifying it again), or null for a request this does not
  // apply to: no document, a delegation, an operation that signs nobody in.
  // Never rejects: an engine that failed answers `{ auth }`, and the
  // standing decides, as it did.
  // ---------------------------------------------------------------------------
  private async doorAssessment(req, doc): Promise<any> {
    const { authn, firstByLocal, log, textByLocal } = this.deps;
    log.debug("Entering WsTrust.doorAssessment().");
    if (!doc || firstByLocal(doc, 'OnBehalfOf') ||
        firstByLocal(doc, 'ActAs')) {
      log.debug("Leaving WsTrust.doorAssessment(). Not a sign-in here.");
      return null;
    }
    const op = String(textByLocal(doc, 'RequestType') || '').split('/')
      .pop().toLowerCase();
    if (op !== 'issue' && op !== 'renew') {
      log.debug("Leaving WsTrust.doorAssessment(). " + (op || 'No') +
                " operation signs nobody in.");
      return null;
    }
    const auth: any = this.authenticate(doc,
      this.oauthIssuer(helpers.baseUrlOf(req)));
    if (!auth.ok || !auth.subject || auth.subject === 'anonymous' ||
        auth.kind === 'delegated') {
      log.debug("Leaving WsTrust.doorAssessment(). Nobody signed in.");
      return { auth: auth };
    }
    const username = String(auth.subject);
    try {
      const assessment = await authn.assessSignIn(req, username,
                                                  'WS-Trust ' + op, {});
      const engine = assessment ? require('../risk/risk_engine') : null;
      if (!engine) {
        log.debug("Leaving WsTrust.doorAssessment(). Not assessed.");
        return { auth: auth };
      }
      const facts = engine.factsOf(engine.riskOf(assessment),
        auth.kind === 'assertion' ? [] : ['pwd'], '1');
      log.debug("Leaving WsTrust.doorAssessment(). " + assessment.level);
      return { auth: auth, username: username, assessment: assessment,
               facts: facts };
    } catch (e) {
      log.debug("Caught in WsTrust.doorAssessment(): " +
                ((e && e.message) || e));
      // assessSignIn() never rejects; a risk module missing from this
      // process is no facts, and the standing decides, as before #499.
      log.debug("Leaving WsTrust.doorAssessment(). Failed.");
      return { auth: auth };
    }
  }

  private stsEndpointNow(req, res, door?: any) {
    const { authn, errorCodes, log } = this.deps;
    log.debug("Entering the WS-Trust STS endpoint.");
    const contentType = req.headers['content-type'] || '';
    try {
      const encrypt = req.query.encrypt === '1' || req.query.encrypt === 'true';
      let issuanceAnswer: any = null;
      const result = this.handleRst(req.body || '', contentType,
        { encrypt: encrypt, base: helpers.baseUrlOf(req),
          preAuthenticated: door ? door.auth : null,
          doorRisk: door && door.facts
            ? { username: door.username, facts: door.facts } : null,
          onIssuanceAnswer: function (answer: any): void {
            issuanceAnswer = answer;
          } });
      // WHAT THE POLICY DECIDED ON THE DOOR'S ASSESSMENT, written back onto
      // it (#499), as the sign-in screen writes its own (`settle()`).
      const doorDecision = door && door.assessment
        ? this.settleDoorRisk(door, issuanceAnswer) : '';
      // THE SESSION, IF THE EXCHANGE MADE ONE. See handleRst()'s note on
      // `signIn` for why the decision is made there and the act is performed
      // here.
      //
      // The cookie goes out on a SOAP response and almost no WS-Trust client
      // will keep it, which is fine and is not what it is for: what matters is
      // the session RECORD, so that `/admin/sessions` can show that this person
      // is signed in and a global sign-out can end it. A browser-based client
      // that does keep the cookie gets single sign-on across to every other
      // protocol here, which is the same thing every other family already gives
      // it.
      if (result.signIn) {
        try {
          // `request` so a UsernameToken exchange from a BROWSER replaces
          // whatever session it was on. A SOAP client sends no cookie, so this
          // ends nothing for the ordinary caller — which is right.
          //
          // A NULL MEANS THE ISSUANCE POLICY REFUSED THE SESSION (2026-09-06),
          // and it is deliberately NOT a refusal of the exchange. The token was
          // already built and the caller is entitled to it — handleRst() asked
          // the gate in its own right, with `gate.ISSUANCE.WSTRUST_TOKEN`, and
          // that is the decision about what this endpoint
          // issues. This one is about the browser SESSION a UsernameToken
          // exchange also starts, which is a side effect of the exchange rather
          // than its product. Refusing the RSTR here would refuse a credential
          // the policy had already permitted.
          // THE DOOR'S ASSESSMENT RIDES IN (#499), so the session is
          // decided on it and carries it, and is not assessed a second time.
          const doorAssessed = door && door.assessment &&
            door.username === result.signIn.username ? door.assessment
            : undefined;
          const signedIn = authn.startSession(res, result.signIn.username,
                                              result.signIn.amr || ['pwd'], '1',
                                              result.signIn.via,
                                              doorAssessed
                                                ? { request: req,
                                                    risk: doorAssessed,
                                                    riskDecision:
                                                      doorDecision }
                                                : { request: req });
          if (!signedIn) {
            log.info('ws-trust: the token was issued and the issuance policy ' +
                     'refused the browser SESSION for ' +
                     result.signIn.username + '. The RSTR is unaffected: the ' +
                     'token was permitted in its own right.');
          }
        } catch (e) {
          // Bookkeeping must never break an exchange that has already succeeded
          // — the token is built, the caller is entitled to it, and a session
          // this service failed to record is a gap in a console page rather
          // than a reason to answer a SOAP Fault.
          log.error(errorCodes.tag('STS-WSTRUST-0016') +
                    'wstrust: starting a session for ' +
                    result.signIn.username +
                    ' failed and was ignored; the token is unaffected: ' +
                    e.message);
        }
      }
      const ct = result.version === '1.1' ? 'text/xml; charset=utf-8' :
                 'application/soap+xml; ' +
          'charset=utf-8';
      if (result.errorCode) {
        errorCodes.mark(res, result.errorCode);
      }
      res.status(result.status).type(ct).send(result.body);
      log.debug("Leaving the WS-Trust STS endpoint. HTTP " + result.status +
                ".");
    } catch (e) {
      log.error(errorCodes.tag('STS-WSTRUST-0015') + 'STS error: ' +
                (e && e.stack ? e.stack : e));
      // A failure of this service, not a refusal: soap:Receiver (soap:Server
      // on 1.1), in the version the request was sent in — it was always
      // SOAP 1.2 until #183. See receiverFault().
      const failedVersion = this.detectSoapVersion(null, contentType);
      errorCodes.mark(res, 'STS-WSTRUST-0015');
      res.status(500)
         .type(failedVersion === '1.1' ? 'text/xml; charset=utf-8'
                                       : 'application/soap+xml; charset=utf-8')
         .send(this.receiverFault(failedVersion,
                         'STS error: ' +
                         (e && e.message ? e.message : String(e))));
      log.debug("Leaving the WS-Trust STS endpoint. It failed.");
    }
  }

  // ---------------------------------------------------------------------------
  // THE DECISION ON THE DOOR'S ASSESSMENT, written back onto it (#499):
  // `permit`, `step-up` or `refuse`, `observe:` before it where development
  // set a risk Deny aside, and the code a refusal was recorded under. The
  // sign-in screen does the same through `authn`'s settleRisk(). Answers the
  // decision, which the session started on it records again with its id.
  // ---------------------------------------------------------------------------
  private settleDoorRisk(door: any, answer: any): string {
    const { log } = this.deps;
    log.debug("Entering WsTrust.settleDoorRisk().");
    const risk = answer && answer.risk ? answer.risk : null;
    const decision = risk
      ? (risk.observed ? 'observe:' : '') + String(risk.action)
      : (answer && !answer.allowed ? 'refuse' : 'permit');
    try {
      const engine = require('../risk/risk_engine');
      const refused = !!(answer && !answer.allowed && risk && !risk.observed);
      engine.settle(require('../common/realms').currentId(),
        String(door.assessment.id || ''), Object.assign(
          { decision: decision, policy: (answer && answer.policy) || '' },
          refused ? { errorCode: risk.action === 'step-up' ? 'STS-RISK-0017'
                                                           : 'STS-RISK-0016' }
            : {}));
    } catch (e) {
      log.debug("Caught in WsTrust.settleDoorRisk(): " +
                ((e && e.message) || e));
      // The record of the decision is bookkeeping: the exchange was decided
      // and answered whatever this could write.
    }
    log.debug("Leaving WsTrust.settleDoorRisk(). " + decision);
    return decision;
  }

  // The startup half of issuerDisagreement(), once, for the process-wide
  // values.
  /**
   * Logs once at startup, for the process-wide values, when the two issuer
   * names disagree.
   */
  warnAtStartup(): void {
    const { log } = this.deps;
    log.debug("Entering WsTrust.warnAtStartup().");
    const disagreement = this.issuerDisagreement();
    if (disagreement) {
      log.warn('wstrust: ' + disagreement);
    }
    log.debug("Leaving WsTrust.warnAtStartup().");
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
const slot = new InstanceSlot<WsTrust>(
  'ws-trust/wstrust',
  () => new WsTrust(WsTrust.defaultDeps()),
  WsTrust.wire,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * WS-Trust 1.0 to 1.4: the RequestSecurityToken endpoint, and the functions
 * that build and check what goes in and out of it.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  WsTrust: WsTrust,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: WsTrust): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  handleRst: slot.forward('handleRst'),
  issuerDisagreement: slot.forward('issuerDisagreement'),
  checkedAssertion: slot.forward('checkedAssertion'),
  buildToken: slot.forward('buildToken'),
  soapFault: slot.forward('soapFault')
};
