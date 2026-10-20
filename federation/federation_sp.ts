// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_sp.ts
//
// ===========================================================================
// THIS SERVICE AS A SERVICE PROVIDER: CONSUMING WHAT SOMEBODY ELSE ISSUED.
//
//   GET  /federation                 what all of this is, and every configured
//                                    relationship, for somebody who clicked the
//                                    link.
//   GET  /federation/login/{id}      START. Sends the browser to the partner —
//                                    an <AuthnRequest> on a binding, an
//                                    inter-site transfer URL, wa=wsignin1.0, or
//                                    an OAuth 2.0 authorization request.
//   GET|POST /federation/acs/{id}    FINISH. The assertion consumer service,
//                                    the WS-Federation wreply and the OAuth 2.0
//                                    redirect_uri, all on one path — see
//                                    decision 2.
//   GET  /federation/link/{handle}   Where link-at-first-sign-in's LOCAL
//                                    sign-in returns (#109): the partner named
//                                    an existing person whose account is not
//                                    linked to its subject, the person signed
//                                    in here as themselves, and this records
//                                    the link and finishes the sign-in.
//   GET  /federation/metadata/{id}   THIS SERVICE'S OWN SAML metadata for that
//                                    partner, so the partner can be configured
//                                    without anybody typing five URLs.
//
// A PARTNER'S SIGN-OUT (#167) is `federation_slo.ts`'s: /federation/slo/{id},
// /federation/backchannel-logout/{id} and /federation/frontchannel-logout/
// {id}. What THIS module keeps for it is what a sign-in learns about the
// partner's session — partnerSessionOf(), sessionBoundOf() — and the ACS's
// refusal of a sign-out sent to it (STS-FED-0024), which now names the path
// that consumes one.
//
// ---------------------------------------------------------------------------
// THIS IS THE MODULE WHERE THE SERVICE'S USUAL POSTURE IS INVERTED, AND EVERY
// REFUSAL IN IT IS DELIBERATE.
//
// Everywhere else here, a check that fails is a check this service chose to
// make and could have skipped: `/oauth2/token` mints a token for any username,
// `/saml2/sso` answers any entityID, every LDAP bind succeeds. Read this file
// expecting that and every refusal below looks like something to relax.
//
// It is the opposite. **What arrives at `/federation/acs/{id}` is an
// unauthenticated HTTP request that claims to be a person.** The only thing
// separating "alice signed in at the partner" from "somebody POSTed some XML"
// is the signature check against `fedSigningCertificate`, and the session that
// comes out of it is the SAME session `/oauth2/authorize`, `/wsfed`, `/saml2`
// and `/admin` all read. A permissive version of this endpoint is not a
// permissive mock — it is an authentication bypass for every protocol in the
// process.
//
// So: **nothing here is skipped, and nothing here is configurable to be
// skipped.** Where a check CAN be relaxed it is a per-relationship attribute
// with its own name and its own sentence on the page (`fedAllowUnsolicited` is
// the only one), never a global setting and never a default.
//
// ---------------------------------------------------------------------------
// SIX DECISIONS THAT ARE NOT OBVIOUS FROM THE SPECIFICATIONS.
//
// 1. **THE PERSON IS AUTHENTICATED THROUGH `authn.js`, NOT HERE.** This module
//    never writes a session cookie. It ends by calling `authn.startSession()`,
//    the same function the sign-in screen calls, which is what makes a
//    federated identity work in every protocol this service speaks without any
//    of them being told federation exists. A session store of this module's own
//    would have been the second store this repository refuses everywhere else,
//    and it would have been the one `/admin/users` could not see.
//
//    The consequence worth stating: a federated sign-in produces a session
//    whose `amr` is `federated` FIRST — the one thing this service did, which
//    was verify a partner's signature — followed by whatever the PARTNER said
//    it did (since 2026-09-12; see federatedAmr()). Where the partner said
//    nothing, the amr is `["federated"]`, which is not an RFC 8176 value and
//    deliberately is not one: inventing `pwd` because a partner probably used
//    a password would put a factor in a token that nobody performed.
//
// 2. **ONE PATH RECEIVES ALL FIVE PROTOCOLS, and it is
//    `/federation/acs/{id}`.** A SAML assertion consumer service, a
//    WS-Federation `wreply` and an OAuth 2.0 `redirect_uri` are three names for
//    "where the answer comes back", and the relationship id in the path already
//    says which protocol is expected. Five paths would mean five URLs to
//    configure at the partner and four ways to configure the wrong one — and
//    the failure of configuring the wrong one is a 404 in a browser after a
//    successful sign-in somewhere else, which is the least diagnosable failure
//    this feature could have.
//
// 3. **THE REQUEST CONTEXT IS SERVER-SIDE AND THE PARTNER CARRIES ONLY A
//    HANDLE.** `RelayState`, `wctx` and `state` all carry one opaque id, and
//    everything about the flow — the `<AuthnRequest>` ID an assertion must
//    answer, the OAuth `nonce`, the PKCE verifier, and WHERE THE PERSON WAS
//    GOING — lives in a Map here. Putting the return URL in the parameter
//    instead would be an open redirect operated by whoever can forge a
//    RelayState, which is everybody.
//
// 4. **THE RETURN IS ALWAYS A PATH ON THIS SERVICE.** `returnTo` is validated
//    the way `authn.beginAuthentication()` validates its own — it must start
//    with a single `/` — and it is stored server-side besides. Both, because
//    they fail differently: the check catches a caller's bug and the storage
//    catches an attacker.
//
// 5. **THE ID TOKEN IS VERIFIED WITH THE RELATIONSHIP'S KEYS AND NOTHING
//    ELSE.** No `alg: none`, no HMAC where an RSA key was configured, no
//    unverified decode used for anything but choosing WHICH key. That last one
//    is `client_auth.js`'s rule about an unverified `sub` and it is the same
//    rule: an unverified value may SELECT, it may never ESTABLISH.
//
// 6. **A FAILURE IS SHOWN, RECORDED AND NOT REDIRECTED.** Every refusal draws a
//    page naming the check that failed and writes `fedLastError` on the
//    relationship. It does NOT bounce the browser back to wherever it came from
//    with an error parameter — the person's sign-in has already succeeded at
//    the partner, so the interesting question is entirely "what did this
//    service dislike about the answer", and that question is unanswerable from
//    a redirect that has thrown the detail away.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS IN THE REQUIRE ORDER AND THE ROUTE ORDER (rule 1).
//
// **AFTER `authn/authn.ts`**, and it is the same dependency `saml2_sso.ts` has
// and stronger than WS-Federation's: it has no sign-in screen of its own and it
// calls `startSession()` directly. It must also be after
// `common/applications.js` is loadable, which it is everywhere, and it requires
// `federation.js`, `federation_map.ts` and `federation_http.ts` — all three
// libraries that register nothing.
//
// It does NOT require `ldap_server.js` and must never: that module is near the
// end of the order because requiring it pulls every `/ldap` route into the
// router, and this module's routes would then sit behind them. The directory
// is reached the way every other module reaches it — through the identity
// funnel, which this module gets to by way of `authn.startSession()` rather
// than by calling `stats.recordAuthentication()` itself. That is not merely
// tidiness: calling both produced TWO authentication records for one federated
// sign-in, which is what `startSession()`'s sixth argument exists to prevent.
// That argument is unchanged by #50's R1: `ldap_server.js` is still
// JavaScript, and still registers its routes when it is required.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `FederationSp` takes every module of this service it reads — and
// each helper it used to destructure — through its constructor as
// `FederationSpDeps`, and its four endpoints are registered by
// `registerRoutes(app)`. node's `zlib`, `jsonwebtoken` and xmldom are
// libraries and are used directly; node's `crypto` is not, since #453 — every
// digest, random value and key goes through `common/crypto.js`. Since #50's
// R2 the composition root builds the instance; the module's old names are
// FACADES forwarding to it, for the modules and tests that require it by
// them, and a process without the root builds a default at load. Loading
// the module registers NOTHING (#50, R1): the module exports
// `registerRoutes(app)`, and `common/protocol_stack.ts` calls it at the
// point in the route order where requiring this module used to register the
// routes (rule 1).
// ---------------------------------------------------------------------------

import zlib = require('zlib');
import jwt = require('jsonwebtoken');
import xmldom = require('@xmldom/xmldom');
// One signer and one verifier for the whole service since 2026-08-27.
import stsCrypto = require('../common/crypto');

import app = require('./../common/app');
import config = require('./../common/config');
import applications = require('./../common/applications');
import authn = require('./../authn/authn');
import federation = require('./federation');
import fedMap = require('./federation_map');
import fedHttp = require('./federation_http');
// The consumer provider profiles (#565): a leaf.
import consumerProviders = require('./consumer_providers');
// The once-ever history (rule 3ae), for a provider's notification (#565).
import usedAssertions = require('./../common/used_assertions');
// THE ERROR CODES. Every refusal here is a SECURITY refusal, so each check has
// a code of its own, marked on the response before refuse() draws the page —
// the code is never on the page. And the audit log, for the one failure that
// does not refuse: an optional UserInfo call that did not answer.
import errorCodes = require('./../common/error_codes');
// A library (rule 3) that registers no route: the revocation check
// `fedSigningCertificate` gets when it has verified a response. See
// `signerStillAccepted()`.
import revocationStatus = require('./../common/revocation_status');
import audit = require('./../common/audit');
// For the context store below only. `realms.js` requires config.js and
// error_codes.js and nothing else here, so it registers no route and cannot
// join a cycle — rule 3m.
import realms = require('./../common/realms');
// The configured XML signature algorithms, for a signed outbound AuthnRequest.
// A leaf in saml/ that registers nothing — the same answer every SAML signer in
// this service reads, so a partner verifying our request and our assertions is
// told one algorithm. See saml/document_settings.ts.
import documentSettings = require('./../saml/document_settings');
import helpers = require('./../common/helpers');
import InstanceSlot = require('./../common/instance_slot');
// THE LANGUAGE A PAGE IS DRAWN IN (#539): a library and a leaf, so it moves
// no route and closes no cycle. Only the pages a PERSON passes through use it
// — the outbound hand-off and the signed-in page; refusals stay English.
import PageLocale = require('./../common/page_locale');
// THE FEDERATION PAGES' SHELL (#580): the landing page, and what the login
// and linking endpoints say, drawn in the browser.
import FederationPages = require('./federation_pages');
// WHICH PEOPLE A PARTNER MAY ASSERT (#109). `mode.js` answers whether a name
// match is allowed at all; `federation_links.ts` is the link's format, a
// static utility class; the console roster (`admin_rbac.ts`, built by the
// composition root before this module) and `roles.js` say who is an
// administrator a partner may not sign in. All four are libraries that
// register nothing and require nothing here back.
import mode = require('./../common/mode');
import links = require('./federation_links');
// A partner's block on a person (#373): a leaf store the receiver writes.
import fedBlocks = require('./federation_blocks');
import rbac = require('./../admin-ui/admin_rbac');
import roles = require('./../common/roles');
// A PARTNER'S ENCRYPTED ASSERTION OR ID TOKEN (#168): the key it is encrypted
// to and the policy it is decrypted under. A static utility class that
// registers no route and requires nothing here back.
import fedEncryption = require('./federation_encryption');
// THE IDLE SWEEP (#358). Requiring it registers `federation.provision-idle`;
// the module offers no route. A second register below is the guard's no-op
// when this file is what loaded it.
import fedProvision = require('./federation_provision');
// A FLOW'S HANDLE NAMES THE CELL THAT HOLDS IT (#98 D10): stamped when it is
// minted (putContext()), read where a partner's answer arrives (consume()).
// Libraries that register no route.
import cellLocator = require('./../common/cell_locator');
import cellPlacement = require('./../common/cell_placement');
import cells = require('./../common/cells');
import cellRouting = require('./../common/cell_routing');

const { DOMParser, XMLSerializer } = xmldom;

type Helpers = typeof helpers;

// Everything this module reads of the rest of the service. The helpers are
// named one by one, as the module destructured them.
interface FederationSpDeps {
  config: typeof config;
  applications: typeof applications;
  authn: typeof authn;
  federation: typeof federation;
  fedMap: typeof fedMap;
  fedHttp: typeof fedHttp;
  errorCodes: typeof errorCodes;
  revocationStatus: typeof revocationStatus;
  audit: typeof audit;
  realms: typeof realms;
  documentSettings: typeof documentSettings;
  stsCrypto: typeof stsCrypto;
  log: Helpers['log'];
  logArtifact: Helpers['logArtifact'];
  STS: Helpers['STS'];
  xmlEscape: Helpers['xmlEscape'];
  firstByLocal: Helpers['firstByLocal'];
  textByLocal: Helpers['textByLocal'];
  iso: Helpers['iso'];
  baseUrlOf: Helpers['baseUrlOf'];
  jsonFromB64u: Helpers['jsonFromB64u'];
  randomId: Helpers['randomId'];
  parseBody: Helpers['parseBody'];
  subjectForName: Helpers['subjectForName'];
  hasSubjectResolver: Helpers['hasSubjectResolver'];
  mode: typeof mode;
  links: typeof links;
  rbac: typeof rbac;
  roles: typeof roles;
  fedEncryption: typeof fedEncryption;
  // An OP discovered through an OpenID Federation (#134), LAZILY: `oidfed/`
  // is loaded after this module (14b) and reads it back for its RP metadata.
  oidfedRp: () => any;
}

// The express app's registration methods, as `registerRoutes()` uses them.
interface RouteRegistrar {
  get(path: string, ...handlers: any[]): unknown;
  post(path: string, ...handlers: any[]): unknown;
}

// READ FROM THE REGISTER rather than written here, and the header of PATHS over
// there says why: the console has to print these URLs and may not require this
// module, so one copy in the library both sides reach is the only arrangement
// in which the page and the router cannot disagree.
const BASE_PATH = federation.PATHS.base;
const LOGIN_PATH = federation.PATHS.login;
const ACS_PATH = federation.PATHS.acs;
const METADATA_PATH = federation.PATHS.metadata;
const LINK_PATH = federation.PATHS.link;
// The inter-cell operation that asks whether a resident carries a partner's
// link (#98 D9): see FederationSp.homeOfSubject().
const LINK_HOME_OP = 'federation-link-home';
// A partner's sign-out (#167), served by `federation_slo.ts`; named here too
// because the ACS points at it and the metadata publishes it.
const SLO_PATH = federation.PATHS.slo;

// The `via` of the local sign-in link-at-first-sign-in asks for (#109): the
// pending record's `protocol`, which `authn.ts` writes onto the session's
// authentication event. The linking step reads it back to know the sign-in it
// is shown was made through ITS screen, as the person, just now.
const LINK_VIA = 'Federation link';
// WHERE A STEP-UP AFTER A PARTNER RETURNS (#565), and what its local second
// factor is recorded as, for the step-up endpoint to recognise.
const STEPUP_PATH = federation.PATHS.stepup;
const STEPUP_VIA = 'Federation step-up';
// WHERE A CONSUMER NEWCOMER GIVES WHAT THE PROVIDER DID NOT SEND (#565,
// rcbj's decision 2 on #729): the values this realm's attribute policy
// requires of every person, asked for on a short form of the federation
// surface before the account is created. Five tries at one form, and a value
// is at most 256 characters, as `person_editor.ts` holds a create's values to
// the attribute's own rules besides.
const PROFILE_PATH = federation.PATHS.profile;
const PROFILE_MAX_ATTEMPTS = 5;
const PROFILE_VALUE_MAX = 256;
// The shape of an address a person types (`ldap/person_editor.ts`'s).
const PROFILE_EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// A control character, never in a value a person types.
const PROFILE_CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
// HOW OLD A PROVIDER NOTIFICATION WITH NO `exp` MAY BE (#565): its `iat`
// bounds it instead, and the once-ever history keeps it that long. A day,
// which covers a provider's own retries.
const NOTIFICATION_MAX_AGE_S = 86400;
// THE INTER-CELL OPERATION A PROVIDER'S NOTIFICATION IS FANNED OUT WITH
// (#727): each peer removes the links it holds for the subject. See
// applyNotification().
const PEER_NOTIFICATION_OP = 'federation-provider-notification';
// What a notification can lead to: the types that remove a link, and the
// ones only recorded.
const UNLINKING_NOTIFICATIONS = ['consent-revoked', 'account-delete'];

// THE BROWSER THAT STARTED A LINKING SIGN-IN (#109). A cookie carrying a
// random value whose SHA-256 is on the context, so the linking step is
// completed only in the browser the partner's response arrived in. Without
// it the step would be account-linking CSRF: somebody signs in at the partner
// as themselves under a name they chose, hands the victim the sign-in screen's
// URL, and the victim's own password links the attacker's partner account to
// the victim's.
const LINK_COOKIE = 'sts_fed_link';

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const NS_SAMLP11 = 'urn:oasis:names:tc:SAML:1.0:protocol';
const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

// ---------------------------------------------------------------------------
// THE REQUEST CONTEXTS. See decision 3.
//
// Keyed by the handle that rides on RelayState / wctx / state. Capped and swept
// on every write, because the key is minted here but the MAP is written to by
// anybody who can reach `/federation/login/{id}` — which, unlike the rest of
// this module, needs no configuration at all to reach.
// ---------------------------------------------------------------------------
//
// PER TRUST REALM since 2026-08-25. A relationship is an entry in the realm's
// own `ou=federations` and `/federation/acs/{id}` verifies against the
// certificate configured on it, so a context minted while `acme` was ambient
// being spendable at the DEFAULT realm's assertion consumer service would let a
// flow that began in one realm finish in another — on the one surface here
// where a missing check is an authentication bypass rather than a fidelity bug.
// Nothing legitimate crossed: a handle is minted and spent inside one flow, and
// a flow carries its realm in every URL it uses.
//
// THE CAP IS NOW PER REALM, which is the one thing to weigh rather than assume:
// MAX_CONTEXTS in flight in each realm rather than 500 for the process. That is
// deliberate — the cap is here so that anybody who can reach
// `/federation/login/{id}` cannot grow this map without limit, and a shared cap
// would have let one realm's flood evict another realm's in-flight sign-ins,
// which is the denial of service the cap exists to bound arriving through the
// door it was meant to close.
//
// **KEYED BY `credentialDigest(handle)`, AND THE HANDLE IS NOT IN THE ROW
// (#614).** The handle is the flow's bearer — whoever presents it as a
// RelayState, wctx or state spends the context — and the store only looks it
// up and spends it, so it holds the digest, computed when the handle is minted
// and again when it comes back. The two callers that build an authorization
// request from a context just stored are handed the handle beside it
// (`heldContext()`), and `takeContext()` answers the record with the handle
// it was asked for put back on. A row of the old shape is simply not found.
const contexts = realms.map({ persist: 'federation_sp.contexts',
                              retain: 'age',
                              // #333: the context's `expires`, ms.
                              expiresAt: realms.expiryField('expires', 1) });

// ---------------------------------------------------------------------------
// PAGES. This module draws two: a refusal and an index. Both are plain HTML
// with no script — `app.js` sets `script-src 'none'` for the whole service and
// nothing here is the exception that needs relaxing, because the one page that
// posts a form (the outbound HTTP-POST binding) is a REAL form with a real
// submit button and no script at all.
//
// THAT IS THE DIFFERENCE FROM THE SCRIPTED PAGES elsewhere here (the root
// CLAUDE.md lists them), and it is worth the sentence so nobody adds another by
// analogy: the ones that auto-submit do so because the person has already
// decided and a click would be ceremony. This
// one is a person LEAVING THIS SERVICE for a foreign identity provider, which
// is exactly the moment a deliberate click is worth having — and it means the
// federation feature adds no CSP relaxation anywhere.
// ---------------------------------------------------------------------------
const STYLE = 'body{font-family:system-ui,Segoe ' +
  'UI,Helvetica,Arial,sans-serif;margin:2rem auto;max-width:52rem;' +
  'line-height:1.5;color:#111}h1{font-size:1.4rem}h2{font-size:1.05rem;' +
  'margin-top:1.6rem}code{background:#f4f4f5;padding:.1rem .3rem;' +
  'border-radius:3px;word-break:break-all}table{border-collapse:collapse;' +
  'width:100%;margin:.6rem 0}th,td{border:1px solid #ddd;padding:.35rem ' +
  '.5rem;text-align:left;font-size:.9rem;vertical-align:top}' +
  'th{background:#fafafa}.bad{color:#a00;font-weight:600}.ok{color:#060}' +
  '.note{color:#555;font-size:.9rem}button{font:inherit;padding:.5rem ' +
  '1rem;border:1px solid #333;background:#111;color:#fff;border-radius:4px;' +
  'cursor:pointer}ul{padding-left:1.2rem}';

// ONE KIND FOR ALL FIVE PROTOCOLS, and it is a ROW ADDED TO `applications.js`'s
// KINDS rather than a reuse of one that was already there.
//
// The first version of this mapped each protocol onto the nearest existing
// kind — a SAML 2.0 partner became a `saml2-service-provider`, an OIDC one an
// `oauth2-client` — which was wrong in the way that is hardest to notice: every
// page drew it correctly, and every one of them said the foreign identity
// provider was a CLIENT of this service. It is the opposite. That list is
// closed on purpose, and its header says a kind outside it is recorded with a
// warning; the sanctioned way to say something new is a row, so there is one.
//
// The PROTOCOL is not lost by collapsing the five: it goes on the same record
// as `appProtocol`, which is where every other party's protocol goes.
const PARTNER_KIND = 'federation-identity-provider';

// ===========================================================================
// STARTING A FLOW.
// ===========================================================================

// ===========================================================================
// FINISHING A FLOW: the one path that receives all five protocols.
// ===========================================================================

/**
 * This service as a service provider: starting a sign-in at a federation
 * partner and consuming what the partner sends back, in five protocols, on one
 * assertion consumer service path per relationship.
 *
 * Nothing is accepted unless it verifies against what the relationship was
 * configured with, in every mode.
 */
class FederationSp {
  /**
   * The path of the federation index page, `/federation`.
   */
  static readonly BASE_PATH = BASE_PATH;
  /**
   * The path that starts a sign-in at a partner (`/{id}` appended).
   */
  static readonly LOGIN_PATH = LOGIN_PATH;
  /**
   * The assertion consumer service path, which receives all five protocols
   * (`/{id}` appended).
   */
  static readonly ACS_PATH = ACS_PATH;
  /**
   * The path of this service's SAML metadata for a partner (`/{id}` appended).
   */
  static readonly METADATA_PATH = METADATA_PATH;
  /**
   * The path link-at-first-sign-in's local sign-in returns to (`/{handle}`
   * appended).
   */
  static readonly LINK_PATH = LINK_PATH;
  /**
   * The `via` of the local sign-in link-at-first-sign-in asks for.
   */
  static readonly LINK_VIA = LINK_VIA;

  /**
   * Builds the service provider over the given dependencies.
   *
   * @param deps - the modules it uses, with `oidfedRp` reached lazily
   */
  constructor(private readonly deps: FederationSpDeps) {
    deps.log.debug("Entering FederationSp.constructor().");
    deps.log.debug("Leaving FederationSp.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies the composition root passes, from the real
   * modules.
   *
   * @returns the dependencies
   */
  static defaultDeps(): FederationSpDeps {
    helpers.log.debug("Entering FederationSp.defaultDeps().");
    helpers.log.debug("Leaving FederationSp.defaultDeps().");
    return {
      config: config,
      applications: applications,
      authn: authn,
      federation: federation,
      fedMap: fedMap,
      fedHttp: fedHttp,
      errorCodes: errorCodes,
      revocationStatus: revocationStatus,
      audit: audit,
      realms: realms,
      documentSettings: documentSettings,
      stsCrypto: stsCrypto,
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      STS: helpers.STS,
      xmlEscape: helpers.xmlEscape,
      firstByLocal: helpers.firstByLocal,
      textByLocal: helpers.textByLocal,
      iso: helpers.iso,
      baseUrlOf: helpers.baseUrlOf,
      jsonFromB64u: helpers.jsonFromB64u,
      randomId: helpers.randomId,
      parseBody: helpers.parseBody,
      subjectForName: helpers.subjectForName,
      hasSubjectResolver: helpers.hasSubjectResolver,
      mode: mode,
      links: links,
      rbac: rbac,
      roles: roles,
      fedEncryption: fedEncryption,
      oidfedRp: function (): any {
        return require('../oidfed/oidfed_rp');
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE ROUTES, in the order this module has always registered them.
  // -------------------------------------------------------------------------
  /**
   * Registers the login, assertion consumer service, link, metadata, JWKS and
   * index routes.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteRegistrar): void {
    const { log } = this.deps;
    log.debug("Entering FederationSp.registerRoutes().");
    // GET /federation/login/{id}
    app.get(LOGIN_PATH + '/:id', (req, res) => {
      return this.loginEndpoint(req, res);
    });
    // GET|POST /federation/acs/{id}
    app.get(ACS_PATH + '/:id', (req, res) => {
      return this.consume(req, res);
    });
    app.post(ACS_PATH + '/:id', (req, res) => {
      return this.consume(req, res);
    });
    // GET /federation/link/{handle} — where link-at-first-sign-in's local
    // sign-in returns (#109).
    app.get(LINK_PATH + '/:handle', (req, res) => {
      return this.linkEndpoint(req, res);
    });
    // GET /federation/stepup/{handle} — where a second factor asked for on
    // risk after a partner's answer returns (#565).
    app.get(STEPUP_PATH + '/:handle', (req, res) => {
      return this.stepUpEndpoint(req, res);
    });
    // GET|POST /federation/profile/{handle} — what a consumer provider's
    // newcomer is asked for before the account is created (#565, #729).
    app.get(PROFILE_PATH + '/:handle', (req, res) => {
      return this.profileEndpoint(req, res);
    });
    app.post(PROFILE_PATH + '/:handle', (req, res) => {
      return this.profileSubmit(req, res);
    });
    // POST /federation/notifications/{id} — a provider's signed
    // server-to-server notification (#565: Sign in with Apple).
    app.post(federation.PATHS.notifications + '/:id', (req, res) => {
      return this.notificationsEndpoint(req, res);
    });
    // GET /federation/metadata/{id}
    app.get(METADATA_PATH + '/:id', (req, res) => {
      return this.metadataEndpoint(req, res);
    });
    // GET /federation/jwks/{id} — an OpenID Connect relationship's
    // encryption key (#168).
    app.get(federation.PATHS.jwks + '/:id', (req, res) => {
      return this.jwksEndpoint(req, res);
    });
    // GET /federation/pages.js — the script of the three pages above that
    // are this service's own (#580): the landing page, and what the login
    // and linking endpoints say.
    app.get(FederationPages.SCRIPT_PATH, (req, res) => {
      return FederationPages.script(req, res);
    });
    // GET /federation
    app.get(BASE_PATH, (req, res) => {
      return this.indexEndpoint(req, res);
    });
    log.debug("Leaving FederationSp.registerRoutes().");
  }

  // `federation.maxContexts` since 2026-09-12; it was the constant
  // MAX_CONTEXTS,
  // 500. Read per use so the console can move it.
  private maxContexts() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.maxContexts().");
    log.debug("Leaving FederationSp.maxContexts().");
    return Number(config.value('federation.maxContexts'));
  }

  // The longest `application` a context will carry. A client_id has no length
  // limit in any specification this service implements, and this value is
  // written into a directory attribute at the far end — so it is bounded where
  // it is accepted rather than where it is spent. It is generous: the longest
  // identifier anything here files an application under is a SAML entityID,
  // which is a URL. `federation.maxApplicationLength` since 2026-09-12; it was
  // the constant 256.
  private maxApplicationLength() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.maxApplicationLength().");
    log.debug("Leaving FederationSp.maxApplicationLength().");
    return Number(config.value('federation.maxApplicationLength'));
  }

  private contextTtlMs() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.contextTtlMs().");
    log.debug("Leaving FederationSp.contextTtlMs().");
    return config.value('federation.requestTtlMin') * 60 * 1000;
  }

  /**
   * Stores the context of a flow in flight and returns a handle for it; the
   * oldest context is dropped once `federation.maxContexts` are held.
   *
   * @param record - what the flow needs back when the response arrives
   * @returns the handle, `fed-` and a random value (stamped with this cell
   *   in a service deployed as cells)
   */
  putContext(record) {
    const { log, randomId, stsCrypto } = this.deps;
    log.debug("Entering FederationSp.putContext().");
    // STAMPED WITH THE CELL THAT HOLDS IT (#98 D10): the context store is
    // the cell's, and a handle comes back — as a RelayState, a wctx, a
    // state, or `/federation/link/{handle}`'s path segment — at whichever
    // cell the browser reaches next. Twelve base64url characters: 40 in all,
    // inside the handle pattern's 64 and SAML's 80-byte RelayState.
    const handle = 'fed-' + cellLocator.stamp(randomId(18));
    const now = Date.now();
    contexts.forEach((value, key) => {
      if (value.expires < now) contexts.delete(key);
    });
    const cap = this.maxContexts();
    if (contexts.size >= cap) {
      // The OLDEST goes, and it is a sweep rather than a refusal because the
      // alternative is a login endpoint anybody can reach that stops working
      // for everybody once it is hit enough times. What is lost is one person's
      // in-flight sign-in, which fails as an unsolicited response and says so.
      let oldestKey = null;
      let oldestAt = Infinity;
      contexts.forEach((value, key) => {
        if (value.startedAt < oldestAt) {
          oldestAt = value.startedAt;
          oldestKey = key;
        }
      });
      if (oldestKey) {
        contexts.delete(oldestKey);
        log.warn('federation: ' + cap + ' sign-ins are in flight ' +
                 '(federation.maxContexts), so the oldest was dropped. ' +
                 'Whoever it belonged to will be told their response was ' +
                 'unsolicited, which is the truth as far as this service can ' +
                 'tell.');
      }
    }
    contexts.set(stsCrypto.credentialDigest(handle),
                 Object.assign({ startedAt: now,
                                 expires: now + this.contextTtlMs() },
                               record));
    log.debug("Leaving FederationSp.putContext(). handle=" + handle + ', ' +
              contexts.size + ' ' +
              'in flight.');
    return handle;
  }

  // ---------------------------------------------------------------------------
  // WHAT A COMPLETED SIGN-IN NEEDS OFF THE REQUEST CONTEXT, in one place.
  //
  // FIVE call sites build the result `completeSignIn()` is handed — one per
  // protocol, plus OAuth 2.0's two ways of learning who somebody is — and each
  // of them reads these fields off the context it holds. They were five copies
  // of `returnTo: (context && context.returnTo) || ''` until `application`
  // joined it, at which point the shape of the mistake became obvious: a sixth
  // field, or a sixth protocol, is five places to remember and one to forget. A
  // federated sign-in that succeeds and lands somebody on a page nobody asked
  // for is what a dropped `returnTo` looks like; a dropped `application` is a
  // count on /admin/federation/map that is quietly short.
  //
  // A MISSING CONTEXT IS NOT AN ERROR HERE. The SAML 1.1 unsolicited case has
  // no context at all (`fedAllowUnsolicited`), so both fields are empty and
  // both callers already behave correctly for that: the person lands on this
  // service's own "signed in" page, and no pair is counted because nothing said
  // what the sign-in was for.
  // ---------------------------------------------------------------------------
  private fromContext(context) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.fromContext().");
    log.debug("Leaving FederationSp.fromContext().");
    return {
      returnTo: (context && context.returnTo) || '',
      application: (context && context.application) || '',
      // The sign-in screen's pending record, for a restart at the person's
      // home cell (#98 D9); '' in single-cell mode.
      authnPending: (context && context.authnPending) || '',
      // A CONNECT FROM THE PORTAL (#565): who is connecting, from which
      // sign-on session and browser, and where to go back to. Null for a
      // sign-in.
      connect: (context && context.connect) || null
    };
  }

  // Read AND SPEND. A context is good for one response, which is what makes a
  // replayed assertion fail the second time even where the partner's own replay
  // window has not closed. The SAML 1.1 case is the one that has no context at
  // all — see `fedAllowUnsolicited` — and it is handled by the caller rather
  // than by pretending there was one.
  /**
   * Reads and spends a flow's context: a context is good for one response.
   *
   * @param handle - the handle `putContext()` returned
   * @returns the context, or null when there is none or it has expired
   */
  takeContext(handle) {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering FederationSp.takeContext(). handle=" +
              (handle || '(none)'));
    const key = stsCrypto.credentialDigest(String(handle || ''));
    const record = contexts.get(key);
    if (!record) {
      log.debug("Leaving FederationSp.takeContext(). No such context.");
      return null;
    }
    contexts.delete(key);
    if (record.expires < Date.now()) {
      log.debug("Leaving FederationSp.takeContext(). It had expired.");
      return null;
    }
    log.debug("Leaving FederationSp.takeContext(). Found it.");
    return Object.assign({ handle: String(handle) }, record);
  }

  // A context just stored, read back WITHOUT spending it, with its handle
  // beside it (#614: the row holds no handle) — for the authorization
  // request that carries the handle as `state`.
  private heldContext(handle) {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering FederationSp.heldContext().");
    const record = contexts.get(stsCrypto.credentialDigest(String(handle)));
    log.debug("Leaving FederationSp.heldContext().");
    return record ? Object.assign({ handle: String(handle) }, record) : null;
  }

  private enabled() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.enabled().");
    log.debug("Leaving FederationSp.enabled().");
    return !!config.value('federation.enabled');
  }

  // `t` is the page's translator (#539), for a page a person passes through;
  // without one the page is English, exactly as it always was.
  private page(title, body, t?) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.page().");
    log.debug("Leaving FederationSp.page().");
    return '<!DOCTYPE html>\n<html' +
      (t ? PageLocale.htmlAttributes(t) : ' lang="en"') +
      '><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + xmlEscape(title) + '</title><style>' + STYLE +
      '</style></head><body>' +
      body + '</body></html>';
  }

  // A refusal, and it does three things every time: it draws the reason, it
  // writes `fedLastError` on the relationship, and it answers a status code a
  // test can assert on. See decision 6 — it never redirects.
  //
  // ON THE LOGIN AND LINKING ENDPOINTS (#580) the reason is drawn in the
  // browser: the shell, with `what`, `why` and the relationship in
  // `data-sts-state` (`federation_pages.ts`), the status unchanged. On the
  // assertion consumer service — a specification's endpoint — it is drawn
  // here, as it always was. `what` and `why` are TEXT either way.
  // error-code: none — the definition of the helper, not a call to it
  private refuse(res, record, status, what, why, extra?) {
    const { federation, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.refuse(). what=" + what);
    const id = (record && record.fedId) || '';
    if (id) federation.recordFailure(id, what + ': ' + why);
    // A SESSION A STEP-UP'S SECOND FACTOR STARTED does not outlive the
    // refusal of the sign-in it was for (rcbj's decision 3 on #729).
    this.endStepUpSession(res, what);
    if (FederationPages.onSurface(res)) {
      FederationPages.send(res, status,
                           FederationPages.refusedView(what, why, id));
      log.debug("Leaving FederationSp.refuse(). " + status + ', the shell.');
      return;
    }
    const body = '<h1>The federated sign-in was refused</h1>' +
      '<p class="bad">' + xmlEscape(what) + '</p>' +
      '<p>' + xmlEscape(why) + '</p>' +
      (extra || '') +
      (id ? '<p class="note">This is recorded on the relationship as ' +
            '<code>fedLastError</code>. The whole record is at <a ' +
            'href="/admin/federation?relationship=' + encodeURIComponent(id) +
            '">/admin/federation</a>, ' +
            'and every refusal is also a row in the audit log.</p>'
          : '') +
      '<p class="note"><strong>This service refuses rather than accepting ' +
      'here, which is the opposite of what it does everywhere else.</strong> ' +
      'What arrives at this endpoint is an unauthenticated request claiming ' +
      'to be a person, and the session it would produce is the one every ' +
      'other protocol in this process reads. See ' +
      'federation/CLAUDE.md.</p><p><a ' +
      'href="' + BASE_PATH + '">Back to the federation index</a></p>';
    res.status(status)
       .type('html')
       .set('Cache-Control', 'no-store')
       .send(this.page('Refused', body));
    log.debug("Leaving FederationSp.refuse(). " + status + '.');
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS SERVICE CALLS ITSELF TO A PARTNER.
  //
  // One function, because the same string is the SAML `<Issuer>` of an outbound
  // AuthnRequest, the `Audience` an inbound assertion must name, the
  // WS-Federation `wtrealm` and the OAuth `client_id` fallback — and four
  // spellings of it would be four things a partner had to be configured with.
  //
  // It is PER RELATIONSHIP rather than one constant: a partner keying its
  // trust store off an entityID must be able to be given one that is only
  // ours-with-them. (The other direction made the same decision until #523,
  // when this service as an IDENTITY PROVIDER became one name per realm.)
  // ---------------------------------------------------------------------------
  //
  // **AND IT IS DERIVED FROM THE BASE URL, WHICH IS THE ONE THING TO KNOW ABOUT
  // IT (2026-09-12).** `base` is `helpers.baseUrlOf(req)`, so an unpinned
  // service names itself after whatever Host header the browser sent — and the
  // same derivation is what the inbound `<Audience>` is compared against, so
  // the two stay in step by construction: the Issuer this service SENDS and the
  // audience it EXPECTS are one call to this function with one base. What that
  // does not give is a name that is stable across hostnames, which a partner
  // keying its trust store off an entityID needs. Two ways to pin it, in order:
  //
  //   * `fedLocalEntityId` on the relationship — the entityID a partner was
  //     given, used verbatim for this relationship alone;
  //   * `global.publicBaseUrl` — which pins `baseUrlOf()` for every
  //     relationship at once, and every other URL this service publishes with
  //     it.
  //
  // The ACS URL below stays derived: it is an ADDRESS a browser posts to, and
  // it must follow the base it can actually reach.
  /**
   * Returns the name this service goes by with a partner: the relationship's
   * `fedLocalEntityId` when pinned, its ACS URL otherwise.
   *
   * @param base - the service's base URL
   * @param record - the federation relationship
   * @returns the entity ID
   */
  ourEntityId(base, record) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.ourEntityId().");
    const pinned = String((record && record.fedLocalEntityId) || '').trim();
    if (pinned) {
      log.debug("Leaving FederationSp.ourEntityId().");
      return pinned;
    }
    log.debug("Leaving FederationSp.ourEntityId().");
    return base + ACS_PATH + '/' + encodeURIComponent(record.fedId);
  }

  /**
   * Returns the relationship's assertion consumer service URL.
   *
   * @param base - the service's base URL
   * @param record - the federation relationship
   * @returns the URL
   */
  acsUrl(base, record) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.acsUrl().");
    log.debug("Leaving FederationSp.acsUrl().");
    return base + ACS_PATH + '/' + encodeURIComponent(record.fedId);
  }

  // Where a partner's browser-borne sign-out arrives (#167): the SAML
  // SingleLogoutService, the WS-Federation cleanup URL and the OpenID Connect
  // post_logout_redirect_uri, one path for the ACS's reason (decision 2).
  /**
   * Returns the address a partner's browser-borne sign-out arrives at for the
   * relationship.
   *
   * @param base - the service's base URL
   * @param record - the federation relationship
   * @returns the URL
   */
  sloUrl(base, record) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.sloUrl().");
    log.debug("Leaving FederationSp.sloUrl().");
    return base + SLO_PATH + '/' + encodeURIComponent(record.fedId);
  }

  // ---------------------------------------------------------------------------
  // THE PARTNER'S CERTIFICATE AS A PEM.
  //
  // `fedSigningCertificate` holds base64 DER, which is what a
  // `<ds:X509Certificate>` carries and what `samlSigningCertificate` on an
  // application entry holds — one spelling across this service. xml-crypto
  // wants a PEM, so this is the one conversion, in one place: two call sites
  // doing it inline is two chances to wrap at 63 characters instead of 64,
  // which produces a key that parses and verifies nothing.
  // ---------------------------------------------------------------------------
  /**
   * Returns the relationship's `fedSigningCertificate` (base64 DER) as a PEM.
   *
   * @param record - the federation relationship
   * @returns the PEM, or the empty string when none is configured
   */
  certPemOf(record) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.certPemOf().");
    const der = String(record.fedSigningCertificate || '').replace(/\s+/g, '');
    if (!der) {
      log.debug("Leaving FederationSp.certPemOf(). There is none configured.");
      return '';
    }
    const wrapped = der.replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
    log.debug("Leaving FederationSp.certPemOf(). " + der.length + ' base64 ' +
        'characters.');
    return '-----BEGIN CERTIFICATE-----\n' + wrapped + '\n-----END ' +
                                                       'CERTIFICATE-----\n';
  }

  // ---------------------------------------------------------------------------
  // THE CONFIGURED CERTIFICATE, CHECKED FOR REVOCATION ONCE IT HAS VERIFIED
  // SOMETHING (2026-09-12).
  //
  // `fedSigningCertificate` is what an administrator wrote onto the
  // relationship, and `verifyXmlSignature()` is right to trust it over anything
  // in the document. What that trust cannot know is that the partner's CA has
  // since REVOKED it — a compromised signing key is exactly the event a partner
  // publishes on its CRL and does not ring anybody about. So after every other
  // check has passed and before the session is started, the certificate is
  // looked up exactly as a presented one is: the register when this service
  // issued it, its issuer's OCSP responder and CRL otherwise, under
  // `pki.revocationCheck`. `common/revocation_status.js`'s
  // `registeredVerdictFor()` argues why its addresses may be dialled.
  //
  // **THE PATH BECAME ASYNCHRONOUS FOR IT**, rather than taking the
  // register-only door, because a partner's certificate is by definition
  // somebody else's and the register would answer nothing about it. `consume()`
  // already returns the OAuth branch's promise, so a promise from these two
  // branches changes nothing for express; a throw inside it is caught here into
  // the same refusal page `consume()`'s own catch draws.
  // ---------------------------------------------------------------------------
  //
  // **AN OIDC OR OAUTH 2.0 PARTNER'S KEY IS THE SAME QUESTION ASKED OF A JWK.**
  // `jwk` is the key out of `fedJwks` or `fedJwksUri` that verified the token;
  // its `x5c`, where it has one, is checked the same way, and a key with none
  // is a bare key with nothing to look up — reported as such on the log line
  // rather than called good.
  /**
   * Checks the configured signing certificate, or the partner key that verified
   * a token, for revocation once it has verified a response, and continues the
   * sign-in only if it is still accepted.
   *
   * A refused certificate is answered 401 (`STS-PKI-0129`); a throw while
   * continuing is answered 500 (`STS-FED-0042`).
   *
   * @param req - the request
   * @param res - the response
   * @param record - the federation relationship
   * @param proceed - what completes the sign-in
   * @param jwk - the partner key that verified a JWT, if that is what is
   *   checked
   * @returns a promise of what `proceed` or the refusal returns
   */
  signerStillAccepted(req, res, record, proceed, jwk?) {
    const { errorCodes, revocationStatus, log } = this.deps;
    log.debug("Entering FederationSp.signerStillAccepted(). id=" +
              record.fedId);
    const checked = jwk
      ? revocationStatus.registeredKeyVerdictFor(jwk,
                                                 'the key "' +
          (jwk.kid || '(no ' +
          'kid)') +
          '" in the relationship "' + record.fedId + '"\'s key set')
      : revocationStatus.registeredVerdictFor({
        certificate: record.fedSigningCertificate,
        source: 'fedSigningCertificate on the relationship "' +
                record.fedId + '"'
      });
    log.debug("Leaving FederationSp.signerStillAccepted(). The verdict is " +
              'pending.');
    return checked.then((verdict) => {
      if (verdict.refused) {
        log.warn('federation: ' + record.fedId + ': the configured signing ' +
                 'certificate verified the response and is ' +
                 'refused: ' + verdict.why);
        errorCodes.mark(res, 'STS-PKI-0129');
        return this.refuse(res, record, 401, 'The partner\'s signing ' +
                                        'certificate may no longer be used',
          verdict.why + ' The signature verified against it, and a signature ' +
          'from a withdrawn key is worth nothing: ' +
          'replace ' + (jwk ? 'the key' : 'fedSigningCertificate') +
          ' with the partner\'s current one.');
      }
      log.debug('signerStillAccepted(): ' +
                revocationStatus.registeredSummary(verdict) + '.');
      return proceed();
    }).catch((e) => {
      log.error(errorCodes.tag('STS-FED-0042') + 'federation: ' + record.fedId +
                ' threw while completing a verified response: ' + e.stack);
      if (res.headersSent) {
        // The sign-in already answered; there is nothing left to refuse with.
        return undefined;
      }
      errorCodes.mark(res, 'STS-FED-0042');
      return this.refuse(res, record, 500, 'This service failed while ' +
                                      'reading the response', e.message);
    });
  }

  // ---------------------------------------------------------------------------
  // VERIFYING AN XML SIGNATURE MADE BY SOMEBODY ELSE.
  //
  // **THIS IS A POLICY WRAPPER OVER `common/crypto.js`, AND THE POLICY IS THE
  // PART THAT MATTERS.** The mechanics — which id spellings resolve, which
  // canonicalization, which signature belongs to which element — are the shared
  // verifier's and are the same everywhere. What is decided HERE is what makes
  // this door different from every other one in the service: no configured
  // certificate means nothing is accepted, and the certificate is always the
  // relationship's rather than the document's.
  //
  // This comment used to explain an `idAttribute` argument that had to be
  // passed for SAML 1.1 and withheld for SAML 2.0, because symmetry between the
  // two call sites produced a signature-wrapping error on a perfectly good
  // document. That argument no longer exists; `saml/CLAUDE.md` keeps the story.
  //
  // **THE KEY IS THE CONFIGURED ONE AND ONLY THE CONFIGURED ONE.** `publicCert`
  // is passed explicitly, so a signature carrying its own `<ds:KeyInfo>` with a
  // certificate inside it is verified against OUR copy and not against the one
  // it brought — which is the difference between a signature check and a
  // decoration. That is the single most important line in this module.
  // ---------------------------------------------------------------------------
  private verifyXmlSignature(xml, record, wanted) {
    const { stsCrypto, log } = this.deps;
    log.debug("Entering FederationSp.verifyXmlSignature(). wanted=" + wanted);
    const pem = this.certPemOf(record);
    if (!pem) {
      // **THE ONE REFUSAL IN THIS SERVICE THAT IS NOT A MODE**, and it stays
      // here rather than moving into the shared verifier: `common/crypto.js`
      // answers "does this signature verify against this key", and "there is no
      // key configured, so nothing is accepted" is a FEDERATION policy about a
      // relationship. See `federation/CLAUDE.md` — the gate is on the SIGNER
      // (and, since #109, on the subject too), and a permissive answer here
      // would be an authentication bypass for every protocol in the process.
      log.debug("Leaving FederationSp.verifyXmlSignature(). No certificate " +
                'is configured.');
      return { ok: false, present: false,
               why: 'no fedSigningCertificate is configured on this ' +
                    'relationship, so there is nothing to verify the ' +
                    'signature against. Nothing is accepted until there is' };
    }
    // **THE PARTNER'S OWN <ds:KeyInfo> CERTIFICATE IS NEVER USED, AND PASSING
    // `certPem` IS WHAT ENSURES IT.** The shared verifier falls back to the
    // certificate inside the document when it is given no other — which is
    // correct for a general-purpose tool and would be the whole hole here,
    // since anybody can sign an assertion and attach the key that verifies it.
    // This call always passes the certificate configured on the RELATIONSHIP,
    // so the fallback is unreachable from this door.
    //
    // The `idAttribute` argument that used to be threaded through three call
    // sites is gone: SAML 1.1's `AssertionID` and SAML 2.0's `ID` are both
    // resolved from the document by the verifier, so a partner's version is no
    // longer something this file has to work out in advance and pass down.
    const result = stsCrypto.verifyXmlSignature(xml, {
      element: wanted,
      certPem: pem
    });
    log.debug("Leaving FederationSp.verifyXmlSignature(). ok=" + result.ok);
    return {
      ok: result.ok,
      present: result.present,
      why: result.ok ? ''
        : (result.why || 'the signature did not verify against ' +
                         'fedSigningCertificate')
    };
  }

  // ---------------------------------------------------------------------------
  // ONE SAML ASSERTION'S CONTENTS, 2.0 and 1.1 alike.
  //
  // The two versions differ in three places and nowhere else that matters here:
  // the subject is `<NameID>` or `<NameIdentifier>`, an attribute's name is
  // `Name` or `AttributeName`, and 1.1 splits the name into a namespace and a
  // local part. All three are handled here rather than in two extractors,
  // because the shape that comes OUT is the same bag either way and two
  // extractors would be two chances to spell a bag member differently.
  // ---------------------------------------------------------------------------
  private assertionContents(assertion) {
    const { log, firstByLocal, textByLocal } = this.deps;
    log.debug("Entering FederationSp.assertionContents().");
    const out = { subject: '', nameFormat: '', bag: {}, authnInstant: '',
                  context: '', nameQualifier: '', spNameQualifier: '',
                  sessionIndex: '', sessionNotOnOrAfter: '' };
    const nameEl = firstByLocal(assertion, 'NameID') ||
                   firstByLocal(assertion, 'NameIdentifier');
    if (nameEl) {
      out.subject = (nameEl.textContent || '').trim();
      out.nameFormat = nameEl.getAttribute('Format') ||
                       nameEl.getAttribute('Format') || '';
      // The two qualifiers a LogoutRequest names the principal with again
      // (saml-core-2.0-os section 3.7.3.2 matches on the NameID WHOLE), kept
      // so a partner's sign-out can be matched and ours can be built (#167).
      out.nameQualifier = nameEl.getAttribute('NameQualifier') || '';
      out.spNameQualifier = nameEl.getAttribute('SPNameQualifier') || '';
    }
    const authn = firstByLocal(assertion, 'AuthnStatement') ||
      firstByLocal(assertion, 'AuthenticationStatement');
    if (authn) {
      out.authnInstant = authn.getAttribute('AuthnInstant') ||
        authn.getAttribute('AuthenticationInstant') || '';
      out.context = textByLocal(authn, 'AuthnContextClassRef') ||
        authn.getAttribute('AuthenticationMethod') || '';
      // THE PARTNER'S SESSION (#167): the SessionIndex its LogoutRequest will
      // name, and the instant it says its session ends (saml-core-2.0-os
      // section 2.7.2). SAML 2.0 only; a SAML 1.1 AuthenticationStatement
      // carries neither, and that profile defines no logout.
      out.sessionIndex = authn.getAttribute('SessionIndex') || '';
      out.sessionNotOnOrAfter = authn.getAttribute('SessionNotOnOrAfter') ||
                                '';
    }
    const attributes = assertion.getElementsByTagName('*');
    for (let i = 0; i < attributes.length; i++) {
      const el = attributes[i];
      if (el.localName !== 'Attribute') continue;
      // SAML 1.1 splits the name. The two halves are joined with a `/` where
      // the namespace does not already end in one, which is how AD FS spells
      // its own claim URIs and therefore how the default map's WS-Federation
      // rows are written — a namespace and a name kept apart would match
      // nothing.
      const namespace = el.getAttribute('AttributeNamespace') || '';
      const local = el.getAttribute('Name') ||
                    el.getAttribute('AttributeName') || '';
      if (!local) continue;
      const name = namespace
        ? (namespace.charAt(namespace.length - 1) === '/' ? namespace + local
                                                          : namespace + '/' +
                                                              local)
        : local;
      const values = [];
      const children = el.getElementsByTagName('*');
      for (let j = 0; j < children.length; j++) {
        if (children[j].localName !== 'AttributeValue') continue;
        const text = (children[j].textContent || '').trim();
        if (text) values.push(text);
      }
      if (!values.length) continue;
      out.bag[name] = (out.bag[name] || []).concat(values);
    }
    log.debug("Leaving FederationSp.assertionContents(). subject=" +
              out.subject + ', ' +
              Object.keys(out.bag).length + ' attribute(s).');
    return out;
  }

  // The validity window, as a check with a sentence. `Conditions` is optional
  // in both versions and an assertion with none is ACCEPTED HERE — refusing it
  // would refuse a perfectly ordinary AD FS assertion — but the fact is
  // reported rather than hidden, because "this assertion can never expire" is
  // worth knowing. (A SAML 2.0 assertion with no Conditions is refused by
  // audienceCheck() since 2026-09-12, for having no audience restriction — a
  // different rule, argued there, and not a change to what this function
  // decides.)
  private conditionsCheck(assertion) {
    const { config, log, firstByLocal } = this.deps;
    log.debug("Entering FederationSp.conditionsCheck().");
    const conditions = firstByLocal(assertion, 'Conditions');
    if (!conditions) {
      log.debug("Leaving FederationSp.conditionsCheck(). There are none.");
      return { ok: true, why: 'the assertion carries no <Conditions>, so it ' +
                              'states no validity window at all and nothing ' +
                              'here can expire it' };
    }
    const notBefore = conditions.getAttribute('NotBefore') || '';
    const notOnOrAfter = conditions.getAttribute('NotOnOrAfter') || '';
    const now = Date.now();
    // The same allowance this service applies to its own tokens, for the reason
    // oauth-oidc/CLAUDE.md gives about clockSkewS: an assertion refused thirty
    // seconds early because two machines disagree reads as a broken federation
    // from both ends. It is the SAME setting rather than a second one, because
    // a deployment that has decided how far out its clock may be has decided it
    // once.
    const skew = config.value('oauth2.clockSkewS') * 1000;
    if (notBefore && Date.parse(notBefore) - skew > now) {
      log.debug("Leaving FederationSp.conditionsCheck(). Not yet valid.");
      return { ok: false, errorCode: 'STS-FED-0017',
               why: 'the assertion is not valid until ' + notBefore +
                    ', which is in the future even allowing ' +
                    config.value('oauth2.clockSkewS') + 's of clock skew' };
    }
    if (notOnOrAfter && Date.parse(notOnOrAfter) + skew <= now) {
      log.debug("Leaving FederationSp.conditionsCheck(). Expired.");
      return { ok: false, errorCode: 'STS-FED-0018',
               why: 'the assertion expired at ' + notOnOrAfter +
                    ' (allowing ' + config.value('oauth2.clockSkewS') +
                    's of clock skew). A partner and this service ' +
                    'disagreeing about the time is the usual cause; the ' +
                    'other is a replay' };
    }
    log.debug("Leaving FederationSp.conditionsCheck(). Inside its window.");
    return { ok: true, why: (notBefore || '(no NotBefore)') + ' to ' +
                            (notOnOrAfter || '(no NotOnOrAfter)') };
  }

  // ---------------------------------------------------------------------------
  // THE AUDIENCE, AS A CHECK WITH A SENTENCE — AND A REFUSAL (2026-09-12).
  //
  // **IT WAS A WARNING AND IT IS A REFUSAL, IN EVERY MODE.** An <Audience>
  // naming a different service provider was logged and ACCEPTED, on the
  // argument that a partner configured with a different name for this service
  // is the ordinary case. That is true of a partner and fatal at this endpoint:
  // an assertion a partner minted for SOMEBODY ELSE — any other service
  // provider it signs for — verifies against the same `fedSigningCertificate`,
  // names the same issuer, and is inside its window, so accepting it lets
  // anybody holding an assertion for another relying party of that partner sign
  // in HERE as its subject. The directory's own header calls this the one
  // surface whose bugs are security bugs, and this was one. The remedy for a
  // partner that calls us something else is `fedLocalEntityId` on the
  // relationship, which says what that name is.
  //
  // What counts as ours is ourEntityId() — the same call that names this
  // service in the outbound AuthnRequest's Issuer, the WS-Federation wtrealm
  // and the SAML 1.1 providerId, with the same base URL — or `fedClientId`
  // where the relationship has one.
  //
  // Every AudienceRestriction must be satisfied, and one is satisfied by ANY of
  // its Audience values: saml-core-2.0-os section 2.5.1.4 (and its SAML 1.1
  // predecessor, AudienceRestrictionCondition) — several restrictions are an
  // AND, several audiences inside one are an OR. Reading only the first
  // <Audience>, as this did, refused a legitimate multi-audience assertion and
  // accepted nothing better for it.
  //
  // AN ASSERTION WITH NO AUDIENCE RESTRICTION: refused for SAML 2.0, whose Web
  // Browser SSO profile makes one a MUST (saml-profiles-2.0-os section
  // 4.1.4.2); accepted with a warning for SAML 1.1 and WS-Federation, whose
  // profiles make it optional and whose deployed identity providers routinely
  // omit it.
  // ---------------------------------------------------------------------------
  /**
   * Checks an assertion's audience restrictions: every restriction must name
   * this service (`ourEntityId()` or `fedClientId`), in every mode.
   *
   * @param assertion - the assertion element
   * @param base - the service's base URL
   * @param record - the federation relationship
   * @param required - whether an assertion with no audience restriction is
   *   refused (SAML 2.0) rather than accepted with a warning
   * @returns `{ ok, why }`, with `errorCode` on a refusal
   */
  audienceCheck(assertion, base, record, required) {
    const { log, firstByLocal } = this.deps;
    log.debug("Entering FederationSp.audienceCheck(). required=" + required);
    const ours = this.ourEntityId(base, record);
    const accepted = [ours];
    if (String(record.fedClientId || '').trim()) {
      accepted.push(String(record.fedClientId).trim());
    }
    const conditions = firstByLocal(assertion, 'Conditions');
    const restrictions = [];
    if (conditions) {
      const all = conditions.getElementsByTagName('*');
      for (let i = 0; i < all.length; i++) {
        if (all[i].localName === 'AudienceRestriction' ||
            all[i].localName === 'AudienceRestrictionCondition') {
          restrictions.push(all[i]);
        }
      }
    }
    if (!restrictions.length) {
      if (required) {
        log.debug("Leaving FederationSp.audienceCheck(). None, and this " +
                  'profile requires one.');
        return { ok: false, errorCode: 'STS-FED-0019',
                 why: 'the assertion carries no <AudienceRestriction>, so it ' +
                      'is not addressed to any service provider in ' +
                      'particular. The SAML 2.0 Web Browser SSO profile ' +
                      'requires one (saml-profiles-2.0-os section 4.1.4.2), ' +
                      'and an assertion any service provider may accept is ' +
                      'one minted for somebody else as readily as for this ' +
                      'service' };
      }
      log.warn('federation: the assertion from ' + record.fedId + ' carries ' +
               'no audience restriction. It is ACCEPTED, because this ' +
               'profile makes one optional — but it is not addressed to this ' +
               'service in particular.');
      log.debug("Leaving FederationSp.audienceCheck(). None, and this " +
                'profile allows that.');
      return { ok: true, why: '' };
    }
    for (let r = 0; r < restrictions.length; r++) {
      const values = [];
      const audiences = restrictions[r].getElementsByTagName('*');
      for (let a = 0; a < audiences.length; a++) {
        if (audiences[a].localName === 'Audience') {
          values.push((audiences[a].textContent || '').trim());
        }
      }
      const matched = values.some((value) => {
        return accepted.indexOf(value) >= 0;
      });
      if (!matched) {
        log.debug("Leaving FederationSp.audienceCheck(). A restriction names " +
                  'somebody else.');
        return { ok: false, errorCode: 'STS-FED-0020',
                 why: 'the assertion is addressed to ' +
                      (values.length ? values.join(', ') : '(an empty ' +
                          'audience restriction)') +
                      ' and this service calls itself ' + accepted.join(' ' +
                          'or ') +
                      ' to this partner. An assertion minted for a different ' +
                      'service provider verifies against the same key, so it ' +
                      'is refused rather than accepted. If the partner was ' +
                      'configured with a different name for this service, ' +
                      'set fedLocalEntityId on the relationship to that name' };
      }
    }
    log.debug("Leaving FederationSp.audienceCheck(). Every restriction names " +
              'this service.');
    return { ok: true, why: '' };
  }

  // The partner's own amr, carried BESIDE `federated` rather than replaced by
  // it (2026-09-12). It was `amr.length ? ['federated'] : ['federated']` — both
  // arms identical — so a partner's authentication context was read and then
  // thrown away. `federated` stays FIRST, because it is the fact about what
  // THIS service did (it verified a partner's signature), and it is what
  // `saml/authn_context.ts` keys on to read everything after it as the
  // PARTNER's statement rather than this service's own sign-in.
  /**
   * Returns the `amr` of a federated sign-in: `federated` first, then the
   * partner's own values.
   *
   * @param partner - the partner's `amr`
   * @returns the values
   */
  federatedAmr(partner) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.federatedAmr().");
    const values = (Array.isArray(partner) ? partner : [])
      .map((value) => { return String(value || '').trim(); })
      .filter((value) => { return value !== '' && value !== 'federated'; });
    log.debug("Leaving FederationSp.federatedAmr().");
    return ['federated'].concat(values);
  }

  // ---------------------------------------------------------------------------
  // THE END OF EVERY SUCCESSFUL FLOW, whichever protocol got here.
  //
  // ONE function, and that is the whole reason the five protocol branches above
  // it are as thin as they are: the mapping, the subject, the directory entry,
  // the counters, the audit trail and the session are the same acts in every
  // protocol, and five copies of them would be five subtly different federated
  // sign-ins.
  //
  // THE ORDER MATTERS AND IS NOT ARBITRARY:
  //
  //   1. map, so the username exists before anything is filed under it;
  //   2. **CHECK THE SUBJECT (#109, 2026-09-22)** — subjectDecision(): which
  //      local person the partner's subject may become under the
  //      relationship's `fedSubjectPolicy`, its three rules and the
  //      console-administrator refusal. A refusal here writes NOTHING: not the
  //      partner's attributes, not a link, not a counter. It must come before
  //      the session because the session is where the identity funnel WRITES
  //      the partner's attributes onto the entry — until this step existed a
  //      partner naming `admin` had overwritten admin's `mail` before any
  //      refusal could be reached. An unlinked subject naming an existing
  //      person is not refused and not signed in either: it is sent to sign in
  //      HERE as that person first (beginLinking()), and the rest of this
  //      list runs when that comes back to `/federation/link/{handle}`;
  //   3. the relationship's counters;
  //   4. the application record for the partner, so `/admin/applications` knows
  //      the foreign identity provider exists;
  //   5. the session, LAST, because it is the thing that has an effect outside
  //      this process and everything above it is a record of why. It goes
  //      through `authn.startSession()`, which is also where the identity
  //      funnel (`recordAuthentication()`) runs — the funnel that seeds the
  //      directory entry AND carries the mapped attributes and the link to it;
  //      see WHAT THE FUNNEL IS TOLD below for why it is not called separately.
  //
  // Steps 3 to 5 are finishSignIn(), which the linking step calls too.
  // ---------------------------------------------------------------------------
  private completeSignIn(req, res, record, result) {
    const { fedMap, errorCodes, log, federation } = this.deps;
    log.debug("Entering FederationSp.completeSignIn(). id=" + record.fedId);
    // A CONNECT FROM THE PORTAL (#565) is not a sign-in: the partner's
    // verified subject is linked to the person who asked, and nothing else
    // happens. See finishConnect().
    if (result.connect) {
      log.debug("Leaving FederationSp.completeSignIn(). A connect.");
      return this.finishConnect(req, res, record, result);
    }
    const mapped = fedMap.mapIncoming(record, result.bag, result.subject);
    // What was dropped, for /admin/federation (#94). A store that cannot be
    // written costs the list and never the sign-in.
    try {
      federation.recordUnmapped(record.fedId, mapped.unmapped);
    } catch (e) {
      log.debug("Caught in FederationSp.completeSignIn(): " +
                ((e && e.message) || e));
    }
    if (!mapped.username) {
      log.debug("Leaving FederationSp.completeSignIn(). There is no username.");
      errorCodes.mark(res, 'STS-FED-0043');
      log.debug("Leaving FederationSp.completeSignIn().");
      return this.refuse(res, record, 400, 'The partner named nobody',
                    'The assertion verified, but nothing in it could be read ' +
                    'as a username: ' +
                    (record.fedUsernameSource
                      ? 'this relationship takes the username from "' +
                        record.fedUsernameSource +
                        '", which was not sent, and there was no subject either'
                      : 'it carried no subject, and no fedUsernameSource is ' +
                        'configured to take one from an attribute instead'),
                    this.bagTable(result.bag));
    }
    // A PERSON HOMED IN ANOTHER CELL (#98 D9), before the subject is decided
    // against a directory that does not hold them — and so before anything
    // is linked, provisioned or signed in here. See homeOfSubject().
    if (cells.isMulti()) {
      const self = this;
      log.debug("Leaving FederationSp.completeSignIn(). Asking where the " +
                "subject is homed.");
      return this.homeOfSubject(record, result, mapped)
        .then(function (home: string): unknown {
          if (home) {
            return self.restartAtHome(req, res, record, result, home);
          }
          return self.decideAndFinish(req, res, record, result, mapped);
        });
    }
    log.debug("Leaving FederationSp.completeSignIn(). Deciding.");
    return this.decideAndFinish(req, res, record, result, mapped);
  }

  // Steps 2 to 5 of completeSignIn(), once the subject is known to be decided
  // HERE.
  private decideAndFinish(req, res, record, result, mapped) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.decideAndFinish(). id=" + record.fedId);
    const decision = this.subjectDecision(record, result, mapped);
    if (!decision.ok) {
      log.debug("Leaving FederationSp.decideAndFinish(). The subject was " +
                "refused: " + decision.code);
      return this.refuseSubject(res, record, result, mapped, decision);
    }
    if (decision.confirm) {
      log.debug("Leaving FederationSp.decideAndFinish(). A local sign-in " +
                "first, to link " + decision.username + ".");
      return this.beginLinking(req, res, record, result, decision);
    }
    log.debug("Leaving FederationSp.decideAndFinish(). " + decision.how + ".");
    return this.finishSignIn(req, res, record, result, mapped, decision);
  }

  // ---------------------------------------------------------------------------
  // WHERE THE PARTNER'S SUBJECT IS HOMED (#98 D9), in a service deployed as
  // cells. subjectDecision() reads THIS cell's directory, which holds its
  // residents and — for a session exported here — projections of people
  // homed elsewhere, which are not residents. A person homed in another cell
  // is found three ways, in the order subjectDecision() would find them:
  //
  //   1. the person a local entry's federationLink names — a projection's
  //      home from the routing index;
  //   2. with no local holder, a RESIDENT of another cell carrying the link,
  //      asked of every peer (`federation-link-home`): the routing index
  //      keeps names and entryUUIDs, not links;
  //   3. the NAMES the relationship's policy would sign in or create — the
  //      mapped username under any-existing and link-at-first-sign-in, and
  //      `<relationship>~<subject>` under every policy that creates one —
  //      from the routing index. A name homed elsewhere is never created
  //      here, which is also what the index's own claim at creation refuses.
  //
  // Nothing personal leaves this cell and the assertion is not forwarded:
  // the flow restarts at home (restartAtHome()), where the partner — which
  // holds its own sign-on session — answers again at home's consumer, and
  // the decision, a link-at-first-sign-in included, is made there.
  // Answers '' to decide here: single-cell mode, a subject resident here or
  // unknown everywhere, and a peer that cannot be asked (STS-CELL-0123).
  // ---------------------------------------------------------------------------
  private homeOfSubject(record, result, mapped): Promise<string> {
    const { federation, links, log } = this.deps;
    log.debug("Entering FederationSp.homeOfSubject(). id=" + record.fedId);
    const realmId = realms.currentId();
    const elsewhere = function (home: string): string {
      return home && home !== cells.id() && cells.get(home) ? home : '';
    };
    const stable = links.stableSubjectOf(record, result);
    const holders = stable.ok ? federation.peopleLinkedBy(stable.value) : [];
    if (holders.length === 1) {
      log.debug("Leaving FederationSp.homeOfSubject(). A linked person.");
      return cellRouting.homeOf(realmId, 'name', holders[0].username)
        .then(elsewhere);
    }
    if (holders.length > 1) {
      log.debug("Leaving FederationSp.homeOfSubject(). Ambiguous; decided " +
                "here.");
      return Promise.resolve('');
    }
    const policy = federation.subjectPolicyOf(record);
    const names = [];
    if (policy === 'any-existing' || policy === 'link-at-first-sign-in') {
      names.push(mapped.username);
    }
    if (policy !== 'any-existing' && policy !== 'pre-linked' && stable.ok) {
      names.push(links.provisionedName(record.fedId, stable.subject));
    }
    const byLink = stable.ok
      ? FederationSp.linkHomeAtPeers(realmId, stable.value)
      : Promise.resolve('');
    log.debug("Leaving FederationSp.homeOfSubject(). Asking the peers and " +
              "the routing index.");
    return byLink.then(function (home: string): Promise<string> | string {
      if (home) {
        return home;
      }
      return names.reduce(function (found: Promise<string>, name: string) {
        return found.then(function (had: string) {
          return had || !name ? had
            : cellRouting.homeOf(realmId, 'name', name).then(elsewhere);
        });
      }, Promise.resolve(''));
    });
  }

  /**
   * Asks every other cell whether one of its RESIDENTS carries a
   * federationLink.
   *
   * @param realmId - the realm
   * @param link - the link value (`links.stableSubjectOf().value`)
   * @returns a promise of the first cell that holds one, or ''
   */
  static linkHomeAtPeers(realmId: string, link: string): Promise<string> {
    helpers.log.debug("Entering FederationSp.linkHomeAtPeers().");
    const channel = require('./../common/cell_channel');
    const asks = cells.peers().map(function (peer) {
      return channel.call(peer.id, LINK_HOME_OP, { realm: realmId,
                                                   link: link })
        .then(function (answer: any) {
          return answer && answer.holds ? peer.id : '';
        }, function (err: any) {
          helpers.log.warn(errorCodes.tag('STS-CELL-0123') + 'federation: ' +
                           'cell "' + peer.id + '" could not be asked ' +
                           'whether a person there carries a partner\'s ' +
                           'link (' + ((err && err.message) || err) + '); ' +
                           'the subject is decided without it.');
          return '';
        });
    });
    helpers.log.debug("Leaving FederationSp.linkHomeAtPeers(). " +
                      asks.length + " peer(s).");
    return Promise.all(asks).then(function (found: string[]) {
      return found.filter(Boolean)[0] || '';
    });
  }

  /**
   * Answers another cell's `federation-link-home`: whether a person RESIDENT
   * here — not a projection — carries the link.
   *
   * @param body - `{ realm, link }`
   * @returns `{ holds }`
   * @throws an Error for an unknown realm
   */
  static answerLinkHome(body: any): { holds: boolean } {
    helpers.log.debug("Entering FederationSp.answerLinkHome().");
    const realmId = String((body && body.realm) || '');
    const realm = realmId ? realms.get(realmId)
                          : realms.get(realms.DEFAULT_ID);
    if (!realm) {
      helpers.log.debug("Leaving FederationSp.answerLinkHome(). No realm.");
      throw new Error('no such realm');
    }
    let holds = false;
    realms.run(realm, function () {
      const cellSessions = require('./../common/cell_sessions');
      holds = federation.peopleLinkedBy(String(body.link || ''))
        .some(function (one) {
          return !cellSessions.isProjected(realmId, 'name', one.username);
        });
    });
    helpers.log.debug("Leaving FederationSp.answerLinkHome(). " + holds);
    return { holds: holds };
  }

  // THE FLOW RESTARTS AT HOME (#98 D9): the browser is pinned to the home
  // cell and sent back to the start the sign-in screen recorded
  // (`authn.restartPendingAtHome()`, the sign-in screen's own restart), or to
  // the flow's return address when it recorded none. The verified assertion
  // is dropped here, unused: nothing about the person is written or carried.
  private restartAtHome(req, res, record, result, home: string) {
    const { authn, log } = this.deps;
    log.debug("Entering FederationSp.restartAtHome(). home=" + home);
    log.info('federation: ' + record.fedId + '\'s partner asserted a person ' +
             'homed in cell "' + home + '"; the flow restarts there (#98 ' +
             'D9).');
    log.debug("Leaving FederationSp.restartAtHome().");
    return authn.restartPendingAtHome(req, res,
                                      String(result.authnPending || ''),
                                      String(result.returnTo || ''), home);
  }

  // ---------------------------------------------------------------------------
  // WHICH LOCAL PERSON THE PARTNER'S SUBJECT MAY BECOME (#109, 2026-09-22).
  //
  // Answers `{ ok: false, code, status, what, why, rule }` — a refusal — or
  // `{ ok: true, username, link, create, how, confirm }`, where `how` is one
  // of:
  //
  //   linked     an entry already carries this subject's federationLink;
  //   confirm    link-at-first-sign-in, and an unlinked subject whose mapped
  //              name is an existing person: that person signs in HERE first;
  //   created    nobody is named, and a new entry may be made — namespaced
  //              `<relationship>~<subject>` except under any-existing, which
  //              uses the mapped name with no namespace — linked at creation
  //              (`create` false where provisioning is off, and the session
  //              is then refused STS-FED-0090 as it always was);
  //   matched    any-existing's name match, development only.
  //
  // THE LINK IS FOUND FIRST, WHATEVER THE POLICY. A subject an administrator,
  // SCIM or an earlier first sign-in linked is the strongest statement this
  // service has about who it is, and it signs in the person it names even
  // where their NAME has since changed at the partner — which is OpenID
  // Connect Core section 5.7's whole point. The policy decides only what
  // happens to a subject nobody linked.
  //
  // THE RULES AND THE ADMINISTRATOR REFUSAL COME LAST AND APPLY TO EVERY
  // ANSWER, a link included: a link says the subject is this person, and the
  // rules say whether this partner may sign this person in at all.
  // ---------------------------------------------------------------------------
  /**
   * Decides which local person a partner's verified subject may become: the
   * person already linked to it, one to confirm and link, a new entry, or a
   * name match (development only), under the relationship's subject policy and
   * rules.
   *
   * @param record - the federation relationship
   * @param result - the verified sign-in
   * @param mapped - the mapped attributes and username
   * @returns `{ ok: true, username, link, create, how, confirm }`, or a refusal
   *   `{ ok: false, code, status, what, why, rule }`
   */
  subjectDecision(record, result, mapped): any {
    const { federation, links, mode, log } = this.deps;
    log.debug("Entering FederationSp.subjectDecision(). id=" + record.fedId);
    const policy = federation.subjectPolicyOf(record);
    if (policy === 'any-existing' && !mode.matchesFederatedNames()) {
      log.debug("Leaving FederationSp.subjectDecision(). any-existing in " +
                "product.");
      return this.subjectRefusal('STS-FED-0094', 'policy',
        'This relationship matches names, which product mode refuses',
        'Its fedSubjectPolicy is any-existing: it would sign in whichever ' +
        'local person has the name the partner sent. Product mode refuses ' +
        'that — OpenID Connect Core section 5.7 makes the issuer and the ' +
        'subject, not a name, the identifier a relying party may rely on. ' +
        'Set the relationship to link-at-first-sign-in, pre-linked or ' +
        'jit-namespaced.');
    }
    const stable = links.stableSubjectOf(record, result);
    const provisioning = this.autocreateOn(record);
    let target = '';
    let how = '';
    let create = false;
    if (stable.ok) {
      const holders = federation.peopleLinkedBy(stable.value);
      if (holders.length > 1) {
        log.debug("Leaving FederationSp.subjectDecision(). Ambiguous.");
        return this.subjectRefusal('STS-FED-0097', 'link',
          'The partner\'s subject is linked to more than one person',
          'The link ' + stable.value + ' is carried by ' +
          holders.map(function (one) { return one.username; }).join(', ') +
          '. A link names one person; remove it from all but one of them ' +
          '(the console\'s person page, POST /admin-api/users/' +
          'federation-unlink or SCIM).');
      }
      if (holders.length === 1) {
        target = holders[0].username;
        how = 'linked';
      }
    }
    if (!target) {
      if (!stable.ok && policy !== 'any-existing') {
        log.debug("Leaving FederationSp.subjectDecision(). Not linkable.");
        return this.subjectRefusal('STS-FED-0096', 'subject',
          'The partner sent no identifier this service can link', 'The ' +
          'assertion verified, but ' + stable.why + '.');
      }
      if (policy === 'pre-linked') {
        log.debug("Leaving FederationSp.subjectDecision(). Not linked.");
        return this.subjectRefusal('STS-FED-0091', 'pre-linked',
          'This person is not linked to the partner',
          'This relationship signs in only people linked to the partner ' +
          'beforehand (fedSubjectPolicy pre-linked), and nobody here carries ' +
          'a link for ' + stable.subject + ' from ' + stable.issuer + '. An ' +
          'administrator links them on their /admin/users page, through ' +
          'POST /admin-api/users/federation-link, or through SCIM.');
      }
      const named = federation.federatedPerson(mapped.username);
      if (policy === 'any-existing') {
        target = mapped.username;
        how = named ? 'matched' : 'created';
        create = !named && provisioning;
      } else if (policy === 'link-at-first-sign-in' && named) {
        target = named.username;
        how = 'confirm';
      } else {
        const namespaced = links.provisionedName(record.fedId,
                                                 stable.subject);
        if (!links.subjectLocalName(stable.subject) ||
            !links.nameFitsDirectory(namespaced)) {
          log.debug("Leaving FederationSp.subjectDecision(). The name " +
                    "cannot be a directory entry.");
          return this.subjectRefusal('STS-FED-0090', 'namespace',
            'This person has not been provisioned',
            'A new entry for this subject would be called ' + namespaced +
            ', and that name cannot be a directory entry here: it is ' +
            'empty, or it carries a character RFC 4514 reserves in a DN. ' +
            'The person has to be created here first and linked to the ' +
            'partner\'s subject.');
        }
        if (federation.federatedPerson(namespaced)) {
          log.debug("Leaving FederationSp.subjectDecision(). The namespaced " +
                    "name is taken.");
          return this.subjectRefusal('STS-FED-0098', 'namespace',
            'The name for this person is already taken',
            'A new entry for this subject would be called ' + namespaced +
            ', and an entry of that name already exists without a link to ' +
            'it. Link that entry to the subject, or remove it.');
        }
        target = namespaced;
        how = 'created';
        create = provisioning;
      }
    }
    const person = federation.federatedPerson(target);
    // THE PARTNER STOPPED VOUCHING FOR THIS PERSON (#373): a verified
    // account-disabled from its own Shared Signals blocks its sign-ins of
    // them, and only its — before any rule, because nothing else this
    // partner says about the person can outweigh the partner saying stop.
    const stopped = fedBlocks.blockOf(record.fedId,
                                      person ? person.username : target);
    if (stopped) {
      log.debug("Leaving FederationSp.subjectDecision(). Blocked.");
      return this.subjectRefusal('STS-FED-0156', 'blocked',
        'The partner has stopped vouching for this person',
        'A verified ' + (stopped.event || 'account-disabled') + ' event ' +
        'from this partner\'s Shared Signals (at ' +
        new Date(Number(stopped.at) || 0).toISOString() + ') blocks its ' +
        'sign-ins of ' + stopped.username + '. Its account-enabled lifts ' +
        'that, and so can an administrator on the relationship\'s page. ' +
        'Signing in here another way is unaffected.');
    }
    const rules = this.subjectRules(record, mapped, target, person);
    if (!rules.ok) {
      log.debug("Leaving FederationSp.subjectDecision(). A rule refused.");
      return rules;
    }
    // THE RELATIONSHIP'S OWN CEILING (#358), after the rules, and only for
    // a person this sign-in would create. A linked person already signed
    // in above. Empty or 0 is unlimited; `ldap.maxEntries` is still the
    // realm's.
    if (!person && create) {
      const cap = federation.provisionCapOf(record);
      if (cap > 0 && federation.provisionedCount(record.fedId) >= cap) {
        log.debug("Leaving FederationSp.subjectDecision(). The cap.");
        return this.subjectRefusal('STS-FED-0090', 'cap',
          'This person has not been provisioned',
          'This relationship may create ' + cap + ' people ' +
          '(fedProvisionCap), and it already has that many. A person ' +
          'already linked still signs in. Raise the cap, or create and ' +
          'link this person here.');
      }
    }
    log.debug("Leaving FederationSp.subjectDecision(). " + how + " " +
              target + ".");
    return { ok: true, policy: policy, how: how,
             username: person ? person.username : target,
             link: stable.ok ? stable.value : '',
             subject: stable.subject, issuer: stable.issuer,
             create: !person && create, confirm: how === 'confirm' };
  }

  // Whether this relationship creates an entry for an unlinked subject.
  // A stored TRUE or FALSE wins. A missing value is development's on and
  // product's off (`mode.defaultsFederatedAutocreate()`), never a literal.
  private autocreateOn(record): boolean {
    const { federation, mode, log } = this.deps;
    log.debug("Entering FederationSp.autocreateOn().");
    const on = federation.boolOf(record && record.fedAutocreateUsers,
      mode.defaultsFederatedAutocreate());
    log.debug("Leaving FederationSp.autocreateOn().");
    return on;
  }

  // The claim names a partner's group list may arrive under. The WS-Federation
  // role claim is not one of them: it maps to employeeType and authorizes
  // nothing. `groups.claimName` is this realm's own name for the same list.
  private groupNamesOf(mapped): string[] {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.groupNamesOf().");
    const flat = (mapped && mapped.flat) || {};
    const wanted = [
      String(config.value('groups.claimName') || ''),
      'groups',
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
      'http://schemas.xmlsoap.org/claims/Group'
    ].map(function (one: string): string {
      return one.trim().toLowerCase();
    }).filter(Boolean);
    const seen: Record<string, boolean> = {};
    const names: string[] = [];
    Object.keys(flat).forEach(function (key: string): void {
      if (wanted.indexOf(String(key).toLowerCase()) < 0) {
        return;
      }
      const values = Array.isArray(flat[key]) ? flat[key] : [flat[key]];
      values.forEach(function (value: unknown): void {
        const name = String(value == null ? '' : value).trim();
        const fold = name.toLowerCase();
        if (!name || seen[fold]) {
          return;
        }
        seen[fold] = true;
        names.push(name);
      });
    });
    log.debug("Leaving FederationSp.groupNamesOf(). " + names.length);
    return names;
  }

  // Memberships from the partner's token, when fedProvisionGroups is on.
  // A name that collides with a group this relationship did not create is
  // ignored and audited; the sign-in already happened and is not undone.
  // One array element is one group name. memberOf is never written.
  private provisionGroups(record, username, mapped, decision): void {
    const { federation, audit, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.provisionGroups().");
    if (!federation.boolOf(record.fedProvisionGroups, false)) {
      log.debug("Leaving FederationSp.provisionGroups(). Off.");
      return;
    }
    const names = this.groupNamesOf(mapped);
    let applied: any = null;
    try {
      applied = federation.applyFederatedGroups(record.fedId, username,
                                                names);
    } catch (e) {
      log.debug("Caught in FederationSp.provisionGroups(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-FED-0161') + 'federation: ' +
               record.fedId + ' could not apply group memberships for ' +
               username + ': ' + ((e && e.message) || e) +
               '. The sign-in stands.');
      log.debug("Leaving FederationSp.provisionGroups(). Threw.");
      return;
    }
    const ignored = (applied && applied.ignored) || [];
    const subject = String((decision && decision.subject) || '');
    ignored.forEach(function (one: any): void {
      const group = String((one && one.name) || '');
      const why = String((one && one.reason) || '');
      // A group that grants something by being held (#358) is its own
      // code: it is a partner reaching for authority, not a name collision.
      const granting = why === 'grants';
      const code = granting ? 'STS-FED-0164' : 'STS-FED-0161';
      const because = granting
        ? 'it grants something by being held: ' +
          String((one && one.detail) || '')
        : why;
      log.warn(errorCodes.tag(code) + 'federation: ' +
               record.fedId + ' did not add ' + username + ' to "' +
               group + '" (' + because + '). The sign-in stands.');
      audit.audit({
        action: 'federation.group-ignored',
        actor: 'federation:' + record.fedId,
        channel: 'internal',
        protocol: 'Federation',
        target: username,
        outcome: 'refused',
        errorCode: granting ? 'STS-FED-0164' : 'STS-FED-0161',
        summary: username + ' was not added to the group "' + group +
                 '" through ' + record.fedId + ' (' + because + ')',
        detail: { relationship: String(record.fedId),
                  username: String(username), subject: subject,
                  group: group, reason: why }
      });
    });
    log.debug("Leaving FederationSp.provisionGroups(). " +
              ((applied && applied.joined) || []).length + " joined, " +
              ignored.length + " ignored.");
  }

  // A refusal in subjectDecision()'s shape. `rule` names what refused, for the
  // audit row.
  // error-code: none — the helper's own shape; every caller passes its code
  private subjectRefusal(code, rule, what, why): any {
    const { log } = this.deps;
    log.debug("Entering FederationSp.subjectRefusal(). " + code);
    log.debug("Leaving FederationSp.subjectRefusal().");
    return { ok: false, code: code, status: 403, rule: rule, what: what,
             why: why };
  }

  // ---------------------------------------------------------------------------
  // THE RULES ON TOP OF EVERY POLICY, and the refusal of an administrator.
  //
  // `person` is the entry the sign-in would land on, or null for one it would
  // create — which is in no group, has no mail of its own yet and is nobody's
  // administrator, so each rule reads that case for itself.
  // ---------------------------------------------------------------------------
  private subjectRules(record, mapped, target, person): any {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSp.subjectRules(). target=" + target);
    if (person && !federation.boolOf(record.fedMayAssertAdministrators,
                                     false)) {
      const administrator = this.administratorRole(person.username);
      if (administrator) {
        log.debug("Leaving FederationSp.subjectRules(). An administrator.");
        return this.subjectRefusal('STS-FED-0093', 'administrator',
          'A partner may not sign in an administrator',
          person.username + ' holds ' + administrator + ', and this ' +
          'relationship does not allow its partner to sign in a console ' +
          'administrator (fedMayAssertAdministrators is off, the default). ' +
          'That holds whatever else is true, a valid link included: a ' +
          'partner\'s signing key must not be a key to this console. ' +
          'Sign in here instead.');
      }
    }
    const groups = (record.fedSubjectGroup || []).map(function (one) {
      return String(one || '').trim();
    }).filter(Boolean);
    if (groups.length) {
      const member = !!person && person.groups.some((group) => {
        return groups.some((wanted) => {
          return wanted.toLowerCase() === String(group.cn || '')
                   .toLowerCase() ||
                 this.dnKey(wanted) === this.dnKey(group.dn);
        });
      });
      if (!member) {
        log.debug("Leaving FederationSp.subjectRules(). Not in the group.");
        return this.subjectRefusal('STS-FED-0092', 'group',
          'This person is outside what the partner may assert',
          (person ? person.username + ' is in none of' :
                    'A new entry would be in none of') + ' the groups this ' +
          'relationship requires (fedSubjectGroup: ' + groups.join(', ') +
          ')' + (person ? '.' : ', so this relationship creates nobody.'));
      }
    }
    const domains = (record.fedSubjectDomain || []).map(function (one) {
      return String(one || '').trim().replace(/^@+/, '').toLowerCase();
    }).filter(Boolean);
    if (domains.length) {
      const sent = this.sentMail(mapped);
      const local = person && person.mail.length ? String(person.mail[0]) : '';
      const sentOk = !!sent && domains.indexOf(this.domainOf(sent)) >= 0;
      const localOk = !local || domains.indexOf(this.domainOf(local)) >= 0;
      if (!sentOk || !localOk) {
        log.debug("Leaving FederationSp.subjectRules(). Outside the domain.");
        return this.subjectRefusal('STS-FED-0092', 'domain',
          'This person is outside what the partner may assert',
          (!sentOk
            ? 'The partner sent ' + (sent ? 'the address ' + sent
                                          : 'no mail address') + ', and'
            : 'The local entry\'s address is ' + local + ', and') +
          ' this relationship admits only ' + domains.join(', ') +
          ' (fedSubjectDomain).');
      }
    }
    const pattern = String(record.fedSubjectPattern || '');
    if (pattern) {
      const dn = person ? person.dn : federation.plannedPersonDn(target);
      if (!federation.subjectPatternMatches(pattern, dn)) {
        log.debug("Leaving FederationSp.subjectRules(). Outside the " +
                  "pattern.");
        return this.subjectRefusal('STS-FED-0092', 'pattern',
          'This person is outside what the partner may assert',
          'The entry ' + (person ? '' : 'this sign-in would create ') + 'is ' +
          (dn || '(nowhere)') + ', which does not match this ' +
          'relationship\'s fedSubjectPattern as a whole.');
      }
    }
    log.debug("Leaving FederationSp.subjectRules(). Allowed.");
    return { ok: true };
  }

  // What makes somebody an administrator a partner may not assert: a place
  // on the realm's console roster (Admin Read or Admin Write) or REMOTE_PEPS,
  // which hands out the policies this service enforces its own access with.
  // '' for nobody. The roster is the one of the realm the sign-in is in.
  private administratorRole(username) {
    const { rbac, roles, realms, log } = this.deps;
    log.debug("Entering FederationSp.administratorRole().");
    const roster = rbac.rolesOf(username, realms.currentId());
    if (roster && roster.groups && roster.groups.length) {
      log.debug("Leaving FederationSp.administratorRole(). The roster.");
      return 'a place on the console roster (' +
             roster.groups.map(function (one) { return one.role; })
               .join(', ') + ')';
    }
    const held = roles.rolesOf({ kind: 'user', name: username,
                                 authenticated: true }) || [];
    if (held.indexOf('REMOTE_PEPS') >= 0) {
      log.debug("Leaving FederationSp.administratorRole(). REMOTE_PEPS.");
      return 'the REMOTE_PEPS role';
    }
    log.debug("Leaving FederationSp.administratorRole(). Nobody.");
    return '';
  }

  // A DN compared the way this directory compares one, near enough for a
  // rule an administrator typed: case and the spaces around `,` and `=`.
  private dnKey(dn) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.dnKey().");
    log.debug("Leaving FederationSp.dnKey().");
    return String(dn || '').trim().toLowerCase()
      .replace(/\s*([,=])\s*/g, '$1');
  }

  // The address the partner SENT: the mapped `mail`, or the mapped username
  // where it is one.
  private sentMail(mapped) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.sentMail().");
    const attributes = mapped.attributes || {};
    let mail = '';
    Object.keys(attributes).forEach(function (name) {
      if (!mail && name.toLowerCase() === 'mail') {
        const values = [].concat(attributes[name] || []);
        mail = String(values[0] || '');
      }
    });
    if (!mail && String(mapped.username || '').indexOf('@') > 0) {
      mail = String(mapped.username);
    }
    log.debug("Leaving FederationSp.sentMail().");
    return mail;
  }

  private domainOf(address) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.domainOf().");
    const text = String(address || '');
    log.debug("Leaving FederationSp.domainOf().");
    return text.slice(text.lastIndexOf('@') + 1).trim().toLowerCase();
  }

  // ---------------------------------------------------------------------------
  // A REFUSED SUBJECT: the refusal page, 403, the code, and an audit row
  // naming the relationship, the subject and the rule — and NOTHING written
  // on any entry, which is the point of refusing here rather than after the
  // session.
  // ---------------------------------------------------------------------------
  private refuseSubject(res, record, result, mapped, decision) {
    const { audit, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.refuseSubject(). " + decision.code);
    audit.failure(decision.code, {
      protocol: 'Federation', channel: 'http', target: record.fedId,
      summary: 'a federated sign-in through ' + record.fedId + ' for the ' +
               'subject ' + String(result.subject || '') + ' (' +
               String(mapped.username || '') + ') was refused by the ' +
               decision.rule + ' rule: ' + decision.what,
      // error-code: none — decision.code, named where subjectDecision() refused
      outcome: 'refused',
      detail: { relationship: record.fedId, rule: decision.rule,
                subject: String(result.subject || ''),
                issuer: String(result.issuer || record.fedPeer || ''),
                username: String(mapped.username || '') }
    });
    log.info('federation: ' + record.fedId + ' asserted ' +
             String(mapped.username || '') + ' and the ' + decision.rule +
             ' rule refused it (' + decision.code + ').');
    errorCodes.mark(res, decision.code);
    log.debug("Leaving FederationSp.refuseSubject().");
    // error-code: none — marked on the line above, from subjectDecision()
    return this.refuse(res, record, decision.status || 403, decision.what,
                       decision.why);
  }

  // ---------------------------------------------------------------------------
  // LINK AT FIRST SIGN-IN: THE LOCAL SIGN-IN FIRST (#109).
  //
  // The partner named an existing person and nothing links its subject to
  // them. A name is not an identifier (OpenID Connect Core section 5.7), so
  // the person proves they ARE that local person the way anybody does here —
  // the sign-in screen, with the username fixed to theirs: a password, and a
  // second factor wherever one is held or required, exactly as a local
  // sign-in asks (`authn.ts`'s `finishPasswordSignIn()`). Nothing is written
  // until that comes back: the verified response is held in the request
  // context store under a single-use handle, and `/federation/link/{handle}`
  // is where the local sign-in returns — through `beginAuthentication()`'s
  // pending record, so the return address is server-side (decision 3).
  // ---------------------------------------------------------------------------
  private beginLinking(req, res, record, result, decision) {
    const { authn, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.beginLinking(). " + decision.username);
    const { config, randomId } = this.deps;
    const binding = randomId(24);
    const handle = this.putContext({
      kind: 'link', id: record.fedId, username: decision.username,
      link: decision.link, linkStartedAt: Date.now(),
      bindingHash: this.bindingHashOf(binding),
      // The verified response, whole enough to finish the sign-in with:
      // what completeSignIn() was handed, and nothing a partner can change.
      result: {
        subject: result.subject, issuer: result.issuer || '',
        nameFormat: result.nameFormat || '', bag: result.bag || {},
        amr: result.amr || [], acr: result.acr || '',
        returnTo: result.returnTo || '', application: result.application || '',
        // THE PARTNER'S SESSION (#167), carried across the linking sign-in so
        // the federated session it starts can be ended by the partner too.
        nameQualifier: result.nameQualifier || '',
        spNameQualifier: result.spNameQualifier || '',
        sessionIndex: result.sessionIndex || '',
        sessionNotOnOrAfter: Number(result.sessionNotOnOrAfter) || 0,
        sid: result.sid || '', idToken: result.idToken || ''
      }
    });
    let target = '';
    try {
      target = authn.beginAuthentication({
        returnTo: LINK_PATH + '/' + encodeURIComponent(handle),
        protocol: LINK_VIA,
        lockedUsername: decision.username,
        application: '',
        details: [
          { label: 'Linking', value: (record.fedName || record.fedId) + ' (' +
                                     (record.fedPeer || record.fedId) + ')',
            note: 'sign in as ' + decision.username + ' to link the ' +
                  'partner\'s account to it' }
        ]
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-FED-0042') + 'federation: the local ' +
                'sign-in to link ' + decision.username + ' through ' +
                record.fedId + ' could not be started: ' + e.message);
      errorCodes.mark(res, 'STS-FED-0042');
      log.debug("Leaving FederationSp.beginLinking(). Threw.");
      return this.refuse(res, record, 500, 'This service failed while ' +
                                           'starting the linking sign-in',
                         e.message);
    }
    log.info('federation: ' + record.fedId + ' asserted ' + decision.username +
             ', whose account is not linked to the partner; they are asked ' +
             'to sign in here first (link-at-first-sign-in).');
    res.append('Set-Cookie', LINK_COOKIE + '=' + binding + '; Path=/; ' +
               'HttpOnly; SameSite=Lax; Max-Age=' +
               Math.max(60, Math.floor(this.contextTtlMs() / 1000)) +
               (config.value('global.https') ? '; Secure' : ''));
    res.set('Cache-Control', 'no-store');
    res.redirect(303, target);
    log.debug("Leaving FederationSp.beginLinking(). Sent to " + target + ".");
  }

  // ---------------------------------------------------------------------------
  // GET /federation/link/{handle} — WHERE THE LINKING SIGN-IN RETURNS.
  //
  // Five things must be true, in this order, before anything is written:
  //   1. the handle is one this service minted for a link, unspent and
  //      unexpired — it is spent now, whatever happens next;
  //   1a. this is the BROWSER the partner's response arrived in: LINK_COOKIE,
  //      whose hash is on the context (STS-FED-0111) — see its header;
  //   2. the sign-in screen did not answer with an error: a Cancel, or a
  //      refusal it could not recover from (STS-FED-0099);
  //   3. the browser holds a session whose MOST RECENT authentication is a
  //      LOCAL one, made through the linking screen (`LINK_VIA`), as the
  //      person being linked, after the partner's response arrived — not
  //      whatever session the browser happened to be on (STS-FED-0101);
  //   4. the subject decision, asked AGAIN, still names that person: the
  //      policy, a link made meanwhile, the rules and the administrator
  //      refusal can all have changed while the person was typing.
  // Then finishSignIn(), which records the link, writes the partner's
  // attributes and starts the federated session — in that funnel, in that
  // order.
  // ---------------------------------------------------------------------------
  private linkEndpoint(req, res) {
    const { federation, fedMap, authn, errorCodes, audit, log } = this.deps;
    log.debug("Entering the federation linking endpoint.");
    // A PAGE OF THE FEDERATION SURFACE (#580): every refusal below, and the
    // signed-in page where nothing asked to be returned to, is the shell.
    FederationPages.mark(res);
    if (!this.enabled()) {
      errorCodes.mark(res, 'STS-FED-0001');
      FederationPages.send(res, 404, FederationPages.notHereView('off'));
      log.debug("Leaving the federation linking endpoint. Federation is off.");
      return;
    }
    const handle = String(req.params.handle || '');
    const context = /^fed-[A-Za-z0-9_-]{1,64}$/.test(handle)
      ? this.takeContext(handle) : null;
    if (!context || context.kind !== 'link') {
      errorCodes.mark(res, 'STS-FED-0100');
      log.debug("Leaving the federation linking endpoint. No such link.");
      return this.refuse(res, null, 400, 'There is no link waiting',
        'The linking step "' + handle + '" is not one this service started, ' +
        'it has already been used, or it expired (federation.requestTtlMin). ' +
        'Start the federated sign-in again.');
    }
    const record = federation.get(context.id);
    if (!record || record.fedRole !== 'service-provider' ||
        !federation.signsIn(record) || !federation.isUsable(record)) {
      errorCodes.mark(res, record && federation.isEnabled(record)
        ? 'STS-FED-0006' : 'STS-FED-0005');
      log.debug("Leaving the federation linking endpoint. The relationship " +
                "is not usable now.");
      return this.refuse(res, record || null, 403, 'That relationship is ' +
                                                   'not usable',
        'The relationship "' + context.id + '" is disabled, ' +
        'half-configured or gone since the partner answered.');
    }
    // THE BROWSER THAT STARTED IT (see LINK_COOKIE), asked before anything
    // else about the person, and the cookie is spent whatever follows.
    const presented = String(authn.cookiesOf(req)[LINK_COOKIE] || '');
    res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
               'SameSite=Lax; Max-Age=0');
    if (!presented || !this.sameBinding(this.bindingHashOf(presented),
                                        String(context.bindingHash || ''))) {
      errorCodes.mark(res, 'STS-FED-0111');
      log.debug("Leaving the federation linking endpoint. Another browser.");
      return this.refuse(res, record, 403, 'The account was not linked',
        'This linking step was started in a different browser, or the ' +
        'cookie that ties it to the one it began in is gone. Nothing was ' +
        'linked. Start the federated sign-in again, in one browser.');
    }
    const asked = String((req.query || {}).authn_error || '');
    if (asked) {
      audit.failure('STS-FED-0099', {
        protocol: 'Federation', channel: 'http', target: record.fedId,
        summary: 'linking ' + context.username + ' to the partner of ' +
                 record.fedId + ' ended without a local sign-in (' + asked +
                 '); nothing was linked or written',
        outcome: 'refused',
        detail: { relationship: record.fedId, username: context.username,
                  subject: String(context.result.subject || ''),
                  rule: 'link-at-first-sign-in', error: asked }
      });
      errorCodes.mark(res, 'STS-FED-0099');
      log.debug("Leaving the federation linking endpoint. The local sign-in " +
                "did not happen.");
      return this.refuse(res, record, 403, 'The account was not linked',
        'Linking your account at the partner to ' + context.username + ' ' +
        'needs you to sign in here as ' + context.username + ' first, and ' +
        'that sign-in ended without one (' + asked + '). Nothing was linked ' +
        'and nothing was written.');
    }
    const session = authn.sessionOf(req);
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const latest = events.length ? events[events.length - 1] : null;
    const fresh = !!session && !!latest &&
      String((session.user && session.user.username) || '').toLowerCase() ===
        String(context.username).toLowerCase() &&
      latest.via === LINK_VIA && latest.authenticated !== false &&
      ((latest.authority || {}).kind || 'local') === 'local' &&
      Number(latest.at || 0) * 1000 >= Number(context.linkStartedAt || 0) -
                                       1000;
    if (!fresh) {
      errorCodes.mark(res, 'STS-FED-0101');
      log.debug("Leaving the federation linking endpoint. No fresh local " +
                "sign-in as " + context.username + ".");
      return this.refuse(res, record, 403, 'The account was not linked',
        'This step needs a sign-in here as ' + context.username + ', made ' +
        'through the linking screen just now, and this browser holds ' +
        (session ? 'a different one' : 'none') + '. Nothing was linked. ' +
        'Start the federated sign-in again.');
    }
    const mapped = fedMap.mapIncoming(record, context.result.bag,
                                      context.result.subject);
    const decision = this.subjectDecision(record, context.result, mapped);
    if (!decision.ok) {
      log.debug("Leaving the federation linking endpoint. The subject is " +
                "refused now.");
      return this.refuseSubject(res, record, context.result, mapped, decision);
    }
    if (String(decision.username).toLowerCase() !==
        String(context.username).toLowerCase() ||
        (decision.how !== 'confirm' && decision.how !== 'linked')) {
      errorCodes.mark(res, 'STS-FED-0101');
      log.debug("Leaving the federation linking endpoint. The subject now " +
                "names somebody else.");
      return this.refuse(res, record, 403, 'The account was not linked',
        'While you were signing in, the partner\'s subject came to name ' +
        (decision.username || 'somebody else') + ' rather than ' +
        context.username + '. Nothing was linked. Start the federated ' +
        'sign-in again.');
    }
    log.debug("Leaving the federation linking endpoint. Linking " +
              context.username + ".");
    return this.finishSignIn(req, res, record, context.result, mapped,
                             Object.assign({}, decision, {
                               how: 'confirmed', create: false,
                               link: context.link || decision.link }));
  }

  // ---------------------------------------------------------------------------
  // SIGN IN WITH APPLE'S CLIENT SECRET (#565, `apple-client-secret`): an ES256
  // JWT — `iss` the team id, `sub` the client id (the Services ID), `aud`
  // Apple's issuer, `kid` the key id — signed through `common/crypto.js` with
  // the relationship's sealed key, minted per token request and living five
  // minutes. Answers '' where anything it needs is missing or will not sign.
  // ---------------------------------------------------------------------------
  appleClientSecret(record) {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSp.appleClientSecret().");
    const key = federation.clientSigningKeyOf(record);
    const team = String(record.fedTeamId || '').trim();
    const kid = String(record.fedKeyId || '').trim();
    const client = String(record.fedClientId || '').trim();
    if (!key || !team || !kid || !client) {
      log.debug("Leaving FederationSp.appleClientSecret(). Incomplete.");
      return '';
    }
    try {
      const now = Math.floor(Date.now() / 1000);
      // certificate-header: none — signed with the key Apple issued for the
      // Services ID (fedClientSigningKey), which no certificate of this
      // service covers; Apple finds it by kid, and an x5c would be refused.
      const jws = stsCrypto.signJws({ iss: team, sub: client,
        aud: 'https://appleid.apple.com', iat: now, exp: now + 300 },
        key, { algorithm: 'ES256', keyid: kid });
      log.debug("Leaving FederationSp.appleClientSecret(). Signed.");
      return String(jws);
    } catch (e) {
      log.debug("Caught in FederationSp.appleClientSecret(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-FED-0185') + 'federation: the Apple ' +
               'client secret of ' + record.fedId + ' could not be signed: ' +
               ((e && e.message) || e));
      return '';
    }
  }

  // ---------------------------------------------------------------------------
  // POST /federation/notifications/{id} — SIGN IN WITH APPLE'S SERVER-TO-SERVER
  // NOTIFICATIONS (#565, `apple-notifications`). Apple POSTs `{ payload }`, a
  // JWT it signs with the keys at fedJwksUri, `iss` its issuer, `aud` this
  // relationship's client id, carrying `events` — a JSON string naming the
  // `type` and the person's `sub`.
  //
  // It is verified exactly as an ID Token from this relationship is, by
  // verifyForeignJwt() against the relationship's keys and nothing else,
  // and it is accepted once ever (the used-assertion history). What it MEANS
  // is the partner's own statement about its sign-ins, so it is answered the
  // way a partner's `account-disabled` is (#373) — about this relationship,
  // never about the person's other ways in:
  //   * `consent-revoked` and `account-delete`: the person stopped using
  //     Sign in with Apple with this service, or deleted their Apple account.
  //     Their link through this relationship is REMOVED, which the directory's
  //     write hook answers by ending every session it started
  //     (`linksRemoved()`). Their entry stays: it is this service's.
  //   * `email-disabled` and `email-enabled`: the private relay address
  //     stopped or started forwarding. Recorded, and nothing changes: the
  //     address is still the person's.
  // Answers 200 for a verified notification whatever it led to, 400 for one
  // that does not verify (STS-FED-0186), and 404 for a relationship that
  // takes none (STS-FED-0187).
  // ---------------------------------------------------------------------------
  private notificationsEndpoint(req, res) {
    const { federation, audit, errorCodes, parseBody, log } = this.deps;
    log.debug("Entering the federation notifications endpoint.");
    const record = federation.get(String(req.params.id || ''));
    if (!this.enabled() || !record || record.fedRole !== 'service-provider' ||
        !consumerProviders.adapts(record, 'apple-notifications') ||
        !federation.isUsable(record)) {
      errorCodes.mark(res, 'STS-FED-0187');
      log.debug("Leaving the federation notifications endpoint. Not here.");
      return res.status(404).json({ error: 'not_found' });
    }
    const body = parseBody(req) || {};
    const token = String(body.payload || '');
    log.debug("Leaving the federation notifications endpoint. Verifying.");
    return this.keysFor(record).then((keySet) => {
      log.debug("Entering the notification's verification.");
      const verified: any = keySet.ok && token
        ? this.verifyForeignJwt(token, record, keySet.keys, {
          issuer: consumerProviders.issuersFor(record),
          audience: String(record.fedClientId || '') || undefined })
        : { ok: false, why: keySet.ok ? 'no payload' : keySet.why };
      let event: any = null;
      try {
        event = verified.ok
          ? JSON.parse(String(verified.payload.events || '{}')) : null;
      } catch (e) {
        log.debug("Caught in the notification's verification: " +
                  ((e && e.message) || e));
        event = null;
      }
      const refused = (why: string) => {
        log.debug("Entering refused().");
        errorCodes.mark(res, 'STS-FED-0186');
        audit.failure('STS-FED-0186', {
          protocol: 'Federation', channel: 'http', target: record.fedId,
          summary: 'a notification for ' + record.fedId + ' was refused: ' +
                   why, outcome: 'refused' });
        log.debug("Leaving refused().");
        return res.status(400).json({ error: 'invalid_request' });
      };
      const jti = String((verified.payload || {}).jti || '');
      if (!verified.ok || !event || !event.type || !event.sub || !jti) {
        log.debug("Leaving the notification's verification. Refused.");
        return refused(verified.ok ? 'it carries no event or no jti'
                                   : String(verified.why ||
                                            'it did not verify'));
      }
      // FRESH, AS WELL AS ONCE. The history below holds a jti only until
      // the notification's own end, and Apple's carries `iat` and no `exp`:
      // an end invented from the moment of acceptance would let a captured
      // notification be accepted AGAIN once its row was purged. So a
      // notification with no `exp` is bounded by its `iat` — issued within
      // NOTIFICATION_MAX_AGE_S, and not in the future past the clock skew —
      // and its row lives exactly as long as it could be accepted.
      const nowS = Math.floor(Date.now() / 1000);
      const skew = Number(this.deps.config.value('oauth2.clockSkewS')) || 0;
      const exp = Number(verified.payload.exp) || 0;
      const iat = Number(verified.payload.iat) || 0;
      if (!exp && (!iat || iat > nowS + skew ||
                   nowS - iat > NOTIFICATION_MAX_AGE_S + skew)) {
        log.debug("Leaving the notification's verification. Not fresh.");
        return refused(iat ? 'it was issued at ' + iat + ', outside the ' +
                             NOTIFICATION_MAX_AGE_S + ' seconds a ' +
                             'notification with no exp is accepted for'
                           : 'it carries neither exp nor iat');
      }
      // ONCE EVER (rule 3ae): a replayed `consent-revoked` would undo a
      // connection the person made again since.
      // BOUND TO THE RESPONSE (#727): a 2xx spends it, anything else releases
      // it, so a notification a peer cell could not be reached for is
      // refused 503 and accepted when the provider sends it again.
      return usedAssertions.claim({ format: 'jwt',
        use: 'provider-notification', issuer: String(record.fedPeer),
        identifier: jti, request: req,
        expiresAt: (exp || iat + NOTIFICATION_MAX_AGE_S + skew) * 1000
      }).then((claimed: any) => {
        log.debug("Entering the notification's claim.");
        if (!claimed.ok) {
          log.debug("Leaving the notification's claim. Refused.");
          return refused(claimed.reason === 'replay'
            ? 'it was already accepted once' : 'the replay history could ' +
              'not prove it unused (' + claimed.reason + ')');
        }
        log.debug("Leaving the notification's claim.");
        return this.applyNotification(res, record, event, req);
      });
    });
  }

  // ---------------------------------------------------------------------------
  // WHAT A VERIFIED PROVIDER NOTIFICATION LEADS TO (#565), IN EVERY CELL (#727).
  // The cell it arrives at removes the links it holds — unlinkHere() — and,
  // in a service deployed as cells, asks every peer to do the same
  // (`PEER_NOTIFICATION_OP`, the partner sign-out's shape: `endAtPeers()` in
  // `federation_slo.ts`), because the person may be homed anywhere and the
  // notification names a subject, not a cell. The match is the relationship
  // and the subject, as data; each cell builds the one link value from them.
  //
  // A PEER THAT CANNOT BE REACHED (STS-CELL-0211) makes the answer 503: the
  // notification's once-ever claim is bound to the response, so it is
  // RELEASED, and the provider's retry is accepted and fanned out again.
  // Removing a link is idempotent, so the cells that did act act again on the
  // retry and change nothing. A 2xx means every cell holding the subject was
  // asked and answered.
  // ---------------------------------------------------------------------------
  private applyNotification(res, record, event, req?) {
    const { audit, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.applyNotification().");
    const type = String(event.type);
    const sub = String(event.sub);
    const here = this.unlinkHere(record, type, sub);
    log.debug("Leaving FederationSp.applyNotification(). Asking the peers.");
    return this.notifyPeers(record, type, sub).then((peers) => {
      log.debug("Entering the notification's fan-out answer.");
      const people = here.people + peers.people;
      const unlinked = here.unlinked + peers.unlinked;
      audit.record({ category: 'federation',
        action: 'federation.provider-notification', target: record.fedId,
        outcome: peers.failed ? 'partial' : 'success',
        summary: record.fedId + ' notified ' + type + ' for a subject held ' +
                 'by ' + people + ' person(s); ' + unlinked +
                 ' link(s) removed' + (peers.failed ? '; ' + peers.failed +
                 ' cell(s) could not be asked, so the notification was not ' +
                 'accepted and the provider may send it again' : '') +
                 ' (#565, #727)',
        detail: { relationship: record.fedId, type: type, people: people,
                  unlinked: unlinked, cellsUnreached: peers.failed } });
      if (peers.failed) {
        errorCodes.mark(res, 'STS-CELL-0211');
        log.debug("Leaving the notification's fan-out answer. Partial.");
        return res.status(503).set('Retry-After', '60')
                  .json({ error: 'temporarily_unavailable' });
      }
      void req;
      log.debug("Leaving the notification's fan-out answer. " + type + ".");
      return res.status(200).json({ ok: true });
    });
  }

  // THIS CELL'S PART OF A NOTIFICATION (#565, #727): the people here holding
  // the subject's link through the relationship, and — for a type that
  // removes one — the links removed, each through the directory's write hook,
  // which ends the sessions it started. Never the entry. `{ people, unlinked }`.
  unlinkHere(record, type, sub) {
    const { federation, links, log } = this.deps;
    log.debug("Entering FederationSp.unlinkHere(). " + type);
    const value = links.linkValue(record.fedId, record.fedPeer, String(sub));
    const holders = federation.peopleLinkedBy(value) || [];
    let unlinked = 0;
    if (UNLINKING_NOTIFICATIONS.indexOf(String(type)) >= 0) {
      holders.forEach(function (one: any): void {
        const written = federation.writeFederationLink(
          String(one.username || one.uid || ''), value, false, {});
        if (written && written.ok !== false) {
          unlinked += 1;
        }
      });
    }
    log.debug("Leaving FederationSp.unlinkHere(). " + unlinked + " of " +
              holders.length + ".");
    return { people: holders.length, unlinked: unlinked };
  }

  // EVERY PEER CELL'S PART (#727). `{ people, unlinked, failed }`; never
  // rejects. Nothing is asked in single-cell mode.
  private notifyPeers(record, type, sub): Promise<{ people: number;
                                                     unlinked: number;
                                                     failed: number }> {
    const { errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.notifyPeers().");
    if (!cells.isMulti()) {
      log.debug("Leaving FederationSp.notifyPeers(). Single-cell.");
      return Promise.resolve({ people: 0, unlinked: 0, failed: 0 });
    }
    const channel = require('./../common/cell_channel');
    const body = { realm: realms.currentId(), relationship: record.fedId,
                   type: String(type), sub: String(sub) };
    const asks = cells.peers().map(function (peer: any) {
      return channel.call(peer.id, PEER_NOTIFICATION_OP, body)
        .then(function (answer: any) {
          return { people: Number(answer && answer.people) || 0,
                   unlinked: Number(answer && answer.unlinked) || 0,
                   failed: 0 };
        }, function (err: any) {
          log.warn(errorCodes.tag('STS-CELL-0211') + 'federation: cell "' +
                   peer.id + '" could not be asked to apply ' +
                   record.fedId + '\'s ' + type + ' notification: ' +
                   ((err && err.message) || err) + '. The notification is ' +
                   'not accepted, so the provider may send it again.');
          return { people: 0, unlinked: 0, failed: 1 };
        });
    });
    log.debug("Leaving FederationSp.notifyPeers(). Asking " + asks.length +
              " peer(s).");
    return Promise.all(asks).then(function (answers) {
      return answers.reduce(function (sum, one) {
        return { people: sum.people + one.people,
                 unlinked: sum.unlinked + one.unlinked,
                 failed: sum.failed + one.failed };
      }, { people: 0, unlinked: 0, failed: 0 });
    });
  }

  /**
   * Applies, in THIS cell, a provider notification another cell verified and
   * spent (`PEER_NOTIFICATION_OP`, #727). What this cell checks is that the
   * relationship exists here and takes notifications — global configuration,
   * so the same answer the sending cell had — and that the type is one a
   * notification can carry.
   *
   * @param body - `{ realm, relationship, type, sub }`
   * @param peer - the calling cell
   * @returns `{ people, unlinked }`
   * @throws an Error for an unknown realm
   */
  notificationForPeer(body: any, peer: string): { people: number;
                                                  unlinked: number } {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSp.notificationForPeer(). from " + peer);
    const realmId = String((body && body.realm) || '');
    const realm = realmId ? realms.get(realmId)
                          : realms.get(realms.DEFAULT_ID);
    if (!realm) {
      log.debug("Leaving FederationSp.notificationForPeer(). No realm.");
      throw new Error('no such realm');
    }
    const self = this;
    let out = { people: 0, unlinked: 0 };
    realms.run(realm, function () {
      const record = federation.get(String(body.relationship || ''));
      if (!record || record.fedRole !== 'service-provider' ||
          !consumerProviders.adapts(record, 'apple-notifications') ||
          !String(body.sub || '')) {
        return;
      }
      out = self.unlinkHere(record, String(body.type || ''),
                            String(body.sub));
    });
    log.debug("Leaving FederationSp.notificationForPeer(). " +
              out.unlinked + " unlinked.");
    return out;
  }

  // The `form` source (#565): Apple's `user` field, parsed, or undefined.
  private formSourceOf(record, context) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.formSourceOf().");
    const text = String((context && context.formUser) || '');
    if (!text || !consumerProviders.adapts(record, 'apple-user-form-field')) {
      log.debug("Leaving FederationSp.formSourceOf(). None.");
      return undefined;
    }
    try {
      const parsed = JSON.parse(text);
      log.debug("Leaving FederationSp.formSourceOf().");
      return parsed && typeof parsed === 'object' ? parsed : undefined;
    } catch (e) {
      log.debug("Caught in FederationSp.formSourceOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving FederationSp.formSourceOf(). Not JSON.");
      return undefined;
    }
  }

  // ---------------------------------------------------------------------------
  // CONNECTING A PROVIDER TO AN ACCOUNT, FROM THE PORTAL (#565, the plan's
  // decision 6). The person is signed in, and asks `/account-api` to connect
  // a consumer provider: this mints the flow — the context of an ordinary
  // federated sign-in, carrying who asked, the sign-on session the token was
  // issued on and the digest of a secret the browser is given in
  // LINK_COOKIE — and answers the provider's authorization address. The
  // provider answers at the assertion consumer service as for any sign-in,
  // every check made there, and completeSignIn() hands the verified answer
  // to finishConnect() rather than signing anybody in.
  //
  // OpenID Connect and OAuth 2.0 relationships only, of the consumer
  // category: an enterprise partner's links are an administrator's (the
  // console, `/admin-api`, SCIM), and this is the person's door.
  // Answers `{ ok, location, binding }` or `{ ok: false, code, why }`.
  // ---------------------------------------------------------------------------
  beginConnect(req, spec) {
    const { federation, randomId, baseUrlOf, log } = this.deps;
    log.debug("Entering FederationSp.beginConnect(). " + spec.relationship);
    const record = federation.get(String(spec.relationship || ''));
    if (!record || record.fedRole !== 'service-provider' ||
        !federation.signsIn(record) || !federation.isUsable(record) ||
        federation.categoryOf(record) !== 'consumer' ||
        (record.fedProtocol !== 'oidc' && record.fedProtocol !== 'oauth2') ||
        String(record.fedTrustAnchor || '').trim()) {
      log.debug("Leaving FederationSp.beginConnect(). Not connectable.");
      return { ok: false, code: 'STS-FED-0184',
               why: 'That provider cannot be connected here now.' };
    }
    const binding = randomId(24);
    const pkce = this.pkcePair();
    const handle = this.putContext({
      id: record.fedId, protocol: record.fedProtocol, returnTo: '',
      authnPending: '', application: '',
      nonce: 'n-' + randomId(16),
      pkceVerifier: pkce.verifier, pkceChallenge: pkce.challenge,
      connect: { username: String(spec.username), at: Date.now(),
                 session: String(spec.sessionId || ''),
                 bindingHash: this.bindingHashOf(binding),
                 back: String(spec.back || '') }
    });
    const location = this.authorizationRequestUrl(baseUrlOf(req), record,
                                                  this.heldContext(handle));
    log.debug("Leaving FederationSp.beginConnect(). To the provider.");
    // A PROVIDER THAT ANSWERS BY FORM POST (#565: Apple) posts across sites,
    // and a browser sends no SameSite=Lax cookie with that POST, so the
    // binding is SameSite=None there — which a browser takes only with
    // Secure, so over https alone. Over http such a connect cannot be bound,
    // and fails closed (STS-FED-0111).
    const crossSite = String(record.fedResponseMode || '') === 'form_post' &&
      !!this.deps.config.value('global.https');
    return { ok: true, location: location, binding: binding,
             cookie: LINK_COOKIE + '=' + binding + '; Path=/; HttpOnly; ' +
                     'SameSite=' + (crossSite ? 'None' : 'Lax') +
                     '; Max-Age=' +
                     Math.max(60, Math.floor(this.contextTtlMs() / 1000)) +
                     (this.deps.config.value('global.https') ? '; Secure'
                                                             : '') };
  }

  // ---------------------------------------------------------------------------
  // THE PROVIDER ANSWERED A CONNECT (#565). Verified already — the signature,
  // the issuer, the audience, the nonce, PKCE — by the protocol branch that
  // called completeSignIn(). What is asked here is the account-linking
  // CSRF's question and the subject's:
  //   1. this is the BROWSER the connect began in (LINK_COOKIE, STS-FED-0111);
  //   2. the sign-on session the token was issued on is still live and still
  //      the person's (STS-FED-0181);
  //   3. the partner may assert this person: a console administrator or a
  //      holder of REMOTE_PEPS only where fedMayAssertAdministrators says so
  //      (STS-FED-0183), and the partner's own stop on them (#373) holds;
  //   4. the link is nobody else's (the directory refuses a link two entries
  //      would carry, STS-FED-0182).
  // Then the link `<relationship> <issuer> <subject>` is written onto the
  // person's entry — through the directory's write hook, which tells CAEP
  // and RISC what changed — the person is mailed a security notice, and the
  // browser goes back to the portal page. Nothing else is written: the
  // partner's attributes are not, because the person did not ask for that.
  // ---------------------------------------------------------------------------
  private finishConnect(req, res, record, result) {
    const { authn, federation, links, audit, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.finishConnect(). " + record.fedId);
    const c = result.connect || {};
    const back = (problem: string, done?: string) => {
      log.debug("Entering back().");
      const target = String(c.back || '/portal/connected-accounts');
      const joiner = target.indexOf('?') >= 0 ? '&' : '?';
      res.status(303).set('Cache-Control', 'no-store')
        .set('Location', target + joiner + (problem
          ? 'problem=' + encodeURIComponent(problem)
          : 'done=' + encodeURIComponent(done))).end();
      log.debug("Leaving back().");
      return undefined;
    };
    const presented = String(authn.cookiesOf(req)[LINK_COOKIE] || '');
    res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
               'SameSite=Lax; Max-Age=0');
    if (!presented || !this.sameBinding(this.bindingHashOf(presented),
                                        String(c.bindingHash || ''))) {
      errorCodes.mark(res, 'STS-FED-0111');
      log.debug("Leaving FederationSp.finishConnect(). Another browser.");
      return back('The provider was not connected: this request was ' +
                  'started in another browser. Start it again from this ' +
                  'page.');
    }
    const signOn = c.session ? authn.sessionById(c.session) : null;
    if (!signOn || authn.sessionEnded(signOn) ||
        signOn.authenticated === false ||
        String((signOn.user || {}).username || '').toLowerCase() !==
          String(c.username || '').toLowerCase()) {
      errorCodes.mark(res, 'STS-FED-0181');
      log.debug("Leaving FederationSp.finishConnect(). Session ended.");
      return back('The provider was not connected: the sign-in it was ' +
                  'started from has ended. Sign in again and connect from ' +
                  'there.');
    }
    if (!federation.boolOf(record.fedMayAssertAdministrators, false) &&
        this.administratorRole(String(c.username))) {
      errorCodes.mark(res, 'STS-FED-0183');
      audit.failure('STS-FED-0183', {
        protocol: 'Federation', channel: 'http', target: record.fedId,
        summary: c.username + ' was not connected to ' + record.fedId +
                 ': a console administrator\'s account is not connected to ' +
                 'a provider unless the relationship allows it',
        outcome: 'refused', detail: { relationship: record.fedId,
                                      username: c.username } });
      log.debug("Leaving FederationSp.finishConnect(). An administrator.");
      return back('The provider was not connected: an administrator\'s ' +
                  'account cannot be signed in to through it.');
    }
    // THE PARTNER'S OWN STOP ON THIS PERSON (#373): a partner that said the
    // person is disabled at its end is not connected to them here.
    if (fedBlocks.blockOf(record.fedId, String(c.username))) {
      errorCodes.mark(res, 'STS-FED-0156');
      log.debug("Leaving FederationSp.finishConnect(). Blocked.");
      return back('The provider was not connected: it has said this ' +
                  'account is disabled at its end.');
    }
    const stable = links.stableSubjectOf(record, result);
    const value = links.linkValue(record.fedId, stable.issuer,
                                  stable.subject);
    const written = federation.writeFederationLink(String(c.username), value,
                                                   true, {});
    if (!written || written.ok === false) {
      errorCodes.mark(res, 'STS-FED-0182');
      audit.failure('STS-FED-0182', {
        protocol: 'Federation', channel: 'http', target: record.fedId,
        summary: c.username + ' was not connected to ' + record.fedId +
                 ': ' + ((written && written.errors) || []).join(' '),
        outcome: 'refused', detail: { relationship: record.fedId,
                                      username: c.username } });
      log.debug("Leaving FederationSp.finishConnect(). Not written.");
      return back('The provider was not connected: that account at the ' +
                  'provider is already connected to somebody here.');
    }
    audit.record({ category: 'portal', action: 'federation.connected',
      actor: String(c.username), target: record.fedId, outcome: 'success',
      summary: '"' + c.username + '" connected ' + record.fedId + ' (' +
               (record.fedName || record.fedId) + ') to their account ' +
               '(#565)' });
    try {
      require('../common/mail_uses').notice('account-connected',
        String(c.username), { values: {
          provider: String(record.fedName || record.fedId) },
          via: 'a connected account' });
    } catch (e) {
      log.debug("Caught in FederationSp.finishConnect(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving FederationSp.finishConnect(). Connected.");
    return back('', String(record.fedName || record.fedId));
  }

  // ---------------------------------------------------------------------------
  // WHETHER THE ISSUANCE POLICY LETS THIS SIGN-IN CREATE AN ACCOUNT (#565):
  // `create-account`, with the sign-in's risk facts and the partner's
  // category, provider and address verification, the roles waived. Null to
  // go on — including where there are no risk facts, which is the gate's
  // own rule: nothing to decide on decides nothing. A refusal is audited by
  // the policy enforcement point under its own decision.
  // ---------------------------------------------------------------------------
  private creationRefusal(username, record, result, amr, assessed, fed) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.creationRefusal().");
    let engine: any = null;
    try {
      engine = require('../risk/risk_engine');
    } catch (e) {
      log.debug("Caught in FederationSp.creationRefusal(): " +
                ((e && e.message) || e));
      engine = null;
    }
    const facts = engine && assessed
      ? engine.factsOf(engine.riskOf(assessed), amr, result.acr || '',
                       ['federation'])
      : null;
    if (!facts) {
      log.debug("Leaving FederationSp.creationRefusal(). No risk facts.");
      return null;
    }
    const gate = require('../common/issuance_gate');
    const answer = gate.check({
      application: '', kind: gate.ISSUANCE.ACCOUNT,
      subject: { kind: 'user', name: username, authenticated: true },
      claims: null, risk: facts, rolesWaived: true, deviceDeferred: true,
      authenticationEvent: { authority: {
        kind: 'federation', id: record.fedId,
        category: String((fed && fed.category) || 'enterprise'),
        provider: String((fed && fed.provider) || ''),
        emailVerified: fed && fed.mailVerified === false ? 'false' : 'true' } }
    });
    log.debug("Leaving FederationSp.creationRefusal(). " +
              (answer.allowed ? 'Allowed.' : 'Refused.'));
    return answer.allowed ? null : answer;
  }

  // ---------------------------------------------------------------------------
  // A STEP-UP ON RISK, AFTER A PARTNER (#565). The partner's verified answer
  // is held in the request-context store under a single-use handle, as the
  // linking step holds it, and the browser is bound to it by LINK_COOKIE for
  // that step's reason. `authn.beginSecondFactorAfterFederation()` asks for a
  // factor the person holds here, on a pending record returning to
  // `/federation/stepup/{handle}`; nothing is written until that returns.
  // ---------------------------------------------------------------------------
  private beginStepUp(req, res, record, result, decision, assessed, factor) {
    const { authn, config, randomId, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.beginStepUp(). " + decision.username);
    const binding = randomId(24);
    const handle = this.putContext({
      kind: 'stepup', id: record.fedId, username: decision.username,
      stepStartedAt: Date.now(), bindingHash: this.bindingHashOf(binding),
      result: Object.assign({}, result, { steppedUp: true })
    });
    res.append('Set-Cookie', LINK_COOKIE + '=' + binding + '; Path=/; ' +
               'HttpOnly; SameSite=Lax; Max-Age=' +
               Math.max(60, Math.floor(this.contextTtlMs() / 1000)) +
               (config.value('global.https') ? '; Secure' : ''));
    res.set('Cache-Control', 'no-store');
    let answer: any = null;
    try {
      answer = authn.beginSecondFactorAfterFederation(req, res, {
        username: decision.username,
        returnTo: STEPUP_PATH + '/' + encodeURIComponent(handle),
        via: STEPUP_VIA, assessment: assessed,
        details: [{ label: 'Signing in through',
                    value: (record.fedName || record.fedId),
                    note: 'this sign-in needs a second factor you hold ' +
                          'here (' + factor + ')' }]
      });
    } catch (e) {
      log.debug("Caught in FederationSp.beginStepUp(): " +
                ((e && e.message) || e));
      answer = { handled: false, errorCode: 'STS-RISK-0018' };
    }
    if (answer && answer.handled) {
      log.info('federation: ' + record.fedId + ' signed in ' +
               decision.username + ' and the issuance policy asked for a ' +
               'step-up (' + factor + '); a second factor held here is ' +
               'asked for.');
      log.debug("Leaving FederationSp.beginStepUp(). Asked.");
      return undefined;
    }
    this.takeContext(handle);
    res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
               'SameSite=Lax; Max-Age=0');
    errorCodes.mark(res, 'STS-RISK-0018');
    log.debug("Leaving FederationSp.beginStepUp(). Nothing answers it.");
    return this.refuse(res, record, 403, 'Authentication failed',
      'The assertion verified, and this sign-in needs a second factor held ' +
      'here, which this account does not have.');
  }

  // ---------------------------------------------------------------------------
  // GET /federation/stepup/{handle} — WHERE THE STEP-UP RETURNS (#565).
  //
  // The linking endpoint's checks, for a step-up: the handle (spent now), the
  // browser (LINK_COOKIE, STS-FED-0111), no error from the step, and a
  // session whose LATEST authentication is a local SECOND FACTOR made
  // through this step (`STEPUP_VIA`, `acr` `mfa`), as that person, after the
  // partner answered (STS-FED-0178). Then the held answer finishes as a
  // federated sign-in whose `amr` is `federated` and the factor proved here,
  // with `acr` `mfa`: two factors really were presented, one at the partner
  // and one here — and the subject decision and the policy are asked again,
  // as everything about the person may have moved while they answered.
  // ---------------------------------------------------------------------------
  private stepUpEndpoint(req, res) {
    const { federation, authn, errorCodes, log } = this.deps;
    log.debug("Entering the federation step-up endpoint.");
    FederationPages.mark(res);
    if (!this.enabled()) {
      errorCodes.mark(res, 'STS-FED-0001');
      FederationPages.send(res, 404, FederationPages.notHereView('off'));
      log.debug("Leaving the federation step-up endpoint. Federation is off.");
      return undefined;
    }
    const handle = String(req.params.handle || '');
    const context = /^fed-[A-Za-z0-9_-]{1,64}$/.test(handle)
      ? this.takeContext(handle) : null;
    if (!context || context.kind !== 'stepup') {
      errorCodes.mark(res, 'STS-FED-0100');
      log.debug("Leaving the federation step-up endpoint. No such step.");
      return this.refuse(res, null, 400, 'There is no sign-in waiting',
        'The step "' + handle + '" is not one this service started, it has ' +
        'already been used, or it expired (federation.requestTtlMin). Start ' +
        'the federated sign-in again.');
    }
    // THE SESSION THIS STEP'S SECOND FACTOR STARTED, if it did (rcbj's
    // decision 3 on #729): held on the response, so a refusal of the
    // federated finish — here, or anywhere completeSignIn() goes — ends it.
    this.holdStepUpSession(req, res, context);
    const record = federation.get(context.id);
    if (!record || record.fedRole !== 'service-provider' ||
        !federation.signsIn(record) || !federation.isUsable(record)) {
      errorCodes.mark(res, record && federation.isEnabled(record)
        ? 'STS-FED-0006' : 'STS-FED-0005');
      log.debug("Leaving the federation step-up endpoint. Not usable now.");
      return this.refuse(res, record || null, 403, 'That relationship is ' +
                                                   'not usable',
        'The relationship "' + context.id + '" is disabled, ' +
        'half-configured or gone since the partner answered.');
    }
    const presented = String(authn.cookiesOf(req)[LINK_COOKIE] || '');
    res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
               'SameSite=Lax; Max-Age=0');
    if (!presented || !this.sameBinding(this.bindingHashOf(presented),
                                        String(context.bindingHash || ''))) {
      errorCodes.mark(res, 'STS-FED-0111');
      log.debug("Leaving the federation step-up endpoint. Another browser.");
      return this.refuse(res, record, 403, 'Authentication failed',
        'This step was started in a different browser, or the cookie that ' +
        'ties it to the one it began in is gone. Start the federated ' +
        'sign-in again, in one browser.');
    }
    const session = authn.sessionOf(req);
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const latest = events.length ? events[events.length - 1] : null;
    const fresh = !String((req.query || {}).authn_error || '') &&
      !!session && !!latest &&
      String((session.user && session.user.username) || '').toLowerCase() ===
        String(context.username).toLowerCase() &&
      latest.via === STEPUP_VIA && latest.authenticated !== false &&
      String(latest.acr || '') === 'mfa' &&
      ((latest.authority || {}).kind || 'local') === 'local' &&
      Number(latest.at || 0) * 1000 >= Number(context.stepStartedAt || 0) -
                                       1000;
    if (!fresh) {
      errorCodes.mark(res, 'STS-FED-0178');
      log.debug("Leaving the federation step-up endpoint. No fresh second " +
                "factor as " + context.username + ".");
      return this.refuse(res, record, 403, 'Authentication failed',
        'This sign-in needed a second factor held here, as ' +
        context.username + ', made just now, and this browser holds ' +
        (session ? 'a different authentication' : 'none') + '. Start the ' +
        'federated sign-in again.');
    }
    // The factor proved here, behind `federated`: the session's own record
    // of what happened, and what meets the step-up the policy asked for.
    const proved = (latest.amr || []).map(String).filter(function (one) {
      return one !== 'federated';
    });
    log.debug("Leaving the federation step-up endpoint. Finishing " +
              context.username + ".");
    return this.completeSignIn(req, res, record,
      Object.assign({}, context.result, {
        amr: this.federatedAmr(proved), acr: 'mfa', steppedUp: true }));
  }

  // ---------------------------------------------------------------------------
  // NO SESSION OUTLIVES A REFUSED SIGN-IN (rcbj's decision 3 on #729).
  //
  // The step-up's second factor is a local sign-in, and its finisher starts
  // a session before the browser returns to `/federation/stepup/{handle}`:
  // that is how the endpoint knows the factor was proved. When the federated
  // finish is then refused — the browser, the freshness, the relationship,
  // the subject decision, the policy, an attribute source — that session was
  // a half of a sign-in that did not happen, and it is ENDED through
  // `authn.endSessionById()` (`dropSession()`, so the audit row, CAEP and
  // the back-channel Logout Tokens are the ones every sign-out has) and its
  // cookie cleared. Only a session the step STARTED: its latest event is
  // the step's second factor, as the person the step was for, and its first
  // event is no older than the step. A person who was already signed in
  // keeps the session they had (`startSession()` re-authenticated it).
  // ---------------------------------------------------------------------------
  private holdStepUpSession(req, res, context): void {
    const { authn, log } = this.deps;
    log.debug("Entering FederationSp.holdStepUpSession().");
    let session: any = null;
    try {
      session = authn.sessionOf(req);
    } catch (e) {
      log.debug("Caught in FederationSp.holdStepUpSession(): " +
                ((e && e.message) || e));
      session = null;
    }
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const latest = events.length ? events[events.length - 1] : null;
    const started = !!session && !!latest && latest.via === STEPUP_VIA &&
      !(Number(session.eventsDropped || 0) > 0) &&
      String((session.user && session.user.username) || '').toLowerCase() ===
        String(context.username || '').toLowerCase() &&
      authn.sessionStartedAt(session) >=
        Number(context.stepStartedAt || 0) - 1000;
    if (!started || !res || !res.locals) {
      log.debug("Leaving FederationSp.holdStepUpSession(). The step started " +
                "no session.");
      return;
    }
    const held = { id: String(session.id || ''),
                   username: String(context.username || ''),
                   realm: realms.current(), ended: false };
    res.locals.fedStepUpSession = held;
    // AND AFTER THE ANSWER, for a refusal drawn by something other than
    // refuse() (an authentication page, an error): the session is ended
    // server-side, in its own realm, where the cookie can no longer be
    // cleared. A success replaced the session (`startSession()`'s
    // `request`) and answers below 400.
    const self = this;
    if (typeof res.on === 'function') {
      res.on('finish', function (): void {
        log.debug("Entering the step-up session's finish check.");
        if (!held.ended && Number(res.statusCode) >= 400) {
          realms.run(held.realm, function (): void {
            self.endStepUpSession(res, 'answered ' + res.statusCode);
          });
        }
        log.debug("Leaving the step-up session's finish check.");
      });
    }
    log.debug("Leaving FederationSp.holdStepUpSession(). Held " + held.id +
              ".");
  }

  // Ends the session holdStepUpSession() held, once. Never throws: the
  // refusal it follows has been decided.
  private endStepUpSession(res, why: string): void {
    const { authn, log } = this.deps;
    log.debug("Entering FederationSp.endStepUpSession().");
    const held = res && res.locals ? res.locals.fedStepUpSession : null;
    if (!held || held.ended || !held.id) {
      log.debug("Leaving FederationSp.endStepUpSession(). None held.");
      return;
    }
    held.ended = true;
    try {
      authn.endSessionById(held.id, 'a refused federated sign-in after its ' +
                           'step-up (' + why + ')', 'policy');
      if (!res.headersSent) {
        authn.clearSessionCookie(res);
      }
      log.info(errorCodes.tag('STS-FED-0192') + 'federation: the federated ' +
               'sign-in of "' + held.username + '" was refused after its ' +
               'step-up (' + why + '), so the session its second factor ' +
               'started was ended.');
    } catch (e) {
      log.debug("Caught in FederationSp.endStepUpSession(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-FED-0193') + 'federation: the session ' +
                'a refused step-up started for "' + held.username +
                '" could not be ended: ' + ((e && e.message) || e));
    }
    log.debug("Leaving FederationSp.endStepUpSession().");
  }

  // ---------------------------------------------------------------------------
  // WHAT A CONSUMER NEWCOMER IS ASKED FOR (rcbj's decision 2 on #729).
  //
  // A consumer provider's newcomer is created by the sign-in, and in product
  // mode this realm's attribute policy (#396, `common/attribute_policy.ts`)
  // refuses a create that leaves a required attribute empty — so a provider
  // that sends no surname, or Apple, which sends the name on the FIRST
  // authorization only, would refuse the person at the door (STS-FED-0158).
  // Nothing in the policy is relaxed: the person is asked for EXACTLY the
  // required values the provider did not send, on a short form of the
  // federation surface (`/federation/profile/{handle}`, common/CLAUDE.md
  // 3cl), and the account is created from the provider's values and theirs.
  //
  // * The answer is the entry as this sign-in would write it — `uid`, the
  //   mapped attributes, a `cn` made of the names (`deriveCommonName()`) —
  //   asked of the policy as the directory asks it (`autoCreateUser()`).
  //   `cn` is never asked: it is made of the names asked for.
  // * Asked only where the policy is enforced (product mode), and only of a
  //   name a person can be given a value for (`mail`, or one
  //   `ldap/person_editor.ts` knows). Anything else keeps the refusal.
  // * The step is the federation surface's own: the partner's verified
  //   answer is held under a single-use handle, the browser bound to it by
  //   LINK_COOKIE as the linking step's is, and the form carries a token
  //   held with the handle. A wrong value draws the form again under a new
  //   handle, five times at most.
  // * A typed address is UNVERIFIED (`mailVerified` false), whatever the
  //   provider said of the address it did not send.
  // ---------------------------------------------------------------------------
  private profileMissing(username: string, mapped): string[] {
    const { log } = this.deps;
    log.debug("Entering FederationSp.profileMissing().");
    const policy = require('../common/attribute_policy');
    const prospective: any = Object.assign({ uid: [String(username)] },
                                           (mapped && mapped.attributes) || {});
    policy.deriveCommonName(prospective);
    const refusal = policy.createRefusal(prospective);
    if (!refusal) {
      log.debug("Leaving FederationSp.profileMissing(). Nothing missing.");
      return [];
    }
    // `cn` is made of the names asked for, and asked only where it is not.
    const filled: any = Object.assign({}, prospective);
    refusal.missing.forEach(function (name: string): void {
      if (name.toLowerCase() !== 'cn') {
        filled[name] = ['x'];
      }
    });
    policy.deriveCommonName(filled);
    const cnStill = policy.missingFrom(filled).some(function (n: string) {
      return n.toLowerCase() === 'cn';
    });
    const asked = refusal.missing.filter(function (name: string): boolean {
      const lower = name.toLowerCase();
      return lower !== 'uid' && (lower !== 'cn' || cnStill);
    });
    log.debug("Leaving FederationSp.profileMissing(). " + asked.join(', '));
    return asked;
  }

  // Whether a person can be asked for a value of an attribute: `mail`, or
  // one the person editor holds a create's values to.
  private profileAskable(name: string): boolean {
    const { log } = this.deps;
    log.debug("Entering FederationSp.profileAskable(). " + name);
    if (name.toLowerCase() === 'mail') {
      log.debug("Leaving FederationSp.profileAskable(). The address.");
      return true;
    }
    let known = false;
    try {
      known = require('../ldap/person_editor')
        .checkCreateValues(name, ['x']) !== null;
    } catch (e) {
      log.debug("Caught in FederationSp.profileAskable(): " +
                ((e && e.message) || e));
      known = false;
    }
    log.debug("Leaving FederationSp.profileAskable(). " + known);
    return known;
  }

  // The label a field is drawn with: the catalogue's, which is the console's
  // (a custom attribute's is its definition's), or the name.
  private profileLabelOf(name: string): string {
    const { log } = this.deps;
    log.debug("Entering FederationSp.profileLabelOf(). " + name);
    let label = name;
    try {
      const row = require('../common/attribute_policy').catalogue()
        .filter(function (one: any): boolean {
          return String(one.name).toLowerCase() === name.toLowerCase();
        })[0];
      label = (row && row.label) || name;
    } catch (e) {
      log.debug("Caught in FederationSp.profileLabelOf(): " +
                ((e && e.message) || e));
      label = name;
    }
    log.debug("Leaving FederationSp.profileLabelOf().");
    return String(label);
  }

  // Holds the partner's answer and sends the browser to the form.
  private beginProfile(req, res, record, result, decision, asked: string[]) {
    const { config, randomId, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.beginProfile(). " + decision.username);
    const binding = randomId(24);
    const handle = this.putContext({
      kind: 'profile', id: record.fedId, username: decision.username,
      asked: asked.slice(0), attempts: 0, csrf: randomId(24), problem: '',
      bindingHash: this.bindingHashOf(binding),
      result: Object.assign({}, result)
    });
    res.append('Set-Cookie', LINK_COOKIE + '=' + binding + '; Path=/; ' +
               'HttpOnly; SameSite=Lax; Max-Age=' +
               Math.max(60, Math.floor(this.contextTtlMs() / 1000)) +
               (config.value('global.https') ? '; Secure' : ''));
    res.set('Cache-Control', 'no-store');
    log.info('federation: ' + record.fedId + ' signed in a newcomer, ' +
             decision.username + ', without ' + asked.join(', ') + ', which ' +
             'this realm\'s attribute policy requires; asking them.');
    errorCodes.mark(res, 'STS-FED-0188');
    log.debug("Leaving FederationSp.beginProfile(). To the form.");
    return res.redirect(303, realms.currentPrefix() + PROFILE_PATH + '/' +
                             encodeURIComponent(handle));
  }

  // The form's view, for the handle that holds it.
  private profileView(record, context, handle: string): any {
    const { log } = this.deps;
    log.debug("Entering FederationSp.profileView().");
    const profile = consumerProviders.profileFor(record.fedProvider);
    const self = this;
    const view = {
      kind: 'profile', relationship: String(record.fedId),
      partner: String(record.fedName || record.fedId),
      provider: String((profile && profile.label) || ''),
      action: PROFILE_PATH + '/' + encodeURIComponent(handle),
      csrf: String(context.csrf || ''),
      problem: String(context.problem || ''),
      fields: [].concat(context.asked || []).map(function (name: string) {
        return { name: name, label: self.profileLabelOf(name),
                 type: name.toLowerCase() === 'mail' ? 'email' : 'text',
                 max: PROFILE_VALUE_MAX };
      })
    };
    log.debug("Leaving FederationSp.profileView().");
    return view;
  }

  // The context a profile handle names, the relationship and the browser
  // checked; or the refusal already answered (null).
  private profileContext(req, res, spend: boolean): any {
    const { federation, authn, errorCodes, log } = this.deps;
    log.debug("Entering FederationSp.profileContext().");
    const handle = String(req.params.handle || '');
    const valid = /^fed-[A-Za-z0-9_-]{1,64}$/.test(handle);
    let context = valid
      ? (spend ? this.takeContext(handle) : this.heldContext(handle)) : null;
    if (context && !spend && Number(context.expires) < Date.now()) {
      context = null;
    }
    if (!context || context.kind !== 'profile') {
      errorCodes.mark(res, 'STS-FED-0100');
      log.debug("Leaving FederationSp.profileContext(). No such step.");
      this.refuse(res, null, 400, 'There is no sign-in waiting',
        'The step "' + handle + '" is not one this service started, it has ' +
        'already been used, or it expired (federation.requestTtlMin). Start ' +
        'the sign-in again.');
      return null;
    }
    const presented = String(authn.cookiesOf(req)[LINK_COOKIE] || '');
    if (!presented || !this.sameBinding(this.bindingHashOf(presented),
                                        String(context.bindingHash || ''))) {
      if (spend) {
        res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
                   'SameSite=Lax; Max-Age=0');
      }
      errorCodes.mark(res, 'STS-FED-0111');
      log.debug("Leaving FederationSp.profileContext(). Another browser.");
      this.refuse(res, null, 403, 'Authentication failed',
        'This step was started in a different browser, or the cookie that ' +
        'ties it to the one it began in is gone. Start the sign-in again, ' +
        'in one browser.');
      return null;
    }
    const record = federation.get(context.id);
    if (!record || record.fedRole !== 'service-provider' ||
        !federation.signsIn(record) || !federation.isUsable(record) ||
        consumerProviders.categoryOf(record) !== 'consumer') {
      errorCodes.mark(res, record && federation.isEnabled(record)
        ? 'STS-FED-0006' : 'STS-FED-0005');
      log.debug("Leaving FederationSp.profileContext(). Not usable now.");
      this.refuse(res, record || null, 403, 'That relationship is not usable',
        'The relationship "' + context.id + '" is disabled, ' +
        'half-configured or gone since the provider answered.');
      return null;
    }
    log.debug("Leaving FederationSp.profileContext().");
    return { context: context, record: record, handle: handle };
  }

  // ---------------------------------------------------------------------------
  // GET /federation/profile/{handle} — THE FORM (rcbj's decision 2 on #729).
  // The surface's shell with the view in it; SCRIPT IS REQUIRED. Nothing is
  // spent: the POST spends the handle.
  // ---------------------------------------------------------------------------
  private profileEndpoint(req, res) {
    const { errorCodes, log } = this.deps;
    log.debug("Entering the federation profile endpoint.");
    FederationPages.mark(res);
    if (!this.enabled()) {
      errorCodes.mark(res, 'STS-FED-0001');
      FederationPages.send(res, 404, FederationPages.notHereView('off'));
      log.debug("Leaving the federation profile endpoint. Federation is off.");
      return undefined;
    }
    const found = this.profileContext(req, res, false);
    if (!found) {
      log.debug("Leaving the federation profile endpoint. Refused.");
      return undefined;
    }
    FederationPages.send(res, 200,
      this.profileView(found.record, found.context, found.handle),
      { application: String((found.context.result || {}).application || '') });
    log.debug("Leaving the federation profile endpoint. The form.");
    return undefined;
  }

  // ---------------------------------------------------------------------------
  // POST /federation/profile/{handle} — THE VALUES. The handle is spent, the
  // browser and the form's token checked, each value held to its attribute's
  // rules; then the held answer finishes as the sign-in it was, with the
  // values beside the provider's — the subject decision, the creation
  // question and the policy asked again.
  // ---------------------------------------------------------------------------
  private profileSubmit(req, res) {
    const { errorCodes, log } = this.deps;
    log.debug("Entering the federation profile submission.");
    FederationPages.mark(res);
    if (!this.enabled()) {
      errorCodes.mark(res, 'STS-FED-0001');
      FederationPages.send(res, 404, FederationPages.notHereView('off'));
      log.debug("Leaving the federation profile submission. Federation is " +
                "off.");
      return undefined;
    }
    const found = this.profileContext(req, res, true);
    if (!found) {
      log.debug("Leaving the federation profile submission. Refused.");
      return undefined;
    }
    const { context, record } = found;
    // The form's body as every POST here is read (`paramsOf()`'s parser),
    // and never the query string.
    const parsed = this.deps.parseBody(req);
    const body = parsed && typeof parsed === 'object' ? parsed : {};
    const token = String(body.csrf || '');
    const held = String(context.csrf || '');
    if (!token || !held || !stsCrypto.constantTimeEquals(token, held)) {
      res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
                 'SameSite=Lax; Max-Age=0');
      errorCodes.mark(res, 'STS-FED-0189');
      log.debug("Leaving the federation profile submission. No token.");
      return this.refuse(res, record, 403, 'Authentication failed',
        'The form did not carry the token this step was given, so nothing ' +
        'was created. Start the sign-in again.');
    }
    const values: Record<string, string> = {};
    const problems: string[] = [];
    [].concat(context.asked || []).forEach((name: string) => {
      const raw = body[name];
      const value = String(Array.isArray(raw) ? (raw[0] === undefined ? ''
                                                                : raw[0])
                                              : (raw === undefined ||
                                                 raw === null ? '' : raw))
        .trim();
      const label = this.profileLabelOf(name);
      if (!value) {
        problems.push(label + ' is required.');
        return;
      }
      if (value.length > PROFILE_VALUE_MAX || PROFILE_CONTROL.test(value)) {
        problems.push(label + ' is at most ' + PROFILE_VALUE_MAX +
                      ' characters, with no control characters.');
        return;
      }
      if (name.toLowerCase() === 'mail') {
        if (!PROFILE_EMAIL_SHAPE.test(value)) {
          problems.push(label + ' is not an email address.');
          return;
        }
        values[name] = value;
        return;
      }
      let checked: any = null;
      try {
        checked = require('../ldap/person_editor')
          .checkCreateValues(name, [value]);
      } catch (e) {
        log.debug("Caught in the federation profile submission: " +
                  ((e && e.message) || e));
        checked = { error: 'The value for ' + label + ' could not be ' +
                           'checked.' };
      }
      if (!checked || checked.error) {
        problems.push(String((checked && checked.error) ||
                             label + ' cannot be given here.'));
        return;
      }
      values[checked.name || name] = String((checked.values || [value])[0]);
    });
    if (problems.length) {
      const attempts = Number(context.attempts || 0) + 1;
      if (attempts >= PROFILE_MAX_ATTEMPTS) {
        res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
                   'SameSite=Lax; Max-Age=0');
        errorCodes.mark(res, 'STS-FED-0191');
        log.debug("Leaving the federation profile submission. Too many " +
                  "tries.");
        return this.refuse(res, record, 400, 'Authentication failed',
          'The form was sent ' + attempts + ' times without the values ' +
          'this service needs, so nothing was created. Start the sign-in ' +
          'again.');
      }
      const again = Object.assign({}, context, {
        attempts: attempts, problem: problems.join(' ') });
      delete again.handle;
      delete again.startedAt;
      delete again.expires;
      const next = this.putContext(again);
      errorCodes.mark(res, 'STS-FED-0190');
      log.debug("Leaving the federation profile submission. Asked again.");
      FederationPages.send(res, 400, this.profileView(record, again, next),
        { application: String((context.result || {}).application || '') });
      return undefined;
    }
    res.append('Set-Cookie', LINK_COOKIE + '=; Path=/; HttpOnly; ' +
               'SameSite=Lax; Max-Age=0');
    log.info('federation: the newcomer ' + context.username + ' through ' +
             record.fedId + ' gave ' + Object.keys(values).join(', ') +
             '; finishing the sign-in.');
    log.debug("Leaving the federation profile submission. Finishing.");
    return this.completeSignIn(req, res, record,
      Object.assign({}, context.result, { profileSupplied: values }));
  }

  // The values a newcomer gave, on the mapped attributes this sign-in
  // writes; only where the partner sent none.
  private withProfileValues(mapped, supplied): any {
    const { log } = this.deps;
    log.debug("Entering FederationSp.withProfileValues().");
    const attributes = Object.assign({}, (mapped && mapped.attributes) || {});
    Object.keys(supplied || {}).forEach(function (name: string): void {
      const already = Object.keys(attributes).some(function (k: string) {
        return k.toLowerCase() === name.toLowerCase() &&
               [].concat(attributes[k] || []).some(function (v: any) {
                 return String(v).trim() !== '';
               });
      });
      if (!already) {
        attributes[name] = [String(supplied[name])];
      }
    });
    log.debug("Leaving FederationSp.withProfileValues().");
    return Object.assign({}, mapped, { attributes: attributes });
  }

  // The SHA-256 of a linking cookie's value, which is what the context holds.
  private bindingHashOf(value) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.bindingHashOf().");
    log.debug("Leaving FederationSp.bindingHashOf().");
    return stsCrypto.digest('sha256', String(value), 'base64url');
  }

  // Two binding hashes compared in constant time.
  private sameBinding(a, b) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.sameBinding().");
    // An empty binding matches nothing; two of different lengths answer
    // false in constantTimeEquals(), as the length check here did.
    const left = String(a || '');
    const same = left.length > 0 &&
                 stsCrypto.constantTimeEquals(left, String(b || ''));
    log.debug("Leaving FederationSp.sameBinding(). " + same);
    return same;
  }

  // ---------------------------------------------------------------------------
  // STEPS 3 TO 5 of completeSignIn()'s list, for a subject the decision has
  // already admitted: the counters, the partner's application record, and the
  // session — which carries the LINK, and the partner's attributes, to the
  // directory through the identity funnel.
  // ---------------------------------------------------------------------------
  private finishSignIn(req, res, record, result, mapped, decision) {
    const {
      applications, authn, federation, errorCodes, log, subjectForName,
      hasSubjectResolver
    } = this.deps;
    log.debug("Entering FederationSp.finishSignIn(). " + decision.username);
    const username = decision.username;
    // WHAT A NEWCOMER GAVE (rcbj's decision 2 on #729), beside what the
    // provider sent, for the account this sign-in creates and no other.
    const supplied = result.profileSupplied && decision.create === true
      ? result.profileSupplied : null;
    if (supplied) {
      mapped = this.withProfileValues(mapped, supplied);
    }
    const protocolLabel = (federation.protocolRow(record.fedProtocol) ||
                           {}).label ||
      record.fedProtocol;
    const via = 'Federation (' + protocolLabel + ')';
    // What the PARTNER said it did, behind `federated`. See decision 1:
    // `federated` is not an RFC 8176 value and deliberately is not one. See
    // federatedAmr() for why it now LEADS the partner's values rather than
    // replacing them — and why every protocol branch goes through that
    // function.
    const amr = this.federatedAmr(result.amr);

    // WHAT THE FUNNEL IS TOLD, and it goes through `startSession()` rather than
    // through a `stats.recordAuthentication()` call of its own. That was
    // written the other way round first and produced TWO authentication records
    // for one federated sign-in — /admin/users counted every arrival twice and
    // the audit log carried a duplicate of each — because `startSession()` has
    // always recorded the authentication itself. See its sixth argument, where
    // the reasoning is written down.
    const detail = {
      // No indefinite article: "a OpenID Connect" and "an SAML 2.0" are both
      // wrong, and picking between them by first letter gets both of those
      // wrong too — the article follows the SOUND, and three of the five labels
      // are initialisms. federation.js's create() note is phrased around the
      // same problem.
      method: protocolLabel + ' assertion from ' +
              (record.fedPeer || record.fedId) +
              ', verified against this relationship\'s configured key',
      sub: result.subject,
      // NO `client_id`. It was here first and was a real bug: the identity
      // funnel passes `client_id` to `applications.recordAuthentication()`,
      // which filed the foreign identity provider as an `oauth2-client` — so
      // the partner's registry entry carried a kind saying it was a client OF
      // this service, which is precisely backwards. The partner is recorded
      // below, once, through `applications.seen()`, under a kind that says what
      // it is.
      summary: username + ' was signed in through the federation ' +
                          'relationship "' +
               record.fedId + '"' + (decision.how === 'confirmed'
                 ? ', linked to the partner after signing in here'
                 : '') + '; this service checked no credential of theirs ' +
                 'and verified ' +
               (record.fedPeer || 'the partner') + '\'s signature',
      note: 'No credential was checked HERE — the partner authenticated this ' +
            'person and this service verified the partner\'s signature. That ' +
            'is the one thing this service does check.',
      // The mapped attributes, riding on the funnel to the directory. It is a
      // field on the existing observer payload rather than a sixth slot, which
      // is exactly what `certificate` and `linkedTo` already are — see rule
      // 3e's test, which this passes because nothing new points anywhere new.
      federation: {
        id: record.fedId,
        peer: record.fedPeer || '',
        protocol: record.fedProtocol,
        // THE CATEGORY AND THE PROVIDER (#565), carried on the event so the
        // issuance policy can tell a social sign-in from an enterprise one.
        category: consumerProviders.categoryOf(record),
        provider: String(record.fedProvider || ''),
        protocolLabel: protocolLabel,
        subject: result.subject,
        // THE LINK AND WHETHER THIS SIGN-IN MAY CREATE ANYBODY (#109), as
        // subjectDecision() answered — the directory writes the first and
        // obeys the second, and decides neither.
        link: decision.link || '',
        create: decision.create === true,
        policy: decision.policy || '',
        how: decision.how || '',
        // Whether the partner's attributes overwrite the entry's on a sign-in
        // that did not create it (2026-09-14). See `fedUpdateUserAttributes`.
        updateAttributes: federation.boolOf(record.fedUpdateUserAttributes,
                                            true),
        attributes: mapped.attributes,
        // WHETHER THE ADDRESS THE PARTNER SENT COUNTS AS VERIFIED (#64): it
        // does — a federation partner is a trusted source, rcbj's ticket says
        // so — unless the partner itself says it is not, which an OpenID
        // provider does with `email_verified: false`. That one is honoured.
        // An address the newcomer TYPED (#729) is unverified, whatever the
        // provider said of the one it did not send.
        mailVerified: !this.partnerDisownsMail(result.bag) &&
                      !(supplied && Object.keys(supplied).some(
                        function (n: string): boolean {
                          return n.toLowerCase() === 'mail';
                        })),
        mapped: mapped.mapped.length,
        unmapped: mapped.unmapped.map((one) => { return one.incoming; })
      },
      // THE PARTNER'S SESSION, AND ITS BOUND (#167): kept on the session by
      // `authn.startSession()` so the partner's sign-out can name it, and
      // the partner's SessionNotOnOrAfter as the session's latest end.
      fedPartnerSession: this.partnerSessionOf(record, result),
      sessionNotOnOrAfter: Number(result.sessionNotOnOrAfter) || 0
    };

    // The relationship's own counts, and — where this sign-in began at an
    // application configured to authenticate through it — that pair's counts
    // beside them. `result.application` is the hint the login endpoint put on
    // the request context; recordUse() decides whether it means anything.
    federation.recordUse(record.fedId,
                         { user: username,
                           application: result.application || '' });

    // The foreign identity provider as an APPLICATION, so that the one question
    // `ou=applications` exists to answer — what parties has this service dealt
    // with? — is not missing the ones on the other side of a federation. It is
    // filed under the partner's own identifier, which is the same key rule that
    // makes an OAuth client and a WS-Federation realm with one string one
    // record.
    try {
      applications.seen({
        identifier: record.fedPeer || record.fedId,
        kind: PARTNER_KIND,
        protocol: protocolLabel,
        note: 'a FOREIGN IDENTITY PROVIDER this service federates with as a ' +
              'service provider, through the relationship ' +
              '"' + record.fedId + '". It ' +
              'is not a client of this service: it authenticates people TO it.',
        fields: this.samlFieldsFor(record)
      });
    } catch (e) {
      log.error(errorCodes.tag('STS-FED-0045') + 'federation: the ' +
                'application registry threw and was ignored; the sign-in ' +
                'itself stands: ' + e.message);
    }

    // LAST, because it is the thing that has an effect outside this process and
    // everything above it is a record of why. It carries `detail`, so the one
    // authentication this sign-in produces is recorded with the partner's own
    // facts on it — including the mapped attributes and the link, which reach
    // the directory through the identity funnel and by no other route.
    // `request` so a federated sign-in REPLACES whatever session this browser
    // was on rather than leaving the previous one alive beside it.
    // THE RISK OF THIS SIGN-IN (#62 P3), assessed before the session and
    // decided with the roles. This door cannot ask for a second factor — the
    // person authenticated at the partner — so a step-up the policy names
    // refuses here like HIGH, unless the partner's assertion already claims
    // two (acr `mfa`). The session is started once the assessment answers;
    // an assessment that cannot be made decides nothing.
    const self = this;
    const assessing = authn.assessSignIn(req, username, via,
      { application: record.fedApplication || '',
        // A newcomer this sign-in would create has no entry to be assessed
        // as (#565): a provisional subject, one per partner subject.
        provisionalSubject: decision.create === true
          ? 'urn:sts:federation-newcomer:' +
            stsCrypto.digest('sha256', record.fedId + ' ' +
                             String(result.subject || ''), 'base64url')
          : undefined,
        // WHICH RELATIONSHIP (#565): each partner is a credential of its
        // own to the risk history, so a provider this person never signed
        // in through before is visible to it.
        credential: { kind: 'federation', id: record.fedId,
                      relationship: record.fedId } });
    log.debug("Leaving FederationSp.finishSignIn(). Assessing.");
    return assessing.then(function (assessed: any): any {
      return self.startFederatedSession(req, res, record, result, mapped,
                                        decision, amr, via, detail,
                                        protocolLabel, assessed);
    }, function (e: any): any {
      log.debug("Caught in FederationSp.finishSignIn(): " +
                ((e && e.message) || e));
      // assessSignIn() never rejects; this is its belt and braces, and a
      // sign-in with no assessment is decided on roles.
      return self.startFederatedSession(req, res, record, result, mapped,
                                        decision, amr, via, detail,
                                        protocolLabel, null);
    });
  }

  // The session, once the sign-in has been assessed — the end of
  // finishSignIn(), moved here so it can wait for the assessment (#62 P3).
  private startFederatedSession(req, res, record, result, mapped, decision,
                                amr, via, detail, protocolLabel, assessed) {
    const {
      authn, federation, errorCodes, log, subjectForName, hasSubjectResolver
    } = this.deps;
    log.debug("Entering FederationSp.startFederatedSession().");
    const username = decision.username;
    // Held, because a refusal says why on it (`refusedWith`, #62 P0).
    const said: any = Object.assign({
      request: req,
      // Which credential answered (#62): a partner's assertion.
      credential: { kind: 'federation', id: record.fedId,
                    relationship: record.fedId },
      application: record.fedApplication || '',
      risk: assessed || undefined
    }, detail);
    // THE ACCOUNT THIS SIGN-IN WOULD CREATE IS ITS OWN QUESTION (#565), asked
    // before the session whose funnel creates it, so a refusal creates
    // nobody.
    if (decision.create === true) {
      const creation = this.creationRefusal(username, record, result, amr,
        assessed, (detail && detail.federation) || {});
      if (creation) {
        errorCodes.mark(res, 'STS-FED-0179');
        log.debug("Leaving FederationSp.startFederatedSession(). Creation " +
                  "refused.");
        return this.refuse(res, record, 403, 'Authentication failed',
          'The assertion verified, and this service will not create an ' +
          'account from it.');
      }
      // WHAT THE ATTRIBUTE POLICY NEEDS AND THE PROVIDER DID NOT SEND
      // (rcbj's decision 2 on #729): a consumer provider's newcomer is
      // asked for it before anything is created. See profileMissing().
      if (consumerProviders.categoryOf(record) === 'consumer') {
        const asked = this.profileMissing(username, mapped);
        if (asked.length && asked.every((n) => this.profileAskable(n))) {
          log.debug("Leaving FederationSp.startFederatedSession(). Asking " +
                    "for " + asked.join(', ') + ".");
          return this.beginProfile(req, res, record, result, decision, asked);
        }
      }
    }
    const session = authn.startSession(res, username, amr,
                                       result.acr || '', via, said);
    // -------------------------------------------------------------------------
    // THE ISSUANCE POLICY CAN REFUSE THE SESSION (2026-09-06), and a null is
    // how `startSession()` says so — it never throws, because two of its
    // callers wrap it in a `try` that treats a failure as bookkeeping.
    //
    // **THIS IS THE SURFACE WHERE THE GATE MATTERS MOST**, and it is the one
    // that never asked. A federated assertion arrives from a partner and the
    // person authenticated somewhere else entirely: everything this service
    // knows about them came out of somebody else's document. An application
    // narrowed to a role refused a password sign-in here and admitted the same
    // name through a partner, which is the shape of hole this directory's own
    // header says its bugs are — security bugs rather than fidelity bugs.
    //
    // The refusal is a PAGE and not a redirect back to the partner: the
    // assertion verified, so there is nothing for the partner to retry and
    // bouncing the browser there would loop.
    // NO ENTRY, AND DYNAMIC PROVISIONING OFF (2026-09-14) — told apart from a
    // policy refusal because they are two different things to fix: one is a
    // person nobody provisioned, the other a role they do not hold.
    // THE REALM'S ATTRIBUTE POLICY REFUSED TO CREATE THEM (#396), told
    // apart from the generic case below: what to fix is the relationship's
    // attribute mapping, and the code is STS-FED-0158, the directory's own.
    const fedSaid = (said && said.federation) || {};
    if (!session && fedSaid.refusedWith === 'STS-FED-0158') {
      const missing = [].concat(fedSaid.refusedMissing || []).map(String);
      log.info('federation: no session for ' + username + ' arriving ' +
               'through ' + record.fedId + ': the realm\'s attribute ' +
               'policy would not create them (missing ' +
               missing.join(', ') + ').');
      errorCodes.mark(res, 'STS-FED-0158');
      log.debug("Leaving FederationSp.startFederatedSession(). Attribute " +
                "policy.");
      return this.refuse(res, record, 403, 'This person has not been ' +
                                           'provisioned',
        'The assertion verified and the partner is configured, but this ' +
        'realm\'s attribute policy requires ' + missing.join(', ') +
        ' of every person and the partner supplied no value of it, so ' +
        'nobody was created. Map the attribute on the relationship ' +
        '(fedAttributeMap), or provision the person first.');
    }
    if (!session && hasSubjectResolver() &&
        !subjectForName(username)) {
      log.info('federation: no session for ' + username + ' arriving ' +
               'through ' +
               '' + record.fedId + ': the directory holds no entry for ' +
               'them and dynamic provisioning is ' +
               (this.autocreateOn(record)
                 ? 'on but the directory declined to create one.'
                 : 'off on this relationship.'));
      errorCodes.mark(res, 'STS-FED-0090');
      log.debug("Leaving FederationSp.startFederatedSession().");
      return this.refuse(res, record, 403, 'This person has not been ' +
                                           'provisioned',
        'The assertion verified and the partner is configured, but this ' +
        'service holds no directory entry for ' + username + ', and ' +
        (this.autocreateOn(record)
          ? 'the directory would not create one (the subject policy ' +
            'refused it, the relationship\'s fedProvisionCap is full, or ' +
            'the directory is full).'
          : 'dynamic provisioning (fedAutocreateUsers) is off on this ' +
            'relationship, so the person has to be created here first — ' +
            'through SCIM, /admin/users/new or the management API — and ' +
            'linked to the partner\'s subject.'));
    }
    // A STEP-UP THE POLICY ASKED FOR (#565, the risk design's decision 1):
    // answered here with a factor the person holds, for a person who already
    // exists — a newcomer this sign-in would create holds nothing — and only
    // once per sign-in, so a step-up that comes back still unmet is refused.
    if (!session && said.riskStepUp && decision.create !== true &&
        !result.steppedUp &&
        String(said.refusedWith || '').indexOf('STS-RISK-') === 0) {
      log.debug("Leaving FederationSp.startFederatedSession(). A step-up.");
      return this.beginStepUp(req, res, record, result, decision, assessed,
                              String(said.riskStepUp));
    }
    if (!session && String(said.refusedWith || '').indexOf('STS-RISK-') ===
        0) {
      log.info('federation: a session for ' + username + ' arriving ' +
               'through ' + record.fedId + ' was refused on risk.');
      errorCodes.mark(res, said.refusedWith === 'STS-RISK-0017'
        ? 'STS-RISK-0017' : 'STS-RISK-0016');
      log.debug("Leaving FederationSp.startFederatedSession(). Risk.");
      return this.refuse(res, record, 403, 'Authentication failed',
        'The assertion verified, and this service will not start a session ' +
        'from it.');
    }
    if (!session) {
      log.info('federation: the issuance policy refused a session for ' +
               username + ' arriving through ' + record.fedId + '.');
      errorCodes.mark(res, 'STS-FED-0044');
      log.debug("Leaving FederationSp.startFederatedSession().");
      return this.refuse(res, record, 403, 'The issuance policy refused the ' +
                                           'session',
        'The assertion verified and the partner is configured — this service ' +
        'will not start a session for ' + username + ' because the ' +
        'issuance policy said no. That is a POLICY decision rather than a ' +
        'problem with the assertion or with the partner, so retrying will ' +
        'not change it. The role an application requires is on /admin/roles ' +
        'and the document that decides is on /admin/xacml.');
    }
    log.info('federation: ' + username + ' signed in through ' +
             record.fedId +
             ' (' + protocolLabel + ' from ' + (record.fedPeer || 'an ' +
                 'unnamed partner') +
             ', ' + decision.how + '). ' + mapped.mapped.length +
             ' attribute(s) mapped, ' +
             mapped.unmapped.length + ' unmapped. Session ' + session.id + '.');
    // AN ACCOUNT THIS SIGN-IN CREATED (#565), recorded for risk scoring's
    // `network-signups`: who, from which network, when, in the failures
    // register's shape and under its own door, which no password signal
    // counts. Reached lazily, as every door reaches the risk libraries, and
    // never a reason to end the session it follows.
    if (decision.create === true && decision.how === 'created') {
      try {
        const riskFailures = require('../risk/risk_failures');
        riskFailures.recordFailure(username,
          riskFailures.FEDERATED_SIGNUP_DOOR, 'STS-RISK-0050');
      } catch (e) {
        log.debug("Caught in FederationSp.startFederatedSession(): " +
                  ((e && e.message) || e));
      }
    }
    // GROUP NAMES FROM THE PARTNER (#358), after the session exists and
    // never a reason to end it. fedSubjectGroup already ran, on an entry
    // that was in none of these groups.
    this.provisionGroups(record, username, mapped, decision);

    const returnTo = result.returnTo || '';
    const self = this;
    // THE ATTRIBUTE SOURCES A SIGN-IN READS (#94), after the partner's
    // attributes are on the entry and before the browser goes on — so a
    // source's column wins over a partner's value for an attribute both
    // name, and a refusing source that failed is this relationship's
    // refusal page rather than a session.
    this.deps.authn.afterSignIn(res, function (): void {
      if (returnTo) {
        // 303, for the reason `authn.js`'s returnToCaller() gives at length:
        // this may follow a POST carrying an assertion, and 302's behaviour
        // after a POST is historically ambiguous where 303's is defined.
        res.redirect(303, returnTo);
        return;
      }
      // THE LINKING STEP'S OUTCOME (#580) is a page of the federation
      // surface: its facts in the shell, drawn in the browser in the
      // person's language — the application's default, then their own.
      if (FederationPages.onSurface(res)) {
        FederationPages.send(res, 200, self.signedInView(record,
          Object.assign({}, mapped, { username: username }), result,
          session), { application: result.application || '',
                      own: self.deps.authn.preferredLanguageOf(username) });
        return;
      }
      // In the person's language (#539): the application they were signing
      // in to, where the login endpoint was told it, and the person.
      const t = PageLocale.forPage({ application: result.application || '',
                                     username: username });
      res.type('html').set('Cache-Control', 'no-store').send(
        self.page(t.text('handoff.federation.signedIn.title'),
                  self.signedInPage(record,
                                    Object.assign({}, mapped,
                                                  { username: username }),
                                    result, session, t), t));
    }, function (why: string): void {
      // error-code: none — afterSignIn() marked STS-ATTR-0012 on `res`
      self.refuse(res, record, 403, 'An attribute source refused the sign-in',
                  why + ' This realm\'s attribute source says a sign-in it ' +
                  'cannot read is refused, and the session was ended.');
    });
    log.debug("Leaving FederationSp.startFederatedSession(). " +
              (returnTo ? "Sending them on to " + returnTo + "."
                        : "Drawing the result page."));
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS SERVICE KNOWS ABOUT THE PARTNER'S SESSION (#167), kept on the
  // session here as `fedPartnerSession`. Everything a partner's sign-out is
  // matched against, and everything this service's own sign-out to the
  // partner is built from, and nothing else:
  //
  //   relationship, protocol, issuer    which partner, through which door
  //   nameId, nameIdFormat, nameQualifier, spNameQualifier
  //                                     SAML: the principal, WHOLE, as
  //                                     section 3.7.3.2 matches it
  //   sessionIndex                      SAML: the partner's session
  //   sub, sid                          OpenID Connect: the End-User and the
  //                                     partner's session (Back-Channel and
  //                                     Front-Channel Logout 1.0)
  //   idToken                           OpenID Connect: id_token_hint for
  //                                     RP-Initiated Logout, only while
  //                                     fedEndSessionUrl is set
  //   at                                when the partner signed them in here
  // ---------------------------------------------------------------------------
  // `email_verified: false` from the partner (#64), in the claim bag of an
  // OpenID Connect partner — a boolean there, a string where a SAML or
  // WS-Federation partner happens to send the same name.
  /**
   * Says whether the partner said `email_verified: false`, as a boolean or a
   * string.
   *
   * @param bag - the partner's claims or attributes
   * @returns whether it did
   */
  partnerDisownsMail(bag) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.partnerDisownsMail().");
    const raw = bag ? bag.email_verified : undefined;
    const value = Array.isArray(raw) ? raw[0] : raw;
    log.debug("Leaving FederationSp.partnerDisownsMail().");
    return value === false || String(value).toLowerCase() === 'false';
  }

  /**
   * Returns what this service keeps about the partner's session, which a
   * partner's sign-out is matched against and this service's own sign-out to
   * the partner is built from.
   *
   * @param record - the federation relationship
   * @param result - the verified sign-in
   * @returns the partner session: relationship, protocol, issuer and time, with
   *   the SAML NameID and session index or the OpenID Connect `sub`, `sid` and
   *   ID Token
   */
  partnerSessionOf(record, result) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.partnerSessionOf().");
    const saml = record.fedProtocol === 'saml2' ||
                 record.fedProtocol === 'wsfed';
    const oidc = record.fedProtocol === 'oidc';
    const out: any = {
      relationship: String(record.fedId || ''),
      protocol: String(record.fedProtocol || ''),
      issuer: String(result.issuer || record.fedPeer || ''),
      at: Date.now()
    };
    if (saml) {
      out.nameId = String(result.subject || '');
      out.nameIdFormat = String(result.nameFormat || '');
      out.nameQualifier = String(result.nameQualifier || '');
      out.spNameQualifier = String(result.spNameQualifier || '');
      out.sessionIndex = String(result.sessionIndex || '');
    }
    if (oidc) {
      out.sub = String(result.subject || '');
      out.sid = String(result.sid || '');
      if (result.idToken) {
        out.idToken = String(result.idToken);
      }
    }
    log.debug("Leaving FederationSp.partnerSessionOf(). " + out.protocol);
    return out;
  }

  private samlFieldsFor(record) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.samlFieldsFor().");
    const fields: any = {};
    if (record.fedProtocol === 'saml2' || record.fedProtocol === 'saml11') {
      if (record.fedPeer) fields.samlEntityId = record.fedPeer;
      if (record.fedSigningCertificate) {
        fields.samlSigningCertificate = record.fedSigningCertificate;
      }
    }
    if (record.fedProtocol === 'wsfed' &&
        record.fedPeer) fields.wsfedRealm = record.fedPeer;
    if (record.fedProtocol === 'oidc' || record.fedProtocol === 'oauth2') {
      if (record.fedClientId) fields.oauthClientId = record.fedClientId;
    }
    log.debug("Leaving FederationSp.samlFieldsFor().");
    return fields;
  }

  private bagTable(bag) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.bagTable().");
    const names = Object.keys(bag || {});
    if (!names.length) {
      log.debug("Leaving FederationSp.bagTable().");
      return '<p class="note">The assertion carried no attributes at all.</p>';
    }
    log.debug("Leaving FederationSp.bagTable().");
    return '<h2>What the partner ' +
           'sent</h2><table><tr><th>Name</th><th>Value(s)</th></tr>' +
      names.map((name) => {
        const values = Array.isArray(bag[name]) ? bag[name] : [bag[name]];
        return '<tr><td><code>' + xmlEscape(name) + '</code></td><td>' +
          values.map((v) => { return xmlEscape(String(v)); }).join('<br>') +
          '</td></tr>';
      }).join('') + '</table>';
  }

  // THE SAME PAGE'S FACTS, for the federation surface (#580): what
  // `signedInPage()` draws, with no word of it — the browser draws them from
  // the `handoff` catalogs (`federation/web_federation_views.ts`).
  private signedInView(record, mapped, result, session) {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSp.signedInView().");
    const view = {
      kind: 'signedIn', relationship: String(record.fedId),
      partner: String(record.fedName || record.fedId),
      peer: String(record.fedPeer || ''),
      protocol: String((federation.protocolRow(record.fedProtocol) ||
                        {}).label || record.fedProtocol || ''),
      subject: String(result.subject || ''),
      username: String(mapped.username || ''),
      usernamePrefixed: !!mapped.usernamePrefixed,
      usernameFrom: String(mapped.usernameFrom || ''),
      session: String((session && session.id) || ''),
      autocreate: this.autocreateOn(record),
      updates: federation.boolOf(record.fedUpdateUserAttributes, true),
      mapped: (mapped.mapped || []).map(function (one) {
        return { incoming: String(one.incoming), ldap: String(one.ldap),
                 values: (one.values || []).map(String),
                 where: String(one.where || '') };
      }),
      unmapped: (mapped.unmapped || []).map(function (one) {
        return { incoming: String(one.incoming),
                 values: (one.values || []).map(String) };
      })
    };
    log.debug("Leaving FederationSp.signedInView().");
    return view;
  }

  //
  // IN THE PERSON'S LANGUAGE (#539): `t` is the page's translator. What the
  // partner sent, the mapping's own words and the setting names are data
  // and stay as they are. No language chooser: the page is drawn by the
  // assertion consumer service, at the end of a POST or a redirect carrying
  // a one-time answer, and no GET draws it again. (The same page at the end
  // of a linking step is the federation surface's since #580:
  // `signedInView()`.)
  private signedInPage(record, mapped, result, session, t) {
    const { federation, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.signedInPage().");
    const rows = mapped.mapped.map((one) => {
      return '<tr><td><code>' + xmlEscape(one.incoming) +
        '</code></td><td><code>' +
        xmlEscape(one.ldap) + '</code></td><td>' +
        one.values.map((v) => { return xmlEscape(v); }).join('<br>') +
        '</td><td class="note">' + xmlEscape(one.where) + '</td></tr>';
    }).join('');
    const unmapped = mapped.unmapped.map((one) => {
      return '<tr><td><code>' + xmlEscape(one.incoming) + '</code></td><td ' +
                                                          'colspan="2">' +
        one.values.map((v) => { return xmlEscape(v); }).join('<br>') +
        '</td><td class="note">' +
        t.html('handoff.federation.signedIn.notWritten') + '</td></tr>';
    }).join('');
    log.debug("Leaving FederationSp.signedInPage().");
    return '<h1>' + t.html('handoff.federation.signedIn.heading',
                           { partner: record.fedName || record.fedId }) +
      '</h1><p>' +
      t.html('handoff.federation.signedIn.lead',
             { username: mapped.username, session: session.id }) +
      '</p><table><tr><th>' + t.html('handoff.federation.signedIn.what') +
      '</th><th>' + t.html('handoff.federation.signedIn.value') +
      '</th></tr><tr><td>' + t.html('handoff.federation.signedIn.partner') +
      '</td><td><code>' + (record.fedPeer ? xmlEscape(record.fedPeer)
        : t.html('handoff.federation.signedIn.unnamed')) +
      '</code></td></tr><tr><td>' +
      t.html('handoff.federation.signedIn.protocol') + '</td><td>' +
        xmlEscape((federation.protocolRow(record.fedProtocol) ||
                   {}).label || record.fedProtocol) +
        '</td></tr>' +
      '<tr><td>' + t.html('handoff.federation.signedIn.subject') +
        '</td><td><code>' + (result.subject ? xmlEscape(result.subject)
          : t.html('handoff.federation.signedIn.none')) +
        '</code></td></tr>' +
      '<tr><td>' + t.html('handoff.federation.signedIn.usernameHere') +
        '</td><td><code>' + xmlEscape(
          mapped.username) + '</code>' +
        (mapped.usernamePrefixed
          ? ' <span class="note">' +
            t.html('handoff.federation.signedIn.prefixed') + '</span>' :
         '') +
        ' <span class="note">' +
        t.html('handoff.federation.signedIn.from',
               { source: mapped.usernameFrom }) +
      '</span></td></tr><tr><td>' +
      t.html('handoff.federation.signedIn.entry') + '</td><td>' +
        (this.autocreateOn(record)
          ? t.html('handoff.federation.signedIn.created') + ' ' +
            '<a href="/admin/users">/admin/users</a>'
          : '<span class="note">' +
            t.html('handoff.federation.signedIn.neverCreated') + '</span>') +
        (federation.boolOf(record.fedUpdateUserAttributes, true)
          ? t.html('handoff.federation.signedIn.updated')
          : '<span class="note">' +
            t.html('handoff.federation.signedIn.writtenOnce') + '</span>') +
        '</td></tr></table>' +
      (rows ? '<h2>' + t.html('handoff.federation.signedIn.mappedHeading') +
        '</h2><table><tr><th>' +
        t.html('handoff.federation.signedIn.partnerSent') + '</th><th>' +
        t.html('handoff.federation.signedIn.became') + '</th><th>' +
        t.html('handoff.federation.signedIn.values') + '</th><th>' +
        t.html('handoff.federation.signedIn.decidedBy') + '</th></tr>' +
        rows + unmapped + '</table>'
        : '<h2>' + t.html('handoff.federation.signedIn.attributes') +
          '</h2><p class="note">' +
          t.html('handoff.federation.signedIn.noAttributes') + '</p>' +
          (unmapped ? '<table>' + unmapped + '</table>' : '')) +
      (mapped.unmapped.length
        ? '<p class="note">' +
          t.html('handoff.federation.signedIn.thrownAway',
                 { n: mapped.unmapped.length }) + ' <a ' +
          'href="/admin/federation?relationship=' +
          encodeURIComponent(record.fedId) +
          '">' + t.html('handoff.federation.signedIn.theRelationship') +
          '</a> ' + t.html('handoff.federation.signedIn.toKeepOne') + '</p>'
        : '') +
      '<p><a href="' + BASE_PATH + '">' +
      t.html('handoff.federation.signedIn.backToIndex') + '</a> · ' +
      '<a href="/admin/federation?relationship=' + encodeURIComponent(
          record.fedId) +
      '">' + t.html('handoff.federation.signedIn.inConsole') + '</a></p>';
  }

  // Where to come back to, validated. See decision 4 — the check catches a
  // caller's bug and the server-side storage catches an attacker, and both are
  // wanted because they fail differently.
  private returnToOf(raw) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.returnToOf().");
    const text = String(raw || '');
    if (!text) {
      log.debug("Leaving FederationSp.returnToOf().");
      return '';
    }
    if (text.charAt(0) !== '/' || text.charAt(1) === '/') {
      log.warn('federation: refused a returnTo of "' + text + '" — it must ' +
               'be a path on this service. The sign-in continues and ends on ' +
               'the result page instead.');
      log.debug("Leaving FederationSp.returnToOf().");
      return '';
    }
    log.debug("Leaving FederationSp.returnToOf().");
    return text;
  }

  // ---------------------------------------------------------------------------
  // SAML 2.0: the <AuthnRequest>.
  //
  // It names `AssertionConsumerServiceURL` explicitly rather than relying on
  // the partner having our metadata, because a partner that HAS our metadata
  // ignores the parameter and one that does not would otherwise have nowhere to
  // send the answer. `ProtocolBinding` asks for HTTP-POST always: a Response on
  // the Redirect binding is DEFLATEd into a URL, and a signed assertion of a
  // few kilobytes does not reliably fit in one.
  // ---------------------------------------------------------------------------
  private authnRequestXml(base, record) {
    const {
      federation, documentSettings, stsCrypto, log, logArtifact, STS,
      xmlEscape, iso
    } = this.deps;
    log.debug("Entering FederationSp.authnRequestXml().");
    const id = '_' + stsCrypto.randomBytes(16).toString('hex');
    const xml =
      '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" xmlns:saml="' +
        NS_SAML + '" ' +
        'ID="' + id + '" Version="2.0" IssueInstant="' + iso(0) + '"' +
        ' Destination="' + xmlEscape(record.fedSsoUrl) + '"' +
        ' ProtocolBinding="' + BINDING_POST + '"' +
        ' AssertionConsumerServiceURL="' + xmlEscape(
            this.acsUrl(base, record)) + '"><saml:Issuer>' +
        xmlEscape(this.ourEntityId(base, record)) +
        '</saml:Issuer><samlp:NameIDPolicy ' +
        'AllowCreate="true"/></samlp:AuthnRequest>';
    logArtifact('federated SAML 2.0 AuthnRequest', 'before signing', xml);
    if (!federation.boolOf(record.fedSignRequest, false)) {
      log.debug("Leaving FederationSp.authnRequestXml(). Unsigned. id=" + id);
      return { id: id, xml: xml };
    }
    // AFTER the Issuer, which is where the schema puts a signature on a request
    // and where a partner will look for it. A signer with no placement appends
    // it to the document element instead, which is schema-invalid and which
    // several identity providers refuse without saying why.
    // The configured algorithms since 2026-09-12 — see
    // saml/document_settings.ts.
    const how = documentSettings.signatureOptions();
    const signed = stsCrypto.signXml(xml, {
      // The XML signing key (#42, D2): `STS.xml`, not the JOSE key — and
      // `STS.xmlSigner`, the one for the configured algorithm (#68).
      privateKeyPem: STS.xmlSigner.privateKeyPem,
      privateKey: STS.xmlSigner.privateKey,
      certPem: STS.xmlSigner.certPem,
      sigAlg: how.sigAlg,
      c14nAlg: how.c14nAlg,
      placement: stsCrypto.PLACEMENT.AFTER_ISSUER,
      refUri: '#' + id,
      what: 'federated SAML 2.0 AuthnRequest'
    });
    logArtifact('federated SAML 2.0 AuthnRequest', 'after signing', signed);
    log.debug("Leaving FederationSp.authnRequestXml(). Signed. id=" + id);
    return { id: id, xml: signed };
  }

  // The HTTP POST binding as a REAL FORM WITH A REAL BUTTON. See the note above
  // STYLE: this is the one place in this service where a self-posting form
  // would have been the obvious thing and is deliberately not done, because the
  // person is leaving this service for somebody else's and a deliberate click
  // is worth having there. It also means this feature adds no CSP relaxation at
  // all.
  //
  // IN THE PERSON'S LANGUAGE (#539): the application they were signing in
  // to, where the login endpoint was told it. With a language chooser, since
  // this page waits for a click: the GET that drew it draws it again, with a
  // fresh request and context — the one on the page it replaces is simply
  // never used, and expires.
  private postBindingPage(action, fields, record, application) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.postBindingPage().");
    const t = PageLocale.forPage({ application: application || '' });
    const inputs = Object.keys(fields).map((name) => {
      return '<input type="hidden" name="' + xmlEscape(name) + '" value="' +
        xmlEscape(String(fields[name])) + '">';
    }).join('');
    const names = Object.keys(fields);
    // Two fields — SAMLRequest and RelayState — is the one case there is;
    // any other count is named as a list, rather than a sentence assumed.
    const posts = names.length === 2
      ? t.html('handoff.federation.continueTo.postsTwo',
               { first: names[0], second: names[1] })
      : t.html('handoff.federation.continueTo.postsList',
               { fields: names.join(', ') });
    const partner = record.fedName || record.fedId;
    log.debug("Leaving FederationSp.postBindingPage().");
    return this.page(t.text('handoff.federation.continueTo.title',
                            { partner: partner }),
      PageLocale.chooser(t, realms.currentPrefix(),
        // The start's own parameters, and no others (`herePath()`).
        PageLocale.herePath(realms.currentPrefix() + LOGIN_PATH + '/' +
                            encodeURIComponent(record.fedId),
                            ['returnTo', 'return_to', 'authn',
                             'application'])) +
      '<h1>' + t.html('handoff.federation.continueTo.title',
                      { partner: partner }) + '</h1>' +
      '<p>' + t.html('handoff.federation.continueTo.lead',
                     { url: record.fedSsoUrl }) + ' ' + posts +
      '</p><p class="note">' + t.html('handoff.federation.continueTo.note') +
      '</p><form method="post" ' +
      'action="' + xmlEscape(action) + '">' + inputs +
      '<button type="submit">' + t.html('handoff.federation.continueToIdp') +
      '</button></form>', t);
  }

  // ---------------------------------------------------------------------------
  // THE OAUTH 2.0 / OIDC AUTHORIZATION REQUEST.
  //
  // PKCE is ALWAYS sent, in both protocols and whatever the partner advertises.
  // RFC 9700 section 2.1.1 requires it of a public client and recommends it of
  // every client, a partner that does not understand `code_challenge` ignores
  // an unknown parameter as RFC 6749 section 3.1 requires, and this service is
  // exactly the kind of client the requirement is about — the code comes back
  // on a redirect a browser followed. There is no setting to turn it off, and
  // that is the point: the one thing worse than not sending PKCE is a flag that
  // stops.
  // ---------------------------------------------------------------------------
  private authorizationRequestUrl(base, record, context) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.authorizationRequestUrl().");
    const params = this.authorizationParams(base, record, context);
    const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
    const url = String(record.fedSsoUrl) + joiner + params.toString();
    log.debug("Leaving FederationSp.authorizationRequestUrl().");
    return url;
  }

  // The authorization request's parameters, for the query or — for an OP
  // discovered through a federation (#134) — for a signed request object.
  private authorizationParams(base, record, context) {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSp.authorizationParams().");
    const responseType = String(record.fedResponseType || 'code');
    const params = new URLSearchParams();
    params.set('response_type', responseType);
    params.set('client_id', String(record.fedClientId || ''));
    params.set('redirect_uri', this.acsUrl(base, record));
    params.set('state', context.handle);
    if (record.fedScope) params.set('scope', String(record.fedScope));
    if (record.fedProtocol === 'oidc') {
      params.set('nonce', context.nonce);
      if (responseType !== 'code') {
        // An ID Token cannot come back on a query string — it would be in the
        // browser's history, in the Referer of everything that page loads, and
        // in every proxy log between here and there. form_post is OIDC's own
        // answer and is the same argument RFC 9700 section 4.3 makes for the
        // authorization response this service ISSUES.
        params.set('response_mode', 'form_post');
      }
    }
    if (responseType === 'code') {
      params.set('code_challenge', context.pkceChallenge);
      params.set('code_challenge_method', 'S256');
      // THE CODE BY FORM POST (#565, OAuth 2.0 Form Post Response Mode),
      // which Sign in with Apple requires when a name or an address is
      // asked for.
      if (String(record.fedResponseMode || '') === 'form_post') {
        params.set('response_mode', 'form_post');
      }
    }
    // THE TIKTOK ADAPTER (#565): its authorization endpoint calls the client
    // id `client_key`, and reads nothing else.
    if (consumerProviders.adapts(record, 'tiktok-client-key')) {
      params.set('client_key', String(record.fedClientId || ''));
      params.delete('client_id');
    }
    // THE PROVIDER'S EXTRA PARAMETERS (#565), never one set above: an
    // `ldapmodify` could write a reserved name the console refuses, so it is
    // skipped here too — the WHOLE reserved list, not only what this flow
    // happened to set, since a `response_mode` or `code_challenge_method`
    // this flow leaves out is still this service's to decide.
    const reserved: string[] = federation.RESERVED_AUTHORIZE_PARAMS || [];
    [].concat(record.fedAuthorizeParams || []).forEach(function (one) {
      const text = String(one || '');
      const at = text.indexOf('=');
      const name = at > 0 ? text.slice(0, at).trim() : '';
      if (name && !params.has(name) &&
          reserved.indexOf(name.toLowerCase()) < 0) {
        params.set(name, text.slice(at + 1));
      }
    });
    log.debug("Leaving FederationSp.authorizationParams(). " +
              'response_type=' + responseType);
    return params;
  }

  private pkcePair() {
    const { log } = this.deps;
    log.debug("Entering FederationSp.pkcePair().");
    const verifier = stsCrypto.randomBytes(32).toString('base64url');
    const challenge = stsCrypto.digest('sha256', verifier, 'base64url');
    log.debug("Leaving FederationSp.pkcePair().");
    return { verifier: verifier, challenge: challenge };
  }

  // ---------------------------------------------------------------------------
  // GET /federation/login/{id}
  // ---------------------------------------------------------------------------
  private loginEndpoint(req, res) {
    const {
      federation, errorCodes, log, xmlEscape, baseUrlOf, randomId
    } = this.deps;
    log.debug("Entering the federation login endpoint. id=" + req.params.id);
    // A PAGE OF THE FEDERATION SURFACE (#580): what this endpoint SAYS — it
    // will not start a sign-in — is the shell, drawn in the browser. Where
    // it starts one it answers the redirect or the POST binding's form, as
    // it always did.
    FederationPages.mark(res);
    if (!this.enabled()) {
      errorCodes.mark(res, 'STS-FED-0001');
      FederationPages.send(res, 404, FederationPages.notHereView('off'));
      log.debug("Leaving the federation login endpoint. Federation is off.");
      return;
    }
    const id = String(req.params.id || '');
    const record = federation.get(id);
    if (!record) {
      errorCodes.mark(res, 'STS-FED-0002');
      FederationPages.send(res, 404,
                           FederationPages.notHereView('noRelationship', id));
      log.debug("Leaving the federation login endpoint. No such relationship.");
      return;
    }
    if (record.fedRole !== 'service-provider') {
      errorCodes.mark(res, 'STS-FED-0004');
      return this.refuse(res, null, 400, 'That relationship goes the other way',
        '"' + id + '" is an identity-provider-side relationship: this ' +
        'service ASSERTS to that partner rather than consuming from it. ' +
        'There is nothing to sign in to here. A partner this service both ' +
        'consumes from and asserts to is two relationships — see ' +
        'federation/CLAUDE.md.');
    }
    // A PARTNER THAT ONLY SENDS SHARED SIGNALS (#374) has nowhere to send
    // anybody: it is a transmitter, and nothing more.
    if (!federation.signsIn(record)) {
      errorCodes.mark(res, 'STS-FED-0155');
      log.debug("Leaving the federation login endpoint. Signals only.");
      return this.refuse(res, record, 400, 'That partner signs nobody in',
        '"' + id + '" is an ssf relationship: the partner sends this ' +
        'service Shared Signals, and signs nobody in.');
    }
    if (!federation.isEnabled(record)) {
      errorCodes.mark(res, 'STS-FED-0005');
      return this.refuse(res, record, 403, 'That relationship is disabled',
        'It exists and is configured, and fedEnabled is FALSE. ' +
        'Every relationship is created disabled deliberately: a partner that ' +
        'half-exists and silently accepts assertions is the failure this ' +
        'whole register is arranged to prevent. Enable it on ' +
        '/admin/federation.');
    }
    // A CONSUMER PROVIDER IN A REALM THAT HAS THEM OFF (#565), named by its
    // own code rather than as a missing field.
    if (federation.categoryOf(record) === 'consumer' &&
        !federation.consumerProvidersOn()) {
      errorCodes.mark(res, 'STS-FED-0175');
      return this.refuse(res, record, 403, 'Consumer providers are off here',
        'This relationship is a consumer or social provider, and this ' +
        'realm has federation.consumerProviders off.');
    }
    const readiness = federation.readinessOf(record);
    if (!readiness.ready) {
      errorCodes.mark(res, 'STS-FED-0006');
      return this.refuse(res, record, 409, 'That relationship is not fully ' +
                                           'configured',
        'It is enabled, but ' + readiness.missing.join(', ') + ' ' +
        (readiness.missing.length === 1 ? 'is' : 'are') + ' still empty. It ' +
        'refuses rather than half-working — a federated sign-in that got ' +
        'half way and produced a session would be the worst possible outcome.');
    }

    const base = baseUrlOf(req);
    const returnTo = this.returnToOf(req.query.returnTo || req.query.return_to);
    const pkce = this.pkcePair();
    const contextRecord: any = {
      id: record.fedId, protocol: record.fedProtocol, returnTo: returnTo,
      // THE SIGN-IN SCREEN'S PENDING RECORD (#98 D9), named by `authn.ts` in
      // a service deployed as cells: where the flow STARTED, should the
      // partner assert a person homed in another cell (completeSignIn()).
      // Only an id; the record stays in the sign-in service's store.
      authnPending: /^[A-Za-z0-9_-]{1,64}$/.test(String(req.query.authn || ''))
        ? String(req.query.authn) : '',
      // WHAT THE PERSON WAS SIGNING IN TO, carried across the round trip so
      // that completeSignIn() can move the relationship's per-application
      // counts.
      //
      // IT IS HERE BECAUSE THERE IS NOWHERE ELSE IT COULD BE. What comes back
      // to `/federation/acs/{id}` is a signed document about a PERSON: it names
      // the partner, the subject and the attributes, and it says nothing
      // whatever about the application at this end — there is no field in any
      // of the five protocols for one. `authn.js` knows the pair at the moment
      // it sends the browser away and never again, so either it rides on the
      // context or the number cannot be had at all.
      //
      // TRUNCATED, AND NOT TRUSTED. It is a query parameter on an endpoint that
      // — alone in this module — needs no configuration at all to reach, so it
      // is bounded here against a context whose size somebody else chose, and
      // `federation.recordUse()` checks the pair against the live register
      // before writing anything anywhere. Neither check is sufficient alone:
      // this one bounds the MAP, that one bounds the DIRECTORY.
      application: String(req.query.application || '')
        .slice(0, this.maxApplicationLength()),
      nonce: 'n-' + randomId(16),
      pkceVerifier: pkce.verifier, pkceChallenge: pkce.challenge
    };

    if (record.fedProtocol === 'saml2') {
      const built = this.authnRequestXml(base, record);
      contextRecord.requestId = built.id;
      const handle = this.putContext(contextRecord);
      if (String(record.fedBinding || 'HTTP-Redirect') === 'HTTP-POST') {
        res.type('html').set('Cache-Control', 'no-store').send(
          this.postBindingPage(record.fedSsoUrl,
                          { SAMLRequest: Buffer.from(built.xml, 'utf8')
                                               .toString('base64'),
                            RelayState: handle },
                          record, contextRecord.application));
        log.debug("Leaving the federation login endpoint. SAML 2.0 over HTTP " +
                  'POST.');
        return;
      }
      // HTTP Redirect: DEFLATE with no zlib header (saml-bindings section
      // 3.4.4.1), then base64, then URL-encode. The request is NOT signed on
      // this binding even when fedSignRequest is on, and that is stated rather
      // than silently dropped: the Redirect binding signs the QUERY STRING with
      // a `Signature` parameter rather than carrying an enveloped ds:Signature,
      // which is a different construction — a partner wanting a signed request
      // should be sent one on the POST binding.
      if (federation.boolOf(record.fedSignRequest, false)) {
        log.warn('federation: ' + record.fedId + ' asks for a signed ' +
                 'AuthnRequest and uses the HTTP Redirect binding, whose ' +
                 'signature is over the QUERY STRING rather than enveloped ' +
                 'in the XML. This service does not build that construction, ' +
                 'so the request goes UNSIGNED. Use HTTP-POST for a signed ' +
                 'request.');
      }
      const deflated = zlib.deflateRawSync(Buffer.from(built.xml, 'utf8'))
                           .toString('base64');
      const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
      const url = record.fedSsoUrl + joiner + 'SAMLRequest=' +
        encodeURIComponent(deflated) +
        '&RelayState=' + encodeURIComponent(handle);
      res.redirect(302, url);
      log.debug("Leaving the federation login endpoint. SAML 2.0 over HTTP " +
                'Redirect.');
      return;
    }

    if (record.fedProtocol === 'saml11') {
      // NO REQUEST MESSAGE. SAML 1.1's browser profiles are
      // identity-provider-initiated: what the browser is sent to is the
      // partner's inter-site transfer service carrying a TARGET, which is where
      // the partner sends them AFTERWARDS. So the handle rides on TARGET rather
      // than on a RelayState, and the response comes back with no InResponseTo
      // to match — which is why fedAllowUnsolicited is forced on for this
      // protocol.
      //
      // AND `shire` BESIDE IT, WHICH IS NOT DECORATION. Shibboleth's parameter
      // for the assertion consumer service — where the <Response> is POSTed, as
      // distinct from where the person goes afterwards. Without it a partner
      // decides the destination for itself, and one that has this service
      // REGISTERED posts to the registered address: the same path with the
      // `fedctx` query STRIPPED, because a registration holds a URL and not a
      // per-flow handle. The assertion then verifies, the sign-in completes,
      // and the person lands on this service's "signed in" page instead of
      // going back to the application that started the flow — a federation that
      // works perfectly and never returns. Sending both is what a real SAML 1.1
      // service provider does, and it makes the flow independent of what is
      // registered at the far end.
      //
      // AND `providerId` WHEN THE CONFIGURED URL DOES NOT ALREADY CARRY ONE
      // (2026-09-12). It is Shibboleth's parameter for the relying party naming
      // itself, and SAML 1.1 has no other: without it a partner guesses the
      // audience — this service's own identity provider takes the ORIGIN of the
      // TARGET — and the assertion comes back audienced to a bare origin. That
      // was accepted with a warning until the audience check below became a
      // refusal, so it is sent now as ourEntityId(), which is what that check
      // compares against. A fedSsoUrl that names a providerId of its own is
      // left alone: the operator said what the partner calls us, and a second
      // parameter would arrive as an array at most servers.
      const handle = this.putContext(contextRecord);
      const target = this.acsUrl(base, record) + '?fedctx=' +
                     encodeURIComponent(handle);
      const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
      const namesProvider = /[?&]providerId=/.test(String(record.fedSsoUrl));
      const url = record.fedSsoUrl + joiner + 'TARGET=' +
        encodeURIComponent(target) +
        '&shire=' + encodeURIComponent(target) +
        (namesProvider ? '' :
         '&providerId=' + encodeURIComponent(this.ourEntityId(base, record)));
      res.redirect(302, url);
      log.debug("Leaving the federation login endpoint. SAML 1.1 inter-site " +
                'transfer.');
      return;
    }

    if (record.fedProtocol === 'wsfed') {
      const handle = this.putContext(contextRecord);
      const params = new URLSearchParams();
      params.set('wa', 'wsignin1.0');
      params.set('wtrealm', this.ourEntityId(base, record));
      params.set('wreply', this.acsUrl(base, record));
      params.set('wctx', handle);
      // section 13.2.1's wct — the current time — which several identity
      // providers use to decide whether the request is fresh.
      params.set('wct', new Date().toISOString());
      const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
      res.redirect(302, record.fedSsoUrl + joiner + params.toString());
      log.debug("Leaving the federation login endpoint. WS-Federation " +
                'wsignin1.0.');
      return;
    }

    // An OP DISCOVERED THROUGH AN OPENID FEDERATION (#134): resolved to the
    // relationship's Trust Anchor, and asked with a signed request object
    // under this realm's own Entity Identifier — automatic registration.
    const rp = this.deps.oidfedRp();
    if (rp.isFederated(record)) {
      rp.effectiveRecord(req, record).then((got) => {
        if (!got.ok) {
          // error-code: none — the resolution's own code, in got.code
          errorCodes.mark(res, String(got.code || 'STS-FED-0148'));
          log.debug("Leaving the federation login endpoint. Not resolved.");
          return this.refuse(res, record, 502, 'The OpenID Provider could ' +
                             'not be trusted', String(got.why));
        }
        const handle = this.putContext(contextRecord);
        const params = this.authorizationParams(base, got.record,
                                                this.heldContext(handle));
        return rp.authorizationRequestUrl(got.record, params)
          .then(function (url) {
            res.redirect(302, url);
            log.debug("Leaving the federation login endpoint. A signed " +
                      "request to an OP in the federation.");
          });
      }).catch((e) => {
        log.error(errorCodes.tag('STS-FED-0042') + 'federation: ' + id +
                  ' threw while starting a federated sign-in: ' +
                  (e && e.stack ? e.stack : e));
        errorCodes.mark(res, 'STS-FED-0042');
        this.refuse(res, record, 500, 'This service failed while starting ' +
                    'the sign-in', String((e && e.message) || e));
      });
      log.debug("Leaving the federation login endpoint. Resolving the OP.");
      return;
    }

    // OIDC and OAuth 2.0.
    const handle = this.putContext(contextRecord);
    const stored = this.heldContext(handle);
    res.redirect(302, this.authorizationRequestUrl(base, record, stored));
    log.debug("Leaving the federation login endpoint. " + record.fedProtocol +
              ' authorization request.');
  }

  private paramsOf(req) {
    const { log, parseBody } = this.deps;
    log.debug("Entering FederationSp.paramsOf(). method=" + req.method);
    const out = {};
    Object.keys(req.query || {}).forEach((k) => { out[k] = req.query[k]; });
    if (req.method === 'POST') {
      const body = parseBody(req);
      Object.keys(body).forEach((k) => { out[k] = body[k]; });
    }
    log.debug("Leaving FederationSp.paramsOf(). " + Object.keys(out).length +
              ' parameter(s).');
    return out;
  }

  // ---------------------------------------------------------------------------
  // A PARTNER'S ENCRYPTED ASSERTION (#168): the token a SAML Response or a
  // WS-Federation RequestedSecurityToken carries, opened.
  //
  // `container` is the element whose CHILDREN are the token — the Response,
  // or the RequestedSecurityToken — and what may be there is ONE of a plain
  // `<Assertion>`, a `<saml:EncryptedAssertion>` (SAML 2.0 core section
  // 2.3.4) or, inside an RSTR, a bare `<xenc:EncryptedData>`. Two of them is
  // refused (STS-FED-0147): which one the signature was over and which one
  // was read would otherwise be a choice, and that choice is how a wrapping
  // attack begins.
  //
  // Answers `{ assertion, assertionXml, encrypted }` — `assertionXml` is the
  // document the ASSERTION's signature is verified in, which for an encrypted
  // one is its own plaintext: signed first, then encrypted, so the signature
  // is inside the ciphertext and is checked on what was decrypted. A
  // Response's own signature is checked on the document as it arrived, and
  // covers the ciphertext. Or `{ refused: true }` once a page is drawn.
  // ---------------------------------------------------------------------------
  private openToken(res, record, container, whole, what) {
    const { federation, errorCodes, fedEncryption, log } = this.deps;
    log.debug("Entering FederationSp.openToken(). " + what);
    const children = [];
    const kids = container ? container.childNodes : [];
    for (let i = 0; kids && i < kids.length; i++) {
      const name = kids[i].nodeType === 1 ? kids[i].localName : '';
      if (name === 'Assertion' || name === 'EncryptedAssertion' ||
          name === 'EncryptedData') {
        children.push(kids[i]);
      }
    }
    const plain = children.filter(function (el) {
      return el.localName === 'Assertion';
    });
    const sealed = children.filter(function (el) {
      return el.localName !== 'Assertion';
    });
    if (!children.length) {
      errorCodes.mark(res, 'STS-FED-0011');
      log.debug("Leaving FederationSp.openToken(). No assertion.");
      this.refuse(res, record, 400, 'There is no assertion in it',
        'The ' + what + ' carried no <Assertion> and no ' +
        '<EncryptedAssertion>. That is a partner answering success with ' +
        'nothing in it.');
      return { refused: true };
    }
    if (sealed.length && (children.length > 1)) {
      errorCodes.mark(res, 'STS-FED-0147');
      log.debug("Leaving FederationSp.openToken(). More than one token.");
      this.refuse(res, record, 400, 'It carries more than one assertion',
        'The ' + what + ' carries ' + children.length + ' assertions, at ' +
        'least one of them encrypted. Which one a signature covered and ' +
        'which one was read must not be a choice, so a response carrying ' +
        'an encrypted assertion must carry exactly one.');
      return { refused: true };
    }
    if (!sealed.length) {
      // PLAINTEXT, which product refuses unless the relationship says
      // otherwise (`mode.acceptsUnencryptedFederatedAssertions()`).
      if (federation.encryptionRequired(record)) {
        errorCodes.mark(res, 'STS-FED-0140');
        log.debug("Leaving FederationSp.openToken(). Plaintext, refused.");
        this.refuse(res, record, 401, 'The assertion is not encrypted',
          'This relationship requires the partner to ENCRYPT the assertion ' +
          'to its key, and this one arrived in clear — so the person\'s ' +
          'identifier and attributes crossed their browser readable. ' +
          'Configure the partner with the encryption certificate in this ' +
          'relationship\'s metadata. (Product mode requires encryption; ' +
          'fedAllowUnencrypted on the relationship accepts plaintext, and ' +
          'its warning says what that costs.)');
        return { refused: true };
      }
      log.debug("Leaving FederationSp.openToken(). A plaintext assertion.");
      return { assertion: plain[0], assertionXml: whole, encrypted: false };
    }
    if (!federation.encrypts(record)) {
      errorCodes.mark(res, 'STS-FED-0011');
      log.debug("Leaving FederationSp.openToken(). Encrypted, SAML 1.1.");
      this.refuse(res, record, 400, 'There is no assertion in it',
        'The ' + what + ' carries an encrypted assertion, and a SAML 1.1 ' +
        'relationship has no encryption construct to decrypt one with — ' +
        'SAML 1.1 defines none.');
      return { refused: true };
    }
    const opened = fedEncryption.decryptXml(record,
      new XMLSerializer().serializeToString(sealed[0]));
    if (!opened.ok) {
      errorCodes.mark(res, opened.code);
      log.debug("Leaving FederationSp.openToken(). " + opened.code);
      this.refuse(res, record, opened.code === 'STS-FED-0137' ? 500 : 401,
        opened.code === 'STS-FED-0139'
          ? 'It is encrypted with an algorithm this relationship refuses'
          : (opened.code === 'STS-FED-0137'
              ? 'There is no key to decrypt it with'
              : 'The assertion could not be decrypted'),
        opened.why);
      return { refused: true };
    }
    let doc = null;
    try {
      doc = new DOMParser().parseFromString(opened.xml, 'text/xml');
    } catch (e) {
      log.debug("Caught in FederationSp.openToken(): " +
                ((e && e.message) || e));
      doc = null;
    }
    const assertion = doc && doc.documentElement;
    if (!assertion || assertion.localName !== 'Assertion') {
      errorCodes.mark(res, 'STS-FED-0011');
      log.debug("Leaving FederationSp.openToken(). No assertion inside.");
      this.refuse(res, record, 400, 'There is no assertion in it',
        'The encrypted element decrypted, and what was inside it is not a ' +
        'self-contained <Assertion>.');
      return { refused: true };
    }
    log.info('federation: ' + record.fedId + ': the ' + what + '\'s ' +
             'assertion was decrypted (' + opened.algorithm + ', key ' +
             opened.kid + ').');
    log.debug("Leaving FederationSp.openToken(). Decrypted.");
    return { assertion: assertion, assertionXml: opened.xml, encrypted: true };
  }

  // ---------------------------------------------------------------------------
  // THE ENCRYPTED PARTS OF AN ASSERTION (#168): an `<EncryptedID>` where the
  // NameID would be (SAML 2.0 core section 2.2.4) and an
  // `<EncryptedAttribute>` beside the attributes (section 2.7.3.2), each
  // decrypted and put in the place of the element that carried it — ONLY
  // AFTER the signature has verified, because the signature is over the
  // ciphertext and replacing it first would verify nothing. Answers true, or
  // false once a page is drawn.
  // ---------------------------------------------------------------------------
  private openEncryptedParts(res, record, assertion) {
    const { errorCodes, fedEncryption, log } = this.deps;
    log.debug("Entering FederationSp.openEncryptedParts().");
    const found = [];
    const all = assertion.getElementsByTagName('*');
    for (let i = 0; i < all.length; i++) {
      if (all[i].localName === 'EncryptedID' ||
          all[i].localName === 'EncryptedAttribute') {
        found.push(all[i]);
      }
    }
    for (let i = 0; i < found.length; i++) {
      const el = found[i];
      const wanted = el.localName === 'EncryptedID' ? ['NameID', 'BaseID']
                                                    : ['Attribute'];
      const opened = fedEncryption.decryptXml(record,
        new XMLSerializer().serializeToString(el));
      let inner = null;
      if (opened.ok) {
        inner = this.fragmentOf(opened.xml);
      }
      if (!opened.ok || !inner || wanted.indexOf(inner.localName) < 0) {
        const code = opened.ok ? 'STS-FED-0138' : opened.code;
        errorCodes.mark(res, code);
        log.debug("Leaving FederationSp.openEncryptedParts(). " + code);
        this.refuse(res, record, code === 'STS-FED-0137' ? 500 : 401,
          'An encrypted ' + (el.localName === 'EncryptedID'
            ? 'identifier' : 'attribute') + ' could not be read',
          opened.ok ? 'It decrypted to something that is not a ' +
                      wanted.join(' or ') + '.'
                    : opened.why);
        return false;
      }
      const imported = assertion.ownerDocument.importNode(inner, true);
      el.parentNode.replaceChild(imported, el);
    }
    log.debug("Leaving FederationSp.openEncryptedParts(). " + found.length +
              " opened.");
    return true;
  }

  // A decrypted fragment as an element: parsed as it stands, and otherwise
  // inside a container declaring the prefixes a SAML fragment may inherit —
  // `common/crypto.js`'s parsesAsFragment() makes the same allowance, for the
  // same NamespaceError.
  private fragmentOf(xml) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.fragmentOf().");
    const attempts = [xml, '<x xmlns:saml="' + NS_SAML + '" xmlns:samlp="' +
                            NS_SAMLP + '">' + xml + '</x>'];
    for (let i = 0; i < attempts.length; i++) {
      try {
        const doc = new DOMParser().parseFromString(attempts[i], 'text/xml');
        const root = doc && doc.documentElement;
        if (root && i === 0) {
          log.debug("Leaving FederationSp.fragmentOf(). As it stands.");
          return root;
        }
        const kids = root ? root.childNodes : [];
        for (let k = 0; kids && k < kids.length; k++) {
          if (kids[k].nodeType === 1) {
            log.debug("Leaving FederationSp.fragmentOf(). Wrapped.");
            return kids[k];
          }
        }
      } catch (e) {
        log.debug("Caught in FederationSp.fragmentOf(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving FederationSp.fragmentOf(). Not XML.");
    return null;
  }

  // ---------------------------------------------------------------------------
  // A SAML RESPONSE, 2.0 or 1.1, verified check by check.
  //
  // Every check is made and the FIRST failure refuses. That is deliberately not
  // the shape the mock relying parties used (deleted, #592) — their whole job
  // was to report every check to a person reading the page, so they collected
  // verdicts and showed them all. THIS endpoint issues a session, so
  // it stops at the first thing that is wrong: continuing past a failed
  // signature in order to report the audience as well would mean parsing an
  // unverified document to build a nicer error page.
  // ---------------------------------------------------------------------------
  private consumeSamlResponse(req, res, record, params, version) {
    const {
      config, federation, errorCodes, log, logArtifact, xmlEscape,
      firstByLocal, textByLocal, baseUrlOf
    } = this.deps;
    log.debug("Entering FederationSp.consumeSamlResponse(). version=" +
              version);
    const encoded = String(params.SAMLResponse || '');
    // A <LogoutRequest> SENT TO THE ASSERTION CONSUMER SERVICE (#167): a
    // partner whose single logout service was configured as the ACS. Refused
    // here, as a wsignout1.0 is, and pointed at the path that consumes it.
    if (!encoded && params.SAMLRequest) {
      errorCodes.mark(res, 'STS-FED-0024');
      log.debug("Leaving FederationSp.consumeSamlResponse(). A SAMLRequest " +
                "at the ACS.");
      return this.refuse(res, record, 400, 'That is a sign-out, and this is ' +
                                           'the sign-in endpoint',
        'A SAMLRequest arrived at the assertion consumer service for "' +
        record.fedId + '". A partner\'s <LogoutRequest> is consumed at ' +
        this.sloUrl(baseUrlOf(req), record) + ' — this relationship\'s ' +
        'SingleLogoutService, published in its metadata. Configure that ' +
        'address at the partner.');
    }
    if (!encoded) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). No SAMLResponse.");
      errorCodes.mark(res, 'STS-FED-0007');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 400, 'Nothing arrived',
        'This is the assertion consumer service for "' + record.fedId + '" ' +
        'and the request carried no SAMLResponse. A browser that reached it ' +
        'by hand will see this; so will a partner configured to send its ' +
        'answer somewhere else.');
    }
    let xml = '';
    try {
      xml = Buffer.from(encoded, 'base64').toString('utf8');
    } catch (e) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). Not base64.");
      errorCodes.mark(res, 'STS-FED-0008');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 400, 'The SAMLResponse is not base64',
                    'It could not be decoded: ' + e.message);
    }
    logArtifact('federated SAML ' + version + ' Response', 'as received', xml);

    let doc = null;
    try {
      doc = new DOMParser().parseFromString(xml, 'text/xml');
    } catch (e) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). Not XML.");
      errorCodes.mark(res, 'STS-FED-0009');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 400, 'The SAMLResponse is not XML',
                         e.message);
    }
    const root = doc && doc.documentElement;
    if (!root) {
      errorCodes.mark(res, 'STS-FED-0009');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 400, 'The SAMLResponse is empty',
                    'It decoded to something with no document element.');
    }

    // The status FIRST, because a partner that refused to authenticate somebody
    // sends a perfectly well-formed Response with no assertion in it, and
    // reporting that as "no assertion" would send somebody looking for a bug in
    // this service.
    const statusEl = firstByLocal(root, 'StatusCode');
    const status = statusEl ? (statusEl.getAttribute('Value') || '') : '';
    const statusMessage = textByLocal(root, 'StatusMessage') || '';
    const succeeded = version === '2.0'
      ? status === STATUS_SUCCESS
      : /Success$/.test(status);
    if (!succeeded) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). The partner " +
                'refused.');
      errorCodes.mark(res, 'STS-FED-0010');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 400, 'The partner refused to ' +
                                           'authenticate them',
        'It answered ' + (status || '(no StatusCode)') +
        (statusMessage ? ' — "' + statusMessage + '"' : '') +
        '. That is the partner\'s answer, not this service\'s: nothing here ' +
        'was asked to accept or refuse anything.');
    }

    // THE ASSERTION, decrypted where the partner encrypted it (#168) — and
    // refused in clear where this relationship requires encryption.
    const token: any = this.openToken(res, record, root, xml, 'Response');
    if (token.refused) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). The token.");
      return undefined;
    }
    const assertion = token.assertion;

    // THE SIGNATURE. Either the Response or the Assertion may carry it and
    // either is enough — which is what every real service provider accepts,
    // because AD FS signs the assertion, Keycloak signs both and Shibboleth
    // signs the response. What is NOT enough is neither. An ENCRYPTED
    // assertion's own signature is inside the ciphertext and is verified on
    // the plaintext; the Response's covers the ciphertext as it arrived.
    const assertionSig = this.verifyXmlSignature(token.assertionXml, record,
                                                 'Assertion');
    const responseSig = this.verifyXmlSignature(xml, record, 'Response');
    if (!assertionSig.ok && !responseSig.ok) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). The signature " +
                'did not verify.');
      errorCodes.mark(res, !this.certPemOf(record) ? 'STS-FED-0014'
        : ((!assertionSig.present && !responseSig.present) ? 'STS-FED-0012' :
            'STS-FED-0013'));
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 401, 'The signature did not verify',
        (!assertionSig.present && !responseSig.present)
          ? 'Neither the <Response> nor the <Assertion> carries a ' +
            'ds:Signature at all. An unsigned assertion is an ' +
            'unauthenticated HTTP request with XML in it, and this is the ' +
            'one endpoint in this service where that cannot be accepted.'
          : 'The Assertion: ' +
            (assertionSig.present ? assertionSig.why : 'unsigned') +
            '. The Response: ' + (responseSig.present ? responseSig.why :
                                  'unsigned') +
            '. Both are checked against fedSigningCertificate on this ' +
            'relationship, and against nothing else — a certificate carried ' +
            'inside the document\'s own ds:KeyInfo is deliberately ignored.',
        '<p class="note">The certificate configured here is ' +
        (record.fedSigningCertificate
          ? '<code>' +
              xmlEscape(String(record.fedSigningCertificate).slice(0, 60)) +
              '…</code> ' +
              '(' +
            String(record.fedSigningCertificate).length + ' base64 characters)'
          : '<strong>empty</strong>') + '.</p>');
    }

    // THE ISSUER. It has to be the partner this relationship names — otherwise
    // any partner whose certificate is configured anywhere could assert for any
    // other, which is the flaw that has broken more than one real federation.
    //
    // **AN EMPTY `fedPeer` NO LONGER SKIPS THIS (2026-09-12).** It was logged
    // and skipped, so a relationship with no peer accepted any issuer the
    // configured key signed for. `fedPeer` is now a field every protocol NEEDS
    // (federation.js's PROTOCOLS table), so a relationship without one is not
    // usable and never reaches here — and this refuses anyway rather than
    // relying on that, because the two checks are in two files.
    const issuer = textByLocal(root, 'Issuer') ||
                   textByLocal(assertion, 'Issuer') ||
                   (assertion.getAttribute('Issuer') || '');
    const expectedIssuer = String(record.fedPeer || '').trim();
    if (!expectedIssuer || issuer !== expectedIssuer) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). Wrong or " +
                'unchecked issuer.');
      errorCodes.mark(res, expectedIssuer ? 'STS-FED-0015' : 'STS-FED-0016');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 401, 'It was issued by somebody else',
        expectedIssuer
          ? 'The assertion names ' + (issuer || '(no issuer)') + ' as its ' +
            'issuer and this relationship ' +
            'expects ' + expectedIssuer + '. The signature ' +
            'verified, which means the key configured here signed an ' +
            'assertion claiming to be from a different party.'
          : 'This relationship has no fedPeer, so there is no issuer to ' +
            'check ' +
            'the assertion\'s (' +
            (issuer || 'none') + ') against, and nothing is accepted until ' +
            'there is. Set fedPeer to the partner\'s own identifier.');
    }

    const validity = this.conditionsCheck(assertion);
    if (!validity.ok) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). Outside its " +
                'validity window.');
      errorCodes.mark(res, validity.errorCode || 'STS-FED-0018');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 401, 'The assertion is not valid now',
                    validity.why);
    }

    // THE AUDIENCE — a refusal since 2026-09-12, where it was a warning. See
    // audienceCheck(), which argues why and what `fedLocalEntityId` is for.
    const audience = this.audienceCheck(assertion, baseUrlOf(req), record,
                                   version === '2.0');
    if (!audience.ok) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). The audience is " +
                'somebody else.');
      errorCodes.mark(res, audience.errorCode || 'STS-FED-0020');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 401, 'It was issued for somebody else',
                    audience.why);
    }

    // THE ENCRYPTED IDENTIFIER AND ATTRIBUTES (#168), now that the signature
    // over their ciphertext has verified.
    if (!this.openEncryptedParts(res, record, assertion)) {
      log.debug("Leaving FederationSp.consumeSamlResponse(). An encrypted " +
                "part.");
      return undefined;
    }
    const contents = this.assertionContents(assertion);

    // InResponseTo. SAML 2.0 only — 1.1 has no request for anything to be in
    // response to — and only where the relationship has not opted out.
    let context = null;
    const handle = String(params.RelayState || params.fedctx || '');
    if (handle) context = this.takeContext(handle);
    if (version === '2.0' &&
        !federation.boolOf(record.fedAllowUnsolicited, false)) {
      const scd = firstByLocal(assertion, 'SubjectConfirmationData');
      const inResponseTo = (scd && scd.getAttribute('InResponseTo')) ||
        root.getAttribute('InResponseTo') || '';
      if (!context) {
        log.debug("Leaving FederationSp.consumeSamlResponse(). Unsolicited.");
        errorCodes.mark(res, handle ? 'STS-FED-0022' : 'STS-FED-0021');
        log.debug("Leaving FederationSp.consumeSamlResponse().");
        return this.refuse(res, record, 401, 'This service did not ask for ' +
                                        'that assertion',
          handle
            ? 'The RelayState "' + handle + '" is not one this service ' +
                                            'minted, ' +
              'or the sign-in it belonged to expired ' +
              '(federation.requestTtlMin ' +
              'is ' +
              config.value('federation.requestTtlMin') + ' minutes).'
            : 'No RelayState came back at all, so there is nothing to match ' +
              'the assertion against. Set fedAllowUnsolicited on the ' +
              'relationship to accept a response this service did not start ' +
              '— which is what identity-provider-initiated sign-on is, and ' +
              'it removes this check.');
      }
      if (inResponseTo && inResponseTo !== context.requestId) {
        log.debug("Leaving FederationSp.consumeSamlResponse(). InResponseTo " +
                  'does not match.');
        errorCodes.mark(res, 'STS-FED-0023');
        log.debug("Leaving FederationSp.consumeSamlResponse().");
        return this.refuse(res, record, 401, 'It answers a different request',
          'The assertion says InResponseTo="' + inResponseTo + '" and the ' +
          'sign-in this RelayState belongs to sent ' +
          '"' + context.requestId + '".');
      }
    }

    // A SAML partner states its authentication context as a class or a method
    // URI, not as RFC 8176 values, so nothing joins `federated` in the amr —
    // the statement travels on `acr`, where saml/authn_context.ts reads it. The
    // old code pushed the context onto an amr and then discarded the list.
    log.debug("Leaving FederationSp.consumeSamlResponse(). Verified; " +
              'completing the sign-in once the signing certificate is known ' +
              'not to be revoked.');
    // THE PARTNER'S SESSION BOUND (#167), refused here when it has already
    // passed rather than started and ended in one breath.
    const bound = this.sessionBoundOf(contents);
    if (bound.refused) {
      errorCodes.mark(res, 'STS-FED-0131');
      log.debug("Leaving FederationSp.consumeSamlResponse(). The partner's " +
                "session has already ended.");
      return this.refuse(res, record, 401, 'The partner\'s session has ' +
                                           'already ended', bound.why);
    }
    return this.signerStillAccepted(req, res, record, () => {
      return this.completeSignIn(req, res, record, {
        subject: contents.subject,
        // THE PARTNER'S STABLE SUBJECT (#109) is the NameID qualified by the
        // issuer this branch has just verified, and a transient NameID is
        // none — see federation_links.ts's stableSubjectOf().
        issuer: issuer,
        nameFormat: contents.nameFormat,
        nameQualifier: contents.nameQualifier,
        spNameQualifier: contents.spNameQualifier,
        sessionIndex: contents.sessionIndex,
        sessionNotOnOrAfter: bound.at,
        bag: contents.bag,
        amr: this.federatedAmr([]),
        acr: contents.context || '',
        returnTo: this.fromContext(context).returnTo,
        connect: this.fromContext(context).connect,
        application: this.fromContext(context).application,
        authnPending: this.fromContext(context).authnPending
      });
    });
  }

  // ---------------------------------------------------------------------------
  // THE PARTNER'S SessionNotOnOrAfter, AS A BOUND ON THE SESSION HERE (#167).
  //
  // `{ at, refused, why }`: `at` is the epoch ms the session here must end by
  // (0 for none), which `authn.startSession()` makes the session's absolute
  // expiry where it is the earlier. The same clock-skew allowance an
  // assertion's own NotOnOrAfter gets (conditionsCheck()), because the two
  // are instants the same partner wrote with the same clock. An instant that
  // has passed even with the allowance is refused: a session that is over
  // before it starts is not one to start. A value that does not parse is
  // refused too — a bound nobody can read is not a bound to ignore.
  // ---------------------------------------------------------------------------
  /**
   * Turns a SAML assertion's `SessionNotOnOrAfter` into the instant the session
   * here must end by, with the clock-skew allowance.
   *
   * An instant already passed, or one that does not parse, is refused.
   *
   * @param contents - the assertion's contents
   * @returns `{ at, refused, why }`, `at` in epoch milliseconds or 0 for none
   */
  sessionBoundOf(contents) {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.sessionBoundOf().");
    const text = String((contents && contents.sessionNotOnOrAfter) || '');
    if (!text) {
      log.debug("Leaving FederationSp.sessionBoundOf(). None.");
      return { at: 0, refused: false, why: '' };
    }
    const parsed = Date.parse(text);
    if (!isFinite(parsed)) {
      log.debug("Leaving FederationSp.sessionBoundOf(). Unreadable.");
      return { at: 0, refused: true,
               why: 'The assertion\'s SessionNotOnOrAfter, "' + text + '", ' +
                    'is not an instant this service can read, so how long ' +
                    'the partner says the session may last is unknown.' };
    }
    const skewMs = config.value('oauth2.clockSkewS') * 1000;
    const at = parsed + skewMs;
    if (at <= Date.now()) {
      log.debug("Leaving FederationSp.sessionBoundOf(). Passed.");
      return { at: at, refused: true,
               why: 'The assertion says the partner\'s session ended at ' +
                    text + ' (SessionNotOnOrAfter, saml-core-2.0-os section ' +
                    '2.7.2), which has passed even allowing ' +
                    config.value('oauth2.clockSkewS') + 's of clock skew. A ' +
                    'session here may not outlive the partner\'s, and one ' +
                    'that is over before it starts is not started.' };
    }
    log.debug("Leaving FederationSp.sessionBoundOf(). " +
              new Date(at).toISOString());
    return { at: at, refused: false, why: '' };
  }

  // ---------------------------------------------------------------------------
  // A WS-FEDERATION SIGN-IN RESPONSE.
  //
  // `wresult` is an RSTR — a `<RequestSecurityTokenResponse>` wrapping a
  // `<RequestedSecurityToken>` wrapping an assertion which may be SAML 1.1 or
  // SAML 2.0. Which one it is USED TO decide the id attribute the signature
  // reference resolves through, and getting that wrong is the bug `wsfed.ts`'s
  // `verifyAssertionSignature()` header records; since 2026-08-27 the shared
  // verifier resolves it from the document (see verifyXmlSignature() above).
  // ---------------------------------------------------------------------------
  private consumeWsFedResponse(req, res, record, params) {
    const {
      federation, errorCodes, log, logArtifact, firstByLocal, textByLocal,
      baseUrlOf
    } = this.deps;
    log.debug("Entering FederationSp.consumeWsFedResponse().");
    const wa = String(params.wa || '');
    if (wa && wa !== 'wsignin1.0') {
      log.debug("Leaving FederationSp.consumeWsFedResponse(). Not a sign-in " +
                'response.');
      errorCodes.mark(res, 'STS-FED-0024');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 400, 'That is not a sign-in response',
        'wa=' + wa + '. This endpoint consumes wa=wsignin1.0. A ' +
        'wsignout1.0 or wsignoutcleanup1.0 arriving here is a partner ' +
        'configured to send its sign-out where its sign-in goes: a ' +
        'partner\'s sign-out is consumed at ' +
        this.sloUrl(baseUrlOf(req), record) + ' (#167). Configure that ' +
        'address at the partner as this relying party\'s sign-out URL.');
    }
    const wresult = String(params.wresult || '');
    if (!wresult) {
      errorCodes.mark(res, 'STS-FED-0007');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 400, 'Nothing arrived',
        'The request carried no wresult. That is what a wsignin1.0 response ' +
        'puts the token in.');
    }
    logArtifact('federated WS-Federation wresult', 'as received', wresult);
    let doc = null;
    try {
      doc = new DOMParser().parseFromString(wresult, 'text/xml');
    } catch (e) {
      errorCodes.mark(res, 'STS-FED-0009');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 400, 'The wresult is not XML', e.message);
    }
    const root = doc && doc.documentElement;
    // THE TOKEN, in the RequestedSecurityToken — an assertion, or one
    // ENCRYPTED to this relationship's key (#168): WS-Federation 1.2 carries
    // whatever token the RSTR holds, and XML Encryption is how that token is
    // sealed. A wresult with no RequestedSecurityToken is read where its
    // assertion is, as it always was.
    const container = root ? (firstByLocal(root, 'RequestedSecurityToken') ||
      ((firstByLocal(root, 'Assertion') || {}).parentNode) || root) : null;
    const token: any = this.openToken(res, record, container, wresult,
                                      'wresult');
    if (token.refused) {
      log.debug("Leaving FederationSp.consumeWsFedResponse(). The token.");
      return undefined;
    }
    const assertion = token.assertion;
    const version = assertion.namespaceURI === NS_SAML ? '2.0' : '1.1';
    log.debug('consumeWsFedResponse(): the token is a SAML ' + version + ' ' +
        'assertion' + (token.encrypted ? ', decrypted.' : '.'));

    const sig = this.verifyXmlSignature(token.assertionXml, record,
                                        'Assertion');
    if (!sig.ok) {
      log.debug("Leaving FederationSp.consumeWsFedResponse(). The signature " +
                'did not verify.');
      errorCodes.mark(res, !this.certPemOf(record) ? 'STS-FED-0014'
        : (sig.present ? 'STS-FED-0013' : 'STS-FED-0012'));
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 401, 'The signature did not verify',
        sig.present
          ? sig.why + '. It is checked against fedSigningCertificate on this ' +
            'relationship and against nothing else.'
          : 'The assertion carries no ds:Signature at all, which makes it an ' +
            'unauthenticated HTTP request with XML in it.');
    }
    // THE ISSUER, and since 2026-09-12 an assertion with NO issuer is refused
    // too: it used to skip the comparison when either side was empty, so an
    // assertion that named nobody passed an issuer check it never took. See the
    // SAML branch above for the empty-fedPeer half.
    const issuer = textByLocal(assertion, 'Issuer') ||
                   assertion.getAttribute('Issuer') || '';
    const expectedIssuer = String(record.fedPeer || '').trim();
    if (!expectedIssuer || issuer !== expectedIssuer) {
      errorCodes.mark(res, expectedIssuer ? 'STS-FED-0015' : 'STS-FED-0016');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 401, 'It was issued by somebody else',
        expectedIssuer
          ? 'The assertion names ' + (issuer || '(no issuer)') + ' and this ' +
            'relationship expects ' + expectedIssuer + '.'
          : 'This relationship has no fedPeer, so there is no issuer to ' +
            'check against. Set fedPeer to the partner\'s own identifier.');
    }
    const validity = this.conditionsCheck(assertion);
    if (!validity.ok) {
      errorCodes.mark(res, validity.errorCode || 'STS-FED-0018');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 401, 'The assertion is not valid now',
                    validity.why);
    }
    // THE AUDIENCE, which this branch never checked at all until 2026-09-12. A
    // wsignin1.0 response is issued for the wtrealm this service sent — which
    // is ourEntityId() — so a token for another relying party of the same
    // partner is refused here exactly as it is on the SAML path. See
    // audienceCheck().
    const audience = this.audienceCheck(assertion, baseUrlOf(req), record,
                                        false);
    if (!audience.ok) {
      errorCodes.mark(res, audience.errorCode || 'STS-FED-0020');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 401, 'It was issued for somebody else',
                    audience.why);
    }
    if (!this.openEncryptedParts(res, record, assertion)) {
      log.debug("Leaving FederationSp.consumeWsFedResponse(). An encrypted " +
                "part.");
      return undefined;
    }
    const contents = this.assertionContents(assertion);
    const context = this.takeContext(String(params.wctx || ''));
    if (!context && !federation.boolOf(record.fedAllowUnsolicited, false)) {
      log.debug("Leaving FederationSp.consumeWsFedResponse(). Unsolicited.");
      errorCodes.mark(res, params.wctx ? 'STS-FED-0022' : 'STS-FED-0021');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 401, 'This service did not ask for ' +
                                           'that token',
        params.wctx
          ? 'The wctx "' + params.wctx + '" is not one this service minted, ' +
            'or the sign-in it belonged to expired.'
          : 'No wctx came back. Section 13.2.1 makes it optional, so a ' +
            'partner that drops it is not misbehaving — set ' +
            'fedAllowUnsolicited on the relationship to accept its responses ' +
            'anyway, and note that doing so removes this check for every ' +
            'response.');
    }
    // A SAML 2.0 TOKEN INSIDE THE RSTR CARRIES A SESSION BOUND TOO (#167),
    // and it binds the session here exactly as it does on the SAML path.
    const bound = this.sessionBoundOf(contents);
    if (bound.refused) {
      errorCodes.mark(res, 'STS-FED-0131');
      log.debug("Leaving FederationSp.consumeWsFedResponse(). The partner's " +
                "session has already ended.");
      return this.refuse(res, record, 401, 'The partner\'s session has ' +
                                           'already ended', bound.why);
    }
    log.debug("Leaving FederationSp.consumeWsFedResponse(). Verified; " +
              'completing the sign-in once the signing certificate is known ' +
              'not to be revoked.');
    return this.signerStillAccepted(req, res, record, () => {
      return this.completeSignIn(req, res, record, {
        subject: contents.subject, bag: contents.bag,
        issuer: issuer, nameFormat: contents.nameFormat,
        nameQualifier: contents.nameQualifier,
        spNameQualifier: contents.spNameQualifier,
        sessionIndex: contents.sessionIndex,
        sessionNotOnOrAfter: bound.at,
        amr: this.federatedAmr([]), acr: contents.context || '',
        returnTo: this.fromContext(context).returnTo,
        connect: this.fromContext(context).connect,
        application: this.fromContext(context).application,
        authnPending: this.fromContext(context).authnPending
      });
    });
  }

  // ---------------------------------------------------------------------------
  // THE PARTNER'S KEYS, AND THE ONE PLACE A JWT FROM SOMEBODY ELSE IS VERIFIED.
  //
  // `fedJwks` is read first and is never refreshed; `fedJwksUri` is fetched.
  // The order is the one the schema rows state and it matters: a relationship
  // carrying pasted keys makes NO outbound request at all, which is what a
  // deployment with no egress needs.
  //
  // The `kid` selects and does not establish — `client_auth.js`'s rule again. A
  // token whose header names a `kid` nothing has is refused rather than being
  // tried against every key: a partner that rotated a key wants to hear that,
  // and trying them all turns a rotation into a silent success against a key
  // the partner has retired.
  // ---------------------------------------------------------------------------
  /**
   * Returns the partner's keys: `fedJwks` when pasted, otherwise fetched from
   * `fedJwksUri`.
   *
   * @param record - the federation relationship
   * @returns a promise of `{ ok, keys, from }`, or `{ ok: false, keys: [],
   *   errorCode, why }`
   */
  keysFor(record) {
    const { fedHttp, log } = this.deps;
    log.debug("Entering FederationSp.keysFor(). id=" + record.fedId);
    const pasted = String(record.fedJwks || '').trim();
    if (pasted) {
      try {
        const parsed = JSON.parse(pasted);
        const keys = Array.isArray(parsed.keys) ? parsed.keys :
                     (parsed.kty ? [parsed] : []);
        log.debug("Leaving FederationSp.keysFor(). " + keys.length + ' ' +
            'pasted key(s).');
        return Promise.resolve({ ok: true, keys: keys, from: 'fedJwks' });
      } catch (e) {
        log.debug("Leaving FederationSp.keysFor(). fedJwks will not parse.");
        return Promise.resolve({ ok: false, keys: [], errorCode: 'STS-FED-0030',
                                 why: 'fedJwks on this relationship is not ' +
                                      'JSON: ' + e.message });
      }
    }
    if (!String(record.fedJwksUri || '').trim()) {
      log.debug("Leaving FederationSp.keysFor(). Neither is configured.");
      return Promise.resolve({ ok: false, keys: [], errorCode: 'STS-FED-0031',
                               why: 'neither fedJwks nor fedJwksUri is ' +
                                    'configured, so there is no key to ' +
                                    'verify the token with' });
    }
    log.debug("Leaving FederationSp.keysFor().");
    return fedHttp.fetchJson(record, 'fedJwksUri', { method: 'GET' })
                  .then((answer) => {
      if (!answer.ok || !answer.json) {
        log.debug("Leaving FederationSp.keysFor(). The JWKS could not be " +
                  'fetched.');
        return { ok: false, keys: [],
                 errorCode: answer.errorCode || 'STS-FED-0056',
                 why: 'the JWKS at ' + answer.url + ' could not be fetched: ' +
                      answer.why };
      }
      const keys = Array.isArray(answer.json.keys) ? answer.json.keys : [];
      log.debug("Leaving FederationSp.keysFor(). " + keys.length + ' fetched ' +
          'key(s).');
      return { ok: true, keys: keys, from: 'fedJwksUri' };
    });
  }

  // The algorithms a partner key of this type may verify, as the family the key
  // admits intersected with `federation.jwtAlgorithms`. See the note at the
  // call.
  /**
   * Returns the algorithms a partner key of a type may verify: the key's family
   * intersected with `federation.jwtAlgorithms`.
   *
   * @param kty - the JWK key type
   * @returns the algorithm names
   */
  familyAlgorithms(kty) {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.familyAlgorithms().");
    const family = kty === 'EC'
      ? ['ES256', 'ES384', 'ES512']
      : ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
    const allowed = config.value('federation.jwtAlgorithms');
    const list = Array.isArray(allowed) ? allowed :
                 String(allowed || '').split(',');
    const wanted = list.map((one) => { return String(one).trim(); });
    log.debug("Leaving FederationSp.familyAlgorithms().");
    return family.filter((alg) => { return wanted.indexOf(alg) >= 0; });
  }

  /**
   * Verifies a JWT a partner signed, an ID Token or a Logout Token, against the
   * partner's keys: the `kid` selects, and the key decides the algorithm
   * family.
   *
   * @param token - the compact JWS
   * @param record - the federation relationship
   * @param keys - the partner's JWKs
   * @param options - further verification options, such as issuer and audience
   * @returns `{ ok: true, payload, kid, jwk }`, or `{ ok: false, errorCode, why
   *   }`
   */
  verifyForeignJwt(token, record, keys, options) {
    const { config, stsCrypto, log, jsonFromB64u } = this.deps;
    log.debug("Entering FederationSp.verifyForeignJwt().");
    let header = null;
    try {
      header = jsonFromB64u(String(token).split('.')[0]);
    } catch (e) {
      log.debug("Leaving FederationSp.verifyForeignJwt(). The header will " +
                'not decode.');
      return { ok: false, errorCode: 'STS-FED-0032', why: 'its header is not ' +
          'base64url JSON: ' + e.message };
    }
    if (!header || !header.alg) {
      log.debug("Leaving FederationSp.verifyForeignJwt().");
      return { ok: false, errorCode: 'STS-FED-0032', why: 'it has no alg in ' +
                                                          'its header' };
    }
    if (String(header.alg).toLowerCase() === 'none') {
      log.debug("Leaving FederationSp.verifyForeignJwt().");
      // Named rather than lumped in with "no key matched", because `alg: none`
      // is an attack with a name and somebody seeing it should know which one.
      return { ok: false, errorCode: 'STS-FED-0033',
               why: 'its header says alg=none, which is an unsigned token ' +
                    'presented as a signed one. It is refused by name rather ' +
                    'than by failing to find a key' };
    }
    const kid = header.kid || '';
    const candidates = keys.filter((key) => {
      if (kid && key.kid) return key.kid === kid;
      return true;
    });
    if (!candidates.length) {
      log.debug("Leaving FederationSp.verifyForeignJwt().");
      return { ok: false, errorCode: kid ? 'STS-FED-0034' : 'STS-FED-0035',
               why: kid
                 ? 'its header names kid "' + kid + '" and the partner\'s ' +
                   'key set has no such key. That is what a key rotation ' +
                   'looks like — refetch or repaste the keys'
                 : 'the partner\'s key set is empty' };
    }
    let lastWhy = '';
    let lastCode = 'STS-FED-0036';
    for (let i = 0; i < candidates.length; i++) {
      let pem = null;
      try {
        pem = stsCrypto.publicKeyFromJwk(candidates[i]);
      } catch (e) {
        lastWhy = 'a key in the set could not be read: ' + e.message;
        lastCode = 'STS-FED-0036';
        continue;
      }
      try {
        const payload = stsCrypto.verifyJws(String(token), pem, Object.assign({
          // THE ALGORITHM FAMILY COMES FROM THE KEY, NOT FROM THE TOKEN. This
          // is `client_auth.js`'s rule and it is the classic JWT forgery:
          // without it, a token nominating HS256 would be verified using the
          // partner's PUBLIC key as an HMAC secret, which anybody can do.
          //
          // AND `federation.jwtAlgorithms` NARROWS THAT FAMILY (2026-09-12) —
          // it was a fixed list. The intersection, never the setting alone: a
          // setting naming HS256 must not be able to put the family rule back.
          algorithms: this.familyAlgorithms(candidates[i].kty),
          clockTolerance: config.value('oauth2.clockSkewS')
        }, options || {}));
        log.debug("Leaving FederationSp.verifyForeignJwt(). Verified.");
        return { ok: true, payload: payload, kid: candidates[i].kid || '',
                 jwk: candidates[i] };
      } catch (e) {
        lastWhy = e.message;
        // Which check failed, for the error code only — the sentence is
        // unchanged.
        if (e.name === 'TokenExpiredError' || e.name === 'NotBeforeError' ||
            /expired|not active|nbf|exp\b/i.test(String(e.message))) {
          lastCode = 'STS-FED-0037';
        } else if (/audience|issuer|\baud\b|\biss\b/i.test(String(e.message))) {
          lastCode = 'STS-FED-0038';
        } else {
          lastCode = 'STS-FED-0036';
        }
      }
    }
    log.debug("Leaving FederationSp.verifyForeignJwt(). Nothing verified " +
              'it: ' + lastWhy);
    return { ok: false, errorCode: lastCode, why: lastWhy || 'no key in the ' +
        'partner\'s set verified it' };
  }

  // ---------------------------------------------------------------------------
  // THE OAUTH 2.0 / OIDC CALLBACK.
  //
  // This is the branch with the back channel in it, and every outbound request
  // goes through `federation_http.ts` — see that file's header for why a
  // configured URL is a different thing from a registered one.
  // ---------------------------------------------------------------------------
  private consumeOauthResponse(req, res, record, params) {
    const {
      config, fedHttp, errorCodes, log, xmlEscape, baseUrlOf
    } = this.deps;
    log.debug("Entering FederationSp.consumeOauthResponse(). protocol=" +
              record.fedProtocol);
    if (params.error) {
      log.debug("Leaving FederationSp.consumeOauthResponse(). The partner " +
                'returned an error.');
      errorCodes.mark(res, 'STS-FED-0025');
      log.debug("Leaving FederationSp.consumeOauthResponse().");
      return this.refuse(res, record, 400, 'The partner refused',
        'It answered <code>' + xmlEscape(String(params.error)) + '</code>' +
        (params.error_description ?
         ' — "' + xmlEscape(String(params.error_description)) + '"' : '') +
        '. That is the partner\'s answer about this service as a CLIENT of ' +
        'it: the usual causes are a redirect_uri it does not have registered ' +
        '(this one is ' +
        '<code>' + xmlEscape(this.acsUrl(baseUrlOf(req), record)) +
        '</code>) or a ' +
        'client_id it does not know.');
    }
    const context = this.takeContext(String(params.state || ''));
    if (!context) {
      log.debug("Leaving FederationSp.consumeOauthResponse(). No state.");
      errorCodes.mark(res, params.state ? 'STS-FED-0022' : 'STS-FED-0021');
      log.debug("Leaving FederationSp.consumeOauthResponse().");
      return this.refuse(res, record, 401, 'This service did not start that ' +
                                           'sign-in',
        params.state
          ? 'The state "' + xmlEscape(String(params.state)) + '" is not one ' +
            'this service minted, or the sign-in it belonged to expired ' +
            '(federation.requestTtlMin is ' +
            config.value('federation.requestTtlMin') + ' minutes). A state ' +
            'that does not match is what a cross-site request forgery on ' +
            'this callback looks like, so it is refused rather than accepted ' +
            'with a warning.'
          : 'No state came back at all. This service always sends one, so a ' +
            'response without one did not come from a flow it started.');
    }

    const responseType = String(record.fedResponseType || 'code');
    // APPLE'S `user` FORM FIELD (#565), posted beside the code on the first
    // authorization only: kept on the context, bounded, for the profile's
    // `form` source. Unsigned, so it is a display value and never identity.
    if (consumerProviders.adapts(record, 'apple-user-form-field')) {
      context.formUser = String(params.user || '').slice(0, 4096);
    }

    // The front-channel shape: an ID Token straight back, no back channel at
    // all.
    if (responseType !== 'code') {
      const idToken = String(params.id_token || '');
      if (!idToken) {
        errorCodes.mark(res, 'STS-FED-0026');
        log.debug("Leaving FederationSp.consumeOauthResponse().");
        return this.refuse(res, record, 400, 'No ID Token arrived',
          'This relationship asks for response_type=' + responseType + ' ' +
          'with response_mode=form_post, so the answer should have POSTed an ' +
          'id_token here.');
      }
      log.debug("Leaving FederationSp.consumeOauthResponse().");
      return this.finishOidc(req, res, record, context, idToken, '');
    }

    const code = String(params.code || '');
    if (!code) {
      errorCodes.mark(res, 'STS-FED-0027');
      log.debug("Leaving FederationSp.consumeOauthResponse().");
      return this.refuse(res, record, 400, 'No authorization code arrived',
        'The partner redirected here with neither a code nor an error, which ' +
        'is not a response RFC 6749 section 4.1.2 describes.');
    }

    // THE TOKEN REQUEST. `client_secret_basic` where there is a secret, because
    // RFC 6749 section 2.3.1 says a server MUST support it and MAY support the
    // body form — so the one that is always available is the one used. A
    // partner that wants the secret in the body will refuse this and say so,
    // which is a better failure than guessing.
    const form: any = {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: this.acsUrl(baseUrlOf(req), record),
      code_verifier: context.pkceVerifier
    };
    const options: any = { method: 'POST', form: form };
    let authenticated: Promise<any> = Promise.resolve(null);
    if (record.fedTokenAuth === 'private_key_jwt') {
      // An OP discovered through a federation (#134): this realm registered
      // automatically, with nothing provisioned, and authenticates with the
      // key its Entity Configuration publishes (RFC 7523, Connect 1.1 12.1).
      form.client_id = String(record.fedClientId || '');
      form.client_assertion_type =
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      authenticated = this.deps.oidfedRp().clientAssertion(record)
        .then(function (assertion) {
          form.client_assertion = assertion;
        });
    } else if (consumerProviders.adapts(record, 'apple-client-secret')) {
      // SIGN IN WITH APPLE (#565): the client secret is a JWT this service
      // signs for this request, in the body with the client id.
      const minted = this.appleClientSecret(record);
      if (!minted) {
        errorCodes.mark(res, 'STS-FED-0185');
        log.debug("Leaving FederationSp.consumeOauthResponse(). No Apple " +
                  "client secret.");
        return this.refuse(res, record, 500, 'The client secret could not ' +
                                             'be signed',
          'This relationship signs its client secret with fedClientSigningKey ' +
          '(the .p8 key), naming fedTeamId and fedKeyId, and one of them is ' +
          'missing, will not open, or is not a P-256 key.');
      }
      form.client_id = String(record.fedClientId || '');
      form.client_secret = minted;
    } else if (consumerProviders.adapts(record, 'tiktok-client-key')) {
      // TIKTOK (#565): the client id is `client_key`, in the body with the
      // secret, and there is no Basic form.
      form.client_key = String(record.fedClientId || '');
      form.client_secret = federation.clientSecretOf(record);
    } else if (federation.clientSecretOf(record) &&
               record.fedTokenAuth === 'client_secret_post') {
      // RFC 6749 section 2.3.1's body form (#565), for a partner that reads
      // the secret nowhere else — GitHub's documented exchange among them.
      form.client_id = String(record.fedClientId || '');
      form.client_secret = federation.clientSecretOf(record);
    } else if (federation.clientSecretOf(record)) {
      options.basic = { user: record.fedClientId,
                        pass: federation.clientSecretOf(record) };
    } else {
      // A public client. The client_id goes in the body, which is what RFC 6749
      // section 4.1.3 requires when the client does not authenticate.
      form.client_id = String(record.fedClientId || '');
    }
    log.debug('consumeOauthResponse(): redeeming the code at the partner.');
    log.debug("Leaving FederationSp.consumeOauthResponse().");
    return authenticated.then(function () {
      return fedHttp.fetchJson(record, 'fedTokenUrl', options);
    }).then((answer) => {
      if (!answer.ok || !answer.json) {
        log.debug("Leaving FederationSp.consumeOauthResponse(). The token " +
                  'request failed.');
        errorCodes.mark(res, answer.errorCode || 'STS-FED-0056');
        return this.refuse(res, record, 502, 'The code could not be redeemed',
          'The token request to ' + (answer.url || 'the partner') + ' ' +
              'failed: ' +
          answer.why +
          (answer.text && !answer.json
            ? '. It answered with something that is not JSON, which usually ' +
              'means a proxy in front of the partner rather than the partner ' +
              'itself.'
            : ''),
          answer.json && answer.json.error_description
            ? '<p class="note">The partner said: <code>' +
              xmlEscape(String(answer.json.error_description)) + '</code></p>'
            : '');
      }
      const tokens = answer.json;
      if (record.fedProtocol === 'oidc') {
        if (!tokens.id_token) {
          errorCodes.mark(res, 'STS-FED-0028');
          return this.refuse(res, record, 502, 'The partner returned no ID ' +
                                               'Token',
            'The code was redeemed and the response carried ' +
            Object.keys(tokens).join(', ') + ' but no <code>id_token</code>. ' +
            'That is an OAuth 2.0 token response rather than an OpenID ' +
            'Connect ' +
            'one — either the `openid` scope was not asked for (this ' +
            'relationship asks for "' +
            xmlEscape(String(record.fedScope || '')) + '") or the partner is ' +
            'not an OpenID Provider, in which case this relationship should ' +
            'be protocol oauth2.');
        }
        return this.finishOidc(req, res, record, context,
                               String(tokens.id_token),
                               String(tokens.access_token || ''));
      }
      return this.finishOauth2(req, res, record, context, tokens);
    }).catch((e) => {
      // fetchJson() never rejects, so this can only be a throw in the code
      // above — and it has to be caught, because an unhandled rejection in the
      // middle of a browser redirect leaves the person on a blank page with the
      // failure only in this process's log.
      log.error(errorCodes.tag('STS-FED-0042') + 'federation: the ' +
          record.fedProtocol + ' ' +
          'callback threw: ' + e.stack);
      errorCodes.mark(res, 'STS-FED-0042');
      return this.refuse(res, record, 500, 'This service failed while ' +
                                      'finishing the sign-in',
                    e.message);
    });
  }

  // ---------------------------------------------------------------------------
  // AN ENCRYPTED ID TOKEN (#168), OpenID Connect Core section 10.2: "signed
  // and then encrypted", a Nested JWT. A five-part JWE is decrypted with the
  // relationship's key under exactly the alg and enc it published, and what
  // is inside must be the signed ID Token, which is then verified exactly as
  // an unencrypted one is — a JWE alone, with nothing signed inside, is not
  // an ID Token (Core section 2: "ID Tokens MUST be signed"). A three-part
  // token on a front-channel relationship that requires encryption is
  // refused as plaintext. Answers `{ token }` or `{ refused: true }`.
  // ---------------------------------------------------------------------------
  private openIdToken(res, record, idToken) {
    const { federation, errorCodes, fedEncryption, log } = this.deps;
    log.debug("Entering FederationSp.openIdToken().");
    const parts = String(idToken).split('.').length;
    if (parts !== 5) {
      if (federation.encryptionRequired(record)) {
        errorCodes.mark(res, 'STS-FED-0140');
        log.debug("Leaving FederationSp.openIdToken(). Plaintext, refused.");
        this.refuse(res, record, 401, 'The ID Token is not encrypted',
          'This relationship requires the partner to ENCRYPT the ID Token ' +
          'it sends through the browser (response_type=id_token) to the key ' +
          'in this relationship\'s JWKS, and this one arrived signed only. ' +
          'Register id_token_encrypted_response_alg and _enc at the partner ' +
          '— the values are on the relationship\'s page. (Product mode ' +
          'requires encryption; fedAllowUnencrypted accepts plaintext, and ' +
          'its warning says what that costs.)');
        return { refused: true };
      }
      log.debug("Leaving FederationSp.openIdToken(). Signed only.");
      return { token: idToken, encrypted: false };
    }
    const opened = fedEncryption.decryptJwe(record, idToken);
    if (!opened.ok) {
      errorCodes.mark(res, opened.code);
      log.debug("Leaving FederationSp.openIdToken(). " + opened.code);
      this.refuse(res, record, opened.code === 'STS-FED-0137' ? 500 : 401,
        opened.code === 'STS-FED-0139'
          ? 'The ID Token is encrypted with an algorithm this relationship ' +
            'refuses'
          : (opened.code === 'STS-FED-0137'
              ? 'There is no key to decrypt the ID Token with'
              : 'The ID Token could not be decrypted'),
        opened.why);
      return { refused: true };
    }
    const inner = String(opened.plaintext || '').trim();
    if (inner.split('.').length !== 3) {
      errorCodes.mark(res, 'STS-FED-0141');
      log.debug("Leaving FederationSp.openIdToken(). Nothing signed inside.");
      this.refuse(res, record, 401, 'The encrypted ID Token is not signed',
        'It decrypted, and what was inside is not a signed JWT. OpenID ' +
        'Connect Core section 10.2 makes an encrypted ID Token a NESTED ' +
        'JWT — signed, then encrypted — and an ID Token that is only ' +
        'encrypted proves nothing about who made it: anybody holding this ' +
        'relationship\'s PUBLIC key can make one.');
      return { refused: true };
    }
    log.info('federation: ' + record.fedId + ': the ID Token was decrypted (' +
             opened.algorithm + ', key ' + opened.kid + ').');
    log.debug("Leaving FederationSp.openIdToken(). Decrypted.");
    return { token: inner, encrypted: true };
  }

  private finishOidc(req, res, record, context, sentToken, accessToken) {
    const { fedHttp, errorCodes, audit, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.finishOidc().");
    const opened: any = this.openIdToken(res, record, sentToken);
    if (opened.refused) {
      log.debug("Leaving FederationSp.finishOidc(). The ID Token.");
      return undefined;
    }
    const idToken = opened.token;
    log.debug("Leaving FederationSp.finishOidc().");
    return this.keysFor(record).then((keySet) => {
      if (!keySet.ok) {
        log.debug("Leaving FederationSp.finishOidc(). No keys.");
        errorCodes.mark(res, keySet.errorCode || 'STS-FED-0031');
        return this.refuse(res, record, 500, 'There is no key to verify the ' +
                                        'ID Token with',
                      keySet.why);
      }
      const verified = this.verifyForeignJwt(idToken, record, keySet.keys, {
        // The audience is this service's client_id at the partner, and the
        // issuer is what the relationship names. Both are checked BY
        // jwt.verify() rather than after it, so a token that fails either is
        // never parsed into anything this service acts on.
        audience: String(record.fedClientId || '') || undefined,
        // `fedPeer` is REQUIRED since 2026-09-12 (federation.js's PROTOCOLS),
        // so this is never undefined for a usable relationship — the `||
        // undefined` that let an empty one skip the issuer check is kept only
        // as the defence in depth readinessOf() already gives, and
        // verifyForeignJwt() is never reached without it. A consumer
        // provider's profile may name other spellings of the same issuer
        // beside it (#565: Google's bare host).
        issuer: consumerProviders.issuersFor(record, idToken)
      });
      if (!verified.ok) {
        log.debug("Leaving FederationSp.finishOidc(). The ID Token did not " +
                  'verify.');
        errorCodes.mark(res, verified.errorCode || 'STS-FED-0036');
        return this.refuse(res, record, 401, 'The ID Token did not verify',
                      verified.why +
          '. It is checked against the keys in ' + keySet.from + ' on this ' +
          'relationship, with ' +
          'aud=' + (record.fedClientId || '(unset)') + ' and iss=' +
          (record.fedPeer || '(unset)') + '.');
      }
      const payload = verified.payload;
      if (context.nonce && payload.nonce && payload.nonce !== context.nonce) {
        // The nonce check. OpenID Connect Core section 3.1.3.7 step 11, and it
        // is the check `oauth2_bcp.js` records as `enforced: 'no'` on the
        // ISSUING side because nothing there can observe a client doing it.
        // Here this service IS the client, so it does it.
        log.debug("Leaving FederationSp.finishOidc(). The nonce does not " +
                  'match.');
        errorCodes.mark(res, 'STS-FED-0039');
        return this.refuse(res, record, 401,
          'The ID Token answers a different request',
          'Its nonce is "' + xmlEscape(String(payload.nonce)) + '" and this ' +
              'sign-in sent "' +
          xmlEscape(context.nonce) + '". A replayed ID Token looks exactly ' +
                                     'like this.');
      }
      if (context.nonce && !payload.nonce) {
        log.warn('federation: the ID Token from ' + record.fedId + ' carries ' +
                 'no nonce and this service sent one. It is ACCEPTED — the ' +
                 'code flow is protected by the state and the PKCE verifier ' +
                 'as well — but a partner that drops the nonce cannot be ' +
                 'used with response_type=id_token, where it is the only ' +
                 'replay protection there is.');
      }
      const bag = {};
      Object.keys(payload).forEach((name) => {
        // The protocol's own members are not attributes about a person and must
        // not become directory attributes. `sub` is handled separately as the
        // subject; the rest are about the token.
        if (['iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'at_hash',
             'c_hash', 's_hash',
             'azp', 'auth_time', 'sid', 'sub', 'acr', 'amr'].indexOf(
                 name) !== -1) return;
        bag[name] = payload[name];
      });
      // The partner's amr BEHIND `federated`, not instead of it — see
      // federatedAmr().
      const amr = this.federatedAmr(payload.amr);
      // What UserInfo answered, whole, for a consumer provider's profile
      // (#565), whose rules name the source a value comes from.
      let userinfo: any = undefined;
      const finish = (extra) => {
        log.debug("Entering finish().");
        // AGGREGATED AND DISTRIBUTED CLAIMS (#147, OIDC Core 5.6.2) from the
        // ID Token and UserInfo together: gathered, taken out of the bag —
        // they are references, never attributes about the person — and
        // resolved by `claims_providers.ts`, which honours a source only
        // when it names a Claims Provider THIS realm registered and its keys
        // verify it. A resolved value fills a claim the partner did not send
        // itself; a source that cannot be honoured is logged and skipped.
        const names = Object.assign({}, bag['_claim_names'] || {},
                                    (extra && extra._claim_names) || {});
        const sources = Object.assign({}, bag['_claim_sources'] || {},
                                      (extra && extra._claim_sources) || {});
        delete bag['_claim_names'];
        delete bag['_claim_sources'];
        Object.keys(extra || {}).forEach((name) => {
          if (name === '_claim_names' || name === '_claim_sources') return;
          if (bag[name] === undefined) bag[name] = extra[name];
        });
        if (Object.keys(sources).length) {
          log.debug("Leaving finish(). Resolving " +
                    Object.keys(sources).length + " claim source(s).");
          return Promise.resolve().then(() => {
            return require('../oauth-oidc/claims_providers').resolve({
              _claim_names: names, _claim_sources: sources });
          }).then((resolved) => {
            Object.keys(resolved.claims || {}).forEach((name) => {
              if (bag[name] === undefined) bag[name] = resolved.claims[name];
            });
            return finish(null);
          }, (e) => {
            log.warn(errorCodes.tag('STS-OAUTH-0683') + 'federation: the ' +
                     'claim sources ' + record.fedId + ' sent could not be ' +
                     'resolved: ' + ((e && e.message) || e));
            return finish(null);
          });
        }
        log.debug("Leaving finish().");
        // A CONSUMER PROVIDER'S READING (#565): the profile's claims over
        // the bag, the address unverified unless it says otherwise, and the
        // provider's MFA claim believed only where the profile trusts it.
        // The subject stays the ID Token's `sub`, which OpenID Connect Core
        // section 5.7 makes the only stable one, whatever a profile says.
        const reading = this.consumerReading(record,
          { id_token: payload, userinfo: userinfo,
            form: this.formSourceOf(record, context) }, bag,
          String(payload.sub || ''), amr, String(payload.acr || ''));
        // The key that verified the ID Token is checked for revocation here,
        // on the one path into the sign-in, whether or not UserInfo was asked.
        return this.signerStillAccepted(req, res, record, () => {
          return this.completeSignIn(req, res, record, {
            subject: String(payload.sub || ''), bag: reading.bag,
            amr: reading.amr,
            // `iss` + `sub` — OpenID Connect Core section 5.7's stable
            // identifier (#109). `iss` has been checked against fedPeer.
            issuer: String(payload.iss || record.fedPeer || ''),
            // THE PARTNER'S SESSION (#167): the `sid` its Back-Channel and
            // Front-Channel logouts will name, and the ID Token itself where
            // this relationship will send it back as id_token_hint — kept
            // only while fedEndSessionUrl is set, because a signed statement
            // about the person is not something to hold for no reason.
            sid: String(payload.sid || ''),
            idToken: String(record.fedEndSessionUrl || '').trim()
              ? String(idToken) : '',
            acr: reading.acr,
            returnTo: this.fromContext(context).returnTo,
            connect: this.fromContext(context).connect,
            application: this.fromContext(context).application,
            authnPending: this.fromContext(context).authnPending
          });
        }, verified.jwk);
      };
      if (!accessToken || !String(record.fedUserinfoUrl || '').trim()) {
        log.debug("Leaving FederationSp.finishOidc(). No UserInfo call.");
        return finish(null);
      }
      log.debug('finishOidc(): asking the partner\'s UserInfo endpoint as ' +
                'well.');
      return fedHttp.fetchJson(record, 'fedUserinfoUrl',
                               { method: 'GET', bearer: accessToken })
                    .then((answer) => {
        if (!answer.ok || !answer.json) {
          // NOT a failure of the sign-in. The ID Token has already verified and
          // named the person; UserInfo adds attributes. Failing the whole
          // sign-in because an optional second call did not answer would be the
          // wrong trade, and the warning is what says the attributes are
          // missing.
          log.warn('federation: UserInfo at ' + answer.url + ' did not ' +
              'answer ' +
              'for ' +
                   record.fedId + ' (' + answer.why + '). The sign-in STANDS ' +
                   'on the ID Token, which has already verified — what is ' +
                   'lost is whatever attributes that endpoint would have ' +
                   'added.');
          // Not a refusal, so no response carries it: the sign-in goes on. The
          // row names the relationship and the reason, never the access token.
          audit.failure('STS-FED-0040', {
            protocol: 'Federation', channel: 'http', target: record.fedId,
            summary: 'the optional UserInfo request for the federation ' +
                     'relationship ' +
                     record.fedId + ' failed (' + answer.why + '); the ' +
                     'sign-in continued on the verified ID Token without ' +
                     'those attributes',
            outcome: 'error',
            detail: { cause: answer.errorCode || 'STS-FED-0056' }
          });
          return finish(null);
        }
        log.debug("Leaving FederationSp.finishOidc(). UserInfo added " +
                  Object.keys(answer.json).length + ' member(s).');
        userinfo = answer.json;
        const extra = {};
        Object.keys(answer.json).forEach((name) => {
          if (name === 'sub') return;
          extra[name] = answer.json[name];
        });
        return finish(extra);
      });
    });
  }

  // ---------------------------------------------------------------------------
  // PLAIN OAUTH 2.0, WHICH IS A DIFFERENT PROTOCOL AND NOT OIDC WITH A FLAG.
  //
  // There is no ID Token, so there is no artifact that says who signed in. Two
  // shapes are supported and the difference between them is the whole reason
  // this protocol is listed separately:
  //
  //   * A JWT ACCESS TOKEN. Verified exactly as an ID Token is — and this is
  //     the ONLY place in this service where an access token from somebody else
  //     is verified. Its claims become the bag.
  //   * AN OPAQUE ACCESS TOKEN plus a userinfo-shaped endpoint. The token is a
  //     bearer credential this service presents; whatever the endpoint answers
  //     is the bag.
  //
  // **NEITHER IS AUTHENTICATION IN THE SENSE OIDC MEANS**, and this service
  // says so on the page rather than pretending otherwise. An access token says
  // a client was authorized, not that a person signed in just now, and the
  // whole of "why you should not use OAuth 2.0 for authentication" lives in
  // that gap. Supporting it anyway is right for a mock — plenty of real
  // deployments do it, and being able to exercise one is the point — but doing
  // it silently would be this repository teaching the mistake.
  // ---------------------------------------------------------------------------
  private finishOauth2(req, res, record, context, tokens) {
    const { fedHttp, errorCodes, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.finishOauth2().");
    const accessToken = String(tokens.access_token || '');
    if (!accessToken) {
      log.debug("Leaving FederationSp.finishOauth2(). No access token.");
      errorCodes.mark(res, 'STS-FED-0029');
      log.debug("Leaving FederationSp.finishOauth2().");
      return this.refuse(res, record, 502, 'The partner returned no access ' +
                                           'token',
        'The token response carried ' + Object.keys(tokens).join(', ') + '.');
    }
    log.warn('federation: ' + record.fedId + ' is a plain OAuth 2.0 ' +
             'relationship, so this sign-in rests on an ACCESS TOKEN rather ' +
             'than on an ID Token. An access token says a client was ' +
             'authorized, not that this person signed in just now — see ' +
             'federation/CLAUDE.md. It is supported because real deployments ' +
             'do it.');
    // A JWE ACCESS TOKEN (#168) is refused by name rather than taken for an
    // opaque one: a plain OAuth 2.0 relationship holds no decryption key, and
    // sending an encrypted token to the userinfo endpoint instead would hide
    // that the partner is configured for something this relationship is not.
    if (accessToken.split('.').length === 5) {
      errorCodes.mark(res, 'STS-FED-0141');
      log.debug("Leaving FederationSp.finishOauth2(). A JWE access token.");
      return this.refuse(res, record, 401, 'The access token is encrypted',
        'The partner returned a JWE where a plain OAuth 2.0 relationship ' +
        'reads a signed JWT or an opaque token. This relationship holds no ' +
        'decryption key — an OpenID Connect relationship does, for its ' +
        'ID Token.');
    }
    const looksLikeJwt = accessToken.split('.').length === 3;
    const useUserinfo = !looksLikeJwt ||
      !String(record.fedJwks || record.fedJwksUri || '').trim();

    if (!useUserinfo) {
      log.debug("Leaving FederationSp.finishOauth2().");
      return this.keysFor(record).then((keySet) => {
        if (!keySet.ok) {
          errorCodes.mark(res, keySet.errorCode || 'STS-FED-0031');
          return this.refuse(res, record, 500, 'There is no key to verify ' +
                                          'the access token with',
                        keySet.why);
        }
        const verified = this.verifyForeignJwt(accessToken, record,
                                               keySet.keys, {
          issuer: String(record.fedPeer || '') || undefined
        });
        if (!verified.ok) {
          errorCodes.mark(res, verified.errorCode || 'STS-FED-0036');
          return this.refuse(res, record, 401, 'The access token did not ' +
                                               'verify',
                        verified.why);
        }
        const payload = verified.payload;
        const bag = {};
        Object.keys(payload).forEach((name) => {
          if (['iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'client_id', 'scope',
               'sub',
               'token_type', 'cnf'].indexOf(name) !== -1) return;
          bag[name] = payload[name];
        });
        // A consumer provider's profile reads the token and its response
        // (#565); an enterprise relationship keeps the token's `sub`.
        const reading = this.consumerReading(record,
          { access_token: payload, token: tokens }, bag,
          String(payload.sub || ''), this.federatedAmr([]), '');
        if (!reading.subject) {
          errorCodes.mark(res, 'STS-FED-0177');
          return this.refuse(res, record, 502, 'The partner named nobody',
            'The access token verified, and the rule that names the person ' +
            'in it found nothing.');
        }
        log.debug("Leaving FederationSp.finishOauth2(). A verified JWT " +
                  'access token.');
        return this.signerStillAccepted(req, res, record, () => {
          return this.completeSignIn(req, res, record, {
            subject: reading.subject, bag: reading.bag,
            issuer: String(payload.iss || record.fedPeer || ''),
            amr: reading.amr,
            acr: reading.acr,
            returnTo: this.fromContext(context).returnTo,
            connect: this.fromContext(context).connect,
            application: this.fromContext(context).application,
            authnPending: this.fromContext(context).authnPending
          });
        }, verified.jwk);
      });
    }

    if (!String(record.fedUserinfoUrl || '').trim()) {
      log.debug("Leaving FederationSp.finishOauth2(). Opaque token and no " +
                'userinfo endpoint.');
      errorCodes.mark(res, 'STS-FED-0041');
      log.debug("Leaving FederationSp.finishOauth2().");
      return this.refuse(res, record, 500, 'There is no way to learn who ' +
                                           'this is',
        'The partner returned an ' + (looksLikeJwt ? 'access token this ' +
        'relationship has no keys to ' +
        'verify' : 'OPAQUE access token') + ', and no fedUserinfoUrl ' +
        'is configured. A plain OAuth 2.0 relationship needs one or the ' +
        'other: an access token that cannot be read and cannot be exchanged ' +
        'for a profile names nobody.');
    }
    log.debug("Leaving FederationSp.finishOauth2().");
    return fedHttp.fetchJson(record, 'fedUserinfoUrl',
                             { method: 'GET', bearer: accessToken })
                  .then((answer) => {
      if (!answer.ok || !answer.json) {
        log.debug("Leaving FederationSp.finishOauth2(). The userinfo call " +
                  'failed.');
        errorCodes.mark(res, answer.errorCode || 'STS-FED-0056');
        return this.refuse(res, record, 502, 'The partner would not say who ' +
                                             'this is',
          'The request to ' + answer.url + ' failed: ' + answer.why + '. ' +
          'Unlike the OIDC case, this call is NOT optional here — it is the ' +
          'only thing that names the person, because a plain OAuth 2.0 flow ' +
          'issues no ID Token.');
      }
      const profile = answer.json;
      const bag = {};
      Object.keys(profile).forEach((name) => {
        if (name === 'sub') return;
        bag[name] = profile[name];
      });
      log.debug("Leaving FederationSp.finishOauth2(). " +
                'The profile endpoint answered.');
      return this.emailsFor(record, accessToken).then((emails) => {
        log.debug("Entering the profile answer's continuation.");
        // THE SUBJECT. A consumer provider's profile names it (#565); an
        // enterprise relationship takes `fedSubjectClaim` where one is set,
        // and otherwise what this service has always taken: `sub`, then
        // `id`, then `user_id`.
        const claim = String(record.fedSubjectClaim || '').trim();
        const named = claim
          ? consumerProviders.readPath(profile, claim) : undefined;
        const fallback = claim
          ? ((typeof named === 'string' || typeof named === 'number')
              ? String(named) : '')
          : String(profile.sub || profile.id || profile.user_id || '');
        const reading = this.consumerReading(record,
          { userinfo: profile, emails: emails, token: tokens }, bag,
          fallback, this.federatedAmr([]), '');
        if (!reading.subject) {
          errorCodes.mark(res, 'STS-FED-0177');
          log.debug("Leaving the profile answer's continuation. No subject.");
          return this.refuse(res, record, 502, 'The partner named nobody',
            'The profile endpoint answered, and ' +
            (claim ? 'fedSubjectClaim (' + xmlEscape(claim) + ')'
                   : record.fedProvider
                     ? 'the ' + xmlEscape(String(record.fedProvider)) +
                       ' profile\'s subject rule'
                     : 'none of sub, id and user_id') +
            ' found a value in it. A sign-in with no stable subject could ' +
            'not be linked to anybody.',
            this.bagTable(bag));
        }
        log.debug("Leaving the profile answer's continuation.");
        return this.completeSignIn(req, res, record, {
          subject: reading.subject,
          // No token names an issuer here: the relationship's partner is the
          // one whose profile endpoint answered.
          issuer: String(record.fedPeer || ''),
          bag: reading.bag, amr: reading.amr, acr: reading.acr,
          returnTo: this.fromContext(context).returnTo,
          connect: this.fromContext(context).connect,
          application: this.fromContext(context).application,
          authnPending: this.fromContext(context).authnPending
        });
      });
    });
  }

  // ---------------------------------------------------------------------------
  // THE SECOND PROFILE ENDPOINT (#565): GitHub's `/user/emails`, the one place
  // that provider says which of a person's addresses is theirs and verified.
  // Asked only for a relationship whose provider profile reads the `emails`
  // source, with the same access token, through `fedEmailsUrl` — the fourth
  // diallable attribute, argued in federation_http.ts. A failure costs the
  // address and never the sign-in: the person is already named by the profile
  // endpoint, and the profile's `email` rule then finds nothing, so no
  // address is written rather than an unverified one.
  // Answers the parsed answer, or undefined.
  // ---------------------------------------------------------------------------
  private emailsFor(record, accessToken): Promise<any> {
    const { fedHttp, audit, log } = this.deps;
    log.debug("Entering FederationSp.emailsFor().");
    const profile = consumerProviders.profileFor(record.fedProvider);
    if (!consumerProviders.reads(profile, 'emails') ||
        !String(record.fedEmailsUrl || '').trim()) {
      log.debug("Leaving FederationSp.emailsFor(). Not asked.");
      return Promise.resolve(undefined);
    }
    log.debug("Leaving FederationSp.emailsFor(). Asking.");
    return fedHttp.fetchJson(record, 'fedEmailsUrl',
                             { method: 'GET', bearer: accessToken })
      .then(function (answer: any): any {
        if (!answer.ok || answer.json == null) {
          log.warn('federation: the address endpoint ' + answer.url + ' did ' +
                   'not answer for ' + record.fedId + ' (' + answer.why +
                   '). The sign-in goes on without an address.');
          audit.failure('STS-FED-0176', {
            protocol: 'Federation', channel: 'http', target: record.fedId,
            summary: 'the address request for the federation relationship ' +
                     record.fedId + ' failed (' + answer.why + '); the ' +
                     'sign-in continued without an address',
            outcome: 'error',
            detail: { cause: answer.errorCode || 'STS-FED-0056' }
          });
          return undefined;
        }
        return answer.json;
      });
  }

  // ---------------------------------------------------------------------------
  // A CONSUMER PROVIDER'S READING OF A SIGN-IN (#565), and nothing at all for
  // an enterprise relationship, whose subject, bag and authentication context
  // pass through exactly as before.
  //
  // For a consumer one, `consumer_providers.ts` reads the profile's rules
  // against the sources in hand: the subject (where the protocol lets a
  // profile name it — never an ID Token's), the named claims over the raw
  // bag, and `email_verified`, false unless the provider's own statement says
  // true. THE PROVIDER'S AUTHENTICATION CONTEXT IS BELIEVED ONLY WHERE THE
  // PROFILE TRUSTS IT (the risk design's decision 2): otherwise the session
  // claims `federated` and nothing more, so a provider asserting `mfa` or
  // `hwk` satisfies no step-up here, and what it claimed is kept on the bag
  // as `provider_amr` / `provider_acr` for the record.
  // ---------------------------------------------------------------------------
  private consumerReading(record, sources, bag, subject, amr, acr) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.consumerReading().");
    const profile = consumerProviders.profileFor(record.fedProvider);
    if (!profile) {
      log.debug("Leaving FederationSp.consumerReading(). Enterprise.");
      return { subject: subject, bag: bag, amr: amr, acr: acr };
    }
    const read = consumerProviders.extract(profile, sources, bag);
    const out = read.bag;
    const claimed = (amr || []).filter(function (one) {
      return one !== 'federated';
    });
    if (claimed.length) out.provider_amr = claimed.join(' ');
    if (acr) out.provider_acr = acr;
    log.debug("Leaving FederationSp.consumerReading(). " + profile.id);
    return {
      // A profile that names the subject is authoritative: nothing found is
      // nobody, never a guess (STS-FED-0177 at the caller).
      subject: record.fedProtocol === 'oidc' ? subject
        : (read.subject || (profile.subject ? '' : subject)),
      bag: out,
      amr: this.federatedAmr(read.mfa),
      acr: read.mfa.length ? 'mfa' : ''
    };
  }

  // ---------------------------------------------------------------------------
  // The endpoint itself. GET and POST, because a SAML Response arrives by POST,
  // a WS-Federation one by POST, an OAuth redirect by GET and an OIDC form_post
  // by POST — and which one it is depends on the relationship rather than on
  // the method.
  // ---------------------------------------------------------------------------
  private consume(req, res) {
    const { federation, errorCodes, log, xmlEscape } = this.deps;
    log.debug("Entering the federation assertion consumer service. id=" +
              req.params.id);
    if (!this.enabled()) {
      errorCodes.mark(res, 'STS-FED-0001');
      res.status(404).type('html').send(this.page('Not here',
        '<h1>Federation is off</h1><p><code>federation.enabled</code> is ' +
        'off.</p>'));
      log.debug("Leaving the assertion consumer service. Federation is off.");
      return;
    }
    const id = String(req.params.id || '');
    const record = federation.get(id);
    // An ssf relationship (#374) has no assertion consumer service.
    if (!record || record.fedRole !== 'service-provider' ||
        !federation.signsIn(record)) {
      errorCodes.mark(res, 'STS-FED-0002');
      res.status(404).type('html').send(this.page('No such relationship',
        '<h1>No such assertion consumer service</h1><p>There is no ' +
        'service-provider-side relationship called ' +
        '<code>' + xmlEscape(id) + '</code>.</p>'));
      log.debug("Leaving the assertion consumer service. No such " +
                'relationship.');
      return;
    }
    if (federation.categoryOf(record) === 'consumer' &&
        !federation.consumerProvidersOn()) {
      errorCodes.mark(res, 'STS-FED-0175');
      log.debug("Leaving FederationSp.consume(). Consumer providers are off.");
      return this.refuse(res, record, 403, 'Consumer providers are off here',
        'This relationship is a consumer or social provider, and this ' +
        'realm has federation.consumerProviders off. A response for it is ' +
        'refused without being looked at.');
    }
    if (!federation.isUsable(record)) {
      errorCodes.mark(res,
                      federation.isEnabled(record) ? 'STS-FED-0006' :
                      'STS-FED-0005');
      log.debug("Leaving FederationSp.consume().");
      return this.refuse(res, record, 403, 'That relationship is not usable',
        federation.isEnabled(record)
          ? 'It is enabled but not fully configured: ' +
            federation.readinessOf(record).missing.join(', ') + ' still to set.'
          : 'It is disabled. A response arriving for a disabled relationship ' +
            'is refused without being looked at — which is what disabling is ' +
            'for.');
    }
    const params = this.paramsOf(req);
    // THE FLOW'S CELL (#98 D10), before the response is verified or anything
    // in it spent: a partner's answer names the context this service stored
    // when the flow began — RelayState, SAML 1.1's fedctx, wctx or state —
    // and that context is held only by the cell that stamped it. A
    // browser pinned elsewhere was placed at the edge already; this is the
    // one that was not. An unsolicited response names nothing and is served
    // here.
    const named: any = params;
    const flowHandle = String(named.RelayState || named.fedctx ||
                              named.wctx || named.state || '');
    if (cellPlacement.relayIfElsewhere(req, res, flowHandle,
                                       'a federation partner\'s response')) {
      log.debug("Leaving FederationSp.consume(). Relayed to the cell that " +
                "holds the flow.");
      return undefined;
    }
    try {
      if (record.fedProtocol === 'saml2') {
        log.debug("Leaving FederationSp.consume().");
        return this.consumeSamlResponse(req, res, record, params, '2.0');
      }
      if (record.fedProtocol === 'saml11') {
        log.debug("Leaving FederationSp.consume().");
        return this.consumeSamlResponse(req, res, record, params, '1.1');
      }
      if (record.fedProtocol === 'wsfed') {
        log.debug("Leaving FederationSp.consume().");
        return this.consumeWsFedResponse(req, res, record, params);
      }
      // An OP discovered through a federation (#134) is resolved again —
      // from the resolution cache, as a rule — so the code is redeemed at,
      // and the ID Token verified against, what its chain vouches for NOW.
      const rp = this.deps.oidfedRp();
      if (rp.isFederated(record)) {
        log.debug("Leaving FederationSp.consume(). Resolving the OP.");
        return rp.effectiveRecord(req, record).then((got) => {
          if (!got.ok) {
            // error-code: none — the resolution's own code, in got.code
            errorCodes.mark(res, String(got.code || 'STS-FED-0148'));
            return this.refuse(res, record, 502, 'The OpenID Provider could ' +
                               'not be trusted', xmlEscape(String(got.why)));
          }
          return this.consumeOauthResponse(req, res, got.record, params);
        }).catch((e) => {
          log.error(errorCodes.tag('STS-FED-0042') + 'federation: ' + id +
                    ' threw while resolving its OP: ' +
                    (e && e.stack ? e.stack : e));
          errorCodes.mark(res, 'STS-FED-0042');
          return this.refuse(res, record, 500, 'This service failed while ' +
                             'reading the response', xmlEscape(String(
                               (e && e.message) || e)));
        });
      }
      log.debug("Leaving FederationSp.consume().");
      return this.consumeOauthResponse(req, res, record, params);
    } catch (e) {
      // Every branch above can throw on a malformed document, and a throw here
      // reaches express's error handler as a 500 with a stack trace in it. This
      // catches it into the same refusal page every other failure draws, so
      // that the relationship records what happened and the person sees a
      // sentence.
      log.error(errorCodes.tag('STS-FED-0042') + 'federation: ' + id + ' ' +
          'threw while consuming a response: ' + e.stack);
      errorCodes.mark(res, 'STS-FED-0042');
      log.debug("Leaving FederationSp.consume().");
      return this.refuse(res, record, 500, 'This service failed while ' +
                                      'reading the response',
                    e.message);
    }
  }

  // ---------------------------------------------------------------------------
  // GET /federation/metadata/{id} — THIS SERVICE'S OWN SAML metadata for one
  // partner.
  //
  // It is per relationship for the reason `ourEntityId()` is: this service
  // calls itself something different to every partner, so one document naming
  // one entityID would be wrong for all but the first.
  //
  // It is UNSIGNED, and that is worth saying rather than leaving to be noticed.
  // `/saml2/metadata/{sp}` — the identity-provider side — IS signed, because a
  // service provider configuring its trust in this service has something to
  // gain from checking who wrote the document. Here the situation is reversed:
  // the partner is being told where to send things and which certificate we
  // sign requests with, and a signature over that made by the very key in
  // question proves nothing they did not already have to trust.
  // ---------------------------------------------------------------------------
  private metadataEndpoint(req, res) {
    const {
      config, federation, errorCodes, log, logArtifact, STS, xmlEscape,
      baseUrlOf
    } = this.deps;
    log.debug("Entering the federation metadata endpoint. id=" + req.params.id);
    const id = String(req.params.id || '');
    const record = federation.get(id);
    if (!record || record.fedRole !== 'service-provider' ||
        (record.fedProtocol !== 'saml2' && record.fedProtocol !== 'saml11' &&
         record.fedProtocol !== 'wsfed')) {
      errorCodes.mark(res, 'STS-FED-0003');
      res.status(404).type('html').send(this.page('No such metadata',
        '<h1>No metadata here</h1><p>There is no SAML or WS-Federation ' +
        'service-provider-side relationship called ' +
        '<code>' + xmlEscape(id) + '</code>. An OpenID Connect ' +
        'relationship publishes its encryption key at ' +
        federation.PATHS.jwks + '/{id} instead, and a plain OAuth 2.0 one ' +
        'publishes nothing — what a partner needs for those is on <a ' +
        'href="' + BASE_PATH + '">' + BASE_PATH + '</a>.</p>'));
      log.debug("Leaving the federation metadata endpoint. Not a SAML " +
                'or WS-Federation relationship.');
      return;
    }
    const base = baseUrlOf(req);
    // THE KEY A PARTNER ENCRYPTS TO (#168): saml-metadata-2.0-os section
    // 2.4.1.1's KeyDescriptor use="encryption", with the EncryptionMethods
    // this relationship accepts and nothing else. SAML 1.1 has no encryption
    // construct and publishes none.
    const encryption = record.fedProtocol === 'saml11' ? ''
      : this.deps.fedEncryption.keyDescriptorOf(record);
    if (record.fedProtocol === 'wsfed') {
      return this.wsfedMetadata(req, res, record, base, encryption);
    }
    // The XML signing key (#42, D2): what this service signs its outbound
    // AuthnRequests with — the PINNED xml key where the realm signs with one
    // (#263), since `STS.xmlSigner` is what signs them then.
    const signer = STS.xmlSigner;
    const der = (signer && signer.pinned ? signer : STS.xml).certPem
      .replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, '');
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ' +
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
        'entityID="' + xmlEscape(this.ourEntityId(base, record)) + '">' +
      '<md:SPSSODescriptor AuthnRequestsSigned="' +
        (federation.boolOf(record.fedSignRequest, false) ? 'true' : 'false') +
      '" ' +
        'WantAssertionsSigned="true" protocolSupportEnumeration="' +
        (record.fedProtocol === 'saml11' ? NS_SAMLP11 : NS_SAMLP) +
      '"><md:KeyDescriptor ' +
      'use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>' +
        der +
      '</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>' +
      encryption +
      // `federation.spNameIdFormat` since 2026-09-12; the literal before it is
      // the setting's default. THE SINGLE LOGOUT SERVICE (#167), on the
      // two bindings a partner's LogoutRequest and LogoutResponse are
      // accepted on — SAML 2.0 only:
      // SAML 1.1 defines no logout, so its SPSSODescriptor names none.
      // saml-metadata-2.0-os section 2.4.2 puts it before NameIDFormat.
      (record.fedProtocol === 'saml2'
        ? '<md:SingleLogoutService Binding="' + BINDING_REDIRECT + '" ' +
          'Location="' + xmlEscape(this.sloUrl(base, record)) + '"/>' +
          '<md:SingleLogoutService Binding="' + BINDING_POST + '" ' +
          'Location="' + xmlEscape(this.sloUrl(base, record)) + '"/>'
        : '') +
      '<md:NameIDFormat>' +
      xmlEscape(String(config.value('federation.spNameIdFormat') || '')) +
        '</md:NameIDFormat>' +
      '<md:AssertionConsumerService Binding="' + BINDING_POST + '" ' +
        'Location="' + xmlEscape(this.acsUrl(base, record)) + '" index="0" ' +
      'isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>';
    logArtifact('federation service provider metadata', 'as served', xml);
    // no-store for the reason every document carrying this service's key gets
    // it: in development mode the signing key is regenerated on every start, so
    // a cached copy describes a key that no longer exists.
    res.type('application/samlmetadata+xml')
       .set('Cache-Control', 'no-store')
       .send(xml);
    log.debug("Leaving the federation metadata endpoint.");
  }

  // ---------------------------------------------------------------------------
  // A WS-FEDERATION RELYING PARTY'S METADATA (#168): WS-Federation 1.2
  // section 3.1's document — an EntityDescriptor holding a RoleDescriptor of
  // type fed:ApplicationServiceType, with the PassiveRequestorEndpoint the
  // partner sends a wresult to and, since #168, the key it encrypts the
  // token to. It is what AD FS imports a relying party from. Unsigned, for
  // the SAML document's reason above.
  //
  // **fed:ApplicationServiceEndpoint IS REQUIRED, AND WAS MISSING UNTIL
  // #188 (2026-09-24).** WS-Federation 1.2's schema gives
  // ApplicationServiceType a sequence of ApplicationServiceEndpoint
  // (minOccurs 1), SingleSignOutNotificationEndpoint and
  // PassiveRequestorEndpoint, so a document holding only the last is invalid
  // against the published schema and a validating importer refuses it — which
  // tests/vendored/sts_xml_schema_validation.js found. Both name the one
  // address this relationship has, as AD FS's own relying-party documents do.
  // ---------------------------------------------------------------------------
  private wsfedMetadata(req, res, record, base, encryption) {
    const { log, logArtifact, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.wsfedMetadata().");
    const fed = 'http://docs.oasis-open.org/wsfed/federation/200706';
    const endpoint = '<wsa:EndpointReference ' +
      'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
      xmlEscape(this.acsUrl(base, record)) +
      '</wsa:Address></wsa:EndpointReference>';
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<md:EntityDescriptor xmlns:md="' + NS_MD + '" ' +
        'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
        'entityID="' + xmlEscape(this.ourEntityId(base, record)) + '">' +
      '<md:RoleDescriptor ' +
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
        'xmlns:fed="' + fed + '" xsi:type="fed:ApplicationServiceType" ' +
        'protocolSupportEnumeration="' + fed + '">' + encryption +
      '<fed:ApplicationServiceEndpoint>' + endpoint +
        '</fed:ApplicationServiceEndpoint>' +
      '<fed:PassiveRequestorEndpoint>' + endpoint +
        '</fed:PassiveRequestorEndpoint>' +
      '</md:RoleDescriptor></md:EntityDescriptor>';
    logArtifact('federation WS-Federation relying party metadata', 'as served',
                xml);
    res.type('application/samlmetadata+xml')
       .set('Cache-Control', 'no-store')
       .send(xml);
    log.debug("Leaving FederationSp.wsfedMetadata().");
  }

  // ---------------------------------------------------------------------------
  // GET /federation/jwks/{id} — AN OPENID CONNECT RELATIONSHIP'S KEY (#168),
  // `use: enc`, what the partner registers as this relying party's `jwks` or
  // `jwks_uri` to encrypt its ID Token to (OpenID Connect Registration section
  // 2). The current key only: a rotated-out key still decrypts through its
  // grace period, and a partner is never TOLD to encrypt to it. `no-store`,
  // as every document carrying a key is.
  // ---------------------------------------------------------------------------
  private jwksEndpoint(req, res) {
    const { federation, errorCodes, fedEncryption, log, xmlEscape } =
      this.deps;
    log.debug("Entering the federation JWKS endpoint. id=" + req.params.id);
    const id = String(req.params.id || '');
    const record = federation.get(id);
    if (!record || record.fedRole !== 'service-provider' ||
        record.fedProtocol !== 'oidc') {
      errorCodes.mark(res, 'STS-FED-0146');
      res.status(404).type('html').send(this.page('No such key set',
        '<h1>No key set here</h1><p>There is no OpenID Connect ' +
        'service-provider-side relationship called <code>' + xmlEscape(id) +
        '</code>. A SAML 2.0 or WS-Federation relationship publishes its ' +
        'encryption key in its metadata at ' + METADATA_PATH + '/{id}.</p>'));
      log.debug("Leaving the federation JWKS endpoint. Not OIDC.");
      return;
    }
    const jwk = fedEncryption.publicJwkOf(record);
    res.status(200).type('application/jwk-set+json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify({ keys: jwk ? [jwk] : [] }));
    log.debug("Leaving the federation JWKS endpoint. " + (jwk ? jwk.kid :
                                                          'No key.'));
  }

  // ---------------------------------------------------------------------------
  // GET /federation — what all of this is.
  //
  // A PAGE OF THE FEDERATION SURFACE SINCE #580: the shell, with the facts
  // in `data-sts-state` — the relationships in each direction, the
  // endpoints' paths, the base this service sees itself at and whether the
  // sign-in screen offers partners — and every word of it drawn in the
  // browser from the `federationPages` catalogs
  // (`federation/web_federation_views.ts`).
  // ---------------------------------------------------------------------------
  private indexEndpoint(req, res) {
    const { config, federation, log, baseUrlOf } = this.deps;
    log.debug("Entering the federation index.");
    FederationPages.mark(res);
    const all = federation.list();
    const protocolOf = function (record): string {
      return String((federation.protocolRow(record.fedProtocol) || {})
        .label || record.fedProtocol || '');
    };
    const consuming = all.filter((one) => {
      return one.fedRole === 'service-provider';
    }).map((record) => {
      const usable = federation.isUsable(record);
      return {
        id: String(record.fedId), protocol: protocolOf(record),
        peer: String(record.fedPeer || ''),
        state: usable ? 'ready'
          : (federation.isEnabled(record) ? 'incomplete' : 'disabled'),
        missing: usable ? [] : federation.readinessOf(record).missing
          .map(String),
        metadata: record.fedProtocol === 'saml2' ||
                  record.fedProtocol === 'saml11'
      };
    });
    const asserting = all.filter((one) => {
      return one.fedRole === 'identity-provider';
    }).map((record) => {
      return {
        id: String(record.fedId), protocol: protocolOf(record),
        application: String(record.fedApplication || ''),
        release: (record.fedRelease || []).map(String)
      };
    });
    const view = {
      kind: 'index', base: String(baseUrlOf(req)),
      loginButtons: !!config.value('federation.loginButtons'),
      consuming: consuming, asserting: asserting,
      paths: { login: LOGIN_PATH, acs: ACS_PATH, metadata: METADATA_PATH,
               slo: SLO_PATH,
               backchannel: federation.PATHS.backchannelLogout,
               frontchannel: federation.PATHS.frontchannelLogout }
    };
    FederationPages.send(res, 200, view);
    log.debug("Leaving the federation index. " + consuming.length +
              " consuming, " + asserting.length + " asserting.");
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
const slot = new InstanceSlot<FederationSp>(
  'federation/federation_sp',
  () => new FederationSp(FederationSp.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

// A PEER'S QUESTION ABOUT A PARTNER'S LINK (#98 D9): see homeOfSubject().
// Registered once at load; registering binds and dials nothing.
fedProvision.registerIdleJob();
require('./../common/cell_channel').registerOp(LINK_HOME_OP,
  function (body: any) {
    return FederationSp.answerLinkHome(body);
  });
// THE PEERS' HALF OF A PROVIDER'S NOTIFICATION (#727): see
// applyNotification(). Registered once at load; it binds and dials nothing.
require('./../common/cell_channel').registerOp(PEER_NOTIFICATION_OP,
  function (body: any, ctx: any) {
    return slot.get().notificationForPeer(body,
                                          String((ctx && ctx.peer) || ''));
  });

/**
 * This service as a federation service provider: signing a person in through a
 * configured partner, in SAML 2.0, SAML 1.1, WS-Federation, OpenID Connect or
 * OAuth 2.0, and this service's metadata for that partner.
 *
 * @namespace
 */
export = {
  /**
   * Forwards to `FederationSp.registerRoutes()` on the installed instance.
   */
  registerRoutes: slot.forward('registerRoutes'),
  FederationSp: FederationSp,
  /**
   * Installs the instance the composition root built, which the facades below
   * forward to.
   *
   * @param instance - the instance to install
   */
  installInstance: (instance: FederationSp): void => slot.install(instance),
  /**
   * Says whether the installed instance came from the root or the default.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * Forwards to `FederationSp.audienceCheck()`.
   */
  audienceCheck: slot.forward('audienceCheck'),
  /**
   * Forwards to `FederationSp.federatedAmr()`.
   */
  federatedAmr: slot.forward('federatedAmr'),
  /**
   * Forwards to `FederationSp.familyAlgorithms()`.
   */
  familyAlgorithms: slot.forward('familyAlgorithms'),
  BASE_PATH: FederationSp.BASE_PATH,
  LOGIN_PATH: FederationSp.LOGIN_PATH,
  ACS_PATH: FederationSp.ACS_PATH,
  METADATA_PATH: FederationSp.METADATA_PATH,
  LINK_PATH: FederationSp.LINK_PATH,
  LINK_VIA: FederationSp.LINK_VIA,
  // For tests/federation_subject_policy.js: which local person a verified
  // subject may become (#109), asked without a partner.
  /**
   * Forwards to `FederationSp.subjectDecision()`.
   */
  subjectDecision: slot.forward('subjectDecision'),
  /**
   * Forwards to `FederationSp.ourEntityId()`.
   */
  ourEntityId: slot.forward('ourEntityId'),
  /**
   * Forwards to `FederationSp.acsUrl()`.
   */
  acsUrl: slot.forward('acsUrl'),
  /**
   * Forwards to `FederationSp.certPemOf()`.
   */
  certPemOf: slot.forward('certPemOf'),
  // For `federation_slo.ts` (#167): the one request-context store (decision
  // 3) — a LogoutRequest this service sent, an end_session round trip and a
  // WS-Federation cleanup confirmation are in-flight flows exactly as a
  // sign-in is — and the SLO address; and, for tests/federation_signout.js,
  // how a partner's SessionNotOnOrAfter becomes the session's bound.
  /**
   * Forwards to `FederationSp.putContext()`.
   */
  putContext: slot.forward('putContext'),
  /**
   * Forwards to `FederationSp.takeContext()`.
   */
  takeContext: slot.forward('takeContext'),
  // The portal's connect (#565), reached by `portal/portal_connected_accounts`
  // at request time.
  beginConnect: slot.forward('beginConnect'),
  // A peer cell's part of a provider's notification (#727): the inter-cell
  // operation's handler, and a test's way to call it.
  notificationForPeer: slot.forward('notificationForPeer'),
  /**
   * Forwards to `FederationSp.sessionBoundOf()`.
   */
  sessionBoundOf: slot.forward('sessionBoundOf'),
  /**
   * Forwards to `FederationSp.sloUrl()`.
   */
  sloUrl: slot.forward('sloUrl'),
  // THE ONE PLACE A JWT FROM SOMEBODY ELSE IS VERIFIED, now for a Logout
  // Token as well as an ID Token (#167): the same keys, the same
  // key-decides-the-family rule, the same refusals.
  /**
   * Forwards to `FederationSp.keysFor()`.
   */
  keysFor: slot.forward('keysFor'),
  /**
   * Forwards to `FederationSp.verifyForeignJwt()`.
   */
  verifyForeignJwt: slot.forward('verifyForeignJwt'),
  SLO_PATH: SLO_PATH,
  // For tests/revocation_status.js: the check a configured signing certificate
  // or partner key gets once it has verified a response.
  /**
   * Forwards to `FederationSp.signerStillAccepted()`.
   */
  signerStillAccepted: slot.forward('signerStillAccepted')
};
