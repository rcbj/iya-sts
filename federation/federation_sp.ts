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
//   GET  /federation/metadata/{id}   THIS SERVICE'S OWN SAML metadata for that
//                                    partner, so the partner can be configured
//                                    without anybody typing five URLs.
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
// `registerRoutes(app)`. node's `crypto` and `zlib`, `jsonwebtoken` and
// xmldom are libraries and are used directly. Since #50's R2 the composition
// root builds the instance; the module's old names are FACADES forwarding to
// it, for the modules and tests that require it by them, and a process
// without the root builds a default at load. Loading the module registers
// NOTHING (#50, R1): the module exports `registerRoutes(app)`, and
// `common/protocol_stack.ts` calls it at the point in the route order where
// requiring this module used to register the routes (rule 1).
// ---------------------------------------------------------------------------

import crypto = require('crypto');
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

const { DOMParser } = xmldom;

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
const contexts = realms.map({ persist: 'federation_sp.contexts',
                              retain: 'age' });

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

class FederationSp {
  static readonly BASE_PATH = BASE_PATH;
  static readonly LOGIN_PATH = LOGIN_PATH;
  static readonly ACS_PATH = ACS_PATH;
  static readonly METADATA_PATH = METADATA_PATH;

  constructor(private readonly deps: FederationSpDeps) {
    deps.log.debug("Entering FederationSp.constructor().");
    deps.log.debug("Leaving FederationSp.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
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
      hasSubjectResolver: helpers.hasSubjectResolver
    };
  }

  // -------------------------------------------------------------------------
  // THE ROUTES, in the order this module has always registered them.
  // -------------------------------------------------------------------------
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
    // GET /federation/metadata/{id}
    app.get(METADATA_PATH + '/:id', (req, res) => {
      return this.metadataEndpoint(req, res);
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

  private putContext(record) {
    const { log, randomId } = this.deps;
    log.debug("Entering FederationSp.putContext().");
    const handle = 'fed-' + randomId(18);
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
    contexts.set(handle, Object.assign({ handle: handle, startedAt: now,
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
      application: (context && context.application) || ''
    };
  }

  // Read AND SPEND. A context is good for one response, which is what makes a
  // replayed assertion fail the second time even where the partner's own replay
  // window has not closed. The SAML 1.1 case is the one that has no context at
  // all — see `fedAllowUnsolicited` — and it is handled by the caller rather
  // than by pretending there was one.
  private takeContext(handle) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.takeContext(). handle=" +
              (handle || '(none)'));
    const record = contexts.get(String(handle || ''));
    if (!record) {
      log.debug("Leaving FederationSp.takeContext(). No such context.");
      return null;
    }
    contexts.delete(record.handle);
    if (record.expires < Date.now()) {
      log.debug("Leaving FederationSp.takeContext(). It had expired.");
      return null;
    }
    log.debug("Leaving FederationSp.takeContext(). Found it.");
    return record;
  }

  private enabled() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSp.enabled().");
    log.debug("Leaving FederationSp.enabled().");
    return !!config.value('federation.enabled');
  }

  private page(title, body) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.page().");
    log.debug("Leaving FederationSp.page().");
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + xmlEscape(title) + '</title><style>' + STYLE +
      '</style></head><body>' +
      body + '</body></html>';
  }

  // A refusal, and it does three things every time: it draws the reason, it
  // writes `fedLastError` on the relationship, and it answers a status code a
  // test can assert on. See decision 6 — it never redirects.
  // error-code: none — the definition of the helper, not a call to it
  private refuse(res, record, status, what, why, extra?) {
    const { federation, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.refuse(). what=" + what);
    const id = (record && record.fedId) || '';
    if (id) federation.recordFailure(id, what + ': ' + why);
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
  // It is PER RELATIONSHIP rather than one constant, which is the same decision
  // `saml2.perApplicationEntityId` makes in the other direction and for the
  // same reason: a partner keying its trust store off an entityID must be able
  // to be given one that is only ours-with-them.
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

  acsUrl(base, record) {
    const { log } = this.deps;
    log.debug("Entering FederationSp.acsUrl().");
    log.debug("Leaving FederationSp.acsUrl().");
    return base + ACS_PATH + '/' + encodeURIComponent(record.fedId);
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
      // relationship. See `federation/CLAUDE.md` — the gate is on the SIGNER,
      // and a permissive answer here would be an authentication bypass for
      // every protocol in the process.
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
                  context: '' };
    const nameEl = firstByLocal(assertion, 'NameID') ||
                   firstByLocal(assertion, 'NameIdentifier');
    if (nameEl) {
      out.subject = (nameEl.textContent || '').trim();
      out.nameFormat = nameEl.getAttribute('Format') ||
                       nameEl.getAttribute('Format') || '';
    }
    const authn = firstByLocal(assertion, 'AuthnStatement') ||
      firstByLocal(assertion, 'AuthenticationStatement');
    if (authn) {
      out.authnInstant = authn.getAttribute('AuthnInstant') ||
        authn.getAttribute('AuthenticationInstant') || '';
      out.context = textByLocal(authn, 'AuthnContextClassRef') ||
        authn.getAttribute('AuthenticationMethod') || '';
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
  // it are as thin as they are: the mapping, the directory entry, the counters,
  // the audit trail and the session are the same five acts in every protocol,
  // and five copies of them would be five subtly different federated sign-ins.
  //
  // THE ORDER MATTERS AND IS NOT ARBITRARY:
  //
  //   1. map, so the username exists before anything is filed under it;
  //   2. the relationship's counters;
  //   3. the application record for the partner, so `/admin/applications` knows
  //      the foreign identity provider exists;
  //   4. the session, LAST, because it is the thing that has an effect outside
  //      this process and everything above it is a record of why. It goes
  //      through `authn.startSession()`, which is also where the identity
  //      funnel (`recordAuthentication()`) runs — the funnel that seeds the
  //      directory entry AND carries the mapped attributes to it; see WHAT THE
  //      FUNNEL IS TOLD below for why it is not called separately.
  // ---------------------------------------------------------------------------
  private completeSignIn(req, res, record, result) {
    const {
      applications, authn, federation, fedMap, errorCodes, log, subjectForName,
      hasSubjectResolver
    } = this.deps;
    log.debug("Entering FederationSp.completeSignIn(). id=" + record.fedId);
    const mapped = fedMap.mapIncoming(record, result.bag, result.subject);
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
      summary: mapped.username + ' was signed in through the federation ' +
                                 'relationship "' +
               record.fedId + '"; this service checked no credential of ' +
                              'theirs ' +
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
        protocolLabel: protocolLabel,
        subject: result.subject,
        autocreate: federation.boolOf(record.fedAutocreateUsers, true),
        // Whether the partner's attributes overwrite the entry's on a sign-in
        // that did not create it (2026-09-14). See `fedUpdateUserAttributes`.
        updateAttributes: federation.boolOf(record.fedUpdateUserAttributes,
                                            true),
        attributes: mapped.attributes,
        mapped: mapped.mapped.length,
        unmapped: mapped.unmapped.map((one) => { return one.incoming; })
      }
    };

    // The relationship's own counts, and — where this sign-in began at an
    // application configured to authenticate through it — that pair's counts
    // beside them. `result.application` is the hint the login endpoint put on
    // the request context; recordUse() decides whether it means anything.
    federation.recordUse(record.fedId,
                         { user: mapped.username,
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
    // facts on it — including the mapped attributes, which reach the directory
    // through the identity funnel and by no other route.
    // `request` so a federated sign-in REPLACES whatever session this browser
    // was on rather than leaving the previous one alive beside it.
    const session = authn.startSession(res, mapped.username, amr,
                                       result.acr || '', via,
                                       Object.assign({
                                         request: req,
                                         application:
                                           record.fedApplication || ''
                                       }, detail));
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
    if (!session && hasSubjectResolver() &&
        !subjectForName(mapped.username)) {
      log.info('federation: no session for ' + mapped.username + ' arriving ' +
               'through ' +
               '' + record.fedId + ': the directory holds no entry for ' +
               'them and dynamic provisioning is ' +
               (federation.boolOf(record.fedAutocreateUsers, true)
                 ? 'on but the directory declined to create one.'
                 : 'off on this relationship.'));
      errorCodes.mark(res, 'STS-FED-0090');
      log.debug("Leaving FederationSp.completeSignIn().");
      return this.refuse(res, record, 403, 'This person has not been ' +
                                           'provisioned',
        'The assertion verified and the partner is configured, but this ' +
        'service holds no directory entry for ' + mapped.username + ', and ' +
        (federation.boolOf(record.fedAutocreateUsers, true)
          ? 'the directory would not create one (ldap.autocreateUsers is ' +
            'off, or it is full).'
          : 'dynamic provisioning (fedAutocreateUsers) is off on this ' +
            'relationship, so the person has to be created here first — ' +
            'through SCIM, /admin/users/new or the management API — under ' +
            'the username this relationship maps them to.'));
    }
    if (!session) {
      log.info('federation: the issuance policy refused a session for ' +
               mapped.username + ' arriving through ' + record.fedId + '.');
      errorCodes.mark(res, 'STS-FED-0044');
      log.debug("Leaving FederationSp.completeSignIn().");
      return this.refuse(res, record, 403, 'The issuance policy refused the ' +
                                           'session',
        'The assertion verified and the partner is configured — this service ' +
        'will not start a session for ' + mapped.username + ' because the ' +
        'issuance policy said no. That is a POLICY decision rather than a ' +
        'problem with the assertion or with the partner, so retrying will ' +
        'not change it. The role an application requires is on /admin/roles ' +
        'and the document that decides is on /admin/xacml.');
    }
    log.info('federation: ' + mapped.username + ' signed in through ' +
             record.fedId +
             ' (' + protocolLabel + ' from ' + (record.fedPeer || 'an ' +
                 'unnamed partner') +
             '). ' + mapped.mapped.length + ' attribute(s) mapped, ' +
             mapped.unmapped.length + ' unmapped. Session ' + session.id + '.');

    const returnTo = result.returnTo || '';
    if (returnTo) {
      // 303, for the reason `authn.js`'s returnToCaller() gives at length: this
      // may follow a POST carrying an assertion, and 302's behaviour after a
      // POST is historically ambiguous where 303's is defined.
      res.redirect(303, returnTo);
      log.debug("Leaving FederationSp.completeSignIn(). Sent them on to " +
                returnTo + '.');
      return;
    }
    res.type('html').set('Cache-Control', 'no-store').send(
      this.page('Signed in',
                this.signedInPage(record, mapped, result, session)));
    log.debug("Leaving FederationSp.completeSignIn(). Drew the result page.");
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

  private signedInPage(record, mapped, result, session) {
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
        '</td><td class="note">nothing maps this name, so it was NOT ' +
        'written</td></tr>';
    }).join('');
    log.debug("Leaving FederationSp.signedInPage().");
    return '<h1>Signed in through ' +
      xmlEscape(record.fedName || record.fedId) +
      '</h1><p>This ' +
      'service is now signing you in as <code>' + xmlEscape(mapped.username) +
      '</code>. The session is <code>' + xmlEscape(session.id) + '</code>, ' +
      'and it is the SAME session every other protocol here reads — so an ' +
      'OAuth 2.0 authorization request, a WS-Federation sign-in or the admin ' +
      'console will now find you signed ' +
      'in.</p><table><tr><th>What</th><th>Value</th></tr><tr><td>Partner' +
      '</td><td><code>' + xmlEscape(record.fedPeer || '(unnamed)') +
      '</code></td></tr><tr><td>Protocol</td><td>' +
        xmlEscape((federation.protocolRow(record.fedProtocol) ||
                   {}).label || record.fedProtocol) +
        '</td></tr>' +
      '<tr><td>Subject the partner sent</td><td><code>' + xmlEscape(
          result.subject || '(none)') +
        '</code></td></tr>' +
      '<tr><td>Username here</td><td><code>' + xmlEscape(
          mapped.username) + '</code>' +
        (mapped.usernamePrefixed
          ? ' <span class="note">(federation.usernamePrefix was ' +
            'applied)</span>' :
         '') +
        ' <span class="note">from ' + xmlEscape(mapped.usernameFrom) +
      '</span></td></tr><tr><td>Directory ' +
      'entry</td><td>' +
        (federation.boolOf(record.fedAutocreateUsers, true)
          ? 'created if absent, under <code>ou=users</code> — see ' +
            '<a href="/admin/users">/admin/users</a>'
          : '<span class="note">NEVER created here: fedAutocreateUsers is ' +
            'off on this relationship, so the person must already have an ' +
            'entry</span>') +
        (federation.boolOf(record.fedUpdateUserAttributes, true)
          ? '; its attributes are updated from this assertion'
          : '<span class="note">; its attributes are written only when this ' +
            'sign-in creates it (fedUpdateUserAttributes is off)</span>') +
        '</td></tr></table>' +
      (rows ? '<h2>Attributes mapped onto the directory ' +
        'entry</h2><table><tr><th>The partner ' +
        'sent</th><th>Became</th><th>Value(s)</th><th>Decided by</th></tr>' +
        rows + unmapped + '</table>'
        : '<h2>Attributes</h2><p class="note">The partner sent no attributes ' +
          'at all, so the entry carries only the ' +
          'username.</p>' +
          (unmapped ? '<table>' + unmapped + '</table>' : '')) +
      (mapped.unmapped.length
        ? '<p class="note"><strong>' + mapped.unmapped.length + ' ' +
            'attribute(s) ' +
          'were thrown away</strong> because nothing maps their names. That ' +
          'is ' +
          'deliberate — this directory has no schema, so an attribute ' +
          'written ' +
          'under an unrecognised name would be accepted silently and nothing ' +
          'would ever report that the name was wrong. Add a mapping on <a ' +
          'href="/admin/federation?relationship=' +
          encodeURIComponent(record.fedId) +
          '">the relationship</a> to keep one.</p>'
        : '') +
      '<p><a href="' + BASE_PATH + '">Back to the federation index</a> · ' +
      '<a href="/admin/federation?relationship=' + encodeURIComponent(
          record.fedId) +
      '">This relationship in the console</a></p>';
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
    const id = '_' + crypto.randomBytes(16).toString('hex');
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
      // The XML signing key (#42, D2): `STS.xml`, not the JOSE key.
      privateKeyPem: STS.xml.privateKeyPem,
      certPem: STS.xml.certPem,
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
  private postBindingPage(action, fields, record) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.postBindingPage().");
    const inputs = Object.keys(fields).map((name) => {
      return '<input type="hidden" name="' + xmlEscape(name) + '" value="' +
        xmlEscape(String(fields[name])) + '">';
    }).join('');
    log.debug("Leaving FederationSp.postBindingPage().");
    return this.page('Continue to ' + (record.fedName || record.fedId),
      '<h1>Continue to ' + xmlEscape(record.fedName || record.fedId) + '</h1>' +
      '<p>This service is about to send you to <code>' +
      xmlEscape(record.fedSsoUrl) +
      '</code> to sign in. It will post ' +
      Object.keys(fields)
            .map((n) => { return '<code>' + xmlEscape(n) + '</code>'; })
        .join(' and ') + ' there.</p><p class="note">There is no script on ' +
      'this page and it does not submit itself. Five pages in this service ' +
      'DO auto-post, and each one argues for itself; this one does not, ' +
      'because you are leaving this service for a foreign identity provider ' +
      'and that is exactly the moment a deliberate click is worth ' +
      'having.</p><form method="post" ' +
      'action="' + xmlEscape(action) + '">' + inputs +
      '<button type="submit">Continue to the identity ' +
      'provider</button></form>');
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
    }
    const joiner = String(record.fedSsoUrl).indexOf('?') === -1 ? '?' : '&';
    const url = String(record.fedSsoUrl) + joiner + params.toString();
    log.debug("Leaving FederationSp.authorizationRequestUrl(). " +
              'response_type=' + responseType);
    return url;
  }

  private pkcePair() {
    const { log } = this.deps;
    log.debug("Entering FederationSp.pkcePair().");
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256')
                            .update(verifier)
                            .digest('base64url');
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
    if (!this.enabled()) {
      errorCodes.mark(res, 'STS-FED-0001');
      res.status(404).type('html').send(this.page('Not here',
        '<h1>Federation is off</h1><p><code>federation.enabled</code> is ' +
        'off, so no federation endpoint answers. No relationship was ' +
        'changed.</p>'));
      log.debug("Leaving the federation login endpoint. Federation is off.");
      return;
    }
    const id = String(req.params.id || '');
    const record = federation.get(id);
    if (!record) {
      errorCodes.mark(res, 'STS-FED-0002');
      res.status(404).type('html').send(this.page('No such relationship',
        '<h1>No such federation relationship</h1><p>There is no relationship ' +
        'called <code>' +
        xmlEscape(id) + '</code>. The configured ones are at <a href="' +
        BASE_PATH + '">' +
        BASE_PATH + '</a>.</p>'));
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
    if (!federation.isEnabled(record)) {
      errorCodes.mark(res, 'STS-FED-0005');
      return this.refuse(res, record, 403, 'That relationship is disabled',
        'It exists and is configured, and <code>fedEnabled</code> is FALSE. ' +
        'Every relationship is created disabled deliberately: a partner that ' +
        'half-exists and silently accepts assertions is the failure this ' +
        'whole register is arranged to prevent. Enable it on ' +
        '/admin/federation.');
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
                          record));
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

    // OIDC and OAuth 2.0.
    const handle = this.putContext(contextRecord);
    const stored = contexts.get(handle);
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
  // A SAML RESPONSE, 2.0 or 1.1, verified check by check.
  //
  // Every check is made and the FIRST failure refuses. That is deliberately not
  // the shape `/wsfed/rp` and `/saml2/sp` use — those are mock relying parties
  // whose whole job is to report every check to a person reading the page, so
  // they collect verdicts and show them all. THIS endpoint issues a session, so
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

    const assertion = firstByLocal(root, 'Assertion');
    if (!assertion) {
      errorCodes.mark(res, 'STS-FED-0011');
      log.debug("Leaving FederationSp.consumeSamlResponse().");
      return this.refuse(res, record, 400, 'There is no assertion in it',
        'The Response reported success and carried no <Assertion>. If the ' +
        'partner is configured to ENCRYPT the assertion, that is the cause: ' +
        'this service does not decrypt one — see federation/CLAUDE.md, where ' +
        'that is listed as a deliberate gap rather than left to be ' +
        'discovered here.');
    }

    // THE SIGNATURE. Either the Response or the Assertion may carry it and
    // either is enough — which is what every real service provider accepts,
    // because AD FS signs the assertion, Keycloak signs both and Shibboleth
    // signs the response. What is NOT enough is neither.
    const assertionSig = this.verifyXmlSignature(xml, record, 'Assertion');
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
    return this.signerStillAccepted(req, res, record, () => {
      return this.completeSignIn(req, res, record, {
        subject: contents.subject,
        bag: contents.bag,
        amr: this.federatedAmr([]),
        acr: contents.context || '',
        returnTo: this.fromContext(context).returnTo,
        application: this.fromContext(context).application
      });
    });
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
        'wa=' + wa + '. This endpoint consumes wa=wsignin1.0. A wsignout1.0 ' +
        'arriving here is a partner configured to send its sign-out where ' +
        'its sign-in goes — this service does not consume a federated ' +
        'sign-out, which is listed as a gap in federation/CLAUDE.md rather ' +
        'than left to be discovered.');
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
    const assertion = root ? firstByLocal(root, 'Assertion') : null;
    if (!assertion) {
      errorCodes.mark(res, 'STS-FED-0011');
      log.debug("Leaving FederationSp.consumeWsFedResponse().");
      return this.refuse(res, record, 400, 'There is no assertion in the ' +
                                           'wresult',
        'The RequestSecurityTokenResponse carried no <Assertion>. An ' +
        'ENCRYPTED token looks exactly like this from here; this service ' +
        'does not decrypt one.');
    }
    const version = assertion.namespaceURI === NS_SAML ? '2.0' : '1.1';
    log.debug('consumeWsFedResponse(): the token is a SAML ' + version + ' ' +
        'assertion.');

    const sig = this.verifyXmlSignature(wresult, record, 'Assertion');
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
    log.debug("Leaving FederationSp.consumeWsFedResponse(). Verified; " +
              'completing the sign-in once the signing certificate is known ' +
              'not to be revoked.');
    return this.signerStillAccepted(req, res, record, () => {
      return this.completeSignIn(req, res, record, {
        subject: contents.subject, bag: contents.bag,
        amr: this.federatedAmr([]), acr: contents.context || '',
        returnTo: this.fromContext(context).returnTo,
        application: this.fromContext(context).application
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
  private keysFor(record) {
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

  private verifyForeignJwt(token, record, keys, options) {
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
        pem = crypto.createPublicKey({ key: candidates[i], format: 'jwk' });
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
    if (record.fedClientSecret) {
      options.basic = { user: record.fedClientId,
                        pass: record.fedClientSecret };
    } else {
      // A public client. The client_id goes in the body, which is what RFC 6749
      // section 4.1.3 requires when the client does not authenticate.
      form.client_id = String(record.fedClientId || '');
    }
    log.debug('consumeOauthResponse(): redeeming the code at the partner.');
    log.debug("Leaving FederationSp.consumeOauthResponse().");
    return fedHttp.fetchJson(record, 'fedTokenUrl', options)
                  .then((answer) => {
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

  private finishOidc(req, res, record, context, idToken, accessToken) {
    const { fedHttp, errorCodes, audit, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSp.finishOidc().");
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
        // verifyForeignJwt() is never reached without it.
        issuer: String(record.fedPeer || '') || undefined
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
             'c_hash',
             'azp', 'auth_time', 'sid', 'sub', 'acr', 'amr'].indexOf(
                 name) !== -1) return;
        bag[name] = payload[name];
      });
      // The partner's amr BEHIND `federated`, not instead of it — see
      // federatedAmr().
      const amr = this.federatedAmr(payload.amr);
      const finish = (extra) => {
        log.debug("Entering finish().");
        Object.keys(extra || {}).forEach((name) => {
          if (bag[name] === undefined) bag[name] = extra[name];
        });
        log.debug("Leaving finish().");
        // The key that verified the ID Token is checked for revocation here,
        // on the one path into the sign-in, whether or not UserInfo was asked.
        return this.signerStillAccepted(req, res, record, () => {
          return this.completeSignIn(req, res, record, {
            subject: String(payload.sub || ''), bag: bag, amr: amr,
            acr: String(payload.acr || ''),
            returnTo: this.fromContext(context).returnTo,
            application: this.fromContext(context).application
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
    const { fedHttp, errorCodes, log } = this.deps;
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
        log.debug("Leaving FederationSp.finishOauth2(). A verified JWT " +
                  'access token.');
        return this.signerStillAccepted(req, res, record, () => {
          return this.completeSignIn(req, res, record, {
            subject: String(payload.sub || ''), bag: bag,
            amr: this.federatedAmr([]),
            acr: '',
            returnTo: this.fromContext(context).returnTo,
            application: this.fromContext(context).application
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
      return this.completeSignIn(req, res, record, {
        subject: String(profile.sub || profile.id || profile.user_id || ''),
        bag: bag, amr: this.federatedAmr([]), acr: '',
        returnTo: this.fromContext(context).returnTo,
        application: this.fromContext(context).application
      });
    });
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
    if (!record || record.fedRole !== 'service-provider') {
      errorCodes.mark(res, 'STS-FED-0002');
      res.status(404).type('html').send(this.page('No such relationship',
        '<h1>No such assertion consumer service</h1><p>There is no ' +
        'service-provider-side relationship called ' +
        '<code>' + xmlEscape(id) + '</code>.</p>'));
      log.debug("Leaving the assertion consumer service. No such " +
                'relationship.');
      return;
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
        (record.fedProtocol !== 'saml2' && record.fedProtocol !== 'saml11')) {
      errorCodes.mark(res, 'STS-FED-0003');
      res.status(404).type('html').send(this.page('No such metadata',
        '<h1>No metadata here</h1><p>There is no SAML service-provider-side ' +
        'relationship called ' +
        '<code>' + xmlEscape(id) + '</code>. Metadata is a SAML thing, ' +
        'so an OIDC, OAuth 2.0 or WS-Federation relationship has none — what ' +
        'a partner needs for those is on <a ' +
        'href="' + BASE_PATH + '">' + BASE_PATH + '</a>.</p>'));
      log.debug("Leaving the federation metadata endpoint. Not a SAML " +
                'relationship.');
      return;
    }
    const base = baseUrlOf(req);
    // The XML signing key (#42, D2): what this service signs its outbound
    // AuthnRequests with.
    const der = STS.xml.certPem.replace(/-----[^-]+-----/g, '')
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
      // `federation.spNameIdFormat` since 2026-09-12; the literal before it is
      // the setting's default.
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
  // GET /federation — what all of this is.
  // ---------------------------------------------------------------------------
  private indexEndpoint(req, res) {
    const { config, federation, log, xmlEscape, baseUrlOf } = this.deps;
    log.debug("Entering the federation index.");
    const base = baseUrlOf(req);
    const all = federation.list();
    const consuming =
        all.filter((one) => { return one.fedRole === 'service-provider'; });
    const asserting = all.filter((one) => {
      return one.fedRole === 'identity-provider';
    });

    const consumeRows = consuming.map((record) => {
      const readiness = federation.readinessOf(record);
      const usable = federation.isUsable(record);
      return '<tr><td><code>' + xmlEscape(record.fedId) + '</code></td>' +
        '<td>' +
        xmlEscape((federation.protocolRow(record.fedProtocol) || {}).label ||
                           record.fedProtocol) + '</td>' +
        '<td><code>' + xmlEscape(record.fedPeer || '(none set)') +
        '</code></td><td ' +
        'class="' + (usable ? 'ok' : 'bad') + '">' +
          (usable ? 'ready'
                  : (federation.isEnabled(record)
                       ? 'enabled, not configured: ' +
                         xmlEscape(readiness.missing.join(', '))
                       : 'disabled')) + '</td>' +
        '<td>' + (usable
          ? '<a href="' + LOGIN_PATH + '/' + encodeURIComponent(record.fedId) +
              '">Sign ' +
              'in</a>'
          : '<span class="note">—</span>') +
          ((record.fedProtocol === 'saml2' || record.fedProtocol === 'saml11')
            ? ' · <a href="' + METADATA_PATH + '/' +
              encodeURIComponent(record.fedId) +
              '">metadata</a>'
            : '') + '</td></tr>';
    }).join('');

    const assertRows = asserting.map((record) => {
      return '<tr><td><code>' + xmlEscape(record.fedId) + '</code></td>' +
        '<td>' +
        xmlEscape((federation.protocolRow(record.fedProtocol) || {}).label ||
                           record.fedProtocol) + '</td>' +
        '<td><code>' +
        xmlEscape(record.fedApplication || '(no application named)') +
        '</code></td><td>' + (record.fedRelease && record.fedRelease.length
          ? xmlEscape(record.fedRelease.join(', '))
          : '<span class="note">no release policy — this partner gets ' +
            'whatever /admin/claims and /admin/saml-attributes would give ' +
            'anybody</span>') + '</td></tr>';
    }).join('');

    const body = '<h1>Federation</h1><p>This service can be <strong>either ' +
      'end</strong> of a federation relationship, in five protocols: SAML ' +
      '2.0, ' +
      'SAML 1.1, WS-Federation 1.2, OpenID Connect and OAuth 2.0.</p><p ' +
      'class="note"><strong>This is the one feature here that has to be ' +
      'configured before it will do anything.</strong> Everywhere else this ' +
      'service accepts what it is given — any username, any client_id, any ' +
      'entityID, any LDAP bind. It cannot do that here: what arrives at an ' +
      'assertion consumer service is an unauthenticated request claiming to ' +
      'be ' +
      'a person, and the session it produces is the one every other protocol ' +
      'in this process reads. So a relationship is created DISABLED, and an ' +
      'assertion is refused unless it verifies against the key configured on ' +
      'it.</p><h2>Consuming: a foreign identity provider signs people in ' +
      'here</h2>' +
      (consumeRows
        ? '<table><tr><th>Relationship</th><th>Protocol</th><th>Partner</th>' +
          '<th>State</th><th></th></tr>' + consumeRows + '</table>'
        : '<p class="note">None configured. Add one on ' +
          '<a href="/admin/federation">/admin/federation</a>, or through ' +
          '<code>POST /admin-api/federation/create</code>.</p>') +
      '<h2>Asserting: this service signs people in to a foreign service ' +
      'provider</h2>' +
      (assertRows
        ? '<table><tr><th>Relationship</th><th>Protocol</th><th>' +
          'Application</th><th>Attributes ' +
          'released</th></tr>' + assertRows + '</table>'
        : '<p class="note">None configured. Every protocol endpoint here ' +
          'already issues to anybody that asks — what an ' +
          'identity-provider-side relationship adds is the partner being ' +
          'marked as a federation partner rather than a test client, and a ' +
          'list of which attributes are released to it.</p>') +
      '<h2>Endpoints</h2><table><tr><th>Path</th><th>What</th></tr>' +
      '<tr><td><code>' + LOGIN_PATH + '/{id}</code></td><td>Start a ' +
        'federated ' +
        'sign-in. Takes <code>?returnTo=</code>, a path on this service to ' +
        'land on ' +
        'afterwards.</td></tr><tr><td><code>' + ACS_PATH +
      '/{id}</code></td><td>Where ' +
        'the answer comes back: the assertion consumer service, the ' +
        'WS-Federation <code>wreply</code> and the OAuth 2.0 ' +
        '<code>redirect_uri</code>, all one path. <strong>This is the URL to ' +
        'configure at the ' +
        'partner.</strong></td></tr><tr><td><code>' + METADATA_PATH +
      '/{id}</code></td><td>This ' +
        'service\'s own SAML metadata for that partner. Unsigned, ' +
        'deliberately.</td></tr></table><p class="note">The base URL this ' +
        'service sees itself at is <code>' + xmlEscape(base) +
      '</code>, so the URLs above are absolute from there.</p>' +
      // **`/portal` AND NOT `/authn/login`, WHICH IS NOT A PAGE ANYBODY CAN BE
      // SENT TO.** That endpoint draws a form for a PENDING AUTHENTICATION
      // RECORD and answers `There is no sign-in waiting under that id` to a
      // request naming none, so this link was an error page for as long as it
      // existed. `/portal` has no session either, so `requireSignIn()` there
      // calls `beginAuthentication()` and the browser arrives at the very
      // screen this link promises — with the partner buttons on it, which is
      // the whole point of the sentence around it — and lands on the reader's
      // own account page once they have used one. The record is minted when the
      // link is PRESSED rather than when this page is drawn, which is what
      // keeps it from expiring on a page somebody left open. `portal/portal.ts`
      // carries the full argument; the same mistake was in two other files on
      // 2026-09-06.
      '<p><a href="/admin/federation">Configure relationships in the ' +
      'console</a> · <a href="/portal">The sign-in screen</a>' +
      (config.value('federation.loginButtons')
        ? ', which offers every usable partner as a button'
        : ' (federation.loginButtons is off, so no partner is offered there)') +
      '</p>';
    res.type('html')
       .set('Cache-Control', 'no-store')
       .send(this.page('Federation', body));
    log.debug("Leaving the federation index.");
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  FederationSp: FederationSp,
  installInstance: (instance: FederationSp): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  audienceCheck: slot.forward('audienceCheck'),
  federatedAmr: slot.forward('federatedAmr'),
  familyAlgorithms: slot.forward('familyAlgorithms'),
  BASE_PATH: FederationSp.BASE_PATH,
  LOGIN_PATH: FederationSp.LOGIN_PATH,
  ACS_PATH: FederationSp.ACS_PATH,
  METADATA_PATH: FederationSp.METADATA_PATH,
  ourEntityId: slot.forward('ourEntityId'),
  acsUrl: slot.forward('acsUrl'),
  certPemOf: slot.forward('certPemOf'),
  // For tests/revocation_status.js: the check a configured signing certificate
  // or partner key gets once it has verified a response.
  signerStillAccepted: slot.forward('signerStillAccepted')
};
