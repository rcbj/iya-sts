'use strict';
//
// File: federation_slo.ts
//
// ===========================================================================
// A FEDERATION PARTNER'S SIGN-OUT, IN BOTH DIRECTIONS (#167).
//
//   GET|POST /federation/slo/{id}            where a partner's BROWSER-BORNE
//                                            sign-out arrives: a SAML 2.0
//                                            <LogoutRequest> (the partner
//                                            signing somebody out) or
//                                            <LogoutResponse> (the partner
//                                            answering ours), on the Redirect
//                                            or POST binding; a WS-Federation
//                                            wsignoutcleanup1.0 / wsignout1.0;
//                                            and the browser coming back from
//                                            an OpenID Provider's
//                                            end_session_endpoint (`state`).
//   POST     /federation/backchannel-logout/{id}
//                                            OpenID Connect Back-Channel
//                                            Logout 1.0, as the relying party:
//                                            the partner's Logout Token.
//   GET      /federation/frontchannel-logout/{id}
//                                            OpenID Connect Front-Channel
//                                            Logout 1.0, as the relying party:
//                                            `iss` and `sid`, in the
//                                            partner's iframe.
//
// And a library half, for `logout/logout.ts`: partnerLogoutFor() builds what
// tells the PARTNER that a session here ended — a signed LogoutRequest, an
// RP-Initiated Logout redirect, a wsignout1.0 — as a link or a form the
// sign-out page draws.
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS. The partner is the authority on the person's sign-on. When
// it ends a session — a sign-out there, an account disabled at the source — a
// logout message is the only signal that reaches this relying party, and until
// #167 it was refused at the ACS (STS-FED-0024) and dropped. The session here,
// and every token this service issued from it, outlived the upstream session
// for hours. The partner's SAML `SessionNotOnOrAfter` was ignored as well;
// that bound now travels with the sign-in (`federation_sp.ts`'s
// sessionBoundOf(), `authn.ts`'s bindPartnerSession()).
//
// ---------------------------------------------------------------------------
// FIVE DECISIONS, and the issue's comment is where they were taken.
//
// 1. **A SIGN-OUT IS AUTHENTICATED EXACTLY AS A SIGN-IN IS.** A SAML logout
//    message is verified against `fedSigningCertificate` and nothing else —
//    `saml/request_signature.ts`'s assess(), the same code a service provider's
//    LogoutRequest to THIS service's identity provider goes through, over the
//    detached Redirect-binding signature (`common/crypto.js`'s
//    verifyQueryString()) or an enveloped one — and it must be signed
//    (saml-profiles-2.0-os section 4.4.4.1; `fedRequireSignedLogout`, off in
//    development only). Its issuer must be `fedPeer`, its Destination this
//    endpoint, its IssueInstant recent, and its ID not seen before. A Logout
//    Token is verified by the one function that verifies a partner's ID Token
//    (`federation_sp.ts`'s verifyForeignJwt()) and then held to Back-Channel
//    Logout 1.0 section 2.6. An unauthenticated request that could end a
//    session would be a denial of service against every federated person.
//
// 2. **A PARTNER'S SIGN-OUT ENDS ONLY THE SESSION IT NAMES** (rcbj's decision
//    4): the federated session carrying that NameID and SessionIndex, or that
//    `sid`, THROUGH THIS RELATIONSHIP — never a local sign-in of the same
//    person, and never a session another partner started. With no
//    SessionIndex (SAML) or only a `sub` (Back-Channel Logout section 2.7),
//    "the session it names" is every session that partner's principal holds
//    here through this relationship, which is what both specifications say.
//
// 3. **ENDING IT IS `logout/logout.ts`'s, NOT THIS FILE'S.** The one model of
//    what a live session is ends the session and the relying parties riding on
//    it (endPartnerSession()), so the cascade is the one every sign-out has:
//    Back-Channel Logout Tokens to this service's own relying parties, CAEP's
//    session-revoked, the RFC 9700 refresh revocation, and — wherever a
//    browser is present — the front-channel iframes, cleanup images and
//    LogoutRequest links, drawn before the answer goes back to the partner.
//    Required LAZILY: `logout.ts` is second to last in the require order and
//    requires `ldap_server.js`, whose routes would come with it.
//
// 4. **WS-FEDERATION'S CLEANUP IS UNSIGNED BY ITS SPECIFICATION, SO THE
//    PERSON CONFIRMS IT** (rcbj's decision 1). A wsignoutcleanup1.0 is a GET
//    anybody's page can embed; ending a session on one would let any page sign
//    anybody out. It draws a page with a real button and no script, bound to
//    the session in THIS browser, and the session ends only when that form
//    comes back (STS-FED-0126 otherwise). No setting makes it silent.
//
// 5. **FRONT-CHANNEL LOGOUT IS FRAMED BY THE PARTNER AND BY NOBODY ELSE**
//    (rcbj's decision 2). Its page is loaded in the OpenID Provider's iframe,
//    so `frame-ancestors` names the partner's origin on this one route —
//    NARROWED through `app.framedContentSecurityPolicy()`, never dropped — and
//    X-Frame-Options, which cannot name an origin, is removed. It carries no
//    script. It matches on `iss` AND `sid` and never on the cookie, because a
//    browser blocking third-party cookies sends none to an iframe; even so it
//    is best-effort by its nature, and Back-Channel Logout is the reliable
//    path. **OpenID Connect Session Management as a relying party is NOT
//    built** (rcbj's decision 3): its `check_session_iframe` is polled by a
//    script in the relying party's page, the root CLAUDE.md admits a script
//    only where a page cannot work without one, and Back-Channel Logout
//    already tells this relying party what that script would find out.
//
// ---------------------------------------------------------------------------
// SAML 1.1 AND OAUTH 2.0 DEFINE NO SIGN-OUT. There is no logout protocol in
// SAML 1.1, and OAuth 2.0 authorizes a client rather than signing anybody in,
// so there is nothing for a partner to send; a message arriving for either is
// refused naming that (STS-FED-0135), and the sign-out page says the partner
// is not told.
//
// ---------------------------------------------------------------------------
// WHERE IT SITS (rule 1): after `federation_sp.ts`, whose request-context
// store (decision 3 there), key verifier and page shell it uses, and after
// `authn/authn.ts`, whose session it reads. It registers its routes through
// `common/protocol_stack.ts` and requires nothing that registers any.
// ===========================================================================

import crypto = require('crypto');
import zlib = require('zlib');
import stsCrypto = require('../common/crypto');
import app = require('../common/app');
import config = require('../common/config');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import mode = require('../common/mode');
import validation = require('../common/validation');
import usedAssertions = require('../common/used_assertions');
import InstanceSlot = require('../common/instance_slot');
import authn = require('../authn/authn');
import federation = require('./federation');
import fedSp = require('./federation_sp');
import requestSignature = require('../saml/request_signature');
import documentSettings = require('../saml/document_settings');
// A PARTNER'S ENCRYPTED NameID OR LOGOUT TOKEN (#168): decrypted with the
// relationship's own key, as a sign-in's assertion is.
import fedEncryption = require('./federation_encryption');
import xmldom = require('@xmldom/xmldom');

type Helpers = typeof helpers;

interface FederationSloDeps {
  config: typeof config;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  mode: typeof mode;
  validation: typeof validation;
  usedAssertions: typeof usedAssertions;
  authn: typeof authn;
  federation: typeof federation;
  fedSp: typeof fedSp;
  fedEncryption: typeof fedEncryption;
  requestSignature: typeof requestSignature;
  documentSettings: typeof documentSettings;
  stsCrypto: typeof stsCrypto;
  app: typeof app;
  log: Helpers['log'];
  logArtifact: Helpers['logArtifact'];
  STS: Helpers['STS'];
  xmlEscape: Helpers['xmlEscape'];
  firstByLocal: Helpers['firstByLocal'];
  textByLocal: Helpers['textByLocal'];
  iso: Helpers['iso'];
  baseUrlOf: Helpers['baseUrlOf'];
  jsonFromB64u: Helpers['jsonFromB64u'];
  parseBody: Helpers['parseBody'];
  // `logout/logout.ts`, asked for when a session is ended — see decision 3.
  logout: () => any;
  // The issuer identifier this service's own OpenID Provider answers under,
  // for the front-channel notifications of its own relying parties.
  issuerOf: (base: string) => string;
}

interface RouteRegistrar {
  get(path: string, ...handlers: any[]): unknown;
  post(path: string, ...handlers: any[]): unknown;
}

const SLO_PATH = federation.PATHS.slo;
const BACKCHANNEL_PATH = federation.PATHS.backchannelLogout;
const FRONTCHANNEL_PATH = federation.PATHS.frontchannelLogout;

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
const STATUS_REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';
const STATUS_RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
const STATUS_UNKNOWN_PRINCIPAL =
  'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';
const STATUS_REQUEST_DENIED =
  'urn:oasis:names:tc:SAML:2.0:status:RequestDenied';
const STATUS_PARTIAL_LOGOUT =
  'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';
const NAMEID_UNSPECIFIED =
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
// Back-Channel Logout 1.0 section 2.4: the event a Logout Token carries.
const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
// Section 2.4's explicit type, and the two forms of it RFC 8725 section 3.11
// allows; `JWT` and an absent `typ` are what a provider that does not type
// its Logout Tokens sends, and section 2.6 does not ask for the check — an ID
// Token cannot pass as a Logout Token here anyway, because it carries no
// `events` member and usually a `nonce`. Any OTHER type names a different
// kind of token and is refused.
const LOGOUT_TYPES = ['logout+jwt', 'application/logout+jwt', 'jwt'];

// What a protocol calls itself on a page, and whether it defines a sign-out.
const PROTOCOL_WORDS = {
  saml2: 'SAML 2.0 Single Logout',
  wsfed: 'WS-Federation sign-out',
  oidc: 'OpenID Connect logout',
  saml11: 'SAML 1.1',
  oauth2: 'OAuth 2.0'
};

const STYLE = 'body{font-family:system-ui,Segoe UI,Helvetica,Arial,' +
  'sans-serif;margin:2rem auto;max-width:52rem;line-height:1.5;color:#111}' +
  'h1{font-size:1.4rem}h2{font-size:1.05rem;margin-top:1.6rem}' +
  'code{background:#f4f4f5;padding:.1rem .3rem;border-radius:3px;' +
  'word-break:break-all}.bad{color:#a00;font-weight:600}.ok{color:#060}' +
  '.note{color:#555;font-size:.9rem}button{font:inherit;padding:.5rem 1rem;' +
  'border:1px solid #333;background:#111;color:#fff;border-radius:4px;' +
  'cursor:pointer}table{border-collapse:collapse;width:100%;margin:.6rem 0}' +
  'th,td{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;' +
  'font-size:.9rem;vertical-align:top}.sub{color:#555;font-size:.9rem}' +
  '.cannot{color:#a00}';

class FederationSlo {
  static readonly SLO_PATH = SLO_PATH;
  static readonly BACKCHANNEL_PATH = BACKCHANNEL_PATH;
  static readonly FRONTCHANNEL_PATH = FRONTCHANNEL_PATH;

  constructor(private readonly deps: FederationSloDeps) {
    deps.log.debug("Entering FederationSlo.constructor().");
    deps.log.debug("Leaving FederationSlo.constructor().");
  }

  static defaultDeps(): FederationSloDeps {
    helpers.log.debug("Entering FederationSlo.defaultDeps().");
    helpers.log.debug("Leaving FederationSlo.defaultDeps().");
    return {
      config: config,
      errorCodes: errorCodes,
      audit: audit,
      mode: mode,
      validation: validation,
      usedAssertions: usedAssertions,
      authn: authn,
      federation: federation,
      fedSp: fedSp,
      fedEncryption: fedEncryption,
      requestSignature: requestSignature,
      documentSettings: documentSettings,
      stsCrypto: stsCrypto,
      app: app,
      log: helpers.log,
      logArtifact: helpers.logArtifact,
      STS: helpers.STS,
      xmlEscape: helpers.xmlEscape,
      firstByLocal: helpers.firstByLocal,
      textByLocal: helpers.textByLocal,
      iso: helpers.iso,
      baseUrlOf: helpers.baseUrlOf,
      jsonFromB64u: helpers.jsonFromB64u,
      parseBody: helpers.parseBody,
      // LAZY, for decision 3's reason.
      logout: function () {
        helpers.log.debug("Entering FederationSlo.defaultDeps().logout().");
        helpers.log.debug("Leaving FederationSlo.defaultDeps().logout().");
        return require('../logout/logout');
      },
      // LAZY too: `oauth2.ts` is loaded long before this is first asked, and a
      // require at build time would be an ordering this file has no reason
      // to depend on.
      issuerOf: function (base) {
        helpers.log.debug("Entering FederationSlo.defaultDeps().issuerOf().");
        helpers.log.debug("Leaving FederationSlo.defaultDeps().issuerOf().");
        return require('../oauth-oidc/oauth2').issuerOf(base);
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE ROUTES, in the order `common/protocol_stack.ts` registers them.
  // -------------------------------------------------------------------------
  registerRoutes(app: RouteRegistrar): void {
    const { log } = this.deps;
    log.debug("Entering FederationSlo.registerRoutes().");
    app.get(SLO_PATH + '/:id', (req, res) => {
      return this.sloEndpoint(req, res);
    });
    app.post(SLO_PATH + '/:id', (req, res) => {
      return this.sloEndpoint(req, res);
    });
    app.post(BACKCHANNEL_PATH + '/:id', (req, res) => {
      return this.backchannelEndpoint(req, res);
    });
    app.get(FRONTCHANNEL_PATH + '/:id', (req, res) => {
      return this.frontchannelEndpoint(req, res);
    });
    log.debug("Leaving FederationSlo.registerRoutes().");
  }

  // =========================================================================
  // SMALL THINGS EVERY PATH NEEDS.
  // =========================================================================

  private page(title, body) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FederationSlo.page().");
    log.debug("Leaving FederationSlo.page().");
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + xmlEscape(title) + '</title><style>' + STYLE +
      '</style></head><body>' + body + '</body></html>';
  }

  // A refusal page, recorded on the relationship as a sign-in's is. The code
  // is marked by the caller on the line before, as everywhere else.
  // error-code: none — the definition of the helper, not a call to it
  private refuse(res, record, status, what, why) {
    const { federation, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSlo.refuse(). " + what);
    const id = (record && record.fedId) || '';
    if (id) {
      federation.recordFailure(id, 'sign-out: ' + what + ': ' + why);
    }
    res.status(status).type('html').set('Cache-Control', 'no-store')
       .send(this.page('Refused',
         '<h1>The partner\'s sign-out was refused</h1><p class="bad">' +
         xmlEscape(what) + '</p><p>' + xmlEscape(why) + '</p>' +
         '<p class="note">No session was ended. A sign-out from a federation ' +
         'partner is authenticated exactly as a sign-in from it is — see ' +
         'federation/CLAUDE.md, <em>A PARTNER\'S SIGN-OUT</em>.' +
         (id ? ' This is recorded on the relationship as ' +
               '<code>fedLastError</code>.' : '') + '</p>'));
    log.debug("Leaving FederationSlo.refuse(). " + status);
  }

  // The back channel answers a server, not a person: section 2.8's 400 with
  // RFC 6749 section 5.2's two members, and never a page.
  // error-code: none — the definition of the helper, not a call to it
  private refuseJson(res, record, status, why) {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSlo.refuseJson(). " + status);
    if (record && record.fedId) {
      federation.recordFailure(record.fedId, 'back-channel logout: ' + why);
    }
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify({ error: status >= 500 ? 'temporarily_unavailable'
                                                   : 'invalid_request',
                              error_description: why }));
    log.debug("Leaving FederationSlo.refuseJson().");
  }

  private enabled() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSlo.enabled().");
    log.debug("Leaving FederationSlo.enabled().");
    return !!config.value('federation.enabled');
  }

  // THE RELATIONSHIP A REQUEST NAMES, or `null` with the answer already sent.
  // The ACS's own three refusals and codes, for its reasons: federation off, no
  // such service-provider-side relationship, or one that is disabled or
  // half-configured — a sign-out arriving for a disabled relationship is
  // refused without being looked at, which is what disabling is for.
  private relationshipFor(req, res, json) {
    const { federation, errorCodes, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSlo.relationshipFor(). id=" + req.params.id);
    if (!this.enabled()) {
      if (json) {
        errorCodes.mark(res, 'STS-FED-0001');
        this.refuseJson(res, null, 400, 'federation.enabled is off');
      } else {
        errorCodes.mark(res, 'STS-FED-0001');
        res.status(404).type('html').send(this.page('Not here',
          '<h1>Federation is off</h1><p><code>federation.enabled</code> is ' +
          'off.</p>'));
      }
      log.debug("Leaving FederationSlo.relationshipFor(). Off.");
      return null;
    }
    const id = String(req.params.id || '');
    const record = federation.get(id);
    if (!record || record.fedRole !== 'service-provider') {
      if (json) {
        errorCodes.mark(res, 'STS-FED-0002');
        this.refuseJson(res, null, 400, 'there is no service-provider-side ' +
                                         'federation relationship "' + id +
                                         '"');
      } else {
        errorCodes.mark(res, 'STS-FED-0002');
        res.status(404).type('html').send(this.page('No such relationship',
          '<h1>No such single logout service</h1><p>There is no ' +
          'service-provider-side relationship called <code>' + xmlEscape(id) +
          '</code>.</p>'));
      }
      log.debug("Leaving FederationSlo.relationshipFor(). None.");
      return null;
    }
    if (!federation.isUsable(record)) {
      const enabled = federation.isEnabled(record);
      const why = enabled
        ? 'the relationship "' + id + '" is enabled but not fully ' +
          'configured: ' + federation.readinessOf(record).missing.join(', ')
        : 'the relationship "' + id + '" is disabled, and a message for a ' +
          'disabled relationship is refused without being looked at';
      if (json) {
        errorCodes.mark(res, enabled ? 'STS-FED-0006' : 'STS-FED-0005');
        this.refuseJson(res, record, 400, why);
      } else {
        errorCodes.mark(res, enabled ? 'STS-FED-0006' : 'STS-FED-0005');
        this.refuse(res, record, 403, 'That relationship is not usable', why);
      }
      log.debug("Leaving FederationSlo.relationshipFor(). Not usable.");
      return null;
    }
    log.debug("Leaving FederationSlo.relationshipFor(). " + record.fedProtocol);
    return record;
  }

  // Query and body, the body winning, as the ACS reads them.
  private paramsOf(req) {
    const { log, parseBody } = this.deps;
    log.debug("Entering FederationSlo.paramsOf().");
    const out: any = {};
    Object.keys(req.query || {}).forEach(function (k) {
      out[k] = req.query[k];
    });
    if (req.method === 'POST') {
      const body = parseBody(req);
      Object.keys(body).forEach(function (k) {
        out[k] = body[k];
      });
    }
    log.debug("Leaving FederationSlo.paramsOf().");
    return out;
  }

  // The query string exactly as it arrived, for the Redirect binding's
  // detached signature (`request_signature.ts` header: never `req.query`).
  private rawQueryOf(req) {
    const { log } = this.deps;
    log.debug("Entering FederationSlo.rawQueryOf().");
    const url = String(req.originalUrl || req.url || '');
    const at = url.indexOf('?');
    log.debug("Leaving FederationSlo.rawQueryOf().");
    return at < 0 ? '' : url.slice(at + 1);
  }

  private accepts(record) {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSlo.accepts().");
    log.debug("Leaving FederationSlo.accepts().");
    return federation.boolOf(record.fedAcceptSignout, true);
  }

  // Whether an UNSIGNED SAML logout message is refused here: always, except
  // on a relationship that turned fedRequireSignedLogout off in a mode that
  // lets it (`mode.acceptsUnsignedFederatedLogout()`).
  private requiresSignature(record) {
    const { federation, mode, log } = this.deps;
    log.debug("Entering FederationSlo.requiresSignature().");
    const off = !federation.boolOf(record.fedRequireSignedLogout, true);
    log.debug("Leaving FederationSlo.requiresSignature().");
    return !(off && mode.acceptsUnsignedFederatedLogout());
  }

  // How far a partner's clock may be from this one, in ms — the setting an
  // assertion's own window is read with.
  private skewMs() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSlo.skewMs().");
    log.debug("Leaving FederationSlo.skewMs().");
    return Number(config.value('oauth2.clockSkewS')) * 1000;
  }

  // How old a partner's sign-out may be: `federation.requestTtlMin`, the
  // lifetime of every federation message in flight. It is also how long the
  // replay history holds one, so the window and the history cover the same
  // span with no gap between them.
  private freshnessMs() {
    const { config, log } = this.deps;
    log.debug("Entering FederationSlo.freshnessMs().");
    log.debug("Leaving FederationSlo.freshnessMs().");
    return Number(config.value('federation.requestTtlMin')) * 60 * 1000;
  }

  // THE LIVE FEDERATED SESSIONS OF THIS RELATIONSHIP THAT `match` ACCEPTS.
  // The session store is persisted and replicated, so this is every node's
  // answer, and it is the ONE store: `fedPartnerSession` rides on the session
  // rather than in an index beside it that could disagree with it.
  private sessionsMatching(record, match) {
    const { authn, log } = this.deps;
    log.debug("Entering FederationSlo.sessionsMatching(). " + record.fedId);
    const out = [];
    authn.sessions.forEach(function (session) {
      const held = session && session.fedPartnerSession;
      if (!held || held.relationship !== record.fedId) {
        return;
      }
      if (authn.sessionEnded(session)) {
        return;
      }
      if (match(held, session)) {
        out.push(session);
      }
    });
    log.debug("Leaving FederationSlo.sessionsMatching(). " + out.length);
    return out;
  }

  // END THE SESSIONS A PARTNER NAMED, through the one model (decision 3), and
  // answer what the browser still has to do for this service's own relying
  // parties. `browser` is false on the back channel, where there is nobody to
  // draw anything for — the Logout Tokens still go, from the session's end.
  private endSessions(sessions, record, how, base, browser) {
    const { log, audit, xmlEscape } = this.deps;
    log.debug("Entering FederationSlo.endSessions(). " + sessions.length);
    const logout = this.deps.logout();
    const by = 'the federation partner "' + record.fedId + '" (' + how + ')';
    const issuer = base ? this.deps.issuerOf(base) : '';
    const results = sessions.map(function (session) {
      return logout.endPartnerSession(session, {
        by: by, issuer: issuer, channel: browser ? 'http' : 'back-channel' });
    });
    const fan = browser ? logout.fanOutOf(results) : { html: '', policy: {} };
    audit.audit({
      action: 'federation.signout',
      actor: record.fedPeer || record.fedId,
      protocol: 'Federation', channel: browser ? 'http' : 'back-channel',
      target: record.fedId,
      summary: 'the federation partner of ' + record.fedId + ' signed ' +
               sessions.length + ' session(s) out (' + how + ')',
      detail: {
        relationship: record.fedId,
        how: how,
        sessions: sessions.map(function (one) {
          return one.id;
        }).join(', '),
        people: sessions.map(function (one) {
          return (one.user && one.user.username) || '';
        }).join(', ')
      }
    });
    log.info('federation: ' + record.fedId + '\'s partner signed out ' +
             sessions.length + ' session(s) (' + how + ').');
    log.debug("Leaving FederationSlo.endSessions().");
    return {
      results: results,
      fanOut: fan,
      partial: results.some(function (one) {
        return (one.logoutRequests || []).some(function (t) {
          return !!t.url;
        });
      }),
      summary: sessions.map(function (one) {
        return '<li>' + xmlEscape((one.user && one.user.username) || '?') +
               ' — session <code>' + xmlEscape(one.id) + '</code></li>';
      }).join('')
    };
  }

  // A verified sign-out that matched nothing. Recorded, because a partner
  // looping on a sign-out for a session that already ended looks exactly
  // like one that works.
  private recordNoMatch(record, how, what) {
    const { audit, log } = this.deps;
    log.debug("Entering FederationSlo.recordNoMatch().");
    audit.failure('STS-FED-0122', {
      protocol: 'Federation', channel: 'http', target: record.fedId,
      outcome: 'refused',
      summary: 'a verified sign-out from the partner of ' + record.fedId +
               ' (' + how + ') matched no session here',
      detail: { relationship: record.fedId, how: how, named: what }
    });
    log.info('federation: a sign-out from ' + record.fedId + '\'s partner (' +
             how + ') matched no session here: ' + what + '.');
    log.debug("Leaving FederationSlo.recordNoMatch().");
  }

  private recordRefusedByRelationship(record, how) {
    const { audit, log } = this.deps;
    log.debug("Entering FederationSlo.recordRefusedByRelationship().");
    audit.failure('STS-FED-0123', {
      protocol: 'Federation', channel: 'http', target: record.fedId,
      outcome: 'refused',
      summary: 'a sign-out from the partner of ' + record.fedId + ' (' + how +
               ') was refused: fedAcceptSignout is off',
      detail: { relationship: record.fedId, how: how }
    });
    log.debug("Leaving FederationSlo.recordRefusedByRelationship().");
  }

  // ONCE EVER (rule 3ae). `{ ok }`, or `{ ok: false, code, status, why }`.
  private spendOnce(format, issuer, identifier, expiresAt) {
    const { usedAssertions, log } = this.deps;
    log.debug("Entering FederationSlo.spendOnce(). " + format);
    log.debug("Leaving FederationSlo.spendOnce().");
    return usedAssertions.claim({
      format: format, use: 'federated-logout', issuer: issuer,
      identifier: identifier, expiresAt: expiresAt
    }).then(function (claimed) {
      if (claimed.ok) {
        return { ok: true };
      }
      if (claimed.reason === 'replay') {
        return { ok: false, code: 'STS-FED-0120', status: 403,
                 why: 'this sign-out (' + identifier + ') has already been ' +
                      'accepted once, and a sign-out is accepted once ever' };
      }
      return { ok: false, code: 'STS-FED-0121', status: 503,
               why: 'the replay history could not prove this sign-out ' +
                    'unused (' + claimed.reason + '), so it is refused ' +
                    'rather than risked; the partner may send it again' };
    });
  }

  // =========================================================================
  // /federation/slo/{id}: WHICH MESSAGE IS THIS?
  // =========================================================================
  private sloEndpoint(req, res) {
    const { errorCodes, log } = this.deps;
    log.debug("Entering FederationSlo.sloEndpoint(). " + req.method);
    const record = this.relationshipFor(req, res, false);
    if (!record) {
      log.debug("Leaving FederationSlo.sloEndpoint().");
      return undefined;
    }
    const params = this.paramsOf(req);
    const protocol = record.fedProtocol;
    const wa = String(params.wa || '');
    let answer;
    try {
      if ((params.SAMLRequest || params.SAMLResponse) &&
          protocol === 'saml2') {
        answer = params.SAMLRequest
          ? this.samlLogoutRequest(req, res, record, params)
          : this.samlLogoutResponse(req, res, record, params);
      } else if ((wa === 'wsignoutcleanup1.0' || wa === 'wsignout1.0') &&
                 protocol === 'wsfed') {
        answer = req.method === 'POST'
          ? this.wsfedConfirmed(req, res, record, params)
          : this.wsfedConfirmation(req, res, record, params);
      } else if (params.state !== undefined && protocol === 'oidc' &&
                 req.method === 'GET') {
        answer = this.endSessionReturned(req, res, record, params);
      } else {
        errorCodes.mark(res, 'STS-FED-0135');
        answer = this.refuse(res, record, 400, 'This endpoint cannot read ' +
                                               'that',
          this.nothingHereWhy(record, params));
      }
    } catch (e) {
      log.error(errorCodes.tag('STS-FED-0136') + 'federation: ' + record.fedId +
                ' threw while reading a partner\'s sign-out: ' + e.stack);
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-FED-0136');
        this.refuse(res, record, 500, 'This service failed while reading ' +
                                      'the sign-out', e.message);
      }
      answer = undefined;
    }
    log.debug("Leaving FederationSlo.sloEndpoint().");
    return answer;
  }

  // What to say about a message this relationship's protocol does not define.
  private nothingHereWhy(record, params) {
    const { log } = this.deps;
    log.debug("Entering FederationSlo.nothingHereWhy().");
    const protocol = record.fedProtocol;
    let why;
    if (protocol === 'saml11' || protocol === 'oauth2') {
      why = PROTOCOL_WORDS[protocol] + ' defines no sign-out, so a partner ' +
            'of this relationship has nothing to send here. SAML 1.1 has no ' +
            'logout protocol at all, and OAuth 2.0 authorizes a client ' +
            'rather than signing anybody in.';
    } else if (!Object.keys(params).length) {
      why = 'Nothing arrived. This is where the partner of "' + record.fedId +
            '" sends a sign-out: ' + this.expectedFor(protocol) + '.';
    } else {
      why = 'This is the single logout endpoint of a ' +
            PROTOCOL_WORDS[protocol] + ' relationship, and what arrived is ' +
            'not ' + this.expectedFor(protocol) + '.';
    }
    log.debug("Leaving FederationSlo.nothingHereWhy().");
    return why;
  }

  private expectedFor(protocol) {
    const { log } = this.deps;
    log.debug("Entering FederationSlo.expectedFor().");
    log.debug("Leaving FederationSlo.expectedFor().");
    return protocol === 'saml2'
      ? 'a SAMLRequest (a <LogoutRequest>) or a SAMLResponse (a ' +
        '<LogoutResponse>), on the Redirect or POST binding'
      : protocol === 'wsfed'
        ? 'wa=wsignoutcleanup1.0 or wa=wsignout1.0'
        : protocol === 'oidc'
          ? 'the browser returning from the partner\'s end_session_endpoint ' +
            'with the state this service sent (the Logout Token goes to ' +
            BACKCHANNEL_PATH + ', the front-channel request to ' +
            FRONTCHANNEL_PATH + ')'
          : 'nothing — this protocol defines no sign-out';
  }

  // =========================================================================
  // SAML 2.0: READING A LOGOUT MESSAGE.
  //
  // `{ ok, root, xml, assessment }` or `{ ok: false }` with the refusal
  // already sent. The checks, in order, and the first failure refuses:
  // decoding, the root element, the signature (and whether one must be
  // there), the issuer, the Destination. saml2_sso.ts's decodeMessage()
  // shape: base64, then DEFLATE when it is not plain XML — bounded by
  // `validation.inflate()`, so a DEFLATE bomb is a refusal and not an outage.
  // =========================================================================
  private readSamlMessage(req, res, record, params, field, rootName) {
    const { validation, requestSignature, errorCodes, log, logArtifact,
            textByLocal, baseUrlOf, fedSp } = this.deps;
    log.debug("Entering FederationSlo.readSamlMessage(). " + rootName);
    const buf = Buffer.from(String(params[field] || ''), 'base64');
    let xml = buf.toString('utf8');
    if (buf.length && buf[0] !== 0x3c) {
      const inflated = validation.inflate(buf, 'SAML ' + rootName);
      if (inflated.ok) {
        xml = inflated.value.toString('utf8');
      }
    }
    logArtifact('a federation partner\'s SAML ' + rootName, 'as received',
                xml);
    const parsed = validation.parseXml(xml, rootName);
    const root = parsed.ok && parsed.value ? parsed.value.documentElement
                                           : null;
    if (!root || root.localName !== rootName || root.namespaceURI !==
        NS_SAMLP) {
      errorCodes.mark(res, 'STS-FED-0114');
      this.refuse(res, record, 400, 'That is not a ' + rootName,
        parsed.ok ? 'The ' + field + ' decoded to <' +
                    ((root && root.localName) || 'nothing') + '> where a ' +
                    'samlp:' + rootName + ' was expected ' +
                    '(saml-core-2.0-os section 3.7).'
                  : 'The ' + field + ' could not be read: ' + parsed.detail);
      log.debug("Leaving FederationSlo.readSamlMessage(). Not a " + rootName);
      return { ok: false };
    }
    // THE SIGNATURE — the relationship's certificate and nothing else, on
    // either binding (decision 1).
    const assessment = requestSignature.assess({
      binding: req.method === 'POST' ? 'post' : 'redirect',
      rawQuery: this.rawQueryOf(req), params: params, xml: xml,
      rootLocalName: rootName, messageField: field,
      fields: { samlSigningCertificate: record.fedSigningCertificate }
    });
    if (assessment.outcome === 'failed') {
      errorCodes.mark(res, 'STS-FED-0116');
      this.refuse(res, record, 403, 'The signature did not verify',
        'The ' + rootName + '\'s signature was checked against ' +
        'fedSigningCertificate on this relationship, and against nothing ' +
        'else: ' + assessment.why + '.');
      log.debug("Leaving FederationSlo.readSamlMessage(). Bad signature.");
      return { ok: false };
    }
    const signed = assessment.outcome === 'verified';
    if (!signed && this.requiresSignature(record)) {
      errorCodes.mark(res, 'STS-FED-0115');
      this.refuse(res, record, 403, 'The ' + rootName + ' is not signed',
        'saml-profiles-2.0-os section 4.4.4.1 says a logout message on the ' +
        'Redirect or POST binding MUST be signed, and this one ' +
        (assessment.outcome === 'no-certificate'
          ? 'could not be checked: the relationship has no certificate'
          : 'carries no signature') + '. An unsigned sign-out is anybody ' +
        'signing anybody out.');
      log.debug("Leaving FederationSlo.readSamlMessage(). Unsigned.");
      return { ok: false };
    }
    if (!signed) {
      log.warn('federation: ' + record.fedId + ' accepted an UNSIGNED ' +
               rootName + ' from its partner, because fedRequireSignedLogout ' +
               'is off in development mode.');
    }
    const issuer = textByLocal(root, 'Issuer') || '';
    if (issuer !== String(record.fedPeer || '').trim()) {
      errorCodes.mark(res, 'STS-FED-0117');
      this.refuse(res, record, 403, 'It was issued by somebody else',
        'The ' + rootName + ' names ' + (issuer || '(no issuer)') + ' and ' +
        'this relationship\'s partner is ' + record.fedPeer + '.');
      log.debug("Leaving FederationSlo.readSamlMessage(). Wrong issuer.");
      return { ok: false };
    }
    // saml-bindings-2.0-os section 3.4.5.2 and 3.5.5.2: a SIGNED message
    // MUST carry a Destination, and it must be where it arrived.
    const destination = root.getAttribute('Destination') || '';
    const here = fedSp.sloUrl(baseUrlOf(req), record);
    if ((signed && !destination) || (destination && destination !== here)) {
      errorCodes.mark(res, 'STS-FED-0118');
      this.refuse(res, record, 403, 'It was sent somewhere else',
        destination
          ? 'The ' + rootName + ' is addressed to ' + destination + ' and ' +
            'it arrived at ' + here + '. A signed message is honoured only ' +
            'where it was meant to go.'
          : 'The ' + rootName + ' is signed and names no Destination, which ' +
            'saml-bindings-2.0-os section 3.4.5.2 says a signed message ' +
            'MUST.');
      log.debug("Leaving FederationSlo.readSamlMessage(). Wrong " +
                "Destination.");
      return { ok: false };
    }
    log.debug("Leaving FederationSlo.readSamlMessage(). Read; " +
              assessment.outcome + ".");
    return { ok: true, root: root, xml: xml, assessment: assessment,
             issuer: issuer, signed: signed };
  }

  // =========================================================================
  // SAML 2.0: THE PARTNER SIGNS SOMEBODY OUT (identity-provider-initiated,
  // or the partner propagating another participant's sign-out).
  // saml-profiles-2.0-os section 4.4.4; saml-core-2.0-os section 3.7.3.2.
  // =========================================================================
  private samlLogoutRequest(req, res, record, params) {
    const { errorCodes, log, firstByLocal, baseUrlOf } = this.deps;
    log.debug("Entering FederationSlo.samlLogoutRequest().");
    const read = this.readSamlMessage(req, res, record, params, 'SAMLRequest',
                                      'LogoutRequest');
    if (!read.ok) {
      log.debug("Leaving FederationSlo.samlLogoutRequest(). Refused.");
      return undefined;
    }
    const root = read.root;
    const requestId = root.getAttribute('ID') || '';
    // THE WINDOW: an IssueInstant neither in the future nor older than a
    // federation message lives, and a NotOnOrAfter not passed. Both allow the
    // clock skew an assertion is read with.
    const now = Date.now();
    const issued = Date.parse(root.getAttribute('IssueInstant') || '');
    const notOnOrAfter = Date.parse(root.getAttribute('NotOnOrAfter') || '');
    const skew = this.skewMs();
    let late = '';
    if (!isFinite(issued) || issued - skew > now) {
      late = 'its IssueInstant, "' + (root.getAttribute('IssueInstant') ||
             '') + '", is missing, unreadable or in the future';
    } else if (issued + this.freshnessMs() + skew < now) {
      late = 'it was issued at ' + root.getAttribute('IssueInstant') + ', ' +
             'longer ago than a federation message lives ' +
             '(federation.requestTtlMin)';
    } else if (isFinite(notOnOrAfter) && notOnOrAfter + skew <= now) {
      late = 'it expired at ' + root.getAttribute('NotOnOrAfter') +
             ' (its NotOnOrAfter, saml-core-2.0-os section 3.7.1)';
    }
    if (!requestId || late) {
      errorCodes.mark(res, 'STS-FED-0119');
      log.debug("Leaving FederationSlo.samlLogoutRequest(). Outside its " +
                "window.");
      return this.refuse(res, record, 403, 'The LogoutRequest is not valid ' +
                                           'now',
        requestId ? 'The LogoutRequest ' + requestId + ' is refused: ' +
                    late + '.'
                  : 'The LogoutRequest carries no ID, so nothing could stop ' +
                    'it being replayed.');
    }
    // THE PRINCIPAL: a <NameID>, or an <EncryptedID> (saml-core-2.0-os
    // section 3.7.1) encrypted to the key this relationship's metadata
    // publishes (#168) and decrypted with it — after the signature over the
    // ciphertext has verified, which it has by here.
    let nameEl = firstByLocal(root, 'NameID');
    const encryptedId = nameEl ? null : firstByLocal(root, 'EncryptedID');
    if (encryptedId) {
      const opened = this.deps.fedEncryption.decryptXml(record,
        new xmldom.XMLSerializer().serializeToString(encryptedId));
      nameEl = opened.ok ? this.nameIdOf(opened.xml) : null;
      if (!nameEl) {
        const code = opened.ok ? 'STS-FED-0138' : opened.code;
        errorCodes.mark(res, code);
        log.debug("Leaving FederationSlo.samlLogoutRequest(). The " +
                  "EncryptedID.");
        return this.refuse(res, record, 400, 'The LogoutRequest\'s ' +
                                             'EncryptedID could not be read',
          opened.ok ? 'It decrypted to something that is not a <NameID>.'
                    : opened.why);
      }
    }
    if (!nameEl) {
      errorCodes.mark(res, 'STS-FED-0114');
      log.debug("Leaving FederationSlo.samlLogoutRequest(). No NameID.");
      return this.refuse(res, record, 400, 'The LogoutRequest names nobody',
        'It carries no <NameID> and no <EncryptedID>, one of which ' +
        'saml-core-2.0-os section 3.7.1 requires.');
    }
    const named = {
      value: String(nameEl.textContent || '').trim(),
      format: nameEl.getAttribute('Format') || '',
      nameQualifier: nameEl.getAttribute('NameQualifier') || '',
      spNameQualifier: nameEl.getAttribute('SPNameQualifier') || ''
    };
    const indexes = [];
    const all = root.getElementsByTagName('*');
    for (let i = 0; i < all.length; i++) {
      if (all[i].localName === 'SessionIndex') {
        indexes.push(String(all[i].textContent || '').trim());
      }
    }
    const base = baseUrlOf(req);
    if (!this.accepts(record)) {
      this.recordRefusedByRelationship(record, 'SAML 2.0 LogoutRequest');
      errorCodes.mark(res, 'STS-FED-0123');
      log.debug("Leaving FederationSlo.samlLogoutRequest(). Not accepted.");
      return this.answerLogoutRequest(res, record, base, params, requestId,
        STATUS_RESPONDER, STATUS_REQUEST_DENIED,
        'This relationship does not accept its partner\'s sign-out ' +
        '(fedAcceptSignout is off).', null);
    }
    const expires = Math.max(isFinite(notOnOrAfter) ? notOnOrAfter : 0,
                             issued + this.freshnessMs()) + skew;
    const self = this;
    log.debug("Leaving FederationSlo.samlLogoutRequest(). Spending the ID.");
    return this.spendOnce('saml-message', read.issuer, requestId, expires)
      .then(function (spent) {
        if (!spent.ok) {
          errorCodes.mark(res, spent.code);
          return self.refuse(res, record, spent.status, spent.code ===
                             'STS-FED-0120' ? 'The LogoutRequest was ' +
                             'replayed' : 'The LogoutRequest could not be ' +
                             'checked for a replay', spent.why + '.');
        }
        return self.endNamedSamlSessions(res, record, base, params,
                                         requestId, named, indexes);
      }).catch(function (e) {
        log.error(errorCodes.tag('STS-FED-0136') + 'federation: ' +
                  record.fedId + ' failed ending the sessions a ' +
                  'LogoutRequest named: ' + ((e && e.stack) || e));
        if (!res.headersSent) {
          errorCodes.mark(res, 'STS-FED-0136');
          self.refuse(res, record, 500, 'This service failed while signing ' +
                                        'out', (e && e.message) || String(e));
        }
      });
  }

  // The LogoutRequest is authentic, fresh and unused: end what it names.
  private endNamedSamlSessions(res, record, base, params, requestId, named,
                               indexes) {
    const { log } = this.deps;
    log.debug("Entering FederationSlo.endNamedSamlSessions().");
    const sameFormat = function (a, b) {
      log.debug("Entering sameFormat().");
      const left = a || NAMEID_UNSPECIFIED;
      const right = b || NAMEID_UNSPECIFIED;
      log.debug("Leaving sameFormat().");
      return left === right;
    };
    const sameQualifier = function (a, b) {
      log.debug("Entering sameQualifier().");
      log.debug("Leaving sameQualifier().");
      return !a || !b || a === b;
    };
    const sessions = this.sessionsMatching(record, function (held) {
      if (held.protocol !== 'saml2' && held.protocol !== 'wsfed') {
        return false;
      }
      // saml-core-2.0-os section 3.7.3.2: the principal is the NameID WHOLE.
      if (String(held.nameId || '') !== named.value ||
          !sameFormat(held.nameIdFormat, named.format) ||
          !sameQualifier(held.nameQualifier, named.nameQualifier) ||
          !sameQualifier(held.spNameQualifier, named.spNameQualifier)) {
        return false;
      }
      // With SessionIndex elements, ONLY those sessions; with none, every
      // session of the principal from this partner (rcbj's decision 4 reads
      // "the matched session" as exactly what the specification names).
      return !indexes.length ||
             indexes.indexOf(String(held.sessionIndex || '')) >= 0;
    });
    if (!sessions.length) {
      this.recordNoMatch(record, 'SAML 2.0 LogoutRequest',
                         named.value + (indexes.length ? ' SessionIndex ' +
                                        indexes.join(', ') : ''));
      log.debug("Leaving FederationSlo.endNamedSamlSessions(). No match.");
      return this.answerLogoutRequest(res, record, base, params, requestId,
        STATUS_REQUESTER, STATUS_UNKNOWN_PRINCIPAL,
        'No session here carries that principal' +
        (indexes.length ? ' and session index' : '') + '.', null);
    }
    const ended = this.endSessions(sessions, record, 'SAML 2.0 Single Logout',
                                   base, true);
    log.debug("Leaving FederationSlo.endNamedSamlSessions(). " +
              sessions.length + " ended.");
    return this.answerLogoutRequest(res, record, base, params, requestId,
      STATUS_SUCCESS, ended.partial ? STATUS_PARTIAL_LOGOUT : '',
      ended.partial ? 'The session ended here; the SAML service providers ' +
                      'it was signed into were offered a LogoutRequest ' +
                      'this service cannot observe.' : '', ended);
  }

  // THE ANSWER TO A LogoutRequest: a signed <LogoutResponse> to the partner's
  // SingleLogoutService on this relationship's binding — straight away where
  // there is nothing else for the browser to do, and after a page drawing this
  // service's own fan-out where there is.
  private answerLogoutRequest(res, record, base, params, inResponseTo, status,
                              subStatus, message, ended) {
    const { errorCodes, log, xmlEscape, app } = this.deps;
    log.debug("Entering FederationSlo.answerLogoutRequest(). " + status);
    const destination = String(record.fedSloUrl || '').trim();
    const fan = ended ? ended.fanOut : { html: '', policy: {} };
    const summary = ended
      ? '<h1>Signed out</h1><p class="ok">The partner ' +
        xmlEscape(record.fedName || record.fedId) + ' signed you out, and ' +
        'this service ended the session it had started for you:</p><ul>' +
        ended.summary + '</ul>'
      : '<h1>' + (status === STATUS_SUCCESS ? 'Signed out' :
                  'Nothing was signed out') + '</h1><p>' +
        xmlEscape(message) + '</p>';
    if (!destination) {
      log.debug("Leaving FederationSlo.answerLogoutRequest(). Nowhere to " +
                "send the LogoutResponse.");
      res.status(200).type('html').set('Cache-Control', 'no-store')
         .set('Content-Security-Policy', app.contentSecurityPolicy(fan.policy))
         .send(this.page('Signed out', summary + fan.html +
           '<p class="note">There is nowhere to send the partner its ' +
           '<code>&lt;LogoutResponse&gt;</code>: this relationship has no ' +
           '<code>fedSloUrl</code>. Set it to the partner\'s ' +
           'SingleLogoutService.</p>'));
      return undefined;
    }
    const xml = this.logoutResponseXml(base, record, destination,
                                       inResponseTo, status, subStatus,
                                       message);
    const target = this.outbound(record, destination, 'SAMLResponse', xml,
                                 String(params.RelayState || ''));
    if (status !== STATUS_SUCCESS && !errorCodes.codeOf(res)) {
      errorCodes.mark(res, 'STS-FED-0122');
    }
    if (target.kind === 'link' && !fan.html) {
      res.set('Cache-Control', 'no-store').redirect(303, target.url);
      log.debug("Leaving FederationSlo.answerLogoutRequest(). Redirected.");
      return undefined;
    }
    res.status(200).type('html').set('Cache-Control', 'no-store')
       .set('Content-Security-Policy', app.contentSecurityPolicy(fan.policy))
       .send(this.page('Signed out', summary + fan.html +
         '<h2>Back to ' + xmlEscape(record.fedName || record.fedId) +
         '</h2>' + this.continueControl(target, 'Continue to the partner') +
         '<p class="note">There is no script on this page. A ' +
         'LogoutResponse is the partner\'s to receive and this service ' +
         'sends it by the binding the relationship names ' +
         '(<code>fedSloBinding</code>).</p>'));
    log.debug("Leaving FederationSlo.answerLogoutRequest(). Drew the page.");
    return undefined;
  }

  // A link or a form, with a real button and no script.
  private continueControl(target, label) {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FederationSlo.continueControl(). " + target.kind);
    if (target.kind === 'link') {
      log.debug("Leaving FederationSlo.continueControl().");
      return '<p><a href="' + xmlEscape(target.url) + '">' + xmlEscape(label) +
             '</a></p>';
    }
    log.debug("Leaving FederationSlo.continueControl().");
    return '<form method="post" action="' + xmlEscape(target.action) + '">' +
      Object.keys(target.fields).map(function (name) {
        return '<input type="hidden" name="' + xmlEscape(name) + '" value="' +
               xmlEscape(String(target.fields[name])) + '">';
      }).join('') + '<button type="submit">' + xmlEscape(label) +
      '</button></form>';
  }

  private logoutResponseXml(base, record, destination, inResponseTo, status,
                            subStatus, message) {
    const { fedSp, iso, xmlEscape, log, logArtifact } = this.deps;
    log.debug("Entering FederationSlo.logoutResponseXml().");
    const id = '_' + crypto.randomBytes(16).toString('hex');
    const xml = '<samlp:LogoutResponse xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
      'IssueInstant="' + iso(0) + '" Destination="' + xmlEscape(destination) +
      '"' + (inResponseTo ? ' InResponseTo="' + xmlEscape(inResponseTo) + '"'
                          : '') +
      '><saml:Issuer>' + xmlEscape(fedSp.ourEntityId(base, record)) +
      '</saml:Issuer><samlp:Status><samlp:StatusCode Value="' + status + '"' +
      (subStatus ? '><samlp:StatusCode Value="' + subStatus +
                   '"/></samlp:StatusCode>'
                 : '/>') +
      (message ? '<samlp:StatusMessage>' + xmlEscape(message) +
                 '</samlp:StatusMessage>' : '') +
      '</samlp:Status></samlp:LogoutResponse>';
    logArtifact('federated SAML 2.0 LogoutResponse', 'before signing', xml);
    log.debug("Leaving FederationSlo.logoutResponseXml(). " + id);
    return { id: id, xml: xml };
  }

  // A SAML MESSAGE TO THE PARTNER, SIGNED, ON THE RELATIONSHIP'S BINDING.
  // HTTP-Redirect: DEFLATE, base64, and the detached signature over
  // `<field>=…&RelayState=…&SigAlg=…` (saml-bindings-2.0-os section 3.4.4.1)
  // — built by `common/crypto.js`'s signQueryString(), the construction this
  // service's own identity provider uses, with no enveloped signature in the
  // XML (the section says to remove it). HTTP-POST: an enveloped signature
  // after the Issuer, on a form with a real button. The algorithms are the
  // configured ones (`saml/document_settings.ts`), post-quantum included.
  private outbound(record, destination, field, built, relayState) {
    const { documentSettings, stsCrypto, STS, log, logArtifact } = this.deps;
    log.debug("Entering FederationSlo.outbound(). " + field);
    const how = documentSettings.signatureOptions();
    if (String(record.fedSloBinding || 'HTTP-Redirect') === 'HTTP-POST') {
      const signed = stsCrypto.signXml(built.xml, {
        privateKeyPem: STS.xml.privateKeyPem, certPem: STS.xml.certPem,
        sigAlg: how.sigAlg, c14nAlg: how.c14nAlg,
        placement: stsCrypto.PLACEMENT.AFTER_ISSUER, refUri: '#' + built.id,
        what: 'federated SAML 2.0 ' + field
      });
      logArtifact('federated SAML 2.0 ' + field, 'after signing', signed);
      const fields: any = {};
      fields[field] = Buffer.from(signed, 'utf8').toString('base64');
      if (relayState) {
        fields.RelayState = relayState;
      }
      log.debug("Leaving FederationSlo.outbound(). HTTP-POST.");
      return { kind: 'form', action: destination, fields: fields,
               url: '', binding: 'HTTP-POST' };
    }
    let qs = field + '=' + encodeURIComponent(
      zlib.deflateRawSync(Buffer.from(built.xml, 'utf8')).toString('base64'));
    if (relayState) {
      qs += '&RelayState=' + encodeURIComponent(relayState);
    }
    qs += '&SigAlg=' + encodeURIComponent(how.sigAlg);
    qs += '&Signature=' + encodeURIComponent(
      stsCrypto.signQueryString(qs, STS.xml.privateKeyPem, how.sigAlg));
    const url = destination + (destination.indexOf('?') >= 0 ? '&' : '?') +
                qs;
    log.debug("Leaving FederationSlo.outbound(). HTTP-Redirect.");
    return { kind: 'link', url: url, action: '', fields: {},
             binding: 'HTTP-Redirect' };
  }

  // =========================================================================
  // SAML 2.0: THE PARTNER ANSWERS OURS (service-provider-initiated).
  // =========================================================================
  private samlLogoutResponse(req, res, record, params) {
    const { fedSp, errorCodes, audit, log, xmlEscape, firstByLocal,
            textByLocal } = this.deps;
    log.debug("Entering FederationSlo.samlLogoutResponse().");
    const read = this.readSamlMessage(req, res, record, params,
                                      'SAMLResponse', 'LogoutResponse');
    if (!read.ok) {
      log.debug("Leaving FederationSlo.samlLogoutResponse(). Refused.");
      return undefined;
    }
    const root = read.root;
    const inResponseTo = root.getAttribute('InResponseTo') || '';
    // THE REQUEST IT ANSWERS: spent on first sight, so a LogoutResponse is
    // accepted once. RelayState is the handle, and saml-bindings-2.0-os
    // section 3.4.3 says a responder MUST return the RelayState it was sent.
    const handle = String(params.RelayState || '');
    const context = /^fed-[A-Za-z0-9_-]{1,64}$/.test(handle)
      ? fedSp.takeContext(handle) : null;
    if (!context || context.kind !== 'slo-request' ||
        context.id !== record.fedId || !inResponseTo ||
        context.requestId !== inResponseTo) {
      errorCodes.mark(res, 'STS-FED-0124');
      log.debug("Leaving FederationSlo.samlLogoutResponse(). Unsolicited.");
      return this.refuse(res, record, 400, 'This service did not ask for ' +
                                           'that answer',
        'The LogoutResponse answers ' + (inResponseTo || 'nothing') +
        (handle ? ' under RelayState ' + handle : ' and carries no ' +
                  'RelayState') + ', and this service is waiting for no such ' +
        'answer: it sent none, it was already answered, or it expired ' +
        '(federation.requestTtlMin).');
    }
    const statusEl = firstByLocal(root, 'StatusCode');
    const status = statusEl ? (statusEl.getAttribute('Value') || '') : '';
    const message = textByLocal(root, 'StatusMessage') || '';
    if (status !== STATUS_SUCCESS) {
      errorCodes.mark(res, 'STS-FED-0125');
      audit.failure('STS-FED-0125', {
        protocol: 'Federation', channel: 'http', target: record.fedId,
        outcome: 'refused',
        summary: 'the partner of ' + record.fedId + ' answered this ' +
                 'service\'s LogoutRequest with ' + (status || 'no status'),
        detail: { relationship: record.fedId, status: status,
                  message: message, request: inResponseTo }
      });
      log.debug("Leaving FederationSlo.samlLogoutResponse(). Not success.");
      res.status(200).type('html').set('Cache-Control', 'no-store')
         .send(this.page('Signed out here',
           '<h1>Signed out here, and not at the partner</h1><p>The session ' +
           'here had already ended. ' + xmlEscape(record.fedName ||
           record.fedId) + ' answered <code>' + xmlEscape(status ||
           '(no status)') + '</code>' +
           (message ? ': ' + xmlEscape(message) : '') + ', so you may still ' +
           'be signed in there.</p>'));
      return undefined;
    }
    audit.audit({
      action: 'federation.signout-answered', actor: context.username || '',
      protocol: 'Federation', channel: 'http', target: record.fedId,
      summary: 'the partner of ' + record.fedId + ' confirmed this ' +
               'service\'s LogoutRequest',
      detail: { relationship: record.fedId, request: inResponseTo }
    });
    log.debug("Leaving FederationSlo.samlLogoutResponse(). Success.");
    res.status(200).type('html').set('Cache-Control', 'no-store')
       .send(this.page('Signed out',
         '<h1>Signed out</h1><p class="ok">You are signed out here, and ' +
         xmlEscape(record.fedName || record.fedId) + ' confirmed that you ' +
         'are signed out there too.</p>'));
    return undefined;
  }

  // =========================================================================
  // WS-FEDERATION: wsignoutcleanup1.0 / wsignout1.0 — CONFIRMED BY THE
  // PERSON (decision 4). WS-Federation 1.2 section 13.2.4.
  // =========================================================================
  private browserFederatedSession(req, record) {
    const { authn, log } = this.deps;
    log.debug("Entering FederationSlo.browserFederatedSession().");
    const session = authn.sessionOf(req);
    const held = session && session.fedPartnerSession;
    log.debug("Leaving FederationSlo.browserFederatedSession().");
    return held && held.relationship === record.fedId ? session : null;
  }

  private wsfedConfirmation(req, res, record, params) {
    const { fedSp, errorCodes, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSlo.wsfedConfirmation().");
    if (!this.accepts(record)) {
      this.recordRefusedByRelationship(record, 'WS-Federation cleanup');
      errorCodes.mark(res, 'STS-FED-0123');
      log.debug("Leaving FederationSlo.wsfedConfirmation(). Not accepted.");
      return this.refuse(res, record, 403, 'This relationship does not ' +
                                           'accept a sign-out',
        'fedAcceptSignout is off on "' + record.fedId + '".');
    }
    const session = this.browserFederatedSession(req, record);
    if (!session) {
      this.recordNoMatch(record, 'WS-Federation ' + params.wa,
                         'no federated session in this browser');
      errorCodes.mark(res, 'STS-FED-0122');
      log.debug("Leaving FederationSlo.wsfedConfirmation(). Nothing here.");
      res.status(200).type('html').set('Cache-Control', 'no-store')
         .send(this.page('Nothing to sign out',
           '<h1>Nothing to sign out</h1><p>This browser holds no session ' +
           'that ' + xmlEscape(record.fedName || record.fedId) + ' signed ' +
           'in here.</p>'));
      return undefined;
    }
    const handle = fedSp.putContext({ kind: 'wsfed-signout',
                                      id: record.fedId,
                                      sessionId: session.id });
    log.debug("Leaving FederationSlo.wsfedConfirmation(). Asking.");
    res.status(200).type('html').set('Cache-Control', 'no-store')
       .send(this.page('Sign out?',
         '<h1>Sign out of this service?</h1><p>' +
         xmlEscape(record.fedName || record.fedId) + ' asked this service to ' +
         'end the session it signed you in to (WS-Federation ' +
         '<code>' + xmlEscape(String(params.wa)) + '</code>).</p>' +
         '<form method="post" action="' +
         xmlEscape(fedSp.sloUrl(this.deps.baseUrlOf(req), record)) + '">' +
         '<input type="hidden" name="wa" value="wsignoutcleanup1.0">' +
         '<input type="hidden" name="confirm" value="' + xmlEscape(handle) +
         '"><button type="submit">Sign out</button></form>' +
         '<p class="note">WS-Federation\'s sign-out is not signed by its ' +
         'specification, so any page can send one. That is why this service ' +
         'asks rather than acting on it: nothing ends until this button is ' +
         'pressed, in this browser. There is no script on this page.</p>'));
    return undefined;
  }

  private wsfedConfirmed(req, res, record, params) {
    const { fedSp, errorCodes, log, xmlEscape, app, baseUrlOf } = this.deps;
    log.debug("Entering FederationSlo.wsfedConfirmed().");
    const handle = String(params.confirm || '');
    const context = /^fed-[A-Za-z0-9_-]{1,64}$/.test(handle)
      ? fedSp.takeContext(handle) : null;
    const session = this.browserFederatedSession(req, record);
    if (!context || context.kind !== 'wsfed-signout' ||
        context.id !== record.fedId || !session ||
        session.id !== context.sessionId) {
      errorCodes.mark(res, 'STS-FED-0126');
      log.debug("Leaving FederationSlo.wsfedConfirmed(). Not confirmed.");
      return this.refuse(res, record, 403, 'The sign-out was not confirmed',
        'A WS-Federation sign-out ends a session only when the person ' +
        'presses the button this service drew for it, in the browser it ' +
        'was drawn for. This request carries ' +
        (handle ? 'a confirmation this service did not draw, one already ' +
                  'used or expired, or one drawn for another browser\'s ' +
                  'session' : 'no confirmation') + '.');
    }
    if (!this.accepts(record)) {
      this.recordRefusedByRelationship(record, 'WS-Federation cleanup');
      errorCodes.mark(res, 'STS-FED-0123');
      log.debug("Leaving FederationSlo.wsfedConfirmed(). Not accepted.");
      return this.refuse(res, record, 403, 'This relationship does not ' +
                                           'accept a sign-out',
        'fedAcceptSignout is off on "' + record.fedId + '".');
    }
    const ended = this.endSessions([session], record, 'WS-Federation ' +
                                   'sign-out, confirmed', baseUrlOf(req),
                                   true);
    this.deps.authn.clearSessionCookie(res);
    log.debug("Leaving FederationSlo.wsfedConfirmed(). Ended.");
    res.status(200).type('html').set('Cache-Control', 'no-store')
       .set('Content-Security-Policy',
            app.contentSecurityPolicy(ended.fanOut.policy))
       .send(this.page('Signed out',
         '<h1>Signed out</h1><p class="ok">The session ' +
         xmlEscape(record.fedName || record.fedId) + ' signed you in to has ' +
         'ended.</p><ul>' + ended.summary + '</ul>' + ended.fanOut.html));
    return undefined;
  }

  // =========================================================================
  // OPENID CONNECT: BACK FROM THE PARTNER'S end_session_endpoint.
  // =========================================================================
  private endSessionReturned(req, res, record, params) {
    const { fedSp, errorCodes, log, xmlEscape } = this.deps;
    log.debug("Entering FederationSlo.endSessionReturned().");
    const handle = String(params.state || '');
    const context = /^fed-[A-Za-z0-9_-]{1,64}$/.test(handle)
      ? fedSp.takeContext(handle) : null;
    if (!context || context.kind !== 'end-session' ||
        context.id !== record.fedId) {
      errorCodes.mark(res, 'STS-FED-0134');
      log.debug("Leaving FederationSlo.endSessionReturned(). Unknown state.");
      return this.refuse(res, record, 400, 'This service did not send you ' +
                                           'there',
        'The state "' + handle + '" is not one this service sent to the ' +
        'partner\'s end_session_endpoint, or it was already used or ' +
        'expired (federation.requestTtlMin).');
    }
    log.debug("Leaving FederationSlo.endSessionReturned().");
    res.status(200).type('html').set('Cache-Control', 'no-store')
       .send(this.page('Signed out',
         '<h1>Signed out</h1><p class="ok">You are signed out here, and ' +
         xmlEscape(record.fedName || record.fedId) + ' has sent you back ' +
         'from its own sign-out.</p>'));
    return undefined;
  }

  // A decrypted EncryptedID's NameID, which may lean on its parent for the
  // `saml:` prefix — parsed as it stands, and otherwise inside a container
  // declaring it. Null when it is not a NameID.
  private nameIdOf(xml) {
    const { log } = this.deps;
    log.debug("Entering FederationSlo.nameIdOf().");
    const attempts = [xml, '<x xmlns:saml="' + NS_SAML + '">' + xml + '</x>'];
    for (let i = 0; i < attempts.length; i++) {
      try {
        const doc = new xmldom.DOMParser().parseFromString(attempts[i],
                                                           'text/xml');
        let el: any = doc && doc.documentElement;
        if (el && i === 1) {
          el = el.firstChild;
          while (el && el.nodeType !== 1) {
            el = el.nextSibling;
          }
        }
        if (el && el.localName === 'NameID') {
          log.debug("Leaving FederationSlo.nameIdOf(). Found.");
          return el;
        }
      } catch (e) {
        log.debug("Caught in FederationSlo.nameIdOf(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving FederationSlo.nameIdOf(). Not a NameID.");
    return null;
  }

  // =========================================================================
  // OPENID CONNECT BACK-CHANNEL LOGOUT 1.0, AS THE RELYING PARTY.
  // Section 2.5 (the request), 2.6 (validation), 2.7 (what the RP does),
  // 2.8 (the response).
  // =========================================================================
  private backchannelEndpoint(req, res) {
    const { fedSp, errorCodes, log, jsonFromB64u, parseBody } = this.deps;
    log.debug("Entering FederationSlo.backchannelEndpoint().");
    const record = this.relationshipFor(req, res, true);
    if (!record) {
      log.debug("Leaving FederationSlo.backchannelEndpoint().");
      return undefined;
    }
    if (record.fedProtocol !== 'oidc') {
      errorCodes.mark(res, 'STS-FED-0135');
      log.debug("Leaving FederationSlo.backchannelEndpoint(). Not OIDC.");
      return this.refuseJson(res, record, 400, 'the relationship "' +
        record.fedId + '" is ' + PROTOCOL_WORDS[record.fedProtocol] +
        ', and a Logout Token belongs to an OpenID Connect relationship');
    }
    const body = parseBody(req);
    let token = typeof body.logout_token === 'string' ? body.logout_token
                                                       : '';
    // AN ENCRYPTED LOGOUT TOKEN (#168): section 2.4 encrypts one "the same
    // way as ID Tokens", so it is decrypted with this relationship's key
    // under the alg and enc it published, and what is inside must be the
    // signed token — verified below exactly as an unencrypted one is.
    if (token.split('.').length === 5) {
      const opened = this.deps.fedEncryption.decryptJwe(record, token);
      if (!opened.ok) {
        errorCodes.mark(res, opened.code);
        log.debug("Leaving FederationSlo.backchannelEndpoint(). " +
                  opened.code);
        return this.refuseJson(res, record, 400, 'the encrypted ' +
                               'logout_token could not be read: ' +
                               opened.why);
      }
      token = String(opened.plaintext || '').trim();
      if (token.split('.').length !== 3) {
        errorCodes.mark(res, 'STS-FED-0141');
        log.debug("Leaving FederationSlo.backchannelEndpoint(). Nothing " +
                  "signed inside.");
        return this.refuseJson(res, record, 400, 'the encrypted ' +
                               'logout_token holds no signed JWT; a Logout ' +
                               'Token is signed, and then encrypted');
      }
    }
    const parts = token.split('.');
    if (!token || parts.length !== 3) {
      errorCodes.mark(res, 'STS-FED-0127');
      log.debug("Leaving FederationSlo.backchannelEndpoint(). No token.");
      return this.refuseJson(res, record, 400, !token
        ? 'the request carries no logout_token (section 2.5)'
        : 'the logout_token is not a signed JWT');
    }
    let header: any = null;
    try {
      header = jsonFromB64u(parts[0]);
    } catch (e) {
      log.debug("Caught in FederationSlo.backchannelEndpoint(): " +
                ((e && e.message) || e));
      header = null;
    }
    const typ = String((header && header.typ) || 'jwt').toLowerCase();
    if (!header || LOGOUT_TYPES.indexOf(typ) < 0) {
      errorCodes.mark(res, 'STS-FED-0129');
      log.debug("Leaving FederationSlo.backchannelEndpoint(). Wrong typ.");
      return this.refuseJson(res, record, 400, header
        ? 'the token is typed "' + header.typ + '", which is not a Logout ' +
          'Token (section 2.4 types one logout+jwt)'
        : 'the token\'s header is not base64url JSON');
    }
    const self = this;
    log.debug("Leaving FederationSlo.backchannelEndpoint(). Verifying.");
    return fedSp.keysFor(record).then(function (keySet) {
      if (!keySet.ok) {
        errorCodes.mark(res, 'STS-FED-0128');
        return self.refuseJson(res, record, 400, 'there is no partner key ' +
                                                 'to verify it with: ' +
                                                 keySet.why);
      }
      const verified = fedSp.verifyForeignJwt(token, record, keySet.keys, {
        audience: String(record.fedClientId || '') || undefined,
        issuer: String(record.fedPeer || '') || undefined
      });
      if (!verified.ok) {
        errorCodes.mark(res, 'STS-FED-0128');
        return self.refuseJson(res, record, 400, 'the Logout Token did not ' +
                                                 'verify: ' + verified.why);
      }
      return self.acceptLogoutToken(req, res, record, verified.payload);
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-FED-0136') + 'federation: ' +
                record.fedId + ' failed on a Logout Token: ' +
                ((e && e.stack) || e));
      if (!res.headersSent) {
        errorCodes.mark(res, 'STS-FED-0136');
        self.refuseJson(res, record, 500, 'this relying party failed while ' +
                                          'reading the Logout Token');
      }
    });
  }

  // Section 2.6 steps 4 to 8, on a token whose signature, issuer and audience
  // verified; then section 2.7.
  private acceptLogoutToken(req, res, record, claims) {
    const { errorCodes, log, baseUrlOf } = this.deps;
    log.debug("Entering FederationSlo.acceptLogoutToken().");
    const events = claims.events;
    let problem = '';
    if (!events || typeof events !== 'object' || Array.isArray(events) ||
        !events[BACKCHANNEL_EVENT] ||
        typeof events[BACKCHANNEL_EVENT] !== 'object') {
      problem = 'it carries no events member naming ' + BACKCHANNEL_EVENT +
                ' with an object value (step 5)';
    } else if (claims.nonce !== undefined) {
      problem = 'it carries a nonce, which a Logout Token MUST NOT (step 6), ' +
                'so it is refused as the ID Token it may be';
    } else if (!claims.sub && !claims.sid) {
      problem = 'it names neither a sub nor a sid (step 4)';
    } else if (!claims.jti || typeof claims.jti !== 'string') {
      problem = 'it carries no jti, and section 2.4 requires one';
    }
    if (problem) {
      errorCodes.mark(res, 'STS-FED-0129');
      log.debug("Leaving FederationSlo.acceptLogoutToken(). " + problem);
      return this.refuseJson(res, record, 400, 'the Logout Token is refused: ' +
                                               problem);
    }
    const now = Date.now();
    const skew = this.skewMs();
    const iat = Number(claims.iat) * 1000;
    if (!isFinite(iat) || iat - skew > now ||
        iat + this.freshnessMs() + skew < now) {
      errorCodes.mark(res, 'STS-FED-0119');
      log.debug("Leaving FederationSlo.acceptLogoutToken(). Stale.");
      return this.refuseJson(res, record, 400, 'the Logout Token\'s iat is ' +
        'missing, in the future, or older than a federation message lives ' +
        '(federation.requestTtlMin)');
    }
    if (!this.accepts(record)) {
      this.recordRefusedByRelationship(record, 'Back-Channel Logout');
      errorCodes.mark(res, 'STS-FED-0123');
      log.debug("Leaving FederationSlo.acceptLogoutToken(). Not accepted.");
      return this.refuseJson(res, record, 400, 'this relying party does not ' +
                                               'accept its partner\'s ' +
                                               'sign-out (fedAcceptSignout)');
    }
    const expires = Math.max(Number(claims.exp) * 1000 || 0,
                             iat + this.freshnessMs()) + skew;
    const self = this;
    log.debug("Leaving FederationSlo.acceptLogoutToken(). Spending the jti.");
    return this.spendOnce('jwt', String(claims.iss), String(claims.jti),
                          expires).then(function (spent) {
      if (!spent.ok) {
        errorCodes.mark(res, spent.code);
        return self.refuseJson(res, record, spent.status === 503 ? 503 : 400,
                               spent.why);
      }
      const sid = claims.sid ? String(claims.sid) : '';
      const sub = claims.sub ? String(claims.sub) : '';
      const sessions = self.sessionsMatching(record, function (held) {
        return held.protocol === 'oidc' &&
               (!sid || String(held.sid || '') === sid) &&
               (!sub || String(held.sub || '') === sub);
      });
      if (!sessions.length) {
        self.recordNoMatch(record, 'Back-Channel Logout',
                           (sid ? 'sid ' + sid : '') + (sub ? ' sub ' + sub
                                                            : ''));
        errorCodes.mark(res, 'STS-FED-0122');
      } else {
        self.endSessions(sessions, record, 'Back-Channel Logout',
                         baseUrlOf(req), false);
      }
      // Section 2.8: 200, and no-store.
      res.status(200).set('Cache-Control', 'no-store').end();
      return undefined;
    });
  }

  // =========================================================================
  // OPENID CONNECT FRONT-CHANNEL LOGOUT 1.0, AS THE RELYING PARTY (decision
  // 5). Section 2: `iss` and `sid` in the query, loaded in the partner's
  // iframe; section 3's session-required variant is the only one accepted.
  // =========================================================================
  private frontchannelEndpoint(req, res) {
    const { errorCodes, log, xmlEscape, app, baseUrlOf } = this.deps;
    log.debug("Entering FederationSlo.frontchannelEndpoint().");
    const record = this.relationshipFor(req, res, false);
    if (!record) {
      log.debug("Leaving FederationSlo.frontchannelEndpoint().");
      return undefined;
    }
    const partnerOrigins = this.partnerOrigins(record);
    const framed = function (body, overrides) {
      log.debug("Entering framed().");
      res.set('Content-Security-Policy',
              app.framedContentSecurityPolicy(partnerOrigins, overrides || {}));
      res.removeHeader('X-Frame-Options');
      res.set('Cache-Control', 'no-cache, no-store').set('Pragma', 'no-cache');
      log.debug("Leaving framed().");
      return body;
    };
    if (record.fedProtocol !== 'oidc') {
      errorCodes.mark(res, 'STS-FED-0135');
      log.debug("Leaving FederationSlo.frontchannelEndpoint(). Not OIDC.");
      return this.refuse(res, record, 400, 'That relationship is not OpenID ' +
                                           'Connect',
        'Front-Channel Logout belongs to an OpenID Connect relationship, and ' +
        '"' + record.fedId + '" is ' + PROTOCOL_WORDS[record.fedProtocol] +
        '.');
    }
    const iss = typeof req.query.iss === 'string' ? req.query.iss : '';
    const sid = typeof req.query.sid === 'string' ? req.query.sid : '';
    if (!iss || !sid || iss !== String(record.fedPeer || '').trim()) {
      errorCodes.mark(res, 'STS-FED-0130');
      log.debug("Leaving FederationSlo.frontchannelEndpoint(). No iss/sid.");
      framed('', {});
      return this.refuse(res, record, 400, 'The request does not name the ' +
                                           'partner\'s session',
        !iss || !sid
          ? 'A front-channel logout here needs iss and sid (register this ' +
            'URI with frontchannel_logout_session_required): without them ' +
            'the only session it could name is whatever this browser holds, ' +
            'and a URL any page can load must not end that.'
          : 'iss is ' + iss + ' and this relationship\'s partner is ' +
            record.fedPeer + '.');
    }
    if (!this.accepts(record)) {
      this.recordRefusedByRelationship(record, 'Front-Channel Logout');
      errorCodes.mark(res, 'STS-FED-0123');
      framed('', {});
      log.debug("Leaving FederationSlo.frontchannelEndpoint(). Not accepted.");
      return this.refuse(res, record, 403, 'This relationship does not ' +
                                           'accept a sign-out',
        'fedAcceptSignout is off on "' + record.fedId + '".');
    }
    const sessions = this.sessionsMatching(record, function (held) {
      return held.protocol === 'oidc' && String(held.sid || '') === sid;
    });
    let body;
    let overrides = {};
    if (!sessions.length) {
      this.recordNoMatch(record, 'Front-Channel Logout', 'sid ' + sid);
      errorCodes.mark(res, 'STS-FED-0122');
      body = '<h1>Nothing to sign out</h1><p>No session here was started ' +
             'by that partner session.</p>';
    } else {
      const ended = this.endSessions(sessions, record, 'Front-Channel Logout',
                                     baseUrlOf(req), true);
      overrides = ended.fanOut.policy;
      body = '<h1>Signed out</h1><ul>' + ended.summary + '</ul>' +
             ended.fanOut.html;
    }
    log.debug("Leaving FederationSlo.frontchannelEndpoint().");
    res.status(200).type('html')
       .send(framed(this.page('Signed out', body + '<p class="note">' +
         xmlEscape(record.fedName || record.fedId) + ' loaded this page in ' +
         'a frame to end the session it signed you in to here.</p>'),
         overrides));
    return undefined;
  }

  // The partner's origins, which alone may frame the front-channel page: its
  // issuer's and its authorization endpoint's, where each is an http(s) URL.
  private partnerOrigins(record) {
    const { log } = this.deps;
    log.debug("Entering FederationSlo.partnerOrigins().");
    const out = [];
    [record.fedPeer, record.fedSsoUrl, record.fedEndSessionUrl]
      .forEach(function (one) {
        try {
          const url = new URL(String(one || ''));
          if ((url.protocol === 'https:' || url.protocol === 'http:') &&
              out.indexOf(url.origin) < 0) {
            out.push(url.origin);
          }
        } catch (e) {
          log.debug("Caught in FederationSlo.partnerOrigins(): " +
                    ((e && e.message) || e));
        }
      });
    log.debug("Leaving FederationSlo.partnerOrigins(). " + out.length);
    return out;
  }

  // =========================================================================
  // TELLING THE PARTNER (service-provider-initiated), for `logout/logout.ts`.
  //
  // `{ ok: true, target }`, or `{ ok: false, why }`. The target is a link or
  // a form the sign-out page draws, because every one of these is a browser
  // going to the partner: a signed <LogoutRequest> to `fedSloUrl` on
  // `fedSloBinding` (saml-profiles-2.0-os section 4.4.3), RP-Initiated Logout
  // 1.0 to `fedEndSessionUrl` with the partner's ID Token as id_token_hint,
  // or WS-Federation's wsignout1.0 to the partner's passive endpoint. What
  // comes back — a LogoutResponse, the post-logout redirect — arrives at
  // /federation/slo/{id} and is matched against the context minted here.
  // `base` is the sign-out request's own, which names this service to the
  // partner exactly as its sign-in did.
  // =========================================================================
  canTellPartner(held) {
    const { federation, log } = this.deps;
    log.debug("Entering FederationSlo.canTellPartner().");
    const record = held ? federation.get(held.relationship) : null;
    if (!record || record.fedRole !== 'service-provider' ||
        !federation.isUsable(record)) {
      log.debug("Leaving FederationSlo.canTellPartner(). Not usable.");
      return { ok: false, record: record,
               why: 'the relationship it came through is gone, disabled or ' +
                    'not fully configured' };
    }
    const protocol = record.fedProtocol;
    let why = '';
    if (protocol === 'saml11' || protocol === 'oauth2') {
      why = PROTOCOL_WORDS[protocol] + ' defines no sign-out to send';
    } else if (protocol === 'saml2' && !String(record.fedSloUrl || '')
               .trim()) {
      why = 'the relationship has no fedSloUrl, the partner\'s ' +
            'SingleLogoutService';
    } else if (protocol === 'oidc' && !String(record.fedEndSessionUrl || '')
               .trim()) {
      why = 'the relationship has no fedEndSessionUrl, the partner\'s ' +
            'end_session_endpoint';
    }
    log.debug("Leaving FederationSlo.canTellPartner(). " + (why || 'yes'));
    return { ok: !why, record: record, why: why };
  }

  partnerLogoutFor(session, base) {
    const { fedSp, iso, xmlEscape, log, config } = this.deps;
    log.debug("Entering FederationSlo.partnerLogoutFor().");
    const held = session && session.fedPartnerSession;
    const can = this.canTellPartner(held);
    if (!can.ok) {
      log.debug("Leaving FederationSlo.partnerLogoutFor(). " + can.why);
      return { ok: false, why: can.why };
    }
    const record = can.record;
    const label = record.fedName || record.fedId;
    const username = (session.user && session.user.username) || '';
    if (record.fedProtocol === 'saml2') {
      const id = '_' + crypto.randomBytes(16).toString('hex');
      const destination = String(record.fedSloUrl).trim();
      const until = new Date(Date.now() + Number(config.value(
        'federation.requestTtlMin')) * 60 * 1000).toISOString()
        .replace(/\.\d{3}Z$/, 'Z');
      const attrs = (held.nameIdFormat ? ' Format="' +
                     xmlEscape(held.nameIdFormat) + '"' : '') +
        (held.nameQualifier ? ' NameQualifier="' +
         xmlEscape(held.nameQualifier) + '"' : '') +
        (held.spNameQualifier ? ' SPNameQualifier="' +
         xmlEscape(held.spNameQualifier) + '"' : '');
      const xml = '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ' +
        'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
        'IssueInstant="' + iso(0) + '" Destination="' +
        xmlEscape(destination) + '" NotOnOrAfter="' + until + '">' +
        '<saml:Issuer>' + xmlEscape(fedSp.ourEntityId(base, record)) +
        '</saml:Issuer><saml:NameID' + attrs + '>' +
        xmlEscape(held.nameId || '') + '</saml:NameID>' +
        (held.sessionIndex ? '<samlp:SessionIndex>' +
         xmlEscape(held.sessionIndex) + '</samlp:SessionIndex>' : '') +
        '</samlp:LogoutRequest>';
      const handle = fedSp.putContext({ kind: 'slo-request', id: record.fedId,
                                        requestId: id, username: username });
      const target = this.outbound(record, destination, 'SAMLRequest',
                                   { id: id, xml: xml }, handle);
      log.debug("Leaving FederationSlo.partnerLogoutFor(). SAML.");
      return { ok: true, target: Object.assign({
        relationship: record.fedId, label: label, protocol: 'SAML 2.0',
        what: 'a signed LogoutRequest to ' + destination }, target) };
    }
    if (record.fedProtocol === 'oidc') {
      const handle = fedSp.putContext({ kind: 'end-session', id: record.fedId,
                                        username: username });
      const params = new URLSearchParams();
      if (held.idToken) {
        params.set('id_token_hint', String(held.idToken));
      }
      params.set('client_id', String(record.fedClientId || ''));
      params.set('post_logout_redirect_uri', fedSp.sloUrl(base, record));
      params.set('state', handle);
      const endpoint = String(record.fedEndSessionUrl).trim();
      log.debug("Leaving FederationSlo.partnerLogoutFor(). OIDC.");
      return { ok: true, target: {
        relationship: record.fedId, label: label, protocol: 'OpenID Connect',
        what: 'RP-Initiated Logout at ' + endpoint, kind: 'link',
        url: endpoint + (endpoint.indexOf('?') >= 0 ? '&' : '?') +
             params.toString(), action: '', fields: {} } };
    }
    // WS-Federation 1.2 section 13.2.4: wa=wsignout1.0 to the partner's
    // passive endpoint. No wreply — the partner's own sign-out page is where
    // the person should end up, and a wreply here would ask the partner to
    // send them somewhere it has not registered.
    const passive = String(record.fedSsoUrl || '').trim();
    log.debug("Leaving FederationSlo.partnerLogoutFor(). WS-Federation.");
    return { ok: true, target: {
      relationship: record.fedId, label: label, protocol: 'WS-Federation',
      what: 'wsignout1.0 to ' + passive, kind: 'link',
      url: passive + (passive.indexOf('?') >= 0 ? '&' : '?') +
           'wa=wsignout1.0', action: '', fields: {} } };
  }

  // How the sign-out page draws the targets partnerLogoutFor() built.
  renderPartnerLogouts(targets) {
    const { log, xmlEscape } = this.deps;
    const self = this;
    log.debug("Entering FederationSlo.renderPartnerLogouts(). " +
              (targets || []).length);
    if (!targets || !targets.length) {
      log.debug("Leaving FederationSlo.renderPartnerLogouts(). None.");
      return '';
    }
    log.debug("Leaving FederationSlo.renderPartnerLogouts().");
    return '<h2>Federation partners</h2><table><thead><tr><th>Partner</th>' +
      '<th>Sign out there too</th></tr></thead><tbody>' +
      targets.map(function (target) {
        return '<tr><td><code>' + xmlEscape(target.label) + '</code><br>' +
          '<span class="sub">' + xmlEscape(target.protocol) + '</span></td>' +
          '<td>' + self.continueControl(target, 'Sign out at ' +
                                        target.label) +
          '<span class="sub">' + xmlEscape(target.what) + '</span></td></tr>';
      }).join('') + '</tbody></table><p class="sub">You signed in here ' +
      'through these identity providers, and your session there is still ' +
      'live. Each is a link or a form rather than an automatic redirect: ' +
      'this page runs no script, and leaving for a partner is a deliberate ' +
      'click.</p>';
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), with facades for the
// JavaScript and the tests that require this module by name.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<FederationSlo>(
  'federation/federation_slo',
  () => new FederationSlo(FederationSlo.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  FederationSlo: FederationSlo,
  installInstance: (instance: FederationSlo): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  canTellPartner: slot.forward('canTellPartner'),
  partnerLogoutFor: slot.forward('partnerLogoutFor'),
  renderPartnerLogouts: slot.forward('renderPartnerLogouts'),
  SLO_PATH: FederationSlo.SLO_PATH,
  BACKCHANNEL_PATH: FederationSlo.BACKCHANNEL_PATH,
  FRONTCHANNEL_PATH: FederationSlo.FRONTCHANNEL_PATH
};
