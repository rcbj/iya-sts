'use strict';
//
// File: frontchannel_logout.ts
//
// ---------------------------------------------------------------------------
// OPENID CONNECT FRONT-CHANNEL LOGOUT 1.0 — TELLING THE RELYING PARTIES.
//
// The other half of a sign-out. Ending the session here drops a cookie and
// revokes what this service issued; every relying party the person signed into
// still believes they are signed in, and will go on believing it until its own
// session expires. Front-Channel Logout is how an OpenID Provider says
// otherwise: each RP registers a `frontchannel_logout_uri`, and the sign-out
// page loads all of them in hidden iframes so that each RP's own logout runs in
// the browser that is doing the signing out.
//
// It is a LIBRARY (rule 3): it registers no route, so its position in the
// require order does not matter and it cannot be the reason a route is missing.
// It requires `helpers.js`, `config.js`, `app.js`, `applications.js`,
// `validation.js` and `error_codes.js` (and `authn/authn.ts` lazily, once a
// session changes) — none of which requires it back — and deliberately NOT
// `oauth2.ts`, because that module requires THIS one. That is the whole reason
// this file exists rather than the code living in `oauth2.ts`:
// `/oauth2/logout`, the protocol-independent `/logout` and the console's
// sign-outs (both through `logout/logout.ts`) all have to render the same
// fan-out, and `logout/logout.ts` reaching into `oauth2.ts` for it would be a
// require this file makes unnecessary.
//
// ---------------------------------------------------------------------------
// FIVE THINGS ARE WORTH KNOWING BEFORE READING FURTHER.
//
// **THE LIST OF RELYING PARTIES LIVES ON THE SESSION.** `noteClient()` writes
// `session.oidcClients` at the moment an authorization response goes out, which
// is the one point where both the client and the session are in scope. It is on
// the session object rather than in a map of its own because that is exactly
// the lifetime it should have: when the session goes, so does the list, and
// nothing has to be swept. The same decision `wsfed.ts` makes about
// `session.wsfedRealms` and `saml2_sso.ts` makes about
// `session.saml2ServiceProviders` — three protocols, one shape, deliberately.
//
// **`sid` IS THE SESSION ID AND IT REVERSED A DOCUMENTED DECISION.**
// `admin_stats.js` used to say, in as many words, that no token this service
// issues carries a session identifier and that inventing one to make a console
// page easier would be changing what every client receives. That was right at
// the time and the reasoning is worth keeping: a claim is added because a
// SPECIFICATION needs it, not because something here would find it convenient.
// Front-Channel Logout is that specification — section 3 requires the OP to
// send `sid` to any RP that registered `frontchannel_logout_session_required`,
// and an RP holding two sessions in one browser cannot tell which one ended
// without it. So the ID Token carries `sid` when it was issued ON a session,
// and `oauth2.frontchannelLogout` turns the whole feature — the claim, the
// advertisement and the fan-out — off in one place for anybody who wants the
// tokens this service used to issue.
//
// **THE IFRAMES ARE A CSP RELAXATION AND IT IS THE NARROW ONE.** `app.js` sets
// `default-src 'none'`, from which `frame-src` falls back — so an iframe to
// another origin is blocked, which is the correct default for every other page
// here. The sign-out page relaxes `frame-src` to THE ORIGINS IT IS ACTUALLY
// LOADING, enumerated from the URIs themselves, rather than to `*`. It goes
// through `app.contentSecurityPolicy()` like every other relaxation in this
// service, so `frame-ancestors` and `base-uri` cannot be dropped by it — see
// the repository CLAUDE.md's two CSP rules, which this is one more caller of
// (it was the sixth relaxation when it was written).
//
// **THE URLS ARE LISTED VISIBLY BESIDE THE IFRAMES.** A hidden iframe that
// failed — a dead RP, a certificate a browser will not accept, a URI somebody
// mistyped into the directory — is indistinguishable from one that worked,
// because a front-channel notification has no answer the OP can read. Section 5
// of the specification says as much: the OP cannot know whether the logout
// succeeded. So the page shows each URL as a link, which is the only thing that
// turns "nothing happened" into something a person can click and see. It is the
// same decision `wsfed.ts` made about its cleanup pings, for the same reason.
//
// **IT SENDS `iss` AND `sid` ONLY WHERE THE CLIENT ASKED FOR THEM.** Section 2
// says the two are sent when `frontchannel_logout_session_required` is true and
// that they are otherwise omitted, and an RP that did not ask may well be
// validating the query string it gets. RFC 7591 section 2 makes an omitted
// boolean FALSE rather than unknown, which is what `clientConfigOf()` applies.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `FrontchannelLogout` takes the app (for its CSP builder), the
// settings, the application registry, the validator, the error-code table
// and the logger through its constructor, and reaches `authn/authn.ts`
// through a LOADER in the same place it used to require it, because that
// require was lazy and stays lazy. The module still exports every function it
// exported, as FACADES over the instance the composition root builds and
// installs (R2); a process without the root builds a default one at load.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import app = require('../common/app');
import config = require('../common/config');
import applications = require('../common/applications');
// The one question asked of a stored URI before it is framed. `validation.js`
// requires config.js, error_codes.js and npm packages and nothing here.
import validation = require('../common/validation');
import errorCodes = require('../common/error_codes');

// A session, a notification row.
type Json = any;

// The one thing this module asks of `authn/authn.ts`.
interface SessionNotice {
  noteSessionChanged(session: Json): unknown;
}

interface FrontchannelLogoutDeps {
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  app: typeof app;
  config: typeof config;
  applications: typeof applications;
  validation: typeof validation;
  errorCodes: typeof errorCodes;
  // `authn/authn.ts`, required at the moment a session changes, never at
  // load.
  loadAuthn(): SessionNotice;
}

// A notification row, as `notificationsFor()` builds it.
interface Notification {
  clientId: string;
  uri: string;
  url: string;
  sessionRequired: boolean;
  why: string;
}

class FrontchannelLogout {
  constructor(private readonly deps: FrontchannelLogoutDeps) {
    deps.log.debug("Entering FrontchannelLogout.constructor().");
    deps.log.debug("Leaving FrontchannelLogout.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): FrontchannelLogoutDeps {
    helpers.log.debug("Entering FrontchannelLogout.defaultDeps().");
    helpers.log.debug("Leaving FrontchannelLogout.defaultDeps().");
    return {
      log: helpers.log,
      xmlEscape: helpers.xmlEscape,
      app: app,
      config: config,
      applications: applications,
      validation: validation,
      errorCodes: errorCodes,
      loadAuthn: function (): SessionNotice {
        return require('../authn/authn');
      }
    };
  }

  // Is the feature on at all? Read per call rather than captured at require
  // time, which is what `runtime: true` on the setting claims — a `const`
  // here is the one thing /admin/config could not change.
  enabled(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering FrontchannelLogout.enabled().");
    log.debug("Leaving FrontchannelLogout.enabled().");
    return !!config.value('oauth2.frontchannelLogout');
  }

  // -------------------------------------------------------------------------
  // WHICH CLIENTS A SESSION HAS SIGNED INTO.
  //
  // Called from `issueAuthorizationResponse()` — the point at which this
  // service issues something to a client ON a session, which is exactly the
  // event that makes the client an RP of that session. Not from the token
  // endpoint: a code redeemed there is the same transaction continuing, and
  // counting it again would say nothing new. Not from the direct grants
  // either, which have no session to sign out of.
  //
  // It cannot throw. It is called in the middle of building an authorization
  // response, and a bookkeeping failure must never be the reason a client does
  // not get its code — the same rule `audit()`, `signJwt()`'s recorder and the
  // directory's user observer follow.
  // -------------------------------------------------------------------------
  //
  // `facts` (2026-09-17, #36) carries what Back-Channel Logout needs and only
  // this moment knows: `iss`, the issuer identifier the client's ID Token is
  // issued under — this process runs several named authorization servers and
  // a Logout Token must name the one the relying party trusts — and `sub`.
  // Both are kept on the row, the latest winning, because a client served by
  // one authorization server is served by it every time.
  noteClient(session: Json, clientId: string, facts?: Json): void {
    const { log, loadAuthn } = this.deps;
    log.debug("Entering FrontchannelLogout.noteClient().");
    try {
      if (!session || !clientId) {
        log.debug("Leaving FrontchannelLogout.noteClient().");
        return;
      }
      session.oidcClients = session.oidcClients || {};
      const known = session.oidcClients[clientId];
      const said = facts || {};
      session.oidcClients[clientId] = {
        first: (known && known.first) || Date.now(),
        last: Date.now(),
        count: ((known && known.count) || 0) + 1,
        iss: String(said.iss || (known && known.iss) || ''),
        sub: String(said.sub || (known && known.sub) || '')
      };
      // AND THE SESSION STORE IS TOLD (2026-09-14, #46): the assignment above
      // edits an object the store does not journal, so another node's copy of
      // the session never learnt the client and its sign-out drew no iframe
      // for it. `authn.noteSessionChanged()` carries the argument. LAZILY, and
      // only for a real session row (one with an id): authn.js is loaded long
      // before this module is used, and a caller passing a plain object has
      // no store.
      if (session.id) {
        loadAuthn().noteSessionChanged(session);
      }
    } catch (e) {
      log.debug("Caught in FrontchannelLogout.noteClient(): " +
                ((e && e.message) || e));
      log.warn('front-channel logout: could not record the client on the ' +
               'session: ' + e.message);
    }
    log.debug("Leaving FrontchannelLogout.noteClient().");
  }

  // Every client this session signed into, in the order they were first seen.
  // Read straight off the session, so a caller holding a session it is about
  // to discard still gets the list — which is the whole reason `endSession()`
  // and `endSessionById()` RETURN the session rather than a boolean.
  clientsOf(session: Json): string[] {
    const { log } = this.deps;
    log.debug("Entering FrontchannelLogout.clientsOf().");
    const held = (session && session.oidcClients) || {};
    log.debug("Leaving FrontchannelLogout.clientsOf().");
    return Object.keys(held).sort(function (a, b) {
      return (held[a].first || 0) - (held[b].first || 0);
    });
  }

  // -------------------------------------------------------------------------
  // THE NOTIFICATIONS THIS SIGN-OUT SHOULD SEND.
  //
  // One row per client the session signed into, whether or not it can be
  // notified — a client with no `frontchannel_logout_uri` is REPORTED with
  // `uri: ''` rather than filtered out, because "this RP still thinks you are
  // signed in and there is nowhere to tell it" is the single most useful
  // sentence this page can produce, and a filtered list would say nothing at
  // all.
  //
  // `iss` IS THE ISSUER THE CLIENT'S ID TOKEN NAMED (#122, 2026-09-22): the
  // one `noteClient()` recorded when this session answered the client. This
  // service runs several named authorization servers and several realms in
  // one process, and a sign-out at `/logout` or at another server's
  // `/oauth2/logout` used to send every client the issuer of the SIGN-OUT
  // request — one a client of `/:as/…` does not recognise, so section 2's
  // check on `iss` failed and its logout did not run. `issuer`, which the
  // caller supplies, is used only for a client recorded before the issuer
  // was (a session from before 2026-09-17, #36).
  // -------------------------------------------------------------------------
  notificationsFor(session: Json, issuer: string): Notification[] {
    const { log, applications, validation, errorCodes } = this.deps;
    log.debug("Entering FrontchannelLogout.notificationsFor(). issuer=" +
              issuer);
    const sid = (session && session.id) || '';
    const held = (session && session.oidcClients) || {};
    const rows = this.clientsOf(session).map(function (clientId) {
      const client = applications.clientConfigOf(clientId);
      const iss = String((held[clientId] && held[clientId].iss) || issuer ||
                         '');
      const stored = String((client && client.frontchannel_logout_uri) || '');
      // THE SAME RULE REGISTRATION APPLIES, APPLIED AGAIN WHEN IT IS READ
      // (2026-09-13). Registration, the console and `/admin-api` refuse
      // anything but http or https here now, and `ldapmodify` reaches this
      // attribute without passing any of them — and until that date none of
      // the three checked it either. What is stored here is loaded in an
      // IFRAME and printed as a LINK on the sign-out page, so a `javascript:`
      // value put here by either route is skipped and reported rather than
      // drawn.
      const storedProblem = stored ?
                            validation.frontchannelUriProblem(stored) :
                            null;
      if (storedProblem) {
        log.warn(errorCodes.tag('STS-OAUTH-0288') + 'front-channel logout: ' +
                 clientId + '\'s stored frontchannel_logout_uri is not ' +
                 'notified, because it ' + storedProblem + '.');
      }
      // AND SECTION 2's ORIGIN RULE, read the same way (#122, 2026-09-22):
      // the URI must be on the origin of one of the client's redirect URIs,
      // or this sign-out would frame another host's page with the session's
      // `sid` on it. Registration and the console refuse it now; a value
      // written through `ldapmodify`, or before that date, is skipped here.
      const originProblem = stored && !storedProblem
        ? applications.frontchannelOriginProblem(stored,
            (client && client.redirect_uris) || [])
        : null;
      if (originProblem) {
        log.warn(errorCodes.tag('STS-OAUTH-0572') + 'front-channel logout: ' +
                 clientId + '\'s stored frontchannel_logout_uri is not ' +
                 'notified: ' + originProblem);
      }
      const uri = storedProblem || originProblem ? '' : stored;
      const wantsSession = !!(client &&
                              client.frontchannel_logout_session_required);
      let url = '';
      if (uri) {
        // Section 2: iss and sid are added when the client required them, and
        // omitted otherwise. Appended rather than rebuilt through URL(),
        // because a registered URI may carry a query string of its own and
        // this service must hand back what was registered plus what the
        // specification adds — reserialising somebody's URI is how a logout
        // endpoint stops matching whatever the RP is comparing against.
        url = uri;
        if (wantsSession) {
          url += (url.indexOf('?') >= 0 ? '&' : '?') +
                 'iss=' + encodeURIComponent(iss) +
                 '&sid=' + encodeURIComponent(sid);
        }
      }
      return {
        clientId: clientId,
        uri: uri,
        url: url,
        sessionRequired: wantsSession,
        // Why this client will not be notified, in words, or '' when it will
        // be. Stated here rather than worked out again by each renderer.
        why: uri ? ''
                  : originProblem
                  ? 'the frontchannel_logout_uri stored for this client is ' +
                    'not notified: ' + originProblem + ' Correct ' +
                    'oauthFrontchannelLogoutUri or oauthRedirectUri on its ' +
                    'entry.'
                  : storedProblem
                  ? 'the frontchannel_logout_uri stored for this client ' +
                    'cannot be framed — it ' + storedProblem + ' — so it is ' +
                    'not notified. Correct oauthFrontchannelLogoutUri on its ' +
                    'entry.'
                  : (client && client.known
                      ? 'this client has registered no ' +
                        'frontchannel_logout_uri, so there is nowhere to ' +
                        'tell it. Register one, or set ' +
                        'oauthFrontchannelLogoutUri on its entry under ' +
                        'ou=applications.'
                      : 'this service has never been told anything about ' +
                        'this client beyond its identifier, so it has no ' +
                        'logout URI to be notified at.')
      };
    });
    log.debug("Leaving FrontchannelLogout.notificationsFor(). " +
              rows.length + " client(s), " +
              rows.filter(function (r) {
                return !!r.url;
              }).length + " notifiable.");
    return rows;
  }

  // The distinct origins of the notifications that will actually load — what
  // `frame-src` has to allow. A URI this service cannot parse is DROPPED from
  // the policy rather than widening it: the iframe then does not load, which
  // is the safe direction, and the row beside it still shows the URL so the
  // failure is visible rather than silent.
  frameOriginsOf(notifications: Notification[]): string[] {
    const { log } = this.deps;
    log.debug("Entering FrontchannelLogout.frameOriginsOf().");
    const origins = {};
    notifications.forEach(function (row) {
      if (!row.url) {
        return;
      }
      try {
        origins[new URL(row.url).origin] = true;
      } catch (e) {
        log.debug("Caught in FrontchannelLogout.frameOriginsOf(): " +
                  ((e && e.message) || e));
        // Not a URL this runtime will parse. Logged rather than swallowed: it
        // is almost always a value typed into the directory by hand, and it
        // is worth saying so once rather than leaving an iframe that never
        // loads.
        log.warn('front-channel logout: ' + row.clientId + '\'s ' +
            'frontchannel_logout_uri (' +
                 row.uri + ') is not a URL this runtime can parse, so it is ' +
                 'left out of the Content-Security-Policy and its iframe ' +
                 'will not load: ' + e.message);
      }
    });
    const list = Object.keys(origins);
    log.debug("Leaving FrontchannelLogout.frameOriginsOf(). " + list.length +
              " origin(s).");
    return list;
  }

  // The Content-Security-Policy for a page carrying these iframes. Through
  // `app.contentSecurityPolicy()`, which re-adds `frame-ancestors` and
  // `base-uri` whatever this asks for — a caller cannot drop them, and this
  // one must not want to.
  contentSecurityPolicyFor(notifications: Notification[]): string {
    const { log, app } = this.deps;
    log.debug("Entering FrontchannelLogout.contentSecurityPolicyFor().");
    const origins = this.frameOriginsOf(notifications);
    if (!origins.length) {
      log.debug("Leaving FrontchannelLogout.contentSecurityPolicyFor().");
      return app.contentSecurityPolicy({});
    }
    log.debug("Leaving FrontchannelLogout.contentSecurityPolicyFor().");
    return app.contentSecurityPolicy({ 'frame-src': origins.join(' ') });
  }

  // -------------------------------------------------------------------------
  // THE BLOCK OF HTML: the iframes, and the same URLs as visible links.
  //
  // Returned as a string for the caller to place in its own page, because the
  // three callers draw three different pages around it — `/oauth2/logout` is
  // an OIDC sign-out, `/logout` is a protocol-independent one, and the
  // console's is an operator's report. What must not differ is the fan-out
  // itself.
  //
  // The iframes are 0x0 and `aria-hidden`: they are a side effect and not
  // content, and a screen reader announcing eight empty frames would be
  // reading out the plumbing. The LINKS are the accessible half and carry the
  // same URLs.
  // -------------------------------------------------------------------------
  render(notifications: Notification[]): string {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering FrontchannelLogout.render(). " +
              notifications.length + " notification(s).");
    if (!notifications.length) {
      log.debug("Leaving FrontchannelLogout.render(). Nothing to notify.");
      return '<p>No OpenID Connect relying party was signed into on this ' +
             'session, so there is nothing to notify.</p>';
    }
    const notifiable = notifications.filter(function (row) {
      return !!row.url;
    });
    const rows = notifications.map(function (row) {
      return '<tr><td><code>' + xmlEscape(row.clientId) + '</code></td>' +
        '<td>' + (row.url
          ? '<a href="' + xmlEscape(row.url) + '" target="_blank" ' +
                                               'rel="noopener noreferrer">' +
            xmlEscape(row.url) + '</a>' +
            (row.sessionRequired
              ? '<br><span class="sub">iss and sid are on it: this client ' +
                'registered frontchannel_logout_session_required.</span>'
              : '<br><span class="sub">No iss or sid: this client did not ' +
                'register frontchannel_logout_session_required, and section ' +
                '2 says they are then omitted.</span>')
          : '<span class="sub">' + xmlEscape(row.why) + '</span>') +
        '</td></tr>';
    }).join('');
    const frames = notifiable.map(function (row) {
      return '<iframe src="' + xmlEscape(row.url) + '" width="0" height="0" ' +
             'style="display:none" aria-hidden="true" title=""></iframe>';
    }).join('');
    const inner =
      '<h2>' + notifiable.length + ' of ' + notifications.length +
      ' relying part' +
        (notifications.length === 1 ? 'y' : 'ies') + ' notified</h2><p ' +
      'class="sub">OpenID Connect Front-Channel Logout 1.0. Each URL below ' +
      'was loaded in a hidden iframe as this page rendered, so each relying ' +
      'party\'s own logout ran in this browser.</p><table><thead><tr><th>' +
      'Client</th><th>frontchannel_logout_uri</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table><p ' +
      'class="sub">The URLs are shown as links deliberately. A front-channel ' +
      'notification has no answer this service can read — section 5 says ' +
      'the provider cannot know whether the logout succeeded — so a dead ' +
      'relying party, a certificate this browser will not accept and a URI ' +
      'somebody mistyped all look exactly like success. Clicking one is the ' +
      'only way to see which happened.</p>' +
      frames;
    log.debug("Leaving FrontchannelLogout.render(). " + notifiable.length +
              " iframe(s).");
    return inner;
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
const slot = new InstanceSlot<FrontchannelLogout>(
  'oauth-oidc/frontchannel_logout',
  () => new FrontchannelLogout(FrontchannelLogout.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  FrontchannelLogout: FrontchannelLogout,
  installInstance: (instance: FrontchannelLogout): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  enabled: slot.forward('enabled'),
  noteClient: slot.forward('noteClient'),
  clientsOf: slot.forward('clientsOf'),
  notificationsFor: slot.forward('notificationsFor'),
  frameOriginsOf: slot.forward('frameOriginsOf'),
  contentSecurityPolicyFor: slot.forward('contentSecurityPolicyFor'),
  render: slot.forward('render')
};
