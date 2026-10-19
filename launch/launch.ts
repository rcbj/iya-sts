// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: launch/launch.ts
//
// ---------------------------------------------------------------------------
// GET /launch/{app}[?protocol=saml2|saml11|wsfed|oidc][&target=…] — ONE
// IDENTITY-PROVIDER-INITIATED SIGN-IN LINK PER APPLICATION (#426, #713).
//
// The user portal's Sign in link, the URL at the top of each protocol sub-tab
// in the console, and the link an operator pastes anywhere else are this one
// URL. `common/launch_links.ts` builds it for all of them; this module
// answers it. `launch/CLAUDE.md` is the argument.
//
// **IT DOES NO SIGN-IN OF ITS OWN.** It chooses the protocol, checks that
// identity-provider-initiated sign-in is on for the application in it, and
// sends the browser (303) to that protocol's own endpoint, which does the
// sign-in exactly as it does for a link naming it directly — the session and
// its risk, the issuance policy, `session-presented`, the record of the
// relying party on the session that logout reads — and checks the switch
// again, so going straight to the endpoint is not a way round this door.
//
// **OPENID CONNECT IS THE EXCEPTION, BECAUSE SECTION 4 ENDS AT THE CLIENT.**
// The person must be signed in here first (so `login_hint` names them and the
// launch can be recorded on their session), and the browser goes to the
// client's initiate_login_uri, from which the client starts an ordinary
// authorization request. The launch is recorded so that a client whose own
// start is turned off is answered at /oauth2/authorize within the window.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import applications = require('../common/applications');
import realms = require('../common/realms');
import authn = require('../authn/authn');
import LaunchLinks = require('../common/launch_links');
import Html = require('../common/html');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

// The route, and the one place its spelling lives.
const LAUNCH_PATH = '/launch/:app';

interface LaunchDeps {
  helpers: typeof helpers;
  config: typeof config;
  errorCodes: typeof errorCodes;
  applications: typeof applications;
  realms: typeof realms;
  authn: typeof authn;
  issuerFor: (base: string) => string;
}

/**
 * The identity-provider-initiated sign-in door, `GET /launch/{app}`.
 */
class Launch {
  /**
   * Builds the door from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: LaunchDeps) {
    deps.helpers.log.debug("Entering Launch.constructor().");
    deps.helpers.log.debug("Leaving Launch.constructor().");
  }

  /**
   * Returns the modules this class is built from.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): LaunchDeps {
    helpers.log.debug("Entering Launch.defaultDeps().");
    helpers.log.debug("Leaving Launch.defaultDeps().");
    return {
      helpers: helpers,
      config: config,
      errorCodes: errorCodes,
      applications: applications,
      realms: realms,
      authn: authn,
      // Read when asked: the issuer is the authorization server's to say.
      issuerFor: function issuerFor(base: string): string {
        helpers.log.debug("Entering issuerFor().");
        helpers.log.debug("Leaving issuerFor().");
        return require('../oauth-oidc/jwt_access_token').issuerFor(base);
      }
    };
  }

  /**
   * Registers `GET /launch/{app}`.
   *
   * Called by `common/protocol_stack.ts`; requiring this module registers
   * nothing.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: Json): void {
    const { log } = this.deps.helpers;
    const self = this;
    log.debug("Entering Launch.registerRoutes().");
    app.get(LAUNCH_PATH, function (req: Json, res: Json) {
      return self.launch(req, res);
    });
    log.debug("Leaving Launch.registerRoutes().");
  }

  // A refusal is a short page: the person followed a link, and there is no
  // relying party yet to hand a protocol error to. English, as every refusal
  // here is (#539). No script, so the service's own policy needs no change.
  // error-code: none — the helper's definition; each caller marks its code
  private refuse(res: Json, status: number, title: string,
                 detail: string): void {
    const { log } = this.deps.helpers;
    log.debug("Entering Launch.refuse(). " + status);
    res.status(status)
      .type('text/html')
      .set('Cache-Control', 'no-store')
      .send('<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
            '<meta name="viewport" content="width=device-width, ' +
            'initial-scale=1"><title>' + Html.esc(title) + '</title>' +
            '</head><body><h1>' + Html.esc(title) + '</h1><p>' +
            Html.esc(detail) + '</p></body></html>');
    log.debug("Leaving Launch.refuse().");
  }

  // WHICH PROTOCOL. The link's own `protocol` when it names one, which must
  // be one the application can be launched in; otherwise the one protocol
  // that is switched on, or the entry's `appLaunchProtocol` among several.
  // Nothing on is answered as off rather than as ambiguous, so the person
  // reads the reason that applies.
  /**
   * Chooses the protocol a launch starts, or says why it cannot.
   *
   * @param view - the application
   * @param asked - the link's `protocol`, or ''
   * @returns `{ protocol }` or `{ code, status, title, detail }`
   */
  chooseProtocol(view: Json, asked: string): Json {
    const { log } = this.deps.helpers;
    log.debug("Entering Launch.chooseProtocol(). asked=" + (asked || '-'));
    const possible = LaunchLinks.protocolsOf(view).map(function (row: Json) {
      return row.id;
    });
    if (asked) {
      if (!LaunchLinks.protocol(asked)) {
        log.debug("Leaving Launch.chooseProtocol(). Not a protocol.");
        return { code: 'STS-LAUNCH-0002', status: 400,
                 title: 'Not a protocol a sign-in can be started in',
                 detail: 'protocol="' + asked + '": a launch starts ' +
                   'saml2, saml11, wsfed or oidc.' };
      }
      if (possible.indexOf(asked) < 0) {
        log.debug("Leaving Launch.chooseProtocol(). Not declared for it.");
        return { code: 'STS-LAUNCH-0003', status: 404,
                 title: 'This application does not sign in that way',
                 detail: 'The application is not declared for ' +
                   LaunchLinks.protocol(asked).label + '.' };
      }
      log.debug("Leaving Launch.chooseProtocol(). As asked.");
      return { protocol: asked };
    }
    const on = possible.filter(function (id: string) {
      return LaunchLinks.enabled(view.identifier, id);
    });
    if (on.length === 1) {
      log.debug("Leaving Launch.chooseProtocol(). The one switched on.");
      return { protocol: on[0] };
    }
    // `appLaunchProtocol` is single-valued; a field may still arrive as a
    // list of one.
    const held = (view.fields || {}).appLaunchProtocol;
    const named = String((Array.isArray(held) ? held[0] : held) || '');
    if (on.length > 1 && named && on.indexOf(named) >= 0) {
      log.debug("Leaving Launch.chooseProtocol(). appLaunchProtocol.");
      return { protocol: named };
    }
    if (on.length > 1) {
      log.debug("Leaving Launch.chooseProtocol(). Several, none preferred.");
      return { code: 'STS-LAUNCH-0004', status: 409,
               title: 'Which protocol?',
               detail: 'Identity-provider-initiated sign-in is on for this ' +
                 'application in ' + on.join(', ') + '. Name one with ' +
                 '?protocol=, or set appLaunchProtocol on the application.' };
    }
    log.debug("Leaving Launch.chooseProtocol(). None switched on.");
    return { code: 'STS-LAUNCH-0005', status: 403,
             title: 'This application cannot be started from here',
             detail: 'Identity-provider-initiated sign-in is off for this ' +
               'application. Start the sign-in at the application.' };
  }

  /**
   * Answers `GET /launch/{app}`.
   *
   * @param req - the request
   * @param res - the response
   */
  launch(req: Json, res: Json): void {
    const { applications, errorCodes, realms } = this.deps;
    const { baseUrlOf, log } = this.deps.helpers;
    log.debug("Entering Launch.launch().");
    const identifier = String(req.params.app || '');
    const view = identifier ? applications.get(identifier) : null;
    if (!view) {
      errorCodes.mark(res, 'STS-LAUNCH-0001');
      log.debug("Leaving Launch.launch(). No such application.");
      return this.refuse(res, 404, 'No such application',
        'There is no application "' + identifier + '" in this realm.');
    }
    const query = req.query || {};
    const chosen = this.chooseProtocol(view, String(query.protocol || ''));
    if (!chosen.protocol) {
      errorCodes.mark(res, chosen.code);
      log.debug("Leaving Launch.launch(). " + chosen.title);
      return this.refuse(res, chosen.status, chosen.title, chosen.detail);
    }
    const protocol = chosen.protocol;
    const row = LaunchLinks.protocol(protocol);
    if (!LaunchLinks.enabled(view.identifier, protocol)) {
      errorCodes.mark(res, 'STS-LAUNCH-0005');
      log.debug("Leaving Launch.launch(). Switched off.");
      return this.refuse(res, 403,
        'This application cannot be started from here',
        'Identity-provider-initiated sign-in is off for this application ' +
        'in ' + row.label + ' (' + row.attribute + ', else ' + row.setting +
        '). Start the sign-in at the application.');
    }
    const missing = LaunchLinks.missingOf(view, protocol);
    if (missing.length) {
      errorCodes.mark(res, 'STS-LAUNCH-0006');
      log.debug("Leaving Launch.launch(). Missing " + missing.join(', '));
      return this.refuse(res, 409, 'There is nowhere to send you',
        'The application has no registered ' + missing.join(', ') +
        ', so a ' + row.label + ' sign-in started here has nowhere to go.');
    }
    const base = baseUrlOf(req);
    const target = String(query.target || '');
    if (protocol !== 'oidc') {
      const there = LaunchLinks.endpointUrl(base, view, protocol, target);
      log.info('launch: "' + view.identifier + '" in ' + row.label +
               ', to ' + there + '.');
      log.debug("Leaving Launch.launch(). To the " + row.label +
                " endpoint.");
      return res.set('Cache-Control', 'no-store').redirect(303, there);
    }
    return this.launchOidc(req, res, view, base, target, realms);
  }

  // OPENID CONNECT CORE SECTION 4. Signed in first, through the sign-in
  // every protocol uses — so the session, its risk assessment and CAEP's
  // session-established are what an SP-initiated sign-in gets — then the
  // launch recorded on the session and the browser sent to the client.
  /**
   * The OpenID Connect half of a launch.
   *
   * @param req - the request
   * @param res - the response
   * @param view - the client's entry
   * @param base - this realm's base URL
   * @param target - where to land afterwards, or ''
   * @param realmsModule - the realms module
   */
  launchOidc(req: Json, res: Json, view: Json, base: string, target: string,
             realmsModule: Json): void {
    const { applications, authn, config, errorCodes } = this.deps;
    const { log, nowSec } = this.deps.helpers;
    log.debug("Entering Launch.launchOidc().");
    const clientId = String(view.identifier);
    const session = authn.sessionOf(req);
    if (!session) {
      const url = String(req.originalUrl || req.url || '');
      const at = url.indexOf('?');
      const where = authn.beginAuthentication({
        returnTo: req.path + (at < 0 ? '' : url.slice(at)),
        application: clientId,
        protocol: 'OpenID Connect',
        details: [
          { label: 'Application', value: view.name || clientId,
            note: 'started here — OpenID Connect Core section 4; the ' +
                  'application continues the sign-in.' }
        ]
      });
      log.debug("Leaving Launch.launchOidc(). To the sign-in screen.");
      return res.set('Cache-Control', 'no-store').redirect(303, where);
    }
    let issuer = '';
    try {
      issuer = this.deps.issuerFor(base);
    } catch (e) {
      log.debug("Caught in Launch.launchOidc(): " + ((e && e.message) || e));
      // No issuer, no section 4 link: refused below.
      issuer = '';
    }
    const realm = realmsModule.current();
    const url = LaunchLinks.thirdPartyLoginUrl(
      applications.initiateLoginUriOf(view), {
        issuer: issuer,
        username: String((session.user || {}).username || ''),
        tenant: String(realm.id || ''),
        domain: String(realmsModule.domainOf(realm) || ''),
        target: target || applications.homePageOf(view)
      });
    if (!url) {
      errorCodes.mark(res, 'STS-LAUNCH-0006');
      log.debug("Leaving Launch.launchOidc(). No section 4 address.");
      return this.refuse(res, 409, 'There is nowhere to send you',
        'The client has no usable initiate_login_uri.');
    }
    LaunchLinks.noteLaunch(session, clientId, nowSec());
    authn.noteSessionChanged(session);
    log.info('launch: "' + clientId + '" in OpenID Connect for "' +
             String((session.user || {}).username || '') + '"; the ' +
             'authorization request is answered for ' +
             config.value('oauth2.launchWindowS') + ' s.');
    log.debug("Leaving Launch.launchOidc(). To initiate_login_uri.");
    return res.set('Cache-Control', 'no-store').redirect(303, url);
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2), as every converted
// route module's is: `common/protocol_stack.ts` builds one and installs it,
// and the facades below forward to it.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Launch>(
  'launch/launch',
  () => new Launch(Launch.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a route module always did.
slot.buildNowUnlessDeferred();

/**
 * The identity-provider-initiated sign-in door, `GET /launch/{app}`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  Launch: Launch,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: Launch): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin()
};
