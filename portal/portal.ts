// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal.ts
//
// ---------------------------------------------------------------------------
// THE USER PORTAL: THE PAGES THAT BELONG TO THE PERSON LOOKING AT THEM
// (2026-09-06) — A STATIC APPLICATION SINCE #568 (2026-10-12).
//
// Every browser-facing surface here was for somebody else until the portal:
// the sign-in screen is a step in another protocol's flow, the consent screen
// asks one question and leaves, `/admin` is an operator's. The portal is
// where a person sees what this identity provider knows about THEM and
// changes how they authenticate — `portal/CLAUDE.md` has every page.
//
// **SINCE #568 IT IS DRAWN IN THE BROWSER**, on the admin console's pattern
// (#446): `/portal` and every path under it answer ONE document, the shell,
// which loads `/portal/portal.js` (`web_portal_runtime.ts` with every page's
// renderer) and `/portal/portal.css`. The runtime signs in as the PUBLIC
// client `sts-user-portal` — PKCE, tokens in memory, every one DPoP-bound to
// a key the browser cannot export — and draws every page from an answer of
// `/account-api` (`account-api/account_api.ts`) and sends every form there.
// rcbj's four decisions on #568 are that pattern (reversing #444's D9 for
// the portal too), that API, the pages nobody is signed in to drawn the same
// way, and the console-session adoption (2026-09-30) dropped.
//
// SO WHAT IS LEFT HERE IS SMALL, and each piece is argued where it is:
//
//   * THE SHELL, ungated: it carries nothing, and every fact the portal shows
//     arrives from `/account-api` behind that API's own token check, which is
//     the only gate there is. A method other than GET is answered 404.
//   * THE REALM CHOOSER for a bare `/portal` on a service with realms, before
//     anything sends the browser to sign in (`common/realm_chooser.ts`).
//   * THE SHARED SIGNALS RECEIVE ENDPOINT, `/portal/signals/receive`, which is
//     a protocol endpoint and not a page.
//   * THE DIRECTORY SLOT, filled by `ldap/ldap_server.js`, through which the
//     Overview's view reads the person's own entry (`personEntry()`).
//
// **THE RULE THAT MATTERS MORE THAN THE REST PUT TOGETHER IS UNCHANGED AND
// HAS MOVED**: no operation takes a username, an id or a DN naming whose
// account it acts on. It is held at `/account-api`'s gate now, where the
// person is the access token's subject (OWASP A01).
//
// A ROUTE MODULE (rule 1): `common/protocol_stack.ts` registers it at 8a,
// after `authn` and before `oauth2`.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import authn = require('../authn/authn');
import oidcRp = require('../common/oidc_rp');
import realmChooser = require('../common/realm_chooser');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import signals = require('../ssf/ssf_receivers');
import listenerMap = require('../common/listener_map');
import ShellDocument = require('../common/shell_document');
import kit = require('./web_portal_kit');

type Json = any;

/**
 * The portal's base path.
 */
const BASE = kit.BASE;
/**
 * The activation link's path, which `common/mail_uses.ts` and the console
 * build links to.
 */
const ACTIVATE = BASE + '/activate';
// THE PAGES DRAWN FOR NOBODY: a link a person was sent, or the form that
// sends one. The realm chooser is never asked of them — the link names its
// realm in its own prefix — and the bundle draws them without signing in.
const FOR_NOBODY = [ACTIVATE, BASE + '/reset-password',
                    BASE + '/forgot-password', BASE + '/verify-email',
                    BASE + '/callback'];

interface DirectoryHooks {
  personEntry(username: string): any;
}

interface PortalDeps {
  app: typeof app;
  log: typeof helpers.log;
  config: typeof config;
  authn: typeof authn;
  oidcRp: typeof oidcRp;
  realmChooser: typeof realmChooser;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  signals: typeof signals;
}

/**
 * The user portal's server half: the shell, its script and stylesheet, the
 * Shared Signals receive endpoint and the directory slot.
 */
class Portal {
  /**
   * The portal's base path.
   */
  static readonly BASE = BASE;
  /**
   * The activation link's path.
   */
  static readonly ACTIVATE = ACTIVATE;

  private directory: DirectoryHooks | null = null;
  private script: Json = null;

  /**
   * Builds the portal over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: PortalDeps) {
    deps.log.debug("Entering Portal.constructor().");
    deps.log.debug("Leaving Portal.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalDeps {
    helpers.log.debug("Entering Portal.defaultDeps().");
    helpers.log.debug("Leaving Portal.defaultDeps().");
    return { app: app, log: helpers.log, config: config, authn: authn,
             oidcRp: oidcRp, realmChooser: realmChooser, realms: realms,
             errorCodes: errorCodes, signals: signals };
  }

  // ===========================================================================
  // THE DIRECTORY, THROUGH AN INVERTED HOOK (2026-09-11). `ldap_server.js`
  // fills it: a require of that JavaScript module from here would register
  // every `/ldap` route and the eight `/admin/ldap/*` pages at 8a. One
  // function, validated whole. A process without it is a smaller Overview —
  // the session's facts, said on the page — rather than a broken one.
  // ===========================================================================
  /**
   * Fills the directory slot; something without `personEntry()` is refused
   * whole.
   *
   * @param hooks - the directory's functions
   * @returns whether they were taken
   */
  setDirectory(hooks: Json): boolean {
    const { errorCodes, log } = this.deps;
    log.debug('Entering Portal.setDirectory().');
    if (!hooks || typeof hooks.personEntry !== 'function') {
      log.error(errorCodes.tag('STS-PORTAL-0014') +
                'portal: setDirectory() was given something without ' +
                'personEntry(), so it was refused whole. The Overview will ' +
                'go on drawing the facts the session carries and will say ' +
                'that it is doing so.');
      log.debug('Leaving Portal.setDirectory(). Refused.');
      return false;
    }
    this.directory = hooks;
    log.debug('Leaving Portal.setDirectory().');
    return true;
  }

  // THE SIGNED-IN PERSON'S OWN ENTRY. The name a caller passes is the
  // account API caller's — the token's subject — and never a request's:
  // this is the one function in the portal that reads a directory entry.
  /**
   * The person's directory entry, or null where there is no directory or no
   * entry, or the read failed.
   *
   * @param username - the signed-in person
   * @returns the entry, or null
   */
  personEntry(username: string): Json {
    const { errorCodes, log } = this.deps;
    log.debug('Entering Portal.personEntry().');
    if (!this.directory || !username) {
      log.debug('Leaving Portal.personEntry(). No directory, or nobody.');
      return null;
    }
    let found = null;
    try {
      found = this.directory.personEntry(String(username));
    } catch (e) {
      // NOT rethrown: an account page that fails because the store was
      // mid-write is worse than one that reports what the session knows.
      log.error(errorCodes.tag('STS-PORTAL-0015') +
                'portal: reading the directory entry for ' + username +
                ' threw, so the Overview is drawing what the session ' +
                'carries: ' + ((e && e.message) || e));
      found = null;
    }
    log.debug('Leaving Portal.personEntry(). ' + (found ? 'Found.' : 'None.'));
    return found || null;
  }

  // ---------------------------------------------------------------------------
  // THE SCRIPT. Built by `build-typescript.sh` beside this module, inside an
  // image build only, minified, and precompressed (brotli and gzip) as the
  // console's is, read once. A tree that was never built has none, and the
  // shell then loads a script that says so.
  // ---------------------------------------------------------------------------
  /**
   * The bundle and its precompressed forms.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  bundle(): Json {
    const { log } = this.deps;
    log.debug("Entering Portal.bundle().");
    if (!this.script) {
      // `portal-spa.js` and not `portal.js`, which is this module compiled.
      this.script = ShellDocument.readFile(__dirname, 'portal-spa.js',
        'document.body.textContent = "This service has no portal script ' +
        '(portal/portal-spa.js): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving Portal.bundle().");
    return this.script;
  }

  // WHERE THE PORTAL'S AUTHORIZATION SERVER AND SIGN-OUT ARE, when they are
  // not on the portal's own listener (#472) — the console's
  // `consoleServersElsewhere()`. `/account-api` is the portal's application
  // (`common/hosted_applications.js`), so it is always beside it.
  /**
   * The bases of the authorization server, the sign-in service and the
   * management API when any is on another listener.
   *
   * @param req - the request for the shell
   * @returns `{ oauth, authn, api }`, each '' where it is here
   */
  serversElsewhere(req: Json): Json {
    const { log } = this.deps;
    log.debug("Entering Portal.serversElsewhere().");
    const out = { oauth: '', authn: '', api: '' };
    if (!listenerMap.isTrivial()) {
      const at = listenerMap.listenerOf(req);
      if (!listenerMap.admits(at, 'oauth-oidc')) {
        out.oauth = helpers.baseUrlOf(req, 'oauth-oidc');
      }
      // THE MANAGEMENT API (#607): what an owner administers what they own
      // through, called by the runtime with its second token.
      if (!listenerMap.admits(at, 'management-api')) {
        out.api = helpers.baseUrlOf(req, 'management-api');
      }
      if (!listenerMap.admits(at, 'authn')) {
        out.authn = helpers.baseUrlOf(req, 'authn');
      }
    }
    log.debug("Leaving Portal.serversElsewhere().");
    return out;
  }

  /**
   * The shell document.
   *
   * @param registered - the callback registration's answer: when it was
   *   refused, the shell says why instead of loading
   * @param elsewhere - `serversElsewhere()`'s answer
   * @returns the document
   */
  shellDocument(registered: Json, elsewhere: Json): string {
    const { log } = this.deps;
    log.debug("Entering Portal.shellDocument().");
    const refused = registered && registered.ok === false;
    const there = elsewhere || {};
    // ONE WRITER FOR EVERY STATIC SURFACE'S SHELL (#570): the bytes are
    // what this method drew by hand until then.
    const html = ShellDocument.document({
      title: 'Your account — IYA STS',
      attributes: [['data-sts-oauth', there.oauth || ''],
                   ['data-sts-api', there.api || ''],
                   ['data-sts-authn', there.authn || '']],
      viewport: 'width=device-width,initial-scale=1',
      stylesheets: [BASE + '/portal.css'],
      script: BASE + '/portal.js',
      open: '<div class="wrap"><div class="card"><h1>Your account</h1>',
      close: '</div></div>',
      refusal: refused
        ? '<div class="err">' + kit.esc(registered.why ||
            'The portal cannot sign in at this address.') + '</div>'
        : null,
      noscript: '<div class="err">This portal is a script that runs in ' +
        'your browser and draws every page from <code>/account-api</code>' +
        '; with scripts blocked there is nothing it can show.</div>',
      loading: '<p class="sub">Loading&hellip;</p>',
      esc: kit.esc
    });
    log.debug("Leaving Portal.shellDocument().");
    return html;
  }

  /**
   * The paths this module registers, and the pages the bundle draws, for
   * `sts_metadata.ts`.
   *
   * @returns the paths
   */
  paths(): string[] {
    const { log } = this.deps;
    log.debug("Entering Portal.paths().");
    log.debug("Leaving Portal.paths().");
    return [BASE, BASE + '/*', BASE + '/portal.js', BASE + '/portal.css',
            BASE + '/signals/receive'];
  }

  /**
   * Registers the portal's routes; `common/protocol_stack.ts` calls it at 8a.
   *
   * @param target - the shared express app
   * @returns nothing
   */
  registerRoutes(target: Json): void {
    const { log, authn, oidcRp, realmChooser, errorCodes,
            signals } = this.deps;
    const self = this;
    log.debug("Entering Portal.registerRoutes().");
    // -----------------------------------------------------------------------
    // THE RECEIVE ENDPOINT. Unauthenticated and not a person: what arrives
    // is a Security Event Token addressed to this portal, and what authorises
    // it is the bearer token on this portal's OWN stream. `accept()` checks
    // it in constant time, the audience and the signature, and records what
    // arrived either way. **DELIBERATELY NOT RATE LIMITED**: a limiter would
    // silently drop somebody's account-disabled notice under load.
    // -----------------------------------------------------------------------
    target.post(BASE + '/signals/receive', function (req: Json, res: Json) {
      log.debug('Entering POST ' + BASE + '/signals/receive.');
      const taken = signals.accept(signals.PORTAL, req);
      if (taken.status >= 400) {
        errorCodes.mark(res, errorCodes.codeOf(taken) ||
                             String(taken.errorCode || '') ||
                             'STS-PORTAL-0038');
      }
      res.status(taken.status).set('Cache-Control', 'no-store');
      if (taken.body) {
        res.type('application/json').send(JSON.stringify(taken.body, null, 2));
      } else {
        // 202 with an EMPTY body, which is what RFC 8935 section 2.3 says.
        res.end();
      }
      log.debug('Leaving POST ' + BASE + '/signals/receive. ' + taken.status);
    });
    target.get(BASE + '/portal.js', function (req: Json, res: Json) {
      log.debug("Entering the portal's script.");
      // Brotli, gzip or neither, by the request's Accept-Encoding, from the
      // build's precompressed files (`ShellDocument.sendFile()`, #570).
      ShellDocument.sendFile(req, res, self.bundle(),
                             'application/javascript');
      log.debug("Leaving the portal's script.");
    });
    target.get(BASE + '/portal.css', function (req: Json, res: Json) {
      log.debug("Entering the portal's stylesheet.");
      res.set('Cache-Control', 'no-cache').type('text/css').send(kit.STYLE);
      log.debug("Leaving the portal's stylesheet.");
    });
    // ONE HANDLER ON TWO PATHS, `/portal` itself and everything under it.
    const shell = function (req: Json, res: Json): void {
      log.debug("Entering the portal shell. " + req.method + " " + req.path);
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        errorCodes.mark(res, 'STS-PORTAL-0246');
        res.status(404).type('text/plain').set('Cache-Control', 'no-store')
           .send('The user portal is a static application: what it does is ' +
                 'done through /account-api, and nothing is posted here.');
        log.debug("Leaving the portal shell. Not a GET.");
        return;
      }
      // WHICH REALM FIRST (#32), for a portal page on a service with realms,
      // asked only of a browser signed in nowhere — one that holds a sign-on
      // session has answered it — and never of a link a person was sent.
      const path = String(req.path || '').replace(/\/+$/, '') || BASE;
      const linked = FOR_NOBODY.indexOf(path) >= 0;
      const choice = linked || authn.sessionOf(req) ? null
        : realmChooser.decide(req, 'portal');
      // The remembered realm, the same line the console's gate writes.
      realmChooser.writeCookie(res, choice);
      if (choice && choice.kind === 'redirect') {
        res.set('Cache-Control', 'no-store').redirect(303, choice.location);
        log.debug("Leaving the portal shell. To the chosen realm.");
        return;
      }
      if (choice && choice.kind === 'page') {
        if (choice.error) {
          errorCodes.mark(res, 'STS-PORTAL-0074');
        }
        res.status(choice.error ? 400 : 200).set('Cache-Control', 'no-store')
           .type('text/html')
           .send(realmChooser.page(req, 'portal', choice.error));
        log.debug("Leaving the portal shell. The realm chooser.");
        return;
      }
      // The callback the sign-in comes back to, registered on the portal's
      // client entry in the realm the request is under, as the console's is.
      const registered = oidcRp.ensureSurfaceCallback(req, 'portal');
      const elsewhere = self.serversElsewhere(req);
      // The policy through `app.contentSecurityPolicy()`, `no-store`, and the
      // document uncompressed, so `app.js`'s `send()` puts the realm's
      // prefix on its links as on every page (`ShellDocument.serve()`).
      ShellDocument.serve(app, req, res,
                          self.shellDocument(registered, elsewhere), {
        connect: ShellDocument.originsOf([elsewhere.oauth, elsewhere.api]),
        // A QR code is a server-drawn SVG in a `data:` image.
        csp: { 'img-src': "'self' data:" }
      });
      log.debug("Leaving the portal shell.");
    };
    // GET for the document, and the methods a form could send for the
    // refusal — named one by one, as the console's are, rather than
    // `app.all()`, which the router reports as every method.
    ['get', 'post', 'put', 'patch', 'delete'].forEach(function (method) {
      target[method](BASE, shell);
      target[method](BASE + '/*', shell);
    });
    log.debug("Leaving Portal.registerRoutes().");
  }
}

const slot = new InstanceSlot<Portal>(
  'portal/portal',
  () => new Portal(Portal.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The user portal's server half.
 * @namespace
 */
export = {
  // The portal's own routes, and then each page module's server routes —
  // `/portal/claim-sources/callback`, the one a foreign provider redirects a
  // browser to — registered before the shell answers everything under
  // `/portal`.
  registerRoutes: (target: any): void => {
    const claimSources = require('./portal_claim_sources');
    if (typeof claimSources.registerRoutes === 'function') {
      claimSources.registerRoutes(target);
    }
    slot.get().registerRoutes(target);
  },
  Portal: Portal,
  installInstance: (instance: Portal): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BASE: BASE,
  ACTIVATE: ACTIVATE,
  NAV: kit.NAV,
  // Filled by `ldap/ldap_server.js` — see setDirectory().
  setDirectory: slot.forward('setDirectory'),
  personEntry: slot.forward('personEntry'),
  paths: slot.forward('paths'),
  // The shell (#570: `tests/web_foundation.js` holds its bytes).
  shellDocument: slot.forward('shellDocument')
};
