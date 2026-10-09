// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: home.ts
//
// ---------------------------------------------------------------------------
// GET / — the front door.
//
// Until 2026-08-24 the root of this service was an unrouted path, so the first
// thing anybody who typed the host and port into a browser saw was Express's
// `Cannot GET /`. That is a true statement about the router and a useless one
// about the service: this port answers well over a hundred endpoints across
// sixteen protocol families, and none of them is discoverable from the one URL
// a person types first.
//
// So this page exists, and it is deliberately SHORT. It carries the logo of the
// project this service was extracted from, says what this service is called,
// and offers five links — the repository, its issues, the documentation site,
// and the two surfaces on THIS instance that a person rather than a client
// goes to: the admin console and the user portal. It is a signpost, not a
// second documentation site.
//
// **IT DOES NOT LIST ENDPOINTS, AND THAT IS THE ONE RULE TO KEEP.** `GET
// /admin/sts-metadata` builds that list by walking the running Express router,
// so it cannot go stale by omission, and this repository's own
// `tests/vendored/sts_metadata.js` fails on drift in either direction. A
// hand-written list of highlights here would be a second, unchecked copy of it
// — wrong within a month, on the page most likely to be read first and least
// likely to be re-read. The documentation site makes the same argument in
// `docs/endpoints.md` and this page holds to it: LINK to the thing that
// generates the list.
//
// ---------------------------------------------------------------------------
// TWO ROUTES, AND THE SECOND ONE IS A PNG.
//
// `/logo.png` serves `assets/logo.png` from this directory. It is a
// route rather than `express.static()` because one file does not need a static
// middleware, and a middleware mounted at the root would sit in front of every
// protocol module's routes for the rest of the process's life — see rule 1 in
// the repository's CLAUDE.md: `common/protocol_stack.ts` registers each
// module's routes in order (#50, R1), and middleware applies to everything
// registered after it.
//
// The file is read ONCE, here, at require time. A per-request read would be a
// disk hit for a decoration; the file cannot change while the process runs.
//
// **A failure to read it is recorded, not thrown.** A `require` that throws
// takes the whole service down — the same reason the KDC, the directory, the
// SPIFFE listeners and the embedded debugger start their sockets from
// `listen()` rather than at require time — and a missing image is the least
// important thing that could go wrong here. With no image the page is drawn
// without one and `/logo.png` answers 404 with a sentence saying why, which is
// also what keeps that route honest for the link check in
// `tests/vendored/sts_metadata.js`: it fails on Express's own `Cannot GET`, so
// an endpoint answering for itself is the distinction it is looking for.
//
// ---------------------------------------------------------------------------
// THE LOGO IS THIS PROJECT'S OWN (2026-10-01, rcbj): the one README.md
// shows, `docs/logo.png`, copied byte for byte (906 x 269, opaque, 22 kB;
// drawn at half that, so it is sharp on a 2x display). It replaced the
// parent project's debugger artwork, which was white lettering drawn for a
// black band. This one is dark lettering on an off-white ground, so the
// band takes the image's own background colour (#fbfaf8) and the logo sits
// on it with no edge. Copy `docs/logo.png` over it again if the README's
// logo changes.
//
// ---------------------------------------------------------------------------
// NO SCRIPT, NO EXTERNAL RESOURCE.
//
// `app.js` sets `script-src 'none'` service-wide and this page needs no
// exception: it has no behaviour. Its one `<style>` block is covered by the
// `style-src 'unsafe-inline'` several other pages here already rely on, and the
// image is same-origin, which is what `img-src 'self' data:` already allows.
// A page that reached out to a CDN for a font would need the policy widened
// for a decoration, so it does not.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `Home` takes node's `fs` and `path`, the express app, helpers, the
// realm registry, `config`, `mode`, `version` and the error-code registry
// through its constructor, and its three routes are registered by
// `registerRoutes(app)`. Since #50's R2 the composition root builds the
// instance (`Home.defaultDeps()`) and installs it; the module's old export
// names are FACADES that forward to it, for the JavaScript callers, and a
// process without the root builds a default when this module finishes loading.
// The instance registers NOTHING (#50, R1): the module exports its
// `registerRoutes(app)` beside the class, and `common/protocol_stack.ts` calls
// it at the point in the route order where requiring this module used to
// register the routes (rule 1). The logo is still read at require time, at
// module level, for the reason given above.
// ---------------------------------------------------------------------------


import fs = require('fs');

import path = require('path');

import app = require('../common/app');

import helpers = require('../common/helpers');

// The trust realm registry, for GET /realms below.
import realms = require('../common/realms');

// For `realms.enabled`, which GET /realms below reads per request rather than
// capturing here, so that /admin/config and the management API reach it while
// the process runs. Whether the console asks the reader to sign in is no
// longer a setting: `admin.authRequired` went on 2026-09-06 and `mode` below
// answers it.
import config = require('../common/config');

// The mode. A LEAF (rule 3): registers nothing, requires only `config`.
import mode = require('../common/mode');

// THE VERSION, M.N.O. A LEAF (rule 3): registers nothing and requires nothing
// from this repository.
//
// **IT USED TO BE `require('../package.json').version` AND THAT WAS A DIFFERENT
// NUMBER.** The manifest holds M.N.0 — a valid semver with the patch pinned to
// zero, because npm insists on three parts and the third one there is a
// placeholder. The build number is the third part of the REAL version and the
// manifest has nowhere to put it, so this page reported `0.9.0` for every build
// ever made and told a reader nothing about which one they were looking at.
// `load()` reads the record the image build stamped. See common/version.js.
import version = require('../common/version');

// The registry of failure codes, a LEAF — see common/error_codes.js.
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');

// THE LANGUAGE (#539). A LIBRARY (rule 3): it requires `i18n`,
// `locale_policy`, `helpers` and `config`, and no route module, so requiring
// it from here moves no route.
import PageLocale = require('../common/page_locale');

type Translator = ReturnType<typeof PageLocale.forPage>;

const APP_VERSION = version.load();

const VERSION = APP_VERSION.version;

const BUILD_INFO = version.buildInfo(APP_VERSION);

// ---------------------------------------------------------------------------
// THE FIVE LINKS.
//
// Three of them name the repository this service lives in, and they are
// written out rather than derived from `package.json` — that manifest carries
// no `repository` member, and adding one so that this page could compute three
// URLs from it would be the kind of indirection that makes a reader open two
// files to answer "where does this link go".
//
// The documentation URL is GitHub Pages' own arrangement of the same
// repository: `docs/` is built and deployed by `.github/workflows/pages.yml`,
// and `docs/_config.yml` sets `baseurl: /iya-sts`, so the site is served under
// the repository name. Change the repository and all three of these change
// together — and so does that baseurl.
// ---------------------------------------------------------------------------
const REPO_URL = 'https://github.com/rcbj/iya-sts';

const ISSUES_URL = REPO_URL + '/issues';

const DOCS_URL = 'https://rcbj.github.io/iya-sts/';

// Relative on purpose. This service is reached as localhost, as `sts` on a
// compose network and through a published port, and `baseUrlOf()` exists
// because documents that carry absolute URLs have to follow the request. A
// same-origin link does not have to know any of that.
const CONSOLE_PATH = '/admin';

// THE FIFTH LINK, AND IT IS THE SECOND SAME-ORIGIN ONE (2026-09-10). Relative
// for the reason above rather than for a reason of its own.
//
// It is here because the four links above answer *what is this service* and
// none of them answered *and what is it for ME*. The user portal has existed
// since 2026-09-06 and the only ways to reach it were to already know the
// path or to be redirected there by an activation link somebody sent you —
// so the one surface in this service built for a person rather than for an
// operator or a client was the one surface with no door on the front page.
//
// It lists none of the portal's pages, and that is the same rule this page
// keeps about endpoints one paragraph up: `portal/portal.ts`'s `NAV` is the
// page list, `sts_metadata.js` reports it, and a set of highlights here would
// be a second copy that goes stale the first time a page is added there.
const PORTAL_PATH = '/portal';

const LOGO_PATH = path.join(__dirname, 'assets', 'logo.png');

const LOGO_ROUTE = '/logo.png';

// Read once, at require time. See the header for why a failure here is recorded
// rather than thrown.
let logoBytes = null;

try {
  logoBytes = fs.readFileSync(LOGO_PATH);
  helpers.log.debug('home: the logo is ' + logoBytes.length + ' bytes.');
} catch (e) {
  // Swallowed deliberately, and this is the whole reason: the front page is a
  // signpost and the image on it is decoration. Losing it must not stop a
  // service that speaks sixteen protocols from starting, so it is reported at
  // error level — where it is visible — and the page is drawn without it.
  logoBytes = null;
  helpers.log.debug('Caught in home.ts at load: ' + ((e && e.message) || e));
  helpers.log.error(errorCodes.tag('STS-CORE-0037') +
                    'home: the logo could not be read from ' + LOGO_PATH +
                    ': ' + e.message + '. The front page will be drawn ' +
                    'without it and ' + LOGO_ROUTE + ' will answer 404.');
}

interface HomeDeps {
  fs: typeof fs;
  path: typeof path;
  app: typeof app;
  helpers: typeof helpers;
  realms: typeof realms;
  config: typeof config;
  mode: typeof mode;
  version: typeof version;
  errorCodes: typeof errorCodes;
}

/**
 * The front door: `GET /`, the realm directory at `GET /realms`, and the logo
 * the front page draws.
 *
 * It lists no endpoints; `/admin/sts-metadata` does that from the router.
 */
class Home {
  /**
   * Builds the front door from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: HomeDeps) {
    deps.helpers.log.debug("Entering Home.constructor().");
    deps.helpers.log.debug("Leaving Home.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the modules this class was built from before the composition root
   * (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): HomeDeps {
    helpers.log.debug("Entering Home.defaultDeps().");
    helpers.log.debug("Leaving Home.defaultDeps().");
    return {
      fs: fs,
      path: path,
      app: app,
      helpers: helpers,
      realms: realms,
      config: config,
      mode: mode,
      version: version,
      errorCodes: errorCodes
    };
  }

  // The front page, the realm directory and the logo, in the order they were
  // always registered.
  /**
   * Registers `GET /`, `GET /realms` and the logo route, in the order they were
   * always registered.
   *
   * Called by `common/protocol_stack.ts`; requiring this module registers
   * nothing.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: typeof import('../common/app')): void {
    const { config, errorCodes, realms } = this.deps;
    const { baseUrlOf, log } = this.deps.helpers;
    const self = this;
    log.debug("Entering Home.registerRoutes().");
    app.get('/', function (req, res) {
      log.debug('Entering the front page endpoint.');
      res.type('html').send(self.homePage());
      log.debug('Leaving the front page endpoint.');
    });

    // -------------------------------------------------------------------------
    // GET /realms — THE TRUST REALM DIRECTORY, AND IT IS DELIBERATELY UNGATED.
    //
    // A trust realm is a whole logical copy of this service reached under a
    // path prefix (see common/realms.js), and a client that has been told to
    // use one has no way to find out what the prefix is — the prefix segment is
    // configurable and the realm ids are whatever an operator defined. So this
    // answers it, in JSON, to anybody who can reach this port.
    //
    // It is on the FRONT DOOR module rather than in the console because of who
    // needs it: the console already knows, and the thing that does not is the
    // client being pointed at a realm. Gating it would make the one document
    // that says where the endpoints are the one document a client cannot fetch,
    // which is the shape of every RFC 8414 discovery document here and for the
    // same reason.
    //
    // WHAT IT DOES NOT CARRY: a realm's overrides. Those are the realm's
    // configuration — what it is set up to do differently — and that is the
    // console and the management API's business rather than a discovery
    // document's. What is here is the id, the name, the description an operator
    // wrote and the base URL, which is everything needed to construct a URL in
    // that realm and nothing else.
    // -------------------------------------------------------------------------
    app.get('/realms', function (req, res) {
      log.debug('Entering the realm directory endpoint.');
      // The base URL WITHOUT the current realm's prefix, so that a request that
      // arrived inside realm `acme` still lists every realm from the root
      // rather than listing them all as though they hung under `acme`.
      // baseUrlOf() adds the ambient prefix by design — this is the one caller
      // that does not want it, and it says so here rather than working around
      // it elsewhere.
      const root = baseUrlOf(req).slice(0, baseUrlOf(req).length -
                                           realms.currentPrefix().length);
      const body = {
        // What the segment in front of a realm id currently is, because a
        // client that wants to build a URL for a realm it has NOT been told
        // about — a new one, in a test — needs the rule and not just the
        // answers.
        pathSegment: realms.pathSegment(),
        // TWO FLAGS RATHER THAN ONE, because they answer different questions
        // and a single `enabled` was ambiguous in exactly the case that
        // matters. `enabled` is the `realms.enabled` SETTING — whether an
        // operator has switched the feature off. `active` is whether any prefix
        // actually answers, which is false when the setting is on and nobody
        // has defined a realm. A client told "enabled: false" when the truth
        // was "nobody has defined one yet" would look for the wrong problem.
        enabled: config.value('realms.enabled'),
        active: realms.active(),
        current: realms.currentId(),
        realms: realms.list().map(function (realm) {
          return {
            id: realm.id,
            name: realm.name,
            description: realm.description,
            builtin: !!realm.builtin,
            pathPrefix: realms.prefixOf(realm),
            baseUrl: root + realms.prefixOf(realm),
            // The EST label form (#251): the one address an RFC 7030 client
            // that takes a host, a port and ONE label can be given for this
            // realm. Null for the default realm, which has no other form.
            estLabelUrl: realms.estLabelPath(realm)
              ? root + realms.estLabelPath(realm) : null
          };
        }),
        // Which protocol families are realm-aware and by what discriminator. It
        // is here rather than only on the console page because the honest
        // answer for four of the sixteen families is "not by path", and a
        // client driving Kerberos or LDAP against a realm needs to be told that
        // by the service rather than by a README it did not read.
        support: realms.realmSupport()
      };
      res.set('Cache-Control', 'no-store').type('application/json')
         .send(JSON.stringify(body, null, 2));
      log.debug('Leaving the realm directory endpoint. ' +
                body.realms.length + ' realm(s).');
    });

    app.get(LOGO_ROUTE, function (req, res) {
      log.debug('Entering the logo endpoint.');
      if (!logoBytes) {
        // 404 in this service's own words rather than Express's. The difference
        // is load-bearing for the link check in the parent project's
        // tests/vendored/sts_metadata.js, which fails on `Cannot GET` and
        // passes on an endpoint answering for itself — and it is the more
        // useful answer anyway.
        errorCodes.mark(res, 'STS-CORE-0038');
        res.status(404).type('text/plain')
          .send('The logo could not be read from disk at startup. The ' +
                'service log says why; nothing else about this service is ' +
                'affected.\n');
        log.debug('Leaving the logo endpoint. There is no logo.');
        return;
      }
      // An hour. The bytes cannot change while this process runs, and this is a
      // mock whose whole traffic is one browser: a longer max-age would only
      // make a rebuilt image's new logo linger.
      res.set('Cache-Control', 'public, max-age=3600');
      res.type('png').send(logoBytes);
      log.debug('Leaving the logo endpoint.');
    });
    log.debug("Leaving Home.registerRoutes().");
  }

  // ---------------------------------------------------------------------------
  // Rendering. One card, in the same material as `/tls` and the console, so
  // that a reader who follows a link from here does not arrive somewhere that
  // looks like a different service.
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // ONE COPY OF WHAT SIGNING IN HERE MEANS.
  //
  // Both same-origin links below send a reader to a sign-in screen, and what
  // that screen actually CHECKS is a property of the mode rather than of either
  // surface — so it is written once here rather than twice down there, where
  // the two copies would disagree the first time somebody corrected one of
  // them.
  //
  // **IT USED TO BE A CLAUSE ON THE CONSOLE'S ROW READING "it asks you to sign
  // in, and nothing else here does".** That was true when it was written and
  // had stopped being true on 2026-09-06, when the user portal arrived; putting
  // a link to the portal on the same page is what made it wrong in a place a
  // reader could see. It also said "no password checked" unconditionally, which
  // is a DEVELOPMENT-mode fact — `mode.verifiesCredentials()` is what decides
  // it — so the sentence was two small lies on one line in a product
  // deployment.
  //
  // Read per request rather than captured at require time, for the reason this
  // page reads every other conditional fact about the running service that way:
  // it is a front door, and it is drawn from what is true now.
  // ---------------------------------------------------------------------------
  // Translated (#539): the sentence is drawn in the page's language, so it
  // takes the page's translator and answers HTML.
  private signInMeans(t: Translator) {
    const { mode } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Home.signInMeans().");
    log.debug("Leaving Home.signInMeans().");
    return mode.verifiesCredentials()
      ? t.html('home.signInProduct')
      : t.html('home.signInDevelopment');
  }

  // `label` and `note` are HTML since #539: each is a translated message from
  // `t.html()`, which escapes its own parameters, so escaping them again here
  // would draw an apostrophe as `&#39;`.
  private linkRow(href, label, external, note) {
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Home.linkRow().");
    log.debug("Leaving Home.linkRow().");
    return '<li><a href="' + xmlEscape(href) + '"' +
      (external ? ' target="_blank" rel="noopener noreferrer"' : '') + '>' +
      label + '</a><span class="note">' + note + '</span></li>';
  }

  private homePage() {
    const { mode } = this.deps;
    const { log, xmlEscape } = this.deps.helpers;
    const { realms } = this.deps;
    log.debug('Entering Home.homePage().');
    // THE LANGUAGE (#539). The front door is drawn for no application, and it
    // reads no session — it would have to require `authn` for one, and the
    // person's own choice already reaches it through the chooser's cookie.
    const t = PageLocale.forPage({});
    const logo = logoBytes
      ? '<div class="hero"><img src="' + LOGO_ROUTE + '" width="906" ' +
        'height="269" alt="' + xmlEscape(t.text('home.logoAlt')) + '"></div>'
      : '';
    const html = '<!DOCTYPE html>\n<html' + PageLocale.htmlAttributes(t) +
      '><head><meta ' +
      'charset="utf-8"><meta name="viewport" content="width=device-width, ' +
      'initial-scale=1"><title>IYA STS</title><style>' +
      'body{font-family:system-ui,-apple-system,"Segoe ' +
      'UI",Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem ' +
      '1rem;color:#222;line-height:1.45}.card{background:#fff;border:1px ' +
      'solid #d5d5dd;border-radius:10px;padding:0 0 ' +
      '26px;max-width:44rem;margin:0 auto;overflow:hidden;box-shadow:0 6px ' +
      '24px rgba(0,0,0,.08)}' +
      // The band is the logo's own background colour. See the header.
      '.hero{background:#fbfaf8;padding:22px 24px;text-align:center;' +
      'border-bottom:1px solid #ecebe7}' +
      '.hero img{width:100%;max-width:453px;height:auto;display:inline-block}' +
      '.body{padding:22px 28px 0}' +
      'h1{font-size:1.5em;margin:0 0 2px;color:#12107c;letter-spacing:.01em}' +
      'p.sub{color:#666;font-size:.88em;margin:0 0 4px}' +
      'p.ver{color:#8a8a99;font-size:.76em;margin:0 0 16px}' +
      '.warn{background:#fff8e1;border:1px solid #ffe082;padding:9px 12px;' +
      'border-radius:5px;font-size:.82em;margin:0 0 18px}' +
      'ul{list-style:none;margin:0;padding:0}' +
      'li{border-top:1px solid #eee;padding:11px 2px}' +
      'li:first-child{border-top:0}' +
      'a{color:#12107c;font-weight:600;text-decoration:none}' +
      'a:hover{text-decoration:underline}' +
      '.note{display:block;color:#666;font-size:.8em;font-weight:400;' +
      'margin-top:2px}' +
      'form.language-chooser{float:right;font-size:.78em;margin:0 0 6px 8px}' +
      'form.language-chooser label{margin-right:4px}' +
      '</style></head><body><div class="card">' + logo + '<div class="body">' +
      // A GET always draws this page, so the chooser comes back to it.
      PageLocale.chooser(t, realms.currentPrefix(),
        PageLocale.herePath(realms.currentPrefix() + '/')) +
      '<h1>IYA STS</h1>' +
      '<p class="sub">' + t.html('home.sub') + '</p>' +
      // THE VERSION, WITH ITS PROVENANCE IN THE TOOLTIP. The number is what a
      // person quotes in a bug report; the build instant, the commit and
      // whether this is a stamped artifact or a checkout are what somebody
      // needs when two instances of the same M.N do different things. A title
      // attribute rather than a second line because this is the front door and
      // the version is not what anybody came for.
      '<p class="ver" title="' + xmlEscape(BUILD_INFO) + '">' +
      t.html('home.version', { version: VERSION }) + '</p>' +
      '<div class="warn">' + t.html('home.warn') + '</div><ul>' +
      this.linkRow(REPO_URL, t.html('home.repoLabel'), true,
                   t.html('home.repoNote')) +
      this.linkRow(ISSUES_URL, t.html('home.issuesLabel'), true,
                   t.html('home.issuesNote')) +
      this.linkRow(DOCS_URL, t.html('home.docsLabel'), true,
                   t.html('home.docsNote')) +
      // The note is still assembled from sentences, as it was: which ones
      // depend on the mode, and each is a message of its own.
      this.linkRow(CONSOLE_PATH, t.html('home.consoleLabel'), false,
                   t.html('home.consoleNote') + ' ' +
                   (mode.gatesConsole()
                     ? this.signInMeans(t) + ' ' +
                       t.html('home.consoleRoles')
                     : t.html('home.consoleOpen')) +
                   ' ' + t.html('home.consoleMetadata')) +
      this.linkRow(PORTAL_PATH, t.html('home.portalLabel'), false,
                   t.html('home.portalNote') + ' ' + this.signInMeans(t) +
                   ' ' + t.html('home.portalNoRole')) +
      '</ul></div></div></body></html>\n';
    log.debug('Leaving Home.homePage().');
    return html;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<Home>(
  'home/home',
  () => new Home(Home.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Nothing else is exported. This module is required for its
// `registerRoutes(app)` — two routes, which the composition root registers —
// the way every other converted route module here is, and the three URLs above
// are this page's business alone. See rule 1 in the repository's CLAUDE.md.
// The class is exported for the composition root, as the #50 section says.
// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The front door of the service: the page at `GET /` and its logo.
 *
 * A signpost to the repository, the documentation, the console and the portal,
 * deliberately short and never a list of endpoints.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  Home: Home,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: Home): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin()
};
