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
// and offers six links — the repository, its issues, the documentation site,
// and the three surfaces on THIS instance that a person rather than a client
// goes to: the admin console, the user portal and reports. It is a signpost,
// not a second documentation site.
//
// **IT DOES NOT LIST ENDPOINTS, AND THAT IS THE ONE RULE TO KEEP.** `GET
// /admin/sts-metadata` builds that list by walking the running Express router,
// so it cannot go stale by omission, and this repository's own
// `tests/protocol/sts_metadata.js` fails on drift in either direction. A
// hand-written list of highlights here would be a second, unchecked copy of it
// — wrong within a month, on the page most likely to be read first and least
// likely to be re-read. The documentation site makes the same argument in
// `docs/endpoints.md` and this page holds to it: LINK to the thing that
// generates the list.
//
// ---------------------------------------------------------------------------
// THE IMAGE: `/logo.png`, A ROUTE OF ITS OWN.
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
// `tests/protocol/sts_metadata.js`: it fails on Express's own `Cannot GET`, so
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
// A STATIC SURFACE SINCE #579 (2026-10-12): THE FIRST OF #569'S PUBLIC PAGES.
//
// Until #579 this module drew the card itself, as HTML with no script — and
// that page needed no exception to `app.js`'s `script-src 'none'`. #569
// converts every human-facing page into a static application on the
// console's pattern, and the front door is the smallest, so it went first
// and proved #570's foundation (`common/CLAUDE.md` 3cl, the recipe):
//
//   * `GET /` answers the SHELL (`ShellDocument`), the same document for
//     every request but for its `data-sts-*` attributes: the language the
//     chooser picked, the locale policy's default, the build, the realm's
//     prefix, and the sign-in service's base where it is on another
//     listener (#472) — the chooser posts there.
//   * `GET /home.js` is the bundle `build-typescript.sh` built from
//     `web_home.ts` (on disk `home-spa.js`, never `home.js`, which is this
//     module compiled); `GET /home.css` the card's own rules over
//     `/web/card.css`.
//   * `GET /home-api` is the API's index and `GET /home-api/front` the one
//     page's VIEW, language-free: the name, the version and its build, the
//     two facts of the mode a sign-in sentence depends on, the image, and
//     the six links as ids and addresses — the console's, the portal's and
//     reports' on the listener that answers them (#472), relative where it
//     is this one. The browser draws it in its language from the `home`
//     catalogs (`web_home_front.ts`), the same messages the server-drawn
//     page used.
//
// SCRIPT IS REQUIRED (rcbj on #569): with script blocked the shell's
// `<noscript>` says what the page is, and links the documentation, since a
// front door that answers nothing at all is the state 2026-08-24 ended. The
// policy is the shell's: `script-src 'self'`, `style-src 'self'` (no inline
// style any more), `connect-src 'self'` plus the sign-in service's origin
// where it is elsewhere, `img-src 'self'` for the logo, and
// `frame-ancestors` re-added by `app.contentSecurityPolicy()` whatever is
// asked.
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
// it from here moves no route. Since #579 only for the shell's language
// attributes: the browser translates.
import PageLocale = require('../common/page_locale');

// THE SHELL AND THE BUNDLE (#570). A LIBRARY (rule 3): `helpers` and node's
// modules; it takes the express app as an argument and registers nothing.
import ShellDocument = require('../common/shell_document');

// WHICH LISTENER ANSWERS WHICH APPLICATION (#472). A LIBRARY that `helpers`
// already loads; the console's, the portal's and reports' links, and the
// chooser's sign-in service, are addressed where they are answered.
import listenerMap = require('../common/listener_map');

type Json = any;

const APP_VERSION = version.load();

const VERSION = APP_VERSION.version;

const BUILD_INFO = version.buildInfo(APP_VERSION);

// ---------------------------------------------------------------------------
// THE SIX LINKS.
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
// same-origin link does not have to know any of that. SINCE #472 the console
// may be on a listener of its own, and then — only then — the view carries
// its advertised base instead (`linkTo()`).
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

// THE SIXTH LINK (the reports application, #956). Relative for the reason
// above, and addressed with `linkTo()` for the same #472 reason as the
// console and the portal: the page and `/report-api` are one hosted
// application, so a listener that does not answer them would 404 a link
// that stayed on this one. It lists none of the report pages. The page
// list is the application's own, and a set of highlights here would be a
// second copy of it.
const REPORT_PATH = '/report';

const LOGO_PATH = path.join(__dirname, 'assets', 'logo.png');

const LOGO_ROUTE = '/logo.png';

// The logo's own size: drawn at half of it, so it is sharp on a 2x display.
const LOGO_WIDTH = 906;

const LOGO_HEIGHT = 269;

// ---------------------------------------------------------------------------
// THE STATIC SURFACE'S PATHS (#579). Each is EXACT or under `/home-api`, all
// of them the front door's application in `common/hosted_applications.js`
// and `local` in `common/cell_placement.ts`: the same answer in every cell.
//
// `/home.js` and `/home.css` are at the root rather than under a directory
// of their own because the front door owns no prefix — it is `/` — and a
// prefix made up for two files would be one more name for a reader to look
// up. The bundle's FILE is `home-spa.js`: `home.js` beside this module is
// this module compiled (`build-typescript.sh`, `bundle_surface`).
// ---------------------------------------------------------------------------
const API_BASE = '/home-api';

const FRONT_OPERATION = API_BASE + '/front';

const SCRIPT_ROUTE = '/home.js';

const STYLE_ROUTE = '/home.css';

const BUNDLE_FILE = 'home-spa.js';

// THE CARD'S OWN RULES, over `/web/card.css` (the sign-in card every public
// surface links): the server-drawn page's inline `<style>` until #579, which
// the shell's `style-src 'self'` no longer admits inline. What it overrides
// is the sign-in card's centring and width — the front door is a wider card
// at the top of the page — and the rest is the band, the version line, the
// warning and the link rows as they were drawn. The last two rules give a
// problem page (the runtime's own card) and the `<noscript>` notice their
// margins inside this card's zero padding.
const HOME_CSS =
  'body{display:block;min-height:0;padding:2rem 1rem;line-height:1.45}' +
  '.card{width:auto;padding:0 0 26px;max-width:44rem;margin:0 auto;' +
  'overflow:hidden}' +
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
  '.card>h1{margin:22px 28px 8px}.card>.err{margin:0 28px}';

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
 * The front door: `GET /` (a static surface's shell since #579), its script,
 * stylesheet and `/home-api`, the realm directory at `GET /realms`, and the
 * logo the front page draws.
 *
 * It lists no endpoints; `/admin/sts-metadata` does that from the router.
 */
class Home {
  // The bundle, once read (`bundle()`).
  private script: Json = null;

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

  // The front page (and since #579 its script, stylesheet and API), the
  // realm directory and the logo, in the order they were always registered.
  /**
   * Registers `GET /` and its surface's files and API, `GET /realms` and the
   * logo route, in the order they were always registered.
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
    // THE FRONT DOOR AS A STATIC SURFACE (#579): the shell, its script and
    // its stylesheet, and the API its one page is drawn from.
    app.get('/', function (req, res) {
      log.debug('Entering the front page endpoint.');
      const authnAt = self.authnElsewhere(req);
      // The policy through `app.contentSecurityPolicy()` (frame-ancestors
      // and base-uri re-added whatever is asked), `no-store`, and the
      // document uncompressed so `app.js`'s `send()` puts the realm's prefix
      // on its links as on every page.
      ShellDocument.serve(app, req, res, self.shellDocument(req, authnAt), {
        connect: ShellDocument.originsOf([authnAt]),
        csp: { 'style-src': "'self'" }
      });
      log.debug('Leaving the front page endpoint.');
    });

    app.get(SCRIPT_ROUTE, function (req, res) {
      log.debug("Entering the front door's script.");
      // Brotli, gzip or neither, by the request's Accept-Encoding, from the
      // build's precompressed files (`ShellDocument.sendFile()`, #570).
      ShellDocument.sendFile(req, res, self.bundle(),
                             'application/javascript');
      log.debug("Leaving the front door's script.");
    });

    app.get(STYLE_ROUTE, function (req, res) {
      log.debug("Entering the front door's stylesheet.");
      res.set('Cache-Control', 'no-cache').type('text/css').send(HOME_CSS);
      log.debug("Leaving the front door's stylesheet.");
    });

    // THE API: its index — `/account-api`'s convention, which the surface's
    // runtime reads to find the operation a form mirrors; the front door
    // has no form, so nothing it lists is a POST — and the page's view.
    app.get(API_BASE, function (req, res) {
      log.debug('Entering the front door API index.');
      res.set('Cache-Control', 'no-store').type('application/json')
         .send(JSON.stringify(self.apiIndex(), null, 2));
      log.debug('Leaving the front door API index.');
    });

    app.get(FRONT_OPERATION, function (req, res) {
      log.debug('Entering the front page view.');
      // `no-store`: the mode and the listeners can change while the process
      // runs, and the page is drawn from what is true now.
      res.set('Cache-Control', 'no-store').type('application/json')
         .send(JSON.stringify({ ok: true, view: self.frontView(req) },
                              null, 2));
      log.debug('Leaving the front page view.');
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
        // tests/protocol/sts_metadata.js, which fails on `Cannot GET` and
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
  // THE VIEW (#579). Everything the server-drawn card showed, as facts and no
  // words: the browser draws them in its language (`web_home_front.ts`).
  //
  // ONE COPY OF WHAT SIGNING IN HERE MEANS is still the rule, and it moved
  // with the words: the three same-origin links send a reader to a sign-in
  // screen, and what that screen CHECKS is a property of the mode rather
  // than of any one surface — so the view carries the two facts of the mode
  // it depends on, once, and the renderer chooses the sentence once for
  // every such row. **It used to be a clause on the console's row reading
  // "it asks you to sign in, and nothing else here does"**, false from the
  // day the portal arrived, and "no password checked" stated
  // unconditionally, which is a development-mode fact (`home/CLAUDE.md`).
  // Read per request, because a front door is drawn from what is true now.
  // ---------------------------------------------------------------------------

  /**
   * Where one of this instance's own surfaces is, for a link from the front
   * door: its path where the listener this request arrived on answers it
   * (or there are no custom listeners), and its advertised base otherwise
   * (#472).
   *
   * @param req - the request for the view
   * @param application - the surface's application id
   * @param where - its path
   * @returns a root-relative path, or an absolute URL on its listener
   */
  linkTo(req: Json, application: string, where: string): string {
    const { log, baseUrlOf } = this.deps.helpers;
    log.debug("Entering Home.linkTo(). " + application);
    if (listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), application)) {
      log.debug("Leaving Home.linkTo(). Here.");
      return where;
    }
    const out = baseUrlOf(req, application) + where;
    log.debug("Leaving Home.linkTo(). " + out);
    return out;
  }

  /**
   * The front page's view: language-free, everything the page draws.
   *
   * @param req - the request for it
   * @returns `{ name, version, build, mode, logo, links }`
   */
  frontView(req: Json): Json {
    const { mode } = this.deps;
    const { log } = this.deps.helpers;
    log.debug("Entering Home.frontView().");
    const out = {
      name: 'IYA STS',
      // The number is what a bug report quotes; `build` is its provenance
      // (the instant, the commit, stamped or computed), the tooltip.
      version: String(VERSION),
      build: BUILD_INFO,
      mode: {
        verifiesCredentials: !!mode.verifiesCredentials(),
        // True in both modes since 2026-09-06; carried rather than assumed,
        // so the row cannot claim a gate the service does not keep.
        gatesConsole: !!mode.gatesConsole()
      },
      // With no image read at startup there is none to draw (the header).
      logo: logoBytes
        ? { src: LOGO_ROUTE, width: LOGO_WIDTH, height: LOGO_HEIGHT }
        : null,
      // THE SIX LINKS, by id; the renderer has the words for each.
      links: [
        { id: 'repo', href: REPO_URL, external: true },
        { id: 'issues', href: ISSUES_URL, external: true },
        { id: 'docs', href: DOCS_URL, external: true },
        { id: 'console', external: false,
          href: this.linkTo(req, 'admin-console', CONSOLE_PATH) },
        { id: 'portal', external: false,
          href: this.linkTo(req, 'portal', PORTAL_PATH) },
        { id: 'report', external: false,
          href: this.linkTo(req, 'report', REPORT_PATH) }
      ]
    };
    log.debug("Leaving Home.frontView().");
    return out;
  }

  /**
   * The API's index: each operation, and the page it is the door of.
   *
   * @returns `{ api, operations }`
   */
  apiIndex(): Json {
    const { log } = this.deps.helpers;
    log.debug("Entering Home.apiIndex().");
    const out = {
      api: 'IYA STS front door',
      operations: [
        { method: 'GET', path: API_BASE, operationId: 'getIndex',
          access: 'public', mirrors: null,
          summary: 'Lists every operation of this API' },
        { method: 'GET', path: FRONT_OPERATION, operationId: 'getFront',
          access: 'public', mirrors: 'GET /',
          summary: 'The front page\'s view: the name, the version, the ' +
                   'mode\'s two facts, the image and the six links' }
      ]
    };
    log.debug("Leaving Home.apiIndex().");
    return out;
  }

  /**
   * The sign-in service's base where this listener does not answer it, for
   * the language chooser, which posts to `/authn/language` (#472).
   *
   * @param req - the request for the shell
   * @returns the base with the realm's prefix, or ''
   */
  authnElsewhere(req: Json): string {
    const { log, baseUrlOf } = this.deps.helpers;
    log.debug("Entering Home.authnElsewhere().");
    const out = listenerMap.isTrivial() ||
      listenerMap.admits(listenerMap.listenerOf(req), 'authn')
      ? '' : baseUrlOf(req, 'authn');
    log.debug("Leaving Home.authnElsewhere(). " + (out || 'here'));
    return out;
  }

  /**
   * The shell document `GET /` answers.
   *
   * @param req - the request for it
   * @param authnAt - `authnElsewhere()`'s answer
   * @returns the document
   */
  shellDocument(req: Json, authnAt: string): string {
    const { realms } = this.deps;
    const { log, xmlEscape } = this.deps.helpers;
    log.debug("Entering Home.shellDocument().");
    const html = ShellDocument.document({
      title: 'IYA STS',
      attributes: [['data-sts-prefix', realms.currentPrefix()],
                   ['data-sts-authn', authnAt] as [string, string]]
        .concat(PageLocale.shellAttributes(req, '')) as
        Array<[string, string]>,
      stylesheets: ['/web/card.css', STYLE_ROUTE],
      script: SCRIPT_ROUTE,
      open: '<div class="card"><div class="body"><h1>IYA STS</h1>',
      close: '</div></div>',
      // SCRIPT IS REQUIRED (#569), so a browser without it is told what
      // this is and where the documentation is — which is the one link
      // that works without this service drawing anything.
      noscript: '<div class="warn">This front page is a script that runs ' +
        'in your browser and draws itself from <code>' + API_BASE +
        '</code>; with scripts blocked there is nothing it can show. The ' +
        'documentation is at <a href="' + xmlEscape(DOCS_URL) + '">' +
        xmlEscape(DOCS_URL) + '</a>.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    log.debug("Leaving Home.shellDocument().");
    return html;
  }

  /**
   * The bundle and its precompressed forms, read once. A tree that was never
   * built has none, and the shell then loads a script that says so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  bundle(): Json {
    const { log } = this.deps.helpers;
    log.debug("Entering Home.bundle().");
    if (!this.script) {
      this.script = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no front page ' +
        'script (home/' + BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving Home.bundle().");
    return this.script;
  }

  /**
   * The paths this module registers, for `sts_metadata.ts` and the tests.
   *
   * @returns the paths
   */
  paths(): string[] {
    const { log } = this.deps.helpers;
    log.debug("Entering Home.paths().");
    log.debug("Leaving Home.paths().");
    return ['/', SCRIPT_ROUTE, STYLE_ROUTE, API_BASE, FRONT_OPERATION,
            '/realms', LOGO_ROUTE];
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
