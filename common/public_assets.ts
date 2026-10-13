// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: public_assets.ts
//
// ---------------------------------------------------------------------------
// THE FILES EVERY STATIC PUBLIC SURFACE SHARES, UNDER `/web` (#570,
// 2026-10-12).
//
// rcbj's decision 3 on #570 is that the browser translates: a static surface
// negotiates its language and formats its messages itself, from the catalogs
// in `common/locales/` served as STATIC JSON. And the public surfaces are
// drawn with the sign-in screen's card, which a static page links as a
// stylesheet rather than carrying inline. So this module serves:
//
//   GET /web/card.css                       `WebCardCss`: the card, and the
//                                           chooser's rules
//   GET /web/locales/catalogs.json          the catalog index: which
//                                           catalogs exist, their status, and
//                                           what the chooser offers
//   GET /web/locales/<ns>/<catalog>.json    one namespace's messages in one
//                                           catalog, as `common/i18n.ts`
//                                           loaded them
//
// WHY `/web`, AND WHY ON EVERY LISTENER. The files belong to no one
// application: the front door, the sign-in service, consent (an
// authorization server page) and the sign-out each draw with them, and a
// listener that answers any of those must answer these. So `/web` is, with
// `/healthcheck`, a prefix `common/hosted_applications.js` answers EVERYWHERE,
// and a row `local` in `common/cell_placement.ts`: every cell answers it the
// same. They are public — every catalog is shipped text, the console's and
// the portal's included — and carry nothing about a request.
//
// NOTHING IS READ FROM DISK BY A REQUESTED NAME. A catalog file is answered
// from what `common/i18n.ts` already loaded, and only for a namespace and a
// catalog it knows; anything else is a 404 (`STS-I18N-0012`). A known
// namespace with no file for a known catalog — a regional overlay that
// differs nowhere there — is `{}`, which is the truth, and the browser's
// chain falls through to the base and to English as the server's does.
//
// CACHING BY VERSION: an address carrying `?v=` equal to this build's
// version (`common/version.js`, the shell's `data-sts-version`) is the same
// bytes for the life of the build, so it is `public, max-age=31536000,
// immutable`; any other is `no-cache`, revalidated by its ETag. A new build
// is a new version, so a browser never holds a stale catalog past a deploy.
// Compressed where the request accepts it (`ShellDocument.sendCompressed()`):
// static text with no secret beside it, which BREACH needs.
//
// A ROUTE MODULE (rule 1) on #50's R2 pattern: `common/protocol_stack.ts`
// builds it and calls `registerRoutes(app)` just after the front door's.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import i18n = require('./i18n');
import errorCodes = require('./error_codes');
import version = require('./version');
import ShellDocument = require('./shell_document');
import WebCardCss = require('./web_card_css');

type Json = any;

interface PublicAssetsDeps {
  log: typeof helpers.log;
  i18n: typeof i18n;
  errorCodes: typeof errorCodes;
  version: typeof version;
}

/**
 * The paths this module answers.
 */
const PATHS = {
  card: '/web/card.css',
  index: '/web/locales/catalogs.json',
  catalog: '/web/locales/:ns/:file'
};

/**
 * How long a versioned address is kept: a year, the most RFC 9111 allows a
 * cache to be told usefully.
 */
const IMMUTABLE = 'public, max-age=31536000, immutable';

/**
 * The shared static files of the public surfaces: the card and the
 * catalogs.
 */
class PublicAssets {
  /**
   * The paths this module answers.
   */
  static readonly PATHS = PATHS;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: PublicAssetsDeps) {
    deps.log.debug("Entering PublicAssets.constructor().");
    deps.log.debug("Leaving PublicAssets.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PublicAssetsDeps {
    helpers.log.debug("Entering PublicAssets.defaultDeps().");
    helpers.log.debug("Leaving PublicAssets.defaultDeps().");
    return { log: helpers.log, i18n: i18n, errorCodes: errorCodes,
             version: version };
  }

  /**
   * The Cache-Control a request's address earns: for good when it names
   * this build, revalidated otherwise.
   *
   * @param req - the request
   * @returns the header value
   */
  cachingFor(req: Json): string {
    const { log, version } = this.deps;
    log.debug("Entering PublicAssets.cachingFor().");
    const asked = req && req.query && typeof req.query.v === 'string'
      ? req.query.v : '';
    const out = asked && asked === String(version.load().version)
      ? IMMUTABLE : 'no-cache';
    log.debug("Leaving PublicAssets.cachingFor(). " + out);
    return out;
  }

  /**
   * The catalog index as the browser reads it: the source, every catalog's
   * tag, names, status and base, and the locales the chooser offers.
   *
   * @returns the index
   */
  index(): Json {
    const { log, i18n, version } = this.deps;
    log.debug("Entering PublicAssets.index().");
    const out = {
      source: i18n.SOURCE,
      version: String(version.load().version),
      catalogs: i18n.catalogs(),
      offered: i18n.offered()
    };
    log.debug("Leaving PublicAssets.index(). " + out.catalogs.length +
              " catalog(s).");
    return out;
  }

  /**
   * One namespace's messages in one catalog, or null for a namespace, a
   * catalog or a file name this service does not have.
   *
   * @param ns - the namespace, as requested
   * @param file - `<catalog>.json`, as requested
   * @returns the messages, or null
   */
  catalog(ns: unknown, file: unknown): Json {
    const { log, i18n } = this.deps;
    log.debug("Entering PublicAssets.catalog().");
    const name = String(ns || '');
    const m = /^([A-Za-z0-9-]{1,64})\.json$/.exec(String(file || ''));
    const known = i18n.namespaces().indexOf(name) >= 0 && !!m &&
      i18n.catalogs().some(function (info: Json): boolean {
        return info.tag === m[1];
      });
    const out = known ? i18n.messagesOf(name, m[1]) : null;
    log.debug("Leaving PublicAssets.catalog(). " +
              (out ? Object.keys(out).length + " message(s)." : 'Unknown.'));
    return out;
  }

  /**
   * Sends JSON, cached by version and compressed where accepted.
   *
   * @param req - the request
   * @param res - the response
   * @param body - the JSON
   * @returns nothing
   */
  sendJson(req: Json, res: Json, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering PublicAssets.sendJson().");
    res.status(200).type('application/json')
       .set('Cache-Control', this.cachingFor(req));
    ShellDocument.sendCompressed(req, res, JSON.stringify(body), null, null);
    log.debug("Leaving PublicAssets.sendJson().");
  }

  /**
   * Registers the three routes; `common/protocol_stack.ts` calls it.
   *
   * @param app - the shared express app
   * @returns nothing
   */
  registerRoutes(app: Json): void {
    const { log, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering PublicAssets.registerRoutes().");
    app.get(PATHS.card, function (req: Json, res: Json) {
      log.debug("Entering GET " + PATHS.card + ".");
      res.status(200).type('text/css')
         .set('Cache-Control', self.cachingFor(req));
      ShellDocument.sendCompressed(req, res, WebCardCss.CARD_CSS, null, null);
      log.debug("Leaving GET " + PATHS.card + ".");
    });
    app.get(PATHS.index, function (req: Json, res: Json) {
      log.debug("Entering GET " + PATHS.index + ".");
      self.sendJson(req, res, self.index());
      log.debug("Leaving GET " + PATHS.index + ".");
    });
    app.get(PATHS.catalog, function (req: Json, res: Json) {
      log.debug("Entering GET " + PATHS.catalog + ".");
      const found = self.catalog(req.params && req.params.ns,
                                 req.params && req.params.file);
      if (!found) {
        errorCodes.mark(res, 'STS-I18N-0012');
        res.status(404).type('text/plain').set('Cache-Control', 'no-store')
           .send('There is no such catalog file.');
        log.debug("Leaving GET " + PATHS.catalog + ". Not found.");
        return;
      }
      self.sendJson(req, res, found);
      log.debug("Leaving GET " + PATHS.catalog + ".");
    });
    log.debug("Leaving PublicAssets.registerRoutes().");
  }
}

const slot = new InstanceSlot<PublicAssets>(
  'common/public_assets',
  () => new PublicAssets(PublicAssets.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as every module on R2's pattern does.
slot.buildNowUnlessDeferred();

/**
 * The shared static files of the public surfaces (#570).
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  index: slot.forward('index'),
  catalog: slot.forward('catalog'),
  PublicAssets: PublicAssets,
  PATHS: PATHS,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: PublicAssets): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or
   * `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin()
};
