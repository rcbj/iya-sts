// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_demo_api.ts
//
// ---------------------------------------------------------------------------
// `/vc-demo-api`: THE API THE DEMONSTRATION ISSUER AND VERIFIER ARE DRAWN
// FROM (#582, 2026-10-12).
//
// The five pages a person reads in the OpenID4VC demonstration — the
// issuer's page (`/issuer`), the offer (`/issuer/offer`), the bar door
// (`/oid4vp/verifier`), its start (`/oid4vp/start`) and its closing page
// (`/oid4vp/done`) — answer the static surface's shell (`vc_demo_shell.ts`)
// since #582, and the browser draws each from this API in its own language
// (`web_vc_demo*.ts`, `common/CLAUDE.md` 3cl). Language-free: facts, and
// refusals in English with their codes recorded and never sent.
//
//   GET  /vc-demo-api           the operations, each with the page or
//                               control it is the door of (`mirrors`)
//   GET  /vc-demo-api/issuer    the issuer's page's view
//   GET  /vc-demo-api/offer     the offer page's view and CSRF token; the
//                               query checked, NOTHING MINTED
//   POST /vc-demo-api/offer     makes the offer: `location` (the wallet,
//                               same device) or the QR page's view
//   GET  /vc-demo-api/verifier  the bar door's view
//   GET  /vc-demo-api/start     the start page's view and CSRF token; the
//                               query checked, NOTHING BUILT
//   POST /vc-demo-api/start     starts the presentation: `location` (the
//                               wallet, same device) or the QR page's view
//   GET  /vc-demo-api/done      what was decided for `?state=` — the closing
//                               page's view, and what the QR page polls
//
// **THE ACTS ARE NOT GETS ANY MORE, AND THAT IS THE CHANGE A CALLER SEES.**
// `GET /issuer/offer` and `GET /oid4vp/start` minted an offer or a request
// and answered a 302; a GET is followed by prefetchers and link previews, so
// since #582 the page a GET answers creates nothing (#574's rule for the
// wallet's start), and its runtime makes the offer or the request with a
// POST here — at once, as the page loads, replacing itself in the history so
// Back does not make a second. The address the 302 named is this POST's
// `location`, the same bytes, and the QR page's URI is the same URI.
//
// **EVERY ACT IS BOUND AS `/authn-api`'S ARE (#571)**: a JSON body, which a
// cross-site form cannot send (`STS-VC-0116`); an `Origin` this service
// answers on (`STS-VC-0117`); and `X-CSRF-Token`, the token of the browser's
// `sts_session` cookie (`STS-VC-0118`) — derived, not stored, and answered by
// the start pages' views. `/issuer/offer` and `/oid4vp/start` are arrival
// paths (`authn.ts`'s ARRIVAL_PATHS), so a browser arriving there without
// the cookie is given one. A REQUEST RELAYED FROM ANOTHER CELL (#98) was
// bound where it arrived (`req.stsCellRelay`).
//
// **WHAT A WALLET IS HANDED IS NOT THIS MODULE'S**: the offer is
// `VcOffers.makeOffer()`'s and the request `VcVerifier.startVerification()`'s
// (#589, #587) — this module reads what they answer and sends it on.
//
// **A DEMONSTRATION, DEVELOPMENT ONLY (#585)**: every route here carries
// `common/app.js`'s `demoOnly` mark, so a product realm answers each as a
// path nothing is registered on. The administrator's doors that replace
// them in product are `POST /admin-api/verifications/start` (#587) and a
// person's own offer on `/portal/wallet` (#589).
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50) — `VcDemoApi` takes the offers, the Verifier,
// the sign-in service and the libraries through its constructor;
// `registerRoutes(app)` registers the surface's script and the API, and
// `common/protocol_stack.ts` calls it just after the Verifier's (14). It
// requires two route modules, both converted, so a require moves no route.
// ---------------------------------------------------------------------------

import app = require('../common/app');
// THE DEMONSTRATION MARK (#585), read off the shared app here because
// `registerRoutes(app)`'s parameter shadows the name.
const demoOnly = app.demoOnly;
import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import websecurity = require('../common/websecurity');
import cors = require('../common/cors');
import stsCrypto = require('../common/crypto');
import authn = require('../authn/authn');
import vcOffers = require('./vc_offers');
import vcVerifier = require('./vc_verifier');
import VcDemoShell = require('./vc_demo_shell');

type Json = any;

type Req = import('express').Request;
type Res = import('express').Response;
type Next = import('express').NextFunction;
type Handler = (req: Req, res: Res, next?: Next) => unknown;

interface VcDemoApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  config: typeof config;
  errorCodes: typeof errorCodes;
  websecurity: typeof websecurity;
  cors: typeof cors;
  stsCrypto: typeof stsCrypto;
  authn: typeof authn;
  offers: typeof vcOffers;
  verifier: typeof vcVerifier;
}

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
  post(path: string, ...handlers: Handler[]): unknown;
}

const API = VcDemoShell.API;
const CSRF_HEADER = 'x-csrf-token';

// THE OPERATIONS, for the index the surface's runtime reads (`mirrors`: the
// page or control each is the door of — `/account-api`'s convention) and
// for `sts_metadata.ts`.
const OPERATIONS = [
  { method: 'GET', path: API, operationId: 'getIndex', mirrors: null,
    summary: 'Lists every operation of this API' },
  { method: 'GET', path: API + '/issuer', operationId: 'getIssuerPage',
    mirrors: 'GET /issuer',
    summary: 'The demonstration issuer\'s page: the credential on offer, ' +
             'the wallet and the issuer' },
  { method: 'GET', path: API + '/offer', operationId: 'getOfferPage',
    mirrors: 'GET /issuer/offer',
    summary: 'The offer page\'s view and its CSRF token; the query is ' +
             'checked and nothing is minted' },
  { method: 'POST', path: API + '/offer', operationId: 'makeDemoOffer',
    mirrors: 'POST /issuer/offer',
    summary: 'Makes a Credential Offer (OpenID4VCI Appendix H): the wallet ' +
             'to go to, or the QR page\'s view with the Transaction Code' },
  { method: 'GET', path: API + '/verifier', operationId: 'getVerifierPage',
    mirrors: 'GET /oid4vp/verifier',
    summary: 'The demonstration Verifier\'s page: what it asks for, and in ' +
             'which format' },
  { method: 'GET', path: API + '/start', operationId: 'getStartPage',
    mirrors: 'GET /oid4vp/start',
    summary: 'The start page\'s view and its CSRF token; the query is ' +
             'checked and nothing is built' },
  { method: 'POST', path: API + '/start', operationId: 'startDemoPresentation',
    mirrors: 'POST /oid4vp/start',
    summary: 'Starts a presentation (OpenID4VP): the wallet to go to, or ' +
             'the QR page\'s view' },
  { method: 'GET', path: API + '/done', operationId: 'getDonePage',
    mirrors: 'GET /oid4vp/done',
    summary: 'What the Verifier decided for a state: the closing page\'s ' +
             'view, and what the QR page polls' }
];

/**
 * The API the demonstration issuer's and verifier's pages are drawn from.
 */
class VcDemoApi {
  /**
   * Builds the API from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: VcDemoApiDeps) {
    deps.log.debug("Entering VcDemoApi.constructor().");
    deps.log.debug("Leaving VcDemoApi.constructor().");
  }

  // An answer: JSON, never stored.
  private answer(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering VcDemoApi.answer(). " + status);
    // error-code: none — the API's own send; every refusal's code is marked by refuse() first.
    res.status(status)
       .set('Cache-Control', 'no-store')
       .type('application/json')
       .send(JSON.stringify(body));
    log.debug("Leaving VcDemoApi.answer().");
  }

  // A refusal: `{ ok: false, errors }` in English, the code recorded and
  // never sent.
  // error-code: none — the helper's definition; every caller passes its STS-VC code.
  private refuse(res: Res, status: number, code: string, why: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcDemoApi.refuse(). " + status);
    errorCodes.mark(res, code);
    this.answer(res, status, { ok: false, errors: [why] });
    log.debug("Leaving VcDemoApi.refuse().");
  }

  // The browser's CSRF token: `websecurity.tokenFor()` of the `sts_session`
  // cookie's session, '' where there is none (`authn/authn_api.ts`'s
  // `csrfOf()`).
  private csrfOf(req: Req): string {
    const { log, authn, websecurity } = this.deps;
    log.debug("Entering VcDemoApi.csrfOf().");
    const found: any = authn.cookieSession(req, authn.SESSION_COOKIE);
    const token = found && found.id ? websecurity.tokenFor(found.id) : '';
    log.debug("Leaving VcDemoApi.csrfOf(). " + (token ? 'A session.'
                                                       : 'No session.'));
    return token;
  }

  // ---------------------------------------------------------------------------
  // THE BINDING OF AN ACT, `/authn-api`'s three (#571), asked BEFORE
  // anything is minted: a JSON body, an Origin this service answers on, and
  // the X-CSRF-Token of the browser's `sts_session` cookie. A request with
  // no session is refused here rather than let through as `checkCsrf()` lets
  // one through: the start pages are arrival paths, so a browser that loaded
  // one holds the cookie.
  // ---------------------------------------------------------------------------
  private bound(req: Req, res: Res): boolean {
    const { log, cors, stsCrypto } = this.deps;
    log.debug("Entering VcDemoApi.bound().");
    if ((req as any).stsCellRelay) {
      log.debug("Leaving VcDemoApi.bound(). Relayed; bound where it " +
                "arrived.");
      return true;
    }
    const type = String((req.headers && req.headers['content-type']) || '');
    if (!/^application\/json\s*(;|$)/i.test(type)) {
      this.refuse(res, 415, 'STS-VC-0116', 'This operation takes a JSON ' +
                  'body (Content-Type: application/json).');
      log.debug("Leaving VcDemoApi.bound(). Not JSON.");
      return false;
    }
    const origin = String((req.headers && req.headers.origin) || '');
    let own: string[] = [];
    try {
      own = cors.ownOrigins(req) || [];
    } catch (e) {
      log.debug("Caught in VcDemoApi.bound(): " + ((e && e.message) || e));
      // No origin this service can name for the request: nothing matches.
      own = [];
    }
    if (!origin || own.indexOf(origin) < 0) {
      this.refuse(res, 403, 'STS-VC-0117', 'This operation is sent by a ' +
                  'page of this service: the request carried ' +
                  (origin ? 'another origin' : 'no Origin') + '.');
      log.debug("Leaving VcDemoApi.bound(). Not this origin.");
      return false;
    }
    const expected = this.csrfOf(req);
    const presented = String((req.headers && req.headers[CSRF_HEADER]) || '');
    if (!expected || !presented ||
        !stsCrypto.constantTimeEquals(presented, expected)) {
      this.refuse(res, 403, 'STS-VC-0118', expected
        ? 'The ' + CSRF_HEADER + ' header is missing or is not this ' +
          'browser\'s. Load the page again.'
        : 'This browser holds no session for this page. Load the page ' +
          'again.');
      log.debug("Leaving VcDemoApi.bound(). The token.");
      return false;
    }
    log.debug("Leaving VcDemoApi.bound(). Bound.");
    return true;
  }

  // An operation of this API: its answer settled whatever its handler
  // throws, as an English refusal with its code (STS-VC-0119).
  private settled(name: string, handler: Handler): Handler {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcDemoApi.settled(). " + name);
    log.debug("Leaving VcDemoApi.settled().");
    return function (req, res, next) {
      log.debug("Entering " + name + ".");
      Promise.resolve().then(function () {
        return handler(req, res, next);
      }).then(function () {
        log.debug("Leaving " + name + ".");
      }, function (e) {
        log.debug("Caught in " + name + ": " + ((e && e.message) || e));
        log.error(errorCodes.tag('STS-VC-0119') + 'vc-demo-api: ' + name +
                  ' failed: ' + ((e && e.stack) || e));
        if (!res.headersSent) {
          self.refuse(res, 500, 'STS-VC-0119', 'The request could not be ' +
                      'completed.');
        }
        log.debug("Leaving " + name + ". Failed.");
      });
    };
  }

  // The body of an act, as an object; a body that is not one is empty, and
  // what the schema refuses in it is said with the page's code.
  private bodyOf(req: Req): Json {
    const { log, parseBody } = this.deps;
    log.debug("Entering VcDemoApi.bodyOf().");
    const body = parseBody(req);
    log.debug("Leaving VcDemoApi.bodyOf().");
    return body && typeof body === 'object' && !Array.isArray(body)
      ? body : {};
  }

  // How often the QR page asks whether the wallet answered: the wallet
  // sign-in's QR page's interval (`oid4vp.signInPollS`), the one poll a
  // person's browser runs against a Verifier here.
  private pollSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering VcDemoApi.pollSeconds().");
    const seconds = Number(config.value('oid4vp.signInPollS'));
    log.debug("Leaving VcDemoApi.pollSeconds().");
    return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 3;
  }

  /**
   * `GET /vc-demo-api`: the operations, and the page or control each is the
   * door of.
   *
   * @param res - the response
   */
  apiIndex(res: Res): void {
    const { log } = this.deps;
    log.debug("Entering VcDemoApi.apiIndex().");
    this.answer(res, 200, { api: 'IYA STS OpenID4VC demonstration',
                            operations: OPERATIONS });
    log.debug("Leaving VcDemoApi.apiIndex().");
  }

  /**
   * A view a page is drawn from, or its refusal.
   *
   * @param res - the response
   * @param made - `{ ok, view }` or `{ ok: false, status, code, error }`
   * @param extra - members answered beside the view (`csrf`)
   */
  private viewOrRefusal(res: Res, made: Json, extra?: Json): void {
    const { log } = this.deps;
    log.debug("Entering VcDemoApi.viewOrRefusal().");
    if (!made.ok) {
      this.refuse(res, made.status || 400, made.code, String(made.error));
      log.debug("Leaving VcDemoApi.viewOrRefusal(). Refused.");
      return;
    }
    this.answer(res, 200, Object.assign({ ok: true, view: made.view },
                                        extra || {}));
    log.debug("Leaving VcDemoApi.viewOrRefusal().");
  }

  /**
   * An act's answer: `location` or a `view`, or its refusal.
   *
   * @param res - the response
   * @param made - `{ ok, location }`, `{ ok, view }`, or a refusal
   */
  private acted(res: Res, made: Json): void {
    const { log } = this.deps;
    log.debug("Entering VcDemoApi.acted().");
    if (!made.ok) {
      this.refuse(res, made.status || 400, made.code, String(made.error));
      log.debug("Leaving VcDemoApi.acted(). Refused.");
      return;
    }
    this.answer(res, 200, made.location !== undefined
      ? { ok: true, location: made.location }
      : { ok: true, view: made.view });
    log.debug("Leaving VcDemoApi.acted().");
  }

  /**
   * Registers the surface's script and `/vc-demo-api`, every route marked a
   * demonstration (#585).
   *
   * Called by `common/protocol_stack.ts` just after the Verifier's routes.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, offers, verifier } = this.deps;
    log.debug("Entering VcDemoApi.registerRoutes().");

    // THE SURFACE'S SCRIPT: brotli, gzip or neither, by the request's
    // Accept-Encoding, from the build's precompressed files.
    app.get(VcDemoShell.SCRIPT_PATH, demoOnly, function (req, res) {
      log.debug("Entering the demonstration surface's script.");
      VcDemoShell.sendScript(req, res);
      log.debug("Leaving the demonstration surface's script.");
    });

    app.get(API, demoOnly, self.settled('GET ' + API, function (req, res) {
      self.apiIndex(res);
    }));

    app.get(API + '/issuer', demoOnly, self.settled('GET ' + API + '/issuer',
                                                    function (req, res) {
      self.answer(res, 200, { ok: true, view: offers.issuerView(req) });
    }));

    // The offer page's view: the query checked as the act will check it, so
    // a bad link is said before anything is asked; and the CSRF token.
    app.get(API + '/offer', demoOnly, self.settled('GET ' + API + '/offer',
                                                   function (req, res) {
      const checked: Json = offers.offerChecked(req, req.query, 'query');
      self.viewOrRefusal(res, checked.ok
        ? { ok: true, view: { kind: 'offerStart', mode: checked.mode } }
        : checked, { csrf: self.csrfOf(req) });
    }));

    app.post(API + '/offer', demoOnly, self.settled('POST ' + API + '/offer',
                                                    function (req, res) {
      if (!self.bound(req, res)) {
        return;
      }
      self.acted(res, offers.offerAct(req, self.bodyOf(req), 'body'));
    }));

    app.get(API + '/verifier', demoOnly,
            self.settled('GET ' + API + '/verifier', function (req, res) {
      self.viewOrRefusal(res, verifier.verifierView(req, req.query));
    }));

    app.get(API + '/start', demoOnly, self.settled('GET ' + API + '/start',
                                                   function (req, res) {
      const checked: Json = verifier.startChecked(req.query);
      self.viewOrRefusal(res, checked.ok
        ? { ok: true, view: { kind: 'presentStart', mode: checked.mode } }
        : checked, { csrf: self.csrfOf(req) });
    }));

    app.post(API + '/start', demoOnly, self.settled('POST ' + API + '/start',
                                                    async function (req, res) {
      if (!self.bound(req, res)) {
        return;
      }
      self.acted(res, await verifier.startAct(req, self.bodyOf(req),
                                              self.pollSeconds()));
    }));

    app.get(API + '/done', demoOnly, self.settled('GET ' + API + '/done',
                                                  function (req, res) {
      self.answer(res, 200, { ok: true,
        view: verifier.doneView(String(req.query.state || '')) });
    }));

    log.debug("Leaving VcDemoApi.registerRoutes().");
  }

  /**
   * The operations of `/vc-demo-api`, for `sts_metadata.ts` and the tests.
   *
   * @returns the operation table
   */
  static operations(): Json[] {
    helpers.log.debug("Entering VcDemoApi.operations().");
    helpers.log.debug("Leaving VcDemoApi.operations().");
    return OPERATIONS.slice();
  }

  // What the composition root passes (#50, R2): the real modules.
  /**
   * Returns the real modules the instance is built from.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcDemoApiDeps {
    helpers.log.debug("Entering VcDemoApi.defaultDeps().");
    helpers.log.debug("Leaving VcDemoApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      config: config,
      errorCodes: errorCodes,
      websecurity: websecurity,
      cors: cors,
      stsCrypto: stsCrypto,
      authn: authn,
      offers: vcOffers,
      verifier: vcVerifier
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2): `common/
// protocol_stack.ts` builds one and calls `installInstance()`; a process
// that never runs the root gets a default instance (`common/
// instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcDemoApi>(
  'oid4vc/vc_demo_api',
  () => new VcDemoApi(VcDemoApi.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The API the demonstration issuer's and verifier's pages are drawn from.
 *
 * @namespace
 */
export = {
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcDemoApi): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  /**
   * The operations of `/vc-demo-api`.
   *
   * @returns the operation table
   */
  operations: VcDemoApi.operations,
  VcDemoApi: VcDemoApi
};
