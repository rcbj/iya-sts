// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_interact.ts
//
// ---------------------------------------------------------------------------
// THE PAGES A RESOURCE OWNER SEES: WHERE A GNAP INTERACTION STARTS, WHERE THEY
// SIGN IN, WHERE THEY DECIDE, AND HOW THE CLIENT IS TOLD.
//
// RFC 9635 section 4 leaves consent "deliberately flexible", and this service
// runs the shape nearly every AS runs:
//
//   GET  /gnap/interact/:id   the `redirect` start mode (section 4.1.1)
//   GET  /gnap/app/:id        the `app` start mode (section 4.1.4) — an https
//                             URI a native app can hand to the system browser
//   GET  /gnap/code           the static user code page (section 4.1.2), and
//   POST /gnap/code           the short dynamic `user_code_uri` (section
//                             4.1.3)
//   GET  /gnap/approve/:id    sign-in, then the approval page
//   POST /gnap/approve/:id    the resource owner's answer, then the finish
//                             method
//
// Every start mode spends itself and leads to ONE approval page per grant, so
// the rule of section 4.1 — once a start mode has completed, every other must
// be refused — is a property of the grant rather than of four handlers.
//
// ---------------------------------------------------------------------------
// SIGN-IN IS THE ONE AUTHENTICATION SERVICE (the user's requirement).
//
// `authn.beginAuthentication()` with `protocol: 'GNAP'` and the client's
// application identifier, exactly as `/oauth2/authorize` and `/saml2/sso` call
// it — so the sign-in screen's mechanism choice, second factors, federation and
// SPNEGO all apply, the session it mints is the one every other protocol reads
// (single sign-on in both directions), CAEP's `session-established` fires, and
// `startSession()` records the authentication, which is what puts the person's
// entry in the embedded directory (ldap_server.js's observer). A GNAP-specific
// sign-in would have been a second answer to every one of those.
//
// **`notePresented(session, 'GNAP', req)` is called where an EXISTING session
// is honoured**, below every refusal, as the four browser SSO profiles do —
// that is CAEP's `session-presented` (tests/caep_presented_every_protocol.js
// reads the literal call).
//
// ---------------------------------------------------------------------------
// THE APPROVAL PAGE IS GNAP'S OWN, AND THE CONSENT REGISTER IS NOT.
//
// `/oauth2/consent` draws scope strings and writes `oauthConsent` values keyed
// by scope. A GNAP right is an OBJECT (section 8) as often as a string, and the
// resource owner may untick individual rights (section 4: "allow the RO to
// modify the client instance's requested access, including limiting ... that
// access"), which that page cannot express. So the page is GNAP's own, drawn
// on the sign-in screen's card, and the ANSWER goes into the same consent
// register as digest tokens (gnap_grants.ts's header).
//
// **UNLIKE `/oauth2/consent`, THE ANSWER IS CSRF-CHECKED.** The approval page
// is reached from a URI a client chose to send a browser to, which is exactly
// the setup a cross-site form post exploits: a page elsewhere that auto-submits
// "approve" for a signed-in person. Since #578 the answer is an act on
// `/gnap-api` bound three ways, as `/authn-api`'s are (#571): a JSON body, an
// `Origin` of this service, and `X-CSRF-Token` — `websecurity.tokenFor()` of
// the `sts_session` cookie's session.
//
// ---------------------------------------------------------------------------
// A STATIC SURFACE SINCE #578 (2026-10-12, under #569; `common/CLAUDE.md`
// 3cl). The pages a PERSON reads — the user code page, the approval page, and
// what is said after a decision or a refusal — are drawn in the browser by
// `/gnap/interaction.js` (`web_gnap_interact*.ts`, bundled by
// `build-typescript.sh`) from `/gnap-api`, in the browser's language from the
// `gnap` catalogs; every act goes to `/gnap-api`. SCRIPT IS REQUIRED (rcbj on
// #569): the shell's `<noscript>` says so and nothing else is drawn.
//
// **WHAT DID NOT CHANGE IS EVERY ANSWER A CLIENT INSTANCE SEES** (#569's rule
// on a specification's endpoints): the start modes still answer their 303 to
// the approval page, and every finish — the redirect to the client's finish
// URI with `hash` and `interact_ref`, the push — is enacted by
// `grants.finishInteraction()` exactly as before. The approval page's GET
// still answers every redirect it answered (the sign-in screen, a step-up,
// the finish after a cancelled sign-in or a remembered approval); where it
// drew the page it now answers the shell. A page that only SAYS something —
// a refused link, a decision made — is the shell carrying its view in
// `data-sts-state`, with the status and the code it always had: there is
// nothing to fetch, since the state exists only on that response. An answer
// made on `/gnap-api` sends the browser to the finish URI by `location`, the
// same address the 303 named.
//
// **WHY A SURFACE OF ITS OWN, AND NOT ROUTES OF THE SIGN-IN SURFACE.** These
// paths are the `gnap` hosted application's (#472), which may be on a
// listener of its own: a shell there could neither load `/authn/signin.js`
// nor call `/authn-api` under `script-src 'self'` and `connect-src 'self'`.
// And an approval page is placed by its interaction handle (#98,
// `gnap_cells.ts`), where `/authn-api` is placed by a login name. So the
// bundle is `/gnap/interaction.js` and the API `/gnap-api`, both the gnap
// application's, the API placed as the pages are. The session is still the
// sign-in service's `sts_session` cookie (#569's decision 3): no token.
//
// A client logo is drawn only when it is a `data:` image, which `img-src
// 'self' data:` allows — an external logo URI is shown as a link, because
// fetching it would be the "client-hosted logo" section 11.16 warns about,
// and CSP would refuse it anyway.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1): `GnapInteract` takes the
// sign-in service, the stores and the rest through its constructor, and its
// `registerRoutes(app)` holds the pages' routes in their old order, then the
// surface's script and `/gnap-api` (#578). The
// composition root builds the instance (#50, R2), and the module's
// `registerRoutes(app)` is a FACADE forwarding to it, which
// `common/protocol_stack.ts` calls (#50, R1) right after `gnap.ts`'s, where
// requiring this file registered them before. A process that loads this module
// without the root builds a default instance when the module loads.
//
// **THE APPROVAL ROUTES ARE WRITTEN LAST, AND THEIR HANDLERS INLINE**, because
// `tests/cluster_followups.js` reads this file from the approval route to its
// end and counts the calls that record a decision there.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import websecurity = require('../common/websecurity');
import authn = require('../authn/authn');
import store = require('./gnap_store');
import grants = require('./gnap_grants');
import monitor = require('./gnap_monitor');
import gnapCells = require('./gnap_cells');
// #432 phase 5: what a limit means, and the catalogue a lowered one must
// still meet.
import LimitsForm = require('../common/limits_form');
// The rows a right's limits are drawn from (#578): the view carries them and
// the browser draws the controls (`common/web_limits_form.ts`, #576).
import AccessLimits = require('../common/access_limits');
import gnapRights = require('./gnap_rights');
// #432 phase 6: the step-up an approval needs, and approval by an absent
// resource owner. A library.
import gnapApproval = require('./gnap_approval');
// #738: interact.acr's classification. Registers nothing; no cycle.
import gnapRequest = require('./gnap_request');
// THE LANGUAGE A PAGE IS DRAWN IN (#539), and the realm prefix the language
// chooser posts under.
import realms = require('../common/realms');
import PageLocale = require('../common/page_locale');
// THE STATIC SURFACE (#578): the shell, the listener the sign-in service is
// on (for the language chooser's post), the origins an act may come from,
// and the comparison of its CSRF token. Libraries, all four.
import ShellDocument = require('../common/shell_document');
import listenerMap = require('../common/listener_map');
import cors = require('../common/cors');
import stsCrypto = require('../common/crypto');

type Json = any;

type Req = import('express').Request;
type Res = import('express').Response;
type Next = import('express').NextFunction;
type Handler = (req: Req, res: Res, next?: Next) => unknown;

interface GnapInteractDeps {
  config: typeof config;
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  parseBody: typeof helpers.parseBody;
  nowSec: typeof helpers.nowSec;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  websecurity: typeof websecurity;
  authn: typeof authn;
  store: typeof store;
  grants: typeof grants;
  monitor: typeof monitor;
  rights: typeof gnapRights;
  approval: typeof gnapApproval;
  cors: typeof cors;
  stsCrypto: typeof stsCrypto;
}

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, ...handlers: Handler[]): unknown;
  post(path: string, ...handlers: Handler[]): unknown;
}

const vz = validation.z;
const vt = validation.types;

const ID_PARAMS = vz.object({ id: vt.base64url });
const APPROVE_QUERY = vz.object({
  authn_error: vt.opt(vt.token),
  authn_error_description: vt.opt(vt.text),
  // #432 phase 6: the sign-in for a step-up has happened once.
  step_up_honoured: vt.opt(vt.oneOf(['1']))
});
// ---------------------------------------------------------------------------
// `/gnap-api` (#578): THE BODIES OF ITS TWO ACTS, closed shapes as
// `/authn-api`'s are — they are this service's own operations, and a field
// nobody reads must not arrive under a name that looks decisive. They are the
// forms' fields as they were, the CSRF field gone into a header:
//
//   * the user code page: `code`, as typed (spaces, dashes, either case).
//   * the approval: `action` (`allow` or `deny`), `right` — the ticked
//     rights, `t<k>r<r>`, a string where one is ticked and an array where
//     several are, as a form's repeated checkbox reads in JSON — and
//     `subject` (`yes` where "Who you are" stayed ticked). A right's limit
//     controls (`lim_t<k>r<r>_<member>`, #432 phase 5) are not this schema's:
//     `LimitsForm.strip()` takes them off before it is asked, and
//     `limitFieldsRefusal()` holds them to their own bound.
// ---------------------------------------------------------------------------
const API_APPROVE_BODY = vz.object({
  action: vt.oneOf(['allow', 'deny']),
  subject: vt.opt(vt.oneOf(['yes'])),
  right: vt.repeatable(vt.token).optional()
}).strict();
const API_CODE_BODY = vz.object({
  code: vt.opt(vt.text)
}).strict();

// The API's base, the header an act's CSRF token travels in, and the
// surface's script — its path and the build's file (`build-typescript.sh`'s
// `bundle_surface`; never `gnap_interact.js`, the server module this file
// compiles to).
const API = '/gnap-api';
const CSRF_HEADER = 'x-csrf-token';
const SCRIPT_PATH = '/gnap/interaction.js';
const BUNDLE_FILE = 'gnap-interaction-spa.js';

// A limit control's name, and the bound on what one may carry.
const LIMIT_FIELD = /^lim_t\d{1,3}r\d{1,3}_[A-Za-z]{1,32}$/;
const LIMIT_VALUE_MAX = 256;
const LIMIT_VALUES_MAX = 64;

// ---------------------------------------------------------------------------
// THE OPERATIONS, for the index the surface's runtime reads (`mirrors`:
// the page or form control each is the door of — `/account-api`'s
// convention) and for `sts_metadata.ts`.
// ---------------------------------------------------------------------------
const OPERATIONS = [
  { method: 'GET', path: API, operationId: 'getIndex', mirrors: null,
    summary: 'Lists every operation of this API' },
  { method: 'GET', path: API + '/code', operationId: 'getCodePage',
    mirrors: 'GET /gnap/code',
    summary: 'What the user code page needs: its CSRF token' },
  { method: 'POST', path: API + '/code', operationId: 'enterUserCode',
    mirrors: 'POST /gnap/code',
    summary: 'Spends a user code (RFC 9635 sections 4.1.2 and 4.1.3) and ' +
             'names the approval page it leads to' },
  { method: 'GET', path: API + '/approve/{id}', operationId: 'getApproval',
    mirrors: 'GET /gnap/approve/{id}',
    summary: 'What the approval page asks the signed-in resource owner, as ' +
             'facts, and its CSRF token' },
  { method: 'POST', path: API + '/approve/{id}', operationId: 'answerApproval',
    mirrors: 'POST /gnap/approve/{id}',
    summary: 'The resource owner\'s answer: the rights left ticked, the ' +
             'limits as lowered, and whether to say who they are' }
];

/**
 * The pages a GNAP resource owner sees: the four start modes, sign-in through
 * the one authentication service, the approval page, and the finish that tells
 * the client (RFC 9635 section 4).
 */
class GnapInteract {
  /**
   * Builds the interaction pages from the modules they read.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: GnapInteractDeps) {
    deps.log.debug("Entering GnapInteract.constructor().");
    deps.log.debug("Leaving GnapInteract.constructor().");
  }

  // -------------------------------------------------------------------------
  // THE SHELL (#578), drawn by `common/shell_document.ts` on 3cl's recipe:
  // ONE document for every page a person reads here, loading the surface's
  // script and the card from `/web/card.css`. Where a response only SAYS
  // something — a refused link, a decision made, a request sent to its
  // owner — the page's view travels in `data-sts-state` (`kerberos/
  // spnego_authn.ts`'s arrangement, #575), because it exists only on this
  // response and there is nothing the runtime could fetch it from. The
  // status is the caller's, so a refusal is still the 400 it always was.
  //
  // The policy: `script-src 'self'` (the bundle), `connect-src 'self'` and
  // the sign-in service's origin where it is on another listener (the
  // language chooser posts to `/authn/language`, #472), `style-src 'self'`
  // (the card, nothing inline), through `app.contentSecurityPolicy()`, so
  // `frame-ancestors` cannot be dropped. `img-src` stays the service's, which
  // allows the `data:` logo the approval page may draw.
  //
  // `application` is the client instance's application entry, for the
  // locale policy's default (`PageLocale.shellAttributes()`), as the pages
  // were drawn for it; `own` a signed-in person's own language.
  // -------------------------------------------------------------------------
  private sendShell(res: Res, status: number, view: Json,
                    application: string, own?: Json): void {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.sendShell(). " +
              (view ? String(view.kind) : 'fetched'));
    const req: any = (res as any).req || { headers: {} };
    const authnAt = this.authnElsewhere(req);
    const state = view ? JSON.stringify(Object.assign({ view: view },
      own && own.value ? { preferredLanguage: own } : {})) : '';
    const html = ShellDocument.document({
      title: 'GNAP authorization server — IYA STS',
      attributes: ([['data-sts-prefix', realms.currentPrefix()],
                    ['data-sts-authn', authnAt],
                    ['data-sts-state', state]] as Array<[string, string]>)
        .concat(PageLocale.shellAttributes(req, application || '')),
      stylesheets: ['/web/card.css'],
      script: SCRIPT_PATH,
      open: '<div class="card gnap">',
      close: '</div>',
      noscript: '<h1>GNAP authorization</h1><div class="err">This page is ' +
        'a script that runs in your browser, and with scripts blocked ' +
        'there is nothing it can show. Allow scripts for this page to ' +
        'answer the application that sent you here.</div>',
      loading: '<p class="sub">Loading&hellip;</p>'
    });
    // error-code: none — the shell's own send; a refusal's code is marked by its caller (interactionError()) first.
    res.status(status)
       .type('text/html')
       .set('Cache-Control', 'no-store')
       .set('Content-Security-Policy', ShellDocument.policy(app, {
         connect: ShellDocument.originsOf([authnAt]),
         csp: { 'style-src': "'self'" } }))
       .send(html);
    log.debug("Leaving GnapInteract.sendShell().");
  }

  // The sign-in service's base where this listener does not answer it, for
  // the language chooser (`home/home.ts`'s `authnElsewhere()`).
  private authnElsewhere(req: Json): string {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.authnElsewhere().");
    let out = '';
    try {
      out = listenerMap.isTrivial() ||
        listenerMap.admits(listenerMap.listenerOf(req), 'authn')
        ? '' : helpers.baseUrlOf(req, 'authn');
    } catch (e) {
      log.debug("Caught in GnapInteract.authnElsewhere(): " +
                ((e && e.message) || e));
      // A request no listener map can place (an in-process caller): the
      // chooser posts here, as it does on every trivial map.
      out = '';
    }
    log.debug("Leaving GnapInteract.authnElsewhere(). " + (out || 'here'));
    return out;
  }

  // Whether the response is an act or a view on `/gnap-api`, which answers
  // JSON where a page answers the shell.
  private static answersJson(res: Res): boolean {
    helpers.log.debug("Entering GnapInteract.answersJson().");
    helpers.log.debug("Leaving GnapInteract.answersJson().");
    return !!(res.locals && res.locals.gnapApi);
  }

  // An answer of `/gnap-api`: JSON, never stored.
  private answer(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.answer(). " + status);
    // error-code: none — the API's own send; every refusal's code is marked by apiRefusal() or interactionError() first.
    res.status(status)
       .set('Cache-Control', 'no-store')
       .type('application/json')
       .send(JSON.stringify(body));
    log.debug("Leaving GnapInteract.answer().");
  }

  // A refusal of `/gnap-api` that leaves the page standing: `{ ok: false,
  // errors }` in English, and the page drawn again with the sentence over
  // it (a CSRF token gone stale, a malformed body, a raised limit). The code
  // is recorded, never sent.
  // error-code: none — the helper's definition; every caller passes its STS-GNAP code.
  private apiRefusal(res: Res, status: number, code: string,
                     why: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapInteract.apiRefusal(). " + status);
    errorCodes.mark(res, code);
    this.answer(res, status, { ok: false, errors: [why] });
    log.debug("Leaving GnapInteract.apiRefusal().");
  }

  // Section 4.1.1/4.1.2: a URI or code that names no active request gets an
  // error SHOWN, and the browser is NEVER sent back to any client. On a page
  // the shell carries it (400, as before); on `/gnap-api` the answer carries
  // it as a view the runtime draws in place of the page.
  // error-code: none — the helper's definition, not a call to it.
  private interactionError(res: Res, code: string, heading: string,
                           detail: string): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapInteract.interactionError().");
    errorCodes.mark(res, code);
    const view = { kind: 'problem', heading: heading, detail: detail };
    if (GnapInteract.answersJson(res)) {
      // error-code: none — marked on the first line of this helper.
      this.answer(res, 400, { ok: false, errors: [detail], view: view });
      log.debug("Leaving GnapInteract.interactionError(). JSON.");
      return;
    }
    // error-code: none — the helper's own send; every caller passes its STS-GNAP code, marked above.
    this.sendShell(res, 400, view, '');
    log.debug("Leaving GnapInteract.interactionError().");
  }

  private activeForInteraction(grant: any): boolean {
    const { log, store, nowSec } = this.deps;
    log.debug("Entering GnapInteract.activeForInteraction().");
    log.debug("Leaving GnapInteract.activeForInteraction().");
    return grant && grant.state === store.STATE.PENDING &&
      grant.interaction && !grant.interaction.decided &&
      grant.interaction.expiresAt >= nowSec();
  }

  // -------------------------------------------------------------------------
  // START MODES. Each spends itself and forwards to the one approval page.
  // -------------------------------------------------------------------------
  // ASYNCHRONOUS SINCE 2026-09-14 (#46): a start link is spent through
  // `store.spend()` before it is honoured, so two nodes cannot both follow
  // one. The handler is wrapped in `settled()` so a defect is a coded 500
  // rather than an unhandled rejection, which is what `gnap.ts`'s `guarded()`
  // does for the JSON endpoints.
  private startMode(mode: string): Handler {
    const self = this;
    const { log, validation, store, nowSec } = this.deps;
    log.debug("Entering GnapInteract.startMode().");
    log.debug("Leaving GnapInteract.startMode().");
    return this.settled('the GNAP ' + mode + ' start',
                        async function (req, res) {
      log.debug("Entering the GNAP " + mode + " start.");
      const params = validation.checkParsed({ id: req.params.id }, 'params',
                                            ID_PARAMS);
      // WHICH CELL (#98): the grant is pulled to the cell this browser is
      // pinned to, or the request relayed to the cell it moved to — before
      // the link is spent (`gnap_cells.ts`).
      if (params.ok && await gnapCells.placeInteraction(req, res, mode + ':' +
                                                        params.value.id)) {
        log.debug("Leaving the GNAP " + mode + " start. Relayed.");
        return undefined;
      }
      const grant: any = params.ok ?
        store.grantByInteraction(mode + ':' + params.value.id) : null;
      if (!self.activeForInteraction(grant)) {
        log.debug("Leaving the GNAP " + mode + " start. No active request.");
        return self.interactionError(res, 'STS-GNAP-0400',
          'This link is not active',
          'The link does not belong to a request that is still waiting for ' +
          'approval — it may have expired, been used already, or been ' +
          'answered.');
      }
      const one = grant.interaction.modes[mode];
      if (!one || one.used || one.id !== params.value.id) {
        log.debug("Leaving the GNAP " + mode + " start. Already used.");
        return self.interactionError(res, 'STS-GNAP-0401', 'This link has ' +
                                     'already been used',
          'Each interaction link works once (RFC 9635 section 4).');
      }
      // ONCE ACROSS THE CLUSTER (#46): `one.used` is a field on a replicated
      // grant, so another node still reading the grant before this start
      // would follow the same link. Claimed for the interaction's own
      // lifetime.
      const spent: any = await store.spend('interaction', mode + ':' +
                                           params.value.id,
                                           grant.interaction.expiresAt -
                                             nowSec(),
                                           'STS-GNAP-0712');
      if (!spent.ok) {
        log.debug("Leaving the GNAP " + mode + " start. Spent elsewhere.");
        return self.interactionError(res, spent.reason === 'used' ?
                                     'STS-GNAP-0712' : 'STS-GNAP-0716',
                                     'This link has already been used',
          'Each interaction link works once (RFC 9635 section 4).');
      }
      one.used = true;
      grant.interaction.started = grant.interaction.started || mode;
      store.dropInteraction(mode + ':' + params.value.id);
      store.saveGrant(grant, 'interaction started by ' + mode);
      log.debug("Leaving the GNAP " + mode + " start. To the approval page.");
      return res.set('Cache-Control', 'no-store')
                .redirect(303, '/gnap/approve/' +
                               grant.interaction.approvalId);
    });
  }

  // THE APPROVAL PAGE, PLACED FIRST (#98): the grant waiting at the handle is
  // pulled to the cell this browser is pinned to, or the request relayed to
  // the cell it moved to (`gnap_cells.ts`), and then the page is the page it
  // always was. Wrapped in `settled()` for its reason: a defect in the
  // placement is a coded page, not an unhandled rejection.
  private placed(name: string, handler: Handler): Handler {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.placed().");
    log.debug("Leaving GnapInteract.placed().");
    return this.settled(name, async function (req, res, next) {
      const relayed = await gnapCells.placeInteraction(req, res, 'approve:' +
        String((req.params && req.params.id) || ''));
      if (relayed) {
        return undefined;
      }
      return handler(req, res, next);
    });
  }

  // An asynchronous page handler, with its failure caught and coded.
  private settled(name: string, handler: Handler): Handler {
    const self = this;
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapInteract.settled().");
    log.debug("Leaving GnapInteract.settled().");
    return function (req, res, next) {
      Promise.resolve().then(function () {
        return handler(req, res, next);
      }).catch(function (e) {
        log.debug("Caught in GnapInteract.settled(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-GNAP-0160') + 'gnap: ' + name +
                  ' failed: ' + ((e && e.stack) || e));
        if (!res.headersSent) {
          self.interactionError(res, 'STS-GNAP-0160', 'Something went wrong',
                                'The request could not be completed.');
        }
      });
    };
  }

  // -------------------------------------------------------------------------
  // THE APPROVAL PAGE'S VIEW (#578): facts and no words — the browser draws
  // them in its language from the `gnap` catalogs #539 wrote for this page
  // (`web_gnap_interact_views.ts`). The dimension names and values are the
  // request's own (RFC 9635 section 8), and stay as they are.
  // -------------------------------------------------------------------------
  private rightFacts(right: any): Json {
    const { log, store } = this.deps;
    log.debug("Entering GnapInteract.rightFacts().");
    if (typeof right === 'string') {
      const registered: any = store.resourceByReference(right);
      log.debug("Leaving GnapInteract.rightFacts(). A reference.");
      return { reference: right, registered: registered ? {
        rs: String(registered.rsIdentifier || ''),
        access: (registered.access || []).map(function (one: any): string {
          return String(typeof one === 'string' ? one : one.type);
        }) } : null };
    }
    const dimensions: Json[] = [];
    ['actions', 'datatypes', 'locations', 'privileges'].forEach(
        function (dimension) {
      if (right[dimension] && right[dimension].length) {
        dimensions.push({ name: dimension,
                          values: right[dimension].map(String) });
      }
    });
    log.debug("Leaving GnapInteract.rightFacts().");
    return { type: String(right.type || ''), dimensions: dimensions,
             identifier: right.identifier ? String(right.identifier) : '' };
  }

  // =========================================================================
  // #432 PHASE 5 ON THE APPROVAL PAGE: A RIGHT'S LIMITS, AND WHOSE RESOURCE IT
  // IS. Kept in these functions, apart from the page's other business.
  //
  // THE LIMITS are drawn under the right they belong to, each member with a
  // meaning (`common/access_limits.ts`) as a control holding the requested
  // value, so the person can LOWER it — section 4 lets the resource owner
  // limit the access they approve, and a limit is the finest-grained way to.
  // A value the person did not change is sent back unchanged and kept
  // byte for byte; a changed one must be LOWER (`AccessLimits.raised()`:
  // STS-GNAP-0866) and the lowered limits must still meet the type's limits
  // schema (0867). A member this service gives no meaning is shown and not
  // editable. The view carries the limits and their rows, the browser draws
  // the controls (`common/web_limits_form.ts`), and they come back as the
  // act's `lim_*` members (#578).
  //
  // THE OWNERSHIP CHECK runs before the page is drawn and again before an
  // approval is recorded: `grants.approverRefusal()` puts the rights whose
  // identifier somebody else owns to the issuance policy, and a refusal is
  // the page's refusal (STS-GNAP-0862) — RFC 9635 section 1.4: only the
  // resource owner authorizes access to their resource.
  // =========================================================================

  // The ticked rights with the limits the person sent back: `{ ok: true,
  // tokens }`, or `{ ok: false, code, why }`. The body is the act's JSON: a
  // repeated control (a receiver's checkboxes) an array where several are
  // ticked, a string where one is.
  private loweredTokens(body: any, grant: any, tokens: any[]): any {
    const { log, rights } = this.deps;
    log.debug("Entering GnapInteract.loweredTokens().");
    log.debug("Leaving GnapInteract.loweredTokens().");
    return LimitsForm.lowered(grant.request.tokens, tokens, {
      value: function (name: string): string | undefined {
        return typeof body[name] === 'string' ? body[name] : undefined;
      },
      values: function (name: string): string[] {
        return GnapInteract.listOf(body[name]);
      }
    }, rights.conformanceRefusal);
  }

  // A repeated control's values: an array, one string, or none.
  private static listOf(value: unknown): string[] {
    helpers.log.debug("Entering GnapInteract.listOf().");
    helpers.log.debug("Leaving GnapInteract.listOf().");
    if (Array.isArray(value)) {
      return value.map(String);
    }
    return typeof value === 'string' && value !== '' ? [value] : [];
  }

  // The limit controls of an act, held to their own bound before
  // `LimitsForm.strip()` takes them off for the schema: a name of the
  // controls' shape, and a short string or a short list of them. '' where
  // they are all well formed, or the sentence that refuses them.
  private static limitFieldsRefusal(body: Json): string {
    helpers.log.debug("Entering GnapInteract.limitFieldsRefusal().");
    const bad = Object.keys(body || {}).filter(function (key) {
      if (!/^lim_/.test(key)) {
        return false;
      }
      const value = body[key];
      const short = function (one: unknown): boolean {
        return typeof one === 'string' && one.length <= LIMIT_VALUE_MAX;
      };
      return !LIMIT_FIELD.test(key) ||
        !(short(value) || (Array.isArray(value) &&
                           value.length <= LIMIT_VALUES_MAX &&
                           value.every(short)));
    });
    helpers.log.debug("Leaving GnapInteract.limitFieldsRefusal(). " +
                      bad.length);
    return bad.length ? 'A limit control is not one this page draws, or ' +
      'carries more than a limit can: ' + bad.slice(0, 3).join(', ') + '.'
      : '';
  }

  // -------------------------------------------------------------------------
  // The ownership check: true when the page has refused (and answered).
  // -------------------------------------------------------------------------
  private async ownershipRefused(req: Req, res: Res, grant: any,
                                 session: any): Promise<boolean> {
    const { log, grants } = this.deps;
    log.debug("Entering GnapInteract.ownershipRefused().");
    const refused: any = await grants.approverRefusal(req, grant,
                                                      session.user.username);
    if (!refused) {
      log.debug("Leaving GnapInteract.ownershipRefused(). The owner.");
      return false;
    }
    this.interactionError(res, 'STS-GNAP-0862', 'You cannot approve this ' +
      'request', 'It asks for access to a resource that is not yours to ' +
      'give: ' + String(refused.why || '') + ' Only its owner can approve ' +
      'it.');
    log.debug("Leaving GnapInteract.ownershipRefused(). Refused.");
    return true;
  }

  /**
   * The approval page's view: who is asking, for what, and what follows.
   *
   * @param grant - the grant waiting at the page
   * @param session - the signed-in resource owner's session
   * @returns the view
   */
  approvalView(grant: any, session: any): Json {
    const self = this;
    const { log } = this.deps;
    log.debug("Entering GnapInteract.approvalView().");
    const display = grant.client.display || {};
    // ---------------------------------------------------------------------
    // WHAT THE CLIENT SAID ABOUT ITSELF IS SAID TO BE ITS OWN CLAIM (#432
    // phase 7). A name, home page or logo the application ENTRY does not
    // carry came from the request, which any key can send (section 2.3;
    // `gnap_grants.ts`'s displayOf()). It is still drawn — a person needs
    // something to recognise — but beside the words "as it describes
    // itself", and the registered identifier is always shown; a self-declared
    // logo is not drawn at all, because a picture cannot carry that caveat
    // and a borrowed logo is the cheapest impersonation there is. So the
    // view carries a logo only where the page may draw it.
    // ---------------------------------------------------------------------
    const declared: string[] = Array.isArray(display.declared)
      ? display.declared : [];
    const logo = display.logoUri && declared.indexOf('logoUri') < 0 &&
      /^data:image\//i.test(display.logoUri) ? String(display.logoUri) : '';
    const many = grant.request.tokens.length > 1;
    const tokens = grant.request.tokens.map(function (token: any,
                                                      ti: number): Json {
      return {
        label: String(token.label || ''), number: ti + 1,
        bearer: !!token.bearer, heading: many || !!token.label,
        rights: token.access.map(function (right: any, r: number): Json {
          // A right's LIMITS as facts: the member and the rows
          // `AccessLimits.rows()` makes of it, from which the browser draws
          // the controls a person may lower (`common/web_limits_form.ts`,
          // the consent screen's since #576), named `lim_t<k>r<r>_<member>`
          // as `LimitsForm.lowered()` reads them back.
          const limited = right && typeof right === 'object' &&
            right.limits && typeof right.limits === 'object';
          return { field: 't' + ti + 'r' + r, token: ti, index: r,
                   right: self.rightFacts(right),
                   limits: limited ? right.limits : null,
                   limitRows: limited ? AccessLimits.rows(right.limits)
                                      : [] };
        })
      };
    });
    // WHAT THE ISSUANCE POLICY NARROWED BEFORE THIS PAGE WAS DRAWN (#432
    // phase 3): the rights above are already the narrowed ones, and the
    // person is told what was taken off and that it was not their choice.
    const narrowed = (Array.isArray(grant.narrowed) ? grant.narrowed : [])
      .map(function (one: any): Json {
        const before = one.before || {};
        const after = one.after || {};
        const changes: Json[] = [];
        ['actions', 'locations', 'datatypes', 'privileges'].forEach(
            function (dim: string): void {
          const was = Array.isArray(before[dim]) ? before[dim] : null;
          const now = Array.isArray(after[dim]) ? after[dim] : [];
          const off = was ? was.filter(function (v: string): boolean {
            return now.indexOf(v) < 0;
          }) : [];
          if (off.length) {
            changes.push({ how: 'removed', dimension: dim,
                           values: off.map(String) });
          } else if (!was && now.length) {
            changes.push({ how: 'limited', dimension: dim,
                           values: now.map(String) });
          }
        });
        return { type: String(one.type || ''), changes: changes };
      });
    const subjectAsked = grant.request.subject &&
      (grant.request.subject.subIdFormats.length ||
       grant.request.subject.assertionFormats.length);
    const finish = grant.interaction.finish;
    const view = {
      kind: 'approve',
      id: String(grant.interaction.approvalId),
      username: String(session.user.username || ''),
      client: {
        identifier: String(grant.client.identifier || ''),
        name: String(display.name || grant.client.identifier || ''),
        nameDeclared: declared.indexOf('name') >= 0,
        uri: display.uri ? String(display.uri) : '',
        uriDeclared: declared.indexOf('uri') >= 0,
        logo: logo,
        proof: String(grant.client.proof || ''),
        classId: grant.client.classId ? String(grant.client.classId) : '',
        classIdDeclared: !!grant.client.classIdDeclared
      },
      tokens: tokens,
      narrowed: narrowed,
      subject: subjectAsked ? {
        ids: grant.request.subject.subIdFormats.map(String),
        assertions: grant.request.subject.assertionFormats.map(String)
      } : null,
      finish: finish ? { method: String(finish.method),
                         uri: String(finish.uri || '') } : null,
      grantEndpoint: String(grant.grantEndpoint || '')
    };
    log.debug("Leaving GnapInteract.approvalView().");
    return view;
  }

  /**
   * What is said once a decision is made and the finish followed, where
   * the finish sent the browser nowhere.
   *
   * @param grant - the decided grant
   * @param finished - `grants.finishInteraction()`'s answer
   * @returns the view
   */
  doneView(grant: any, finished: any): Json {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.doneView().");
    log.debug("Leaving GnapInteract.doneView().");
    return { kind: 'done',
             approved: !!(grant.decision && grant.decision.approved),
             pushed: finished && finished.pushed === true ? true
               : (finished && finished.pushed === false ? false : null),
             name: String((grant.client.display &&
                           grant.client.display.name) ||
                          grant.client.identifier || '') };
  }

  // What the browser sees once the decision is made and the finish followed:
  // the finish URI where the finish method sends it back — a 303 from a
  // page, `location` from an act on `/gnap-api`, the same address — and the
  // done page otherwise.
  private afterDecision(res: Res, grant: any, finished: any): unknown {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.afterDecision().");
    if (finished.redirect) {
      log.debug("Leaving GnapInteract.afterDecision(). The finish URI.");
      if (GnapInteract.answersJson(res)) {
        return this.answer(res, 200, { ok: true, next: 'redirect',
                                       location: finished.redirect });
      }
      // Section 11.19: 303, so a POST carrying the form is not replayed at the
      // client's callback.
      return res.set('Cache-Control', 'no-store')
                .redirect(303, finished.redirect);
    }
    // THE LANGUAGE (#539), for the client's application: the shell's
    // locale policy default. No GET draws this page again, so it travels
    // in the shell's state.
    const view = this.doneView(grant, finished);
    log.debug("Leaving GnapInteract.afterDecision().");
    if (GnapInteract.answersJson(res)) {
      return this.answer(res, 200, { ok: true, next: 'done', view: view });
    }
    return this.sendShell(res, 200, view,
                          String(grant.client.identifier || ''));
  }

  // -------------------------------------------------------------------------
  // ONE DECISION PER INTERACTION ACROSS THE CLUSTER (2026-09-14, #46
  // follow-up).
  //
  // `activeForInteraction()` refuses a grant whose `interaction.decided` is
  // set, and that field is on a REPLICATED grant: two answers to one approval
  // page — a double submit, or the same form posted to two nodes — each found
  // the grant undecided, each recorded a decision, each enacted the finish
  // method, and the grant kept whichever write landed last, possibly a denial
  // after the client had been told of an approval. So a decision is claimed
  // through `store.spend()` for the interaction's own lifetime before it is
  // recorded; the second is refused (`STS-GNAP-0717`, or `STS-GNAP-0716` when
  // the store cannot be asked), and a decision that then fails to complete
  // gives its claim back. Resolves to the claim, or null once the refusal has
  // been answered.
  // -------------------------------------------------------------------------
  private async claimDecision(res: Res, grant: any): Promise<any> {
    const { log, store, nowSec } = this.deps;
    log.debug("Entering GnapInteract.claimDecision().");
    const spent: any = await store.spend('decision', grant.id + ':' +
                                         grant.interaction.approvalId,
                                         grant.interaction.expiresAt -
                                           nowSec(),
                                         'STS-GNAP-0717');
    if (!spent.ok) {
      this.interactionError(res, spent.reason === 'used' ? 'STS-GNAP-0717' :
                            'STS-GNAP-0716',
                            'This request has already been answered',
        'An answer to this request has already been recorded — on this page ' +
        'in another tab, or by a second submission of it. It is answered ' +
        'once.');
      log.debug("Leaving GnapInteract.claimDecision(). Refused.");
      return null;
    }
    log.debug("Leaving GnapInteract.claimDecision(). Claimed.");
    return spent;
  }

  // ---------------------------------------------------------------------------
  // WHICH ACCOUNT, WHERE THE BROWSER HOLDS SEVERAL (#561). Two hints, both
  // SOFT (`authn.hintAccount()`): the session this approval page was first
  // drawn for, recorded on the interaction (`accountSid`) so that the
  // page's own `/gnap-api` calls — which carry no selection ticket — act as
  // the account the GET resolved; and the grant request's `user`
  // (`userHint`, RFC 9635 section 2.4), the subject the client named.
  // Soft, because a person at the browser who is not that user is a case
  // with a meaning of its own here (#432's owner approval), not a reason to
  // send them to sign in. A sid names a session only in THIS browser's set,
  // whose cookie proves the browser holds it. Nothing changes with
  // `authn.multipleAccounts` off.
  // ---------------------------------------------------------------------------
  private hintAccountFor(req: Req, grant: any): void {
    const { log, authn } = this.deps;
    log.debug("Entering GnapInteract.hintAccountFor().");
    authn.hintAccount(req, {
      sid: String((grant.interaction && grant.interaction.accountSid) || ''),
      loginHint: String(grant.userHint || ''), soft: true });
    log.debug("Leaving GnapInteract.hintAccountFor().");
  }

  // The session the approval page was drawn for, recorded on the
  // interaction for the page's own calls (above). Only with the setting on,
  // so a grant is otherwise written exactly as it was.
  private noteAccountFor(grant: any, session: any): void {
    const { log, authn, store } = this.deps;
    log.debug("Entering GnapInteract.noteAccountFor().");
    if (authn.multipleAccounts() && session && grant.interaction &&
        grant.interaction.accountSid !== session.id) {
      grant.interaction.accountSid = String(session.id);
      store.saveGrant(grant);
    }
    log.debug("Leaving GnapInteract.noteAccountFor().");
  }

  private approvalGrant(req: Req, res: Res): any {
    const { log, validation, store } = this.deps;
    log.debug("Entering GnapInteract.approvalGrant().");
    const params = validation.checkParsed({ id: req.params.id }, 'params',
                                          ID_PARAMS);
    const grant: any = params.ok ?
      store.grantByInteraction('approve:' + params.value.id) : null;
    if (!this.activeForInteraction(grant) || !grant.interaction.started) {
      this.interactionError(res, 'STS-GNAP-0406',
        'This request is not waiting for you',
        'There is no request waiting for approval at this address, or it ' +
        'was already answered or has expired.');
      log.debug("Leaving GnapInteract.approvalGrant().");
      return null;
    }
    log.debug("Leaving GnapInteract.approvalGrant().");
    return grant;
  }

  // The client's interact.acr, or undefined when that member was not
  // sent (#738). Classification is GnapRequest.interactAcrDemand().
  private interactAcrOf(grant: any): any {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.interactAcrOf().");
    const interact = grant && grant.request && grant.request.interact;
    const acr = interact ? interact.acr : undefined;
    log.debug("Leaving GnapInteract.interactAcrOf(). " +
              (acr === undefined ? 'absent' : 'sent'));
    return acr;
  }

  // -------------------------------------------------------------------------
  // #432 PHASE 6, IN TWO CALLS FROM THE APPROVAL ROUTES (`gnap_approval.ts`
  // argues both). `beforeApproval()` decides SYNCHRONOUSLY whether it
  // answers — so the route's own shape is unchanged — and does the
  // asynchronous work itself, answering the page or a coded error:
  //
  //   * the person here is not the user the request named, and approval by
  //     an absent owner is on: the grant goes to that owner's portal and the
  //     interaction finishes (`grants.forwardToOwner()`);
  //   * the session does not meet every acr the requested rights need, or
  //     an interact.acr demand (#738): the person signs in again, once,
  //     with what the screen must demand — and back here still short, the
  //     request is refused `request_denied` (`grants.refuseUnmetStepUp()`,
  //     STS-GNAP-0899, or STS-GNAP-0905 when interact.acr is what came
  //     back unmet). One trip for both; the return marker covers both.
  // -------------------------------------------------------------------------
  private beforeApproval(req: Req, res: Res, grant: any, session: any,
                         honoured: boolean): boolean {
    const self = this;
    const { log, grants, approval, authn, errorCodes } = this.deps;
    log.debug("Entering GnapInteract.beforeApproval().");
    const present = String(session.user.username || '').toLowerCase();
    if (grant.userHint && String(grant.userHint).toLowerCase() !== present &&
        approval.available()) {
      this.claimDecision(res, grant).then(function (claimed) {
        if (!claimed) {
          return undefined;
        }
        return grants.forwardToOwner(req, grant, session)
          .then(function (out: any) {
            if (out && out.finished && out.finished.redirect) {
              return res.set('Cache-Control', 'no-store')
                        .redirect(303, out.finished.redirect);
            }
            if (!out || !out.queued) {
              errorCodes.mark(res, (grant.decision && grant.decision.code) ||
                              'STS-GNAP-0897');
              return self.afterDecision(res, grant,
                                        (out && out.finished) || {});
            }
            // In the reader's language (#539): the client's application's
            // default and the person's own. No GET draws this page again,
            // so its view travels in the shell (#578).
            return self.sendShell(res, 200, { kind: 'sent' },
              String(grant.client.identifier || ''),
              authn.preferredLanguageOf(String(session.user.username || '')));
          });
      }).catch(function (e) {
        log.debug("Caught in GnapInteract.beforeApproval(): " +
                  ((e && e.message) || e));
        log.error(errorCodes.tag('STS-GNAP-0409') + 'gnap: a grant could ' +
                  'not be sent to its owner: ' + ((e && e.stack) || e));
        if (!res.headersSent) {
          self.interactionError(res, 'STS-GNAP-0409', 'Something went wrong',
                                'The request could not be completed.');
        }
      });
      log.debug("Leaving GnapInteract.beforeApproval(). To the owner.");
      return true;
    }
    const assessed = approval.assess(approval.requiredAcr(grant), session,
                                     this.interactAcrOf(grant));
    if (assessed.met) {
      log.debug("Leaving GnapInteract.beforeApproval(). Nothing to do.");
      return false;
    }
    if (!honoured) {
      res.set('Cache-Control', 'no-store')
         .redirect(303, authn.beginAuthentication({
        returnTo: '/gnap/approve/' + grant.interaction.approvalId +
                  '?step_up_honoured=1',
        protocol: 'GNAP',
        application: grant.client.identifier,
        hint: session.user.username,
        forceMfa: !!assessed.forceMfa, forceKey: !!assessed.forceKey,
        phishingClass: assessed.phishingClass || '',
        details: [
          { label: 'Application',
            value: (grant.client.display && grant.client.display.name) ||
                   grant.client.identifier },
          { label: 'Protocol', value: 'GNAP (RFC 9635)' },
          { label: 'Sign-in level needed', value: assessed.ask.join(' ') }
        ]
      }));
      log.debug("Leaving GnapInteract.beforeApproval(). Stepping up.");
      return true;
    }
    // 0905 when the class is what came back unmet, including when a
    // catalogue acr is unmet on the same return. 0899 when only the
    // catalogue is short: interact.acr was absent, mixed, or already met.
    const code = assessed.eapUnmet ? 'STS-GNAP-0905' : 'STS-GNAP-0899';
    this.claimDecision(res, grant).then(function (claimed) {
      if (!claimed) {
        return undefined;
      }
      return grants.refuseUnmetStepUp(req, grant, session, assessed.missing,
                                      code)
        .then(function (finished: any) {
          errorCodes.mark(res, code);
          return self.afterDecision(res, grant, finished);
        });
    }).catch(function (e) {
      log.debug("Caught in GnapInteract.beforeApproval(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-GNAP-0409') + 'gnap: an unmet step-up ' +
                'could not be answered: ' + ((e && e.stack) || e));
      if (!res.headersSent) {
        self.interactionError(res, 'STS-GNAP-0409', 'Something went wrong',
                              'The request could not be completed.');
      }
    });
    log.debug("Leaving GnapInteract.beforeApproval(). Refused: unmet.");
    return true;
  }

  // The rights left ticked need an acr the session does not meet: back to
  // the page, which steps the person up (#432 phase 6) — the act answers
  // `next: page`, the page's own address. True when answered.
  private stepUpOwed(res: Res, grant: any, session: any,
                     ticked: string[]): boolean {
    const { log, approval } = this.deps;
    log.debug("Entering GnapInteract.stepUpOwed().");
    const assessed = approval.assess(approval.requiredAcr(grant, ticked),
                                     session, this.interactAcrOf(grant));
    if (assessed.met) {
      log.debug("Leaving GnapInteract.stepUpOwed(). Met.");
      return false;
    }
    this.toPage(res, grant);
    log.debug("Leaving GnapInteract.stepUpOwed(). Back to the page.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // BACK TO THE PAGE (#578). Everything the approval page's GET answers with
  // a redirect — the sign-in screen, a step-up, the finish after a remembered
  // approval, a grant sent to its owner — is that GET's to do, because those
  // redirects are what a browser at the page has always been sent. So where
  // `/gnap-api` meets one of them it answers `{ ok: true, next: 'page',
  // location }`, the page's own address, and the browser loads it.
  // ---------------------------------------------------------------------------
  private toPage(res: Res, grant: any): void {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.toPage().");
    this.answer(res, 200, { ok: true, next: 'page',
      location: realms.currentPrefix() + '/gnap/approve/' +
                grant.interaction.approvalId });
    log.debug("Leaving GnapInteract.toPage().");
  }

  // The token for the session behind this request's cookie, or '' where
  // there is none (`authn/authn_api.ts`'s `csrfOf()`).
  private csrfOf(req: Req): string {
    const { log, authn, websecurity } = this.deps;
    log.debug("Entering GnapInteract.csrfOf().");
    const found: any = authn.cookieSession(req, authn.SESSION_COOKIE);
    const token = found && found.id ? websecurity.tokenFor(found.id) : '';
    log.debug("Leaving GnapInteract.csrfOf(). " + (token ? 'A session.'
                                                         : 'No session.'));
    return token;
  }

  // ---------------------------------------------------------------------------
  // THE BINDING OF AN ACT (#578), `/authn-api`'s three (#571): a JSON body,
  // which a cross-site form cannot send; an `Origin` this service answers
  // on (`cors.ownOrigins()`); and `X-CSRF-Token`, the token of the
  // `sts_session` cookie's session — derived, not stored, and answered by
  // the views (`csrf`). Every shell path mints that cookie where a browser
  // arrives without one (`authn.ts`'s ARRIVAL_PATHS), so a request with no
  // session is refused here rather than let through as `checkCsrf()` lets
  // one through.
  //
  // A REQUEST RELAYED FROM ANOTHER CELL (#98) was bound where it arrived:
  // `req.stsCellRelay` is set only by the cell channel on a peer's
  // authenticated relay, and the browser's Origin and cookie are not this
  // cell's to judge again.
  //
  // Asked BEFORE anything is looked up, so a request that is not bound
  // learns nothing about which handles or codes are live.
  // ---------------------------------------------------------------------------
  private bound(req: Req, res: Res): boolean {
    const { log, cors, stsCrypto } = this.deps;
    log.debug("Entering GnapInteract.bound().");
    if ((req as any).stsCellRelay) {
      log.debug("Leaving GnapInteract.bound(). Relayed; bound where it " +
                "arrived.");
      return true;
    }
    const type = String((req.headers && req.headers['content-type']) || '');
    if (!/^application\/json\s*(;|$)/i.test(type)) {
      this.apiRefusal(res, 415, 'STS-GNAP-0410', 'This operation takes a ' +
                      'JSON body (Content-Type: application/json).');
      log.debug("Leaving GnapInteract.bound(). Not JSON.");
      return false;
    }
    const origin = String((req.headers && req.headers.origin) || '');
    let own: string[] = [];
    try {
      own = cors.ownOrigins(req) || [];
    } catch (e) {
      log.debug("Caught in GnapInteract.bound(): " + ((e && e.message) || e));
      own = [];
    }
    if (!origin || own.indexOf(origin) < 0) {
      this.apiRefusal(res, 403, 'STS-GNAP-0411', 'This operation is sent ' +
        'by a page of this service: the request carried ' +
        (origin ? 'another origin' : 'no Origin') + '.');
      log.debug("Leaving GnapInteract.bound(). Not this origin.");
      return false;
    }
    const expected = this.csrfOf(req);
    const presented = String((req.headers && req.headers[CSRF_HEADER]) || '');
    if (!expected || !presented ||
        !stsCrypto.constantTimeEquals(presented, expected)) {
      this.apiRefusal(res, 403, 'STS-GNAP-0412', expected
        ? 'The ' + CSRF_HEADER + ' header is missing or is not this ' +
          'browser\'s. Load the page again.'
        : 'This browser holds no session for this page. Load the page ' +
          'again.');
      log.debug("Leaving GnapInteract.bound(). The token.");
      return false;
    }
    log.debug("Leaving GnapInteract.bound(). Bound.");
    return true;
  }

  // An operation of `/gnap-api`: its answers are JSON (`answersJson()`),
  // and one turned off with GNAP is refused as the pages were (0402).
  private api(name: string, handler: Handler): Handler {
    const self = this;
    const { log, config } = this.deps;
    log.debug("Entering GnapInteract.api().");
    log.debug("Leaving GnapInteract.api().");
    return function (req, res, next) {
      log.debug("Entering " + name + ".");
      res.locals.gnapApi = true;
      if (config.value('gnap.enabled') === false) {
        self.apiRefusal(res, 400, 'STS-GNAP-0402', 'This trust realm does ' +
                        'not run GNAP (gnap.enabled).');
        log.debug("Leaving " + name + ". Off.");
        return undefined;
      }
      const out = handler(req, res, next);
      log.debug("Leaving " + name + ".");
      return out;
    };
  }

  /**
   * `GET /gnap-api`: the operations, and the page or control each is the
   * door of.
   *
   * @param res - the response
   */
  apiIndex(res: Res): void {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.apiIndex().");
    this.answer(res, 200, { api: 'IYA STS GNAP interaction',
                            operations: OPERATIONS });
    log.debug("Leaving GnapInteract.apiIndex().");
  }

  /**
   * `GET /gnap-api/approve/{id}`: the approval page's view — or `next:
   * page` where the page's GET has a redirect to answer first (no session,
   * a step-up, a grant for its owner, a remembered approval).
   *
   * @param req - the request
   * @param res - the response
   * @returns a promise settled when the answer is sent
   */
  async apiApprovalView(req: Req, res: Res): Promise<void> {
    const { log, authn, approval, grants } = this.deps;
    log.debug("Entering GnapInteract.apiApprovalView().");
    const grant = this.approvalGrant(req, res);
    if (!grant) {
      log.debug("Leaving GnapInteract.apiApprovalView(). No grant.");
      return;
    }
    this.hintAccountFor(req, grant);
    const session: any = authn.sessionOf(req);
    const present = session
      ? String(session.user.username || '').toLowerCase() : '';
    if (!session ||
        (grant.userHint && String(grant.userHint).toLowerCase() !== present &&
         approval.available()) ||
        !approval.assess(approval.requiredAcr(grant), session,
                         this.interactAcrOf(grant)).met ||
        grants.rememberedFor(grant, session.user.username)) {
      this.toPage(res, grant);
      log.debug("Leaving GnapInteract.apiApprovalView(). The page's GET " +
                "answers first.");
      return;
    }
    // #432 phase 5, asked again here as the page asked it before drawing.
    if (await this.ownershipRefused(req, res, grant, session)) {
      log.debug("Leaving GnapInteract.apiApprovalView(). Not the owner.");
      return;
    }
    const own = authn.preferredLanguageOf(String(session.user.username ||
                                                 ''));
    this.answer(res, 200, Object.assign({ ok: true,
      view: this.approvalView(grant, session), csrf: this.csrfOf(req) },
      own ? { preferredLanguage: own } : {}));
    log.debug("Leaving GnapInteract.apiApprovalView().");
  }

  // The routes, in the order this file has always registered them, then the
  // surface's script and `/gnap-api` (#578).
  /**
   * Registers the interaction routes, in the order this file always
   * registered them, then the static surface's script and its API (#578).
   *
   * Called by `common/protocol_stack.ts` after `gnap.ts`'s routes.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, config, validation, parseBody, errorCodes,
            websecurity, grants, store, monitor, authn, nowSec } = this.deps;
    const { notePresented } = authn;
    log.debug("Entering GnapInteract.registerRoutes().");

    app.get('/gnap/interact/:id', self.startMode('redirect'));
    app.get('/gnap/app/:id', self.startMode('app'));

    // THE USER CODE PAGE (sections 4.1.2 and 4.1.3): the shell; the code is
    // sent to `POST /gnap-api/code`.
    app.get('/gnap/code', function (req, res) {
      log.debug("Entering GET /gnap/code.");
      if (config.value('gnap.enabled') === false) {
        log.debug("Leaving GET /gnap/code. Off.");
        return self.interactionError(res, 'STS-GNAP-0402',
                                     'GNAP is turned off',
                                     'This trust realm does not run GNAP ' +
                                     '(gnap.enabled).');
      }
      self.sendShell(res, 200, null, '');
      log.debug("Leaving GET /gnap/code.");
      return undefined;
    });

    // THE SURFACE'S SCRIPT (#578): brotli, gzip or neither, by the request's
    // Accept-Encoding, from the build's precompressed files.
    app.get(SCRIPT_PATH, function (req, res) {
      log.debug("Entering the GNAP interaction surface's script.");
      ShellDocument.sendFile(req, res, self.bundle(),
                             'application/javascript');
      log.debug("Leaving the GNAP interaction surface's script.");
    });

    app.get(API, self.api('GET ' + API, function (req, res) {
      self.apiIndex(res);
    }));

    // The user code page's view: its CSRF token, and the person's own
    // language where somebody is signed in. No client is known until the
    // code is entered.
    app.get(API + '/code', self.api('GET ' + API + '/code',
                                    function (req, res) {
      const session: any = authn.sessionOf(req);
      const own = session && session.user
        ? authn.preferredLanguageOf(String(session.user.username || ''))
        : null;
      self.answer(res, 200, Object.assign({ ok: true, view: { kind: 'code' },
        csrf: self.csrfOf(req) }, own ? { preferredLanguage: own } : {}));
    }));

    app.post(API + '/code', self.api('POST ' + API + '/code',
                                     self.settled('POST ' + API + '/code',
                                                  async function (req, res) {
      log.debug("Entering POST /gnap-api/code.");
      if (!self.bound(req, res)) {
        log.debug("Leaving POST /gnap-api/code. Refused at the door.");
        return undefined;
      }
      const posted = validation.checkParsed(parseBody(req) || {}, 'body',
                                            API_CODE_BODY);
      if (!posted.ok) {
        log.debug("Leaving POST /gnap-api/code. Malformed.");
        return self.apiRefusal(res, 400, 'STS-GNAP-0403',
                               String(posted.detail));
      }
      // Section 4.1.2: "If the AS detects too many unrecognized code enter
      // attempts, the interaction component SHOULD display an error". Counted
      // per address, because the code is what is being guessed and has no
      // owner yet. COUNTED AGAINST ONE BUDGET FOR THE CLUSTER (#46):
      // `attemptShared()`.
      const allowed: any = await websecurity.attemptShared('gnap-user-code',
                                                           req, '');
      if (!allowed.ok) {
        log.debug("Leaving POST /gnap-api/code. Rate limited.");
        return self.apiRefusal(res, 429, errorCodes.codeOf(allowed) ||
                               'STS-GNAP-0404',
                               'Too many codes have been tried from here. ' +
                               allowed.detail);
      }
      const code = grants.normaliseUserCode(posted.value.code);
      // WHICH CELL (#98): a user code carries no tag, so a code this cell
      // does not hold is asked of the others (`gnap_cells.ts`). AFTER the
      // attempt is counted here, deliberately: the count is what stops a
      // guesser making every cell answer every guess; the owning cell counts
      // the relayed attempt again, and a person who types the right code
      // spends one attempt of each budget.
      if (await gnapCells.placeUserCode(req, res, code)) {
        log.debug("Leaving POST /gnap-api/code. Relayed to its cell.");
        return undefined;
      }
      const grant: any = code ? store.grantByUserCode(code) : null;
      const mode = grant && grant.interaction && grant.interaction.modes
        ? (grant.interaction.modes.user_code &&
           grant.interaction.modes.user_code.code === code ? 'user_code'
          : (grant.interaction.modes.user_code_uri &&
             grant.interaction.modes.user_code_uri.code === code
            ? 'user_code_uri' : null)) : null;
      if (!self.activeForInteraction(grant) || !mode) {
        log.debug("Leaving POST /gnap-api/code. Unknown code.");
        return self.apiRefusal(res, 400, 'STS-GNAP-0405', 'That code is ' +
                               'not recognised, or it has expired.');
      }
      // ONCE ACROSS THE CLUSTER (#46). Both user-code modes of a grant are
      // spent together below, so what is claimed is "a user code of this
      // grant was entered" — one claim however the End-User reached it.
      const codeSpent: any = await store.spend('user-code', grant.id,
                                               grant.interaction.expiresAt -
                                                 nowSec(),
                                               'STS-GNAP-0713');
      if (!codeSpent.ok) {
        log.debug("Leaving POST /gnap-api/code. Spent elsewhere.");
        return self.apiRefusal(res, 400, codeSpent.reason === 'used'
          ? 'STS-GNAP-0713' : 'STS-GNAP-0716', 'That code is not ' +
          'recognised, or it has expired.');
      }
      await websecurity.succeededShared('gnap-user-code', req, '',
                                        { keepAddress: true });
      ['user_code', 'user_code_uri'].forEach(function (one) {
        if (grant.interaction.modes[one]) {
          grant.interaction.modes[one].used = true;
        }
      });
      grant.interaction.started = grant.interaction.started || mode;
      store.dropUserCode(code);
      store.saveGrant(grant, 'interaction started by ' + mode);
      log.debug("Leaving POST /gnap-api/code. To the approval page.");
      // The approval page's own address: its GET signs the person in.
      return self.toPage(res, grant);
    })));

    app.get(API + '/approve/:id', self.api('GET ' + API + '/approve',
      self.placed('GET ' + API + '/approve', function (req, res) {
        return self.apiApprovalView(req, res);
      })));

    // =======================================================================
    // THE APPROVAL ROUTES, LAST AND INLINE (this file's header): the page's
    // GET, then the act that answers it on `/gnap-api` (#578).
    // =======================================================================
    app.get('/gnap/approve/:id', self.placed('GET /gnap/approve',
                                             function (req, res) {
      log.debug("Entering GET /gnap/approve.");
      const grant = self.approvalGrant(req, res);
      if (!grant) {
        log.debug("Leaving GET /gnap/approve. No grant.");
        return undefined;
      }
      const query = validation.check(req, 'query', APPROVE_QUERY);
      if (query.ok && query.value.authn_error) {
        // The person cancelled the sign-in screen. Section 4.2: the finish
        // method is still enacted, with the grant recording the denial.
        log.debug("Leaving GET /gnap/approve. Sign-in cancelled.");
        return self.claimDecision(res, grant).then(function (claimed) {
          if (!claimed) {
            return undefined;
          }
          grant.interaction.decided = true;
          grant.decision = { approved: false, error: 'user_denied' };
          monitor.record(grant.client.identifier, 'grant.denied',
                         { gnapError: 'user_denied' });
          return grants.finishInteraction(req, grant)
            .then(function (finished) {
              store.saveGrant(grant, 'sign-in cancelled');
              return self.afterDecision(res, grant, finished);
            });
        });
      }
      self.hintAccountFor(req, grant);
      const session = authn.sessionOf(req);
      if (!session) {
        // No session yet, so this is the first sign-in, not the step-up
        // return: step_up_honoured stays off, or an eap-met session that
        // is still short of another acr would be refused with no second
        // trip. forceKey only when interact.acr is a demand; phishingClass
        // is '' otherwise, which is what a sign-in with no class stores.
        const demand = gnapRequest.interactAcrDemand(
          self.interactAcrOf(grant));
        const details = [
          { label: 'Application',
            value: (grant.client.display && grant.client.display.name) ||
                   grant.client.identifier },
          { label: 'Protocol', value: 'GNAP (RFC 9635)' }
        ];
        if (demand.eap) {
          details.push({ label: 'Sign-in level needed',
                         value: demand.tokens.join(' ') });
        }
        const signIn: any = {
          returnTo: '/gnap/approve/' + grant.interaction.approvalId,
          protocol: 'GNAP',
          application: grant.client.identifier,
          hint: grant.userHint || '',
          phishingClass: demand.phishingClass || '',
          details: details
        };
        if (demand.forceKey) {
          signIn.forceKey = true;
        }
        log.debug("Leaving GET /gnap/approve. To the sign-in screen.");
        return res.set('Cache-Control', 'no-store')
                  .redirect(303, authn.beginAuthentication(signIn));
      }
      // An EXISTING session is being honoured: CAEP session-presented.
      notePresented(session, 'GNAP', req, grant.client.identifier);
      self.noteAccountFor(grant, session);
      // #432 phase 6: another person's grant goes to its owner's portal, and
      // a session short of the rights' acr is stepped up — both before the
      // page, and before a remembered approval could stand in for it.
      if (self.beforeApproval(req, res, grant, session,
                              query.ok && !!query.value.step_up_honoured)) {
        log.debug("Leaving GET /gnap/approve. Phase 6 answered.");
        return undefined;
      }
      // #432 phase 5, after phase 6's step-up and before anything else: the
      // person must own what the rights name — a remembered approval
      // included, which would otherwise answer for somebody else's
      // resource without the page.
      return self.ownershipRefused(req, res, grant, session)
        .then(function (refused) {
          if (refused) {
            log.debug("Leaving GET /gnap/approve. Not the owner.");
            return undefined;
          }
          if (grants.rememberedFor(grant, session.user.username)) {
            log.debug("Leaving GET /gnap/approve. Already approved before.");
            return self.claimDecision(res, grant).then(function (claimed) {
              if (!claimed) {
                return undefined;
              }
              return grants.decide(req, grant, session, {
                approve: true, tokens: grant.request.tokens, subject: false,
                remembered: true })
                .then(function (finished) {
                  return self.afterDecision(res, grant, finished);
                }, function (e) {
                  log.debug("Caught in GET /gnap/approve: " +
                            ((e && e.message) || e));
                  store.unspend(claimed.handle);
                  throw e;
                });
            });
          }
          // THE PAGE (#578): the shell, which draws it from `GET
          // /gnap-api/approve/{id}` in the person's language.
          self.sendShell(res, 200, null,
                         String(grant.client.identifier || ''));
          log.debug("Leaving GET /gnap/approve. The shell.");
          return undefined;
        });
    }));

    app.post(API + '/approve/:id', self.api('POST ' + API + '/approve',
      self.placed('POST ' + API + '/approve', function (req, res) {
      log.debug("Entering POST /gnap-api/approve.");
      if (!self.bound(req, res)) {
        log.debug("Leaving POST /gnap-api/approve. Refused at the door.");
        return undefined;
      }
      const grant = self.approvalGrant(req, res);
      if (!grant) {
        log.debug("Leaving POST /gnap-api/approve. No grant.");
        return undefined;
      }
      self.hintAccountFor(req, grant);
      const session = authn.sessionOf(req);
      if (!session) {
        log.debug("Leaving POST /gnap-api/approve. No session; back to the " +
                  "page.");
        return self.toPage(res, grant);
      }
      const body = parseBody(req) || {};
      const limitsBad = GnapInteract.limitFieldsRefusal(body);
      if (limitsBad) {
        log.debug("Leaving POST /gnap-api/approve. Limit controls.");
        return self.apiRefusal(res, 400, 'STS-GNAP-0408', limitsBad);
      }
      // `right` is a CHECKBOX COLUMN, one per access right: an array where
      // several are ticked, a string where one is, absent where none is.
      const ticked = GnapInteract.listOf(body.right);
      const posted = validation.checkParsed(Object.assign(
                                              LimitsForm.strip(body),
                                              { right: ticked }),
                                            'body',
                                            API_APPROVE_BODY);
      if (!posted.ok) {
        log.debug("Leaving POST /gnap-api/approve. Malformed: " +
                  posted.detail);
        return self.apiRefusal(res, 400, 'STS-GNAP-0408',
                               String(posted.detail));
      }
      const approve = posted.value.action === 'allow';
      const tokens = grant.request.tokens.map(function (token, t) {
        return { label: token.label, bearer: token.bearer,
                 access: token.access.filter(function (right, r) {
          return ticked.indexOf('t' + t + 'r' + r) >= 0;
        }) };
      });
      const anything = tokens.some(function (token) {
        return token.access.length;
      }) || posted.value.subject === 'yes';
      // #432 phase 6: the rights left ticked are approved only on a session
      // meeting their acr — the page stepped the person up before it was
      // drawn, and an answer sent without that is sent back to it.
      if (approve && self.stepUpOwed(res, grant, session, ticked)) {
        log.debug("Leaving POST /gnap-api/approve. A step-up is owed.");
        return undefined;
      }
      // #432 phase 5: the limits as the person lowered them. Refused, the
      // page is drawn again with the sentence: the grant is still waiting.
      const lowered = approve ? self.loweredTokens(body, grant, tokens)
                              : { ok: true, tokens: tokens };
      if (!lowered.ok) {
        log.debug("Leaving POST /gnap-api/approve. Limits refused.");
        return self.apiRefusal(res, 400, lowered.code === 'STS-GNAP-0867'
                                 ? 'STS-GNAP-0867' : 'STS-GNAP-0866',
                               'These limits could not be accepted: ' +
                               lowered.why);
      }
      let claimedDecision = null;
      return (approve ? self.ownershipRefused(req, res, grant, session)
                      : Promise.resolve(false)).then(function (refused) {
        if (refused) {
          log.debug("Leaving POST /gnap-api/approve. Not the owner.");
          return null;
        }
        return self.claimDecision(res, grant);
      }).then(function (claimed) {
        if (!claimed) {
          log.debug("Leaving POST /gnap-api/approve. Already answered.");
          return undefined;
        }
        claimedDecision = claimed;
        return grants.decide(req, grant, session, {
          approve: approve && anything,
          tokens: lowered.tokens,
          subject: posted.value.subject === 'yes'
        }).then(function (finished) {
          log.debug("Leaving POST /gnap-api/approve. Decided.");
          return self.afterDecision(res, grant, finished);
        });
      }).catch(function (e) {
        log.debug("Caught in GnapInteract.registerRoutes(): " +
                  ((e && e.message) || e));
        if (claimedDecision) {
          store.unspend(claimedDecision.handle);
        }
        log.error(errorCodes.tag('STS-GNAP-0409') + 'gnap: the approval ' +
                  'could not be completed: ' +
                  (e && e.stack || e));
        return self.interactionError(res, 'STS-GNAP-0409',
                                     'Something went wrong',
                                     'The answer could not be completed.');
      });
    })));

    log.debug("Leaving GnapInteract.registerRoutes().");
  }

  /**
   * The surface's bundle and its precompressed forms, read once. A tree that
   * was never built has none, and the shell then loads a script that says
   * so.
   *
   * @returns `ShellDocument.readFile()`'s `{ raw, br, gzip, built }`
   */
  bundle(): Json {
    const { log } = this.deps;
    log.debug("Entering GnapInteract.bundle().");
    if (!this.bundleFile) {
      this.bundleFile = ShellDocument.readFile(__dirname, BUNDLE_FILE,
        'document.body.textContent = "This service has no GNAP interaction ' +
        'script (gnap/' + BUNDLE_FILE + '): it was not built by ' +
        'build-typescript.sh.";');
    }
    log.debug("Leaving GnapInteract.bundle().");
    return this.bundleFile;
  }

  // The built bundle, once read.
  private bundleFile: Json = null;

  /**
   * The operations of `/gnap-api`, for `sts_metadata.ts` and the tests.
   *
   * @returns the operation table
   */
  static operations(): Json[] {
    helpers.log.debug("Entering GnapInteract.operations().");
    helpers.log.debug("Leaving GnapInteract.operations().");
    return OPERATIONS.slice();
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  /**
   * Returns the real modules the instance was built from before the composition
   * root (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapInteractDeps {
    helpers.log.debug("Entering GnapInteract.defaultDeps().");
    helpers.log.debug("Leaving GnapInteract.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      xmlEscape: helpers.xmlEscape,
      parseBody: helpers.parseBody,
      nowSec: helpers.nowSec,
      errorCodes: errorCodes,
      validation: validation,
      websecurity: websecurity,
      authn: authn,
      store: store,
      grants: grants,
      monitor: monitor,
      rights: gnapRights,
      approval: gnapApproval,
      cors: cors,
      stsCrypto: stsCrypto
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapInteract>(
  'gnap/gnap_interact',
  () => new GnapInteract(GnapInteract.defaultDeps()),
  null,
  helpers.log);
// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The pages a GNAP resource owner sees: where an interaction starts, where they
 * sign in and decide, and how the client is told.
 *
 * @namespace
 */
export = {
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapInteract): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  /**
   * The operations of `/gnap-api` (#578).
   *
   * @returns the operation table
   */
  operations: GnapInteract.operations,
  GnapInteract: GnapInteract
};
