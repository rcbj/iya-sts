// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_status_admin.ts
//
// ===========================================================================
// VERIFIABLE CREDENTIALS → CREDENTIAL STATUS (#38's follow-ups): THIS REALM'S
// STATUS LISTS, AND THE ONE CONTROL THEY HAVE.
//
// `GET /admin/vc-status` draws what `oid4vc/vc_status.ts` publishes for the
// realm the console is in: where the Token Status List (JWT and CWT), its
// aggregation and the two Bitstring Status List credentials are served, the
// list size and ttl, how many indexes are allocated, and — paged, newest
// first — every live credential's index, format, configuration, effective
// status and the explicit status beside it, with who set it.
//
// **THE ONE CONTROL** is per row: suspend, reinstate (from SUSPENDED only)
// and revoke. INVALID is final, as the draft means it ("revoked, annulled");
// a credential an administrator revoked on `/admin/tokens` shows INVALID here
// by that act, and a restore there clears it — the list is computed from both
// (`vc_status.ts`'s header), so there is one answer and this page does not
// keep a second. A revoked or suspended credential also stops signing anybody
// in at `/authn/wallet`.
//
// **A REALM'S PAGE**, not a service page: what it shows and changes is the
// ambient realm's own lists, which is #32's rule for a realm administrator.
// It reads with Admin Read and changes with Admin Write.
//
// Rule 7: `GET /admin-api/vc-status` answers `statusView()` and `POST
// /admin-api/vc-status/set` answers `statusAction()`, the two functions the
// page's JSON and its form answer.
//
// TYPESCRIPT, AS A CLASS (#50): `caches_admin.ts`'s shape — dependencies
// through the constructor, `registerRoutes(app)` called by
// `common/protocol_stack.ts` (18h), facades for the JavaScript callers.
// ===========================================================================

import admin = require('./admin');
import adminViews = require('../admin-core/admin_views');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import vcStatus = require('../oid4vc/vc_status');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import VcStatusPage = require('./web_vc_status');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Verifiable Credentials → Credential status.
 */
const PAGE = '/admin/vc-status';

// The acts the control performs, and the status each sets.
/**
 * The acts the page's control performs, and the status each sets: suspend (2),
 * reinstate (0) and revoke (1).
 */
const ACTIONS = { suspend: 2, reinstate: 0, revoke: 1 };

interface VcStatusAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  vcStatus: typeof vcStatus;
  parseBody: typeof helpers.parseBody;
}

/**
 * Verifiable Credentials → Credential status: the realm's status lists, every
 * live credential's index and status, and the one control they have.
 */
class VcStatusAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;
  /**
   * See the module's `ACTIONS`.
   */
  static readonly ACTIONS = ACTIONS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console and `oid4vc/vc_status.ts`
   */
  constructor(private readonly deps: VcStatusAdminDeps) {
    deps.log.debug("Entering VcStatusAdmin.constructor().");
    deps.log.debug("Leaving VcStatusAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): VcStatusAdminDeps {
    helpers.log.debug("Entering VcStatusAdmin.defaultDeps().");
    helpers.log.debug("Leaving VcStatusAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      adminViews: adminViews,
      errorCodes: errorCodes,
      vcStatus: vcStatus,
      parseBody: helpers.parseBody
    };
  }

  // The page's JSON, and the management API's answer.
  /**
   * Builds the page's JSON and the management API's answer: where the realm's
   * status lists are served, their size, and every live credential's status,
   * paged.
   *
   * @param req - the request
   * @param query - the query's values, for paging
   * @returns the JSON and its paging
   */
  statusView(req: Req, query?: Json): Json {
    const { log, vcStatus, adminViews } = this.deps;
    log.debug("Entering VcStatusAdmin.statusView().");
    const summary = vcStatus.summary(req);
    const paged = adminViews.pagedRows(query || {}, summary.rows,
                                       { noun: 'credentials' });
    const out = Object.assign({}, summary, {
      rows: paged.shown,
      rowsPaging: adminViews.pagingJson(paged.paging)
    });
    log.debug("Leaving VcStatusAdmin.statusView(). " + summary.rows.length +
              " row(s).");
    return { json: out, paging: paged.paging };
  }

  // ---------------------------------------------------------------------------
  // ONE ROW'S STATUS, CHANGED: `{ idx, action }` with action one of
  // `suspend`, `reinstate`, `revoke`. Answers `{ ok, message }` or a refusal
  // carrying its code under the Symbol `error_codes.js` reads.
  // ---------------------------------------------------------------------------
  /**
   * Changes one credential's status: suspend, reinstate (from suspended only)
   * or revoke, which is final.
   *
   * @param body - `{ idx, action }`
   * @param via - which surface asked, for the audit row
   * @returns `{ ok, message }`, or a refusal carrying its error code
   */
  statusAction(body: Json, via: string): Json {
    const { log, vcStatus, errorCodes } = this.deps;
    log.debug("Entering VcStatusAdmin.statusAction().");
    const b = body || {};
    const action = String(b.action || '');
    const idx = String(b.idx === undefined ? '' : b.idx).trim();
    const refuse = (why: string): Json => {
      log.debug("Leaving VcStatusAdmin.statusAction(). " + why);
      return errorCodes.mark({ ok: false, errors: [why] }, 'STS-VC-0082');
    };
    if (!Object.prototype.hasOwnProperty.call(ACTIONS, action)) {
      // `Unknown action "x". <phrase>: <list>.` — the shape every action
      // resource answers and `tests/vendored/sts_admin_api_operations.js`
      // reads, because that job checks each console action has an operation
      // here BY reading the list back out of this sentence. "Name an
      // action: …" named them and did not name the action asked for, so the
      // sentence did not match and the check could not run.
      return refuse('Unknown action "' + action + '". The three are: ' +
                    Object.keys(ACTIONS).join(', ') + '.');
    }
    if (!/^\d+$/.test(idx)) {
      return refuse('Name a status-list index, as the list gives it.');
    }
    const wanted = ACTIONS[action];
    const now = vcStatus.statusOf(idx);
    if (action === 'reinstate' && now !== vcStatus.SUSPENDED) {
      return refuse('Only a SUSPENDED credential can be reinstated; index ' +
                    idx + ' is ' + vcStatus.STATUS_NAMES[now] + '.');
    }
    const changed = vcStatus.setStatus(idx, wanted, via);
    if (!changed) {
      return refuse('Index ' + idx + ' was not changed: it is not a live ' +
                    'credential here, it is already ' +
                    vcStatus.STATUS_NAMES[now] + ', or it is INVALID, which ' +
                    'is final.');
    }
    log.debug("Leaving VcStatusAdmin.statusAction(). Changed.");
    return { ok: true, idx: Number(idx),
             status: vcStatus.STATUS_NAMES[wanted],
             message: 'Status-list index ' + idx + ' is now ' +
                      vcStatus.STATUS_NAMES[wanted] + '. Verifiers see it ' +
                      'when they next fetch the list.' };
  }

  // DRAWN BY `web_vc_status.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private html(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering VcStatusAdmin.html().");
    const drawn = VcStatusPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving VcStatusAdmin.html().");
    return drawn;
  }

  /**
   * Registers `GET /admin/vc-status` and its control.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering VcStatusAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      const view = self.statusView(req, req.query);
      admin.respond(req, res, view.json, 'Credential status', PAGE,
                    admin.messagesOf(req) +
                    self.html(req, view.json));
      log.debug('Leaving GET ' + PAGE + '.');
    });
    app.post(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + PAGE + '.');
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-VC-0082');
        admin.respondToAction(req, res, PAGE, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + PAGE + '. Read-only.');
        return;
      }
      const result = self.statusAction(parseBody(req),
                                       'the admin console');
      if (!result.ok) {
        errorCodes.mark(res, 'STS-VC-0082');
      }
      admin.respondToAction(req, res, PAGE, result);
      log.debug('Leaving POST ' + PAGE + '.');
    });
    log.debug("Leaving VcStatusAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<VcStatusAdmin>(
  'admin-ui/vc_status_admin',
  () => new VcStatusAdmin(VcStatusAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Verifiable Credentials → Credential status, `/admin/vc-status`: the realm's
 * status lists, and the control that suspends, reinstates or revokes one
 * credential.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcStatusAdmin: VcStatusAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: VcStatusAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  statusView: slot.forward('statusView'),
  statusAction: slot.forward('statusAction')
};
