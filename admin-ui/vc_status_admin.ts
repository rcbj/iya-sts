// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_status_admin.ts
//
// ===========================================================================
// MONITORING → VERIFIABLE CREDENTIALS (#38's follow-ups; under Monitoring
// since #752): THIS REALM'S STATUS LISTS, AND THE ONE CONTROL THEY HAVE.
//
// `/admin/vc/monitor` draws what `oid4vc/vc_status.ts` publishes for the
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
// **IT WAS THE CREDENTIAL STATUS TAB OF `/admin/vc` UNTIL #752** (rcbj: "for
// consistency"), and is a Monitoring page now for the question it answers —
// what this realm has issued and whether each is still good — beside the
// other families' Monitoring pages; the settings the lists are built with
// stay on Protocols → Verifiable Credentials. The tab's old address lands
// here (`WebPages.movedTo()`), and the two operations below did not change.
//
// **A REALM'S PAGE**, not a service page: what it shows and changes is the
// ambient realm's own lists, which is #32's rule for a realm administrator.
// It reads with Admin Read and changes with Admin Write.
//
// Rule 7: `GET /admin-api/vc-status` answers `statusView()` and `POST
// /admin-api/vc-status/{action}` answers `statusAction()`, the two functions
// the page's JSON and its forms answer.
//
// **AND `publish` (#598)**, per Bitstring Status List purpose: the W3C suites'
// "publish the list now", which was a VC API test hook
// (`/oid4vci/status-lists/bitstring/{purpose}/publish`) until the VC API
// became a product surface. A list here is COMPUTED ON EVERY READ from the
// statuses set so far (`vc_status.ts`), so there is nothing to push: the act
// says so, names what the next fetch will serve, and is recorded. It is an
// operator's act — Admin Write, beside the per-credential controls — rather
// than a protocol endpoint any client holding `vc-api:issue` could call,
// which is what rcbj's decision 2 on #591 moved it for.
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

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Monitoring → Verifiable Credentials.
 */
const PAGE = '/admin/vc/monitor';

// The acts the control performs, and the status each sets.
/**
 * The acts the page's control performs, and the status each sets: suspend (2),
 * reinstate (0) and revoke (1).
 */
const ACTIONS = { suspend: 2, reinstate: 0, revoke: 1, publish: -1 };

/**
 * The Bitstring Status List purposes a `publish` may name.
 */
const PURPOSES = ['revocation', 'suspension'];

interface VcStatusAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  vcStatus: typeof vcStatus;
  parseBody: typeof helpers.parseBody;
}

/**
 * Monitoring → Verifiable Credentials: the realm's status lists, every live
 * credential's index and status, and the one control they have.
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
    // THE PAGE BEFORE THE ROWS (2026-10-22, #820): the counts come from the
    // status list's index, the paging from the count of live entries, and
    // only the page's rows are built — where every live entry was built,
    // sorted and then sliced.
    const counted = vcStatus.counts();
    const paging = adminViews.pagingOf(query || {}, counted.allocated,
                                       { noun: 'credentials' });
    const summary = vcStatus.summary(req, { offset: paging.offset,
                                            limit: paging.perPage });
    const out = Object.assign({}, summary, {
      rowsPaging: adminViews.pagingJson(paging)
    });
    log.debug("Leaving VcStatusAdmin.statusView(). " + summary.rows.length +
              " row(s) of " + counted.allocated + ".");
    return { json: out, paging: paging };
  }

  // ---------------------------------------------------------------------------
  // ONE ROW'S STATUS, CHANGED: `{ idx, action }` with action one of
  // `suspend`, `reinstate`, `revoke` — or ONE LIST PUBLISHED, `{ purpose,
  // action: 'publish' }` (#598). Answers `{ ok, message }` or a refusal
  // carrying its code under the Symbol `error_codes.js` reads.
  // ---------------------------------------------------------------------------
  /**
   * Changes one credential's status: suspend, reinstate (from suspended only)
   * or revoke, which is final; or publishes one Bitstring Status List.
   *
   * @param body - `{ idx, action }`, or `{ purpose, action: 'publish' }`
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
      // resource answers and `tests/protocol/sts_admin_api_operations.js`
      // reads, because that job checks each console action has an operation
      // here BY reading the list back out of this sentence. "Name an
      // action: …" named them and did not name the action asked for, so the
      // sentence did not match and the check could not run.
      return refuse('Unknown action "' + action + '". The four are: ' +
                    Object.keys(ACTIONS).join(', ') + '.');
    }
    if (action === 'publish') {
      const purpose = String(b.purpose || '');
      if (PURPOSES.indexOf(purpose) < 0) {
        return refuse('Name the list to publish: purpose is one of ' +
                      PURPOSES.join(', ') + '.');
      }
      log.info('vc_status_admin: the ' + purpose + ' Bitstring Status List ' +
               'was published by ' + via + ' (computed on every read, so ' +
               'it is current already).');
      log.debug("Leaving VcStatusAdmin.statusAction(). Published.");
      return { ok: true, purpose: purpose, published: true,
               message: 'The ' + purpose + ' Bitstring Status List is ' +
                        'computed on every read, so it already carries ' +
                        'every status set here: the next fetch of it serves ' +
                        'them, signed afresh.' };
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

  /**
   * Registers nothing: the static console draws `/admin/vc/monitor` from
   * the management API's two operations (#446), which call this module.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering VcStatusAdmin.registerRoutes().");
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
 * Monitoring → Verifiable Credentials, `/admin/vc/monitor`: the realm's
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
