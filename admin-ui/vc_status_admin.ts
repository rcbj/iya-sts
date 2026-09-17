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

type Req = any;
type Res = any;
type Json = any;

const PAGE = '/admin/vc-status';

// The acts the control performs, and the status each sets.
const ACTIONS = { suspend: 2, reinstate: 0, revoke: 1 };

interface VcStatusAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  vcStatus: typeof vcStatus;
  parseBody: typeof helpers.parseBody;
}

class VcStatusAdmin {
  static readonly PAGE = PAGE;
  static readonly ACTIONS = ACTIONS;

  constructor(private readonly deps: VcStatusAdminDeps) {
    deps.log.debug("Entering VcStatusAdmin.constructor().");
    deps.log.debug("Leaving VcStatusAdmin.constructor().");
  }

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

  private html(req: Req, json: Json, paging: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering VcStatusAdmin.html().");
    const canWrite = admin.mayWrite(req);
    const tiles = '<div class="tiles">' +
      admin.tile(String(json.allocated), 'credentials with an index') +
      admin.tile(String(json.valid), 'valid') +
      admin.tile(String(json.suspended), 'suspended') +
      admin.tile(String(json.invalid), 'revoked') +
      admin.tile(String(json.size), 'indexes per list') +
      '</div>';
    const where = '<table class="grid"><tbody>' +
      '<tr><th>Token Status List</th><td><a href="' +
      admin.esc(json.tokenStatusList) + '"><code>' +
      admin.esc(json.tokenStatusList) + '</code></a><br><small>' +
      'application/statuslist+jwt, or application/statuslist+cwt by ' +
      'Accept; ' + json.bits + ' bits per credential</small></td></tr>' +
      '<tr><th>Aggregation</th><td><code>' + admin.esc(json.aggregation) +
      '</code></td></tr>' +
      '<tr><th>Bitstring Status Lists</th><td>' +
      json.bitstring.map(function (u: string): string {
        return '<code>' + admin.esc(u) + '</code>';
      }).join('<br>') + '<br><small>application/vc+jwt</small></td></tr>' +
      '<tr><th>Time to live</th><td>' + json.ttlS + ' s (<code>' +
      'oid4vci.statusListTtlS</code>); valid for ' + json.lifetimeS +
      ' s (<code>oid4vci.statusListLifetimeS</code>)</td></tr>' +
      '</tbody></table>';
    const about = admin.note(
      '<p>Every credential this realm issues carries its index here: a ' +
      'dc+sd-jwt and a jwt_vc_json in the Token Status List ' +
      '(draft-ietf-oauth-status-list), a jwt_vc_json and an ldp_vc in the ' +
      'two Bitstring Status Lists (W3C). One index, the same in every list. ' +
      'A verifier fetches the list and reads the bit; this service\'s own ' +
      'Verifier reads it directly.</p><p>A credential is shown ' +
      '<strong>INVALID</strong> when it was revoked here, when an ' +
      'administrator revoked it on <a href="/admin/tokens">Tokens</a>, or ' +
      'when a global sign-out disowned it. INVALID is final. ' +
      '<strong>SUSPENDED</strong> can be reinstated. Either stops the ' +
      'credential signing anybody in at <code>/authn/wallet</code>.</p>',
      'What this page is');
    const nav = admin.pageNavPair(PAGE, {}, paging);
    const rows = json.rows.map(function (r: Json): string {
      const form = function (action: string, label: string): string {
        log.debug("Entering form(). " + action);
        log.debug("Leaving form().");
        return '<form method="post" action="' + PAGE + '" class="inline">' +
          '<input type="hidden" name="idx" value="' + r.idx + '">' +
          '<input type="hidden" name="action" value="' + action + '">' +
          '<button type="submit" id="vc-status-' + action + '-' + r.idx +
          '">' + label + '</button></form>';
      };
      const controls = !canWrite || r.status === 'INVALID' ? '' :
        (r.status === 'SUSPENDED' ? form('reinstate', 'Reinstate')
                                  : form('suspend', 'Suspend')) +
        form('revoke', 'Revoke');
      return '<tr><td class="num">' + r.idx + '</td><td>' +
        admin.esc(r.format) + '<br><small>' + admin.esc(r.configId) +
        '</small></td><td><strong>' + admin.esc(r.status) + '</strong>' +
        (r.status !== r.explicit ? '<br><small>set here: ' +
         admin.esc(r.explicit) + '</small>' : '') + '</td><td>' +
        (r.via ? admin.esc(r.via) + '<br><small>' +
         admin.esc(new Date(r.changedAt).toISOString()) + '</small>' : '—') +
        '</td><td><small>' +
        admin.esc(new Date(r.expiresAt).toISOString()) + '</small></td><td>' +
        controls + '</td></tr>';
    }).join('');
    log.debug("Leaving VcStatusAdmin.html().");
    return tiles + about + where + '<h3>Credentials</h3>' + nav.head +
      '<table class="grid"><thead><tr><th>Index</th><th>Format</th>' +
      '<th>Status</th><th>Changed by</th><th>Expires</th><th></th></tr>' +
      '</thead><tbody>' +
      (rows || '<tr><td colspan="6">No credential issued here carries a ' +
       'status yet.</td></tr>') + '</tbody></table>' + nav.foot;
  }

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering VcStatusAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      const view = self.statusView(req, req.query);
      admin.respond(req, res, view.json, 'Credential status', PAGE,
                    admin.messagesOf(req) +
                    self.html(req, view.json, view.paging));
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  VcStatusAdmin: VcStatusAdmin,
  installInstance: (instance: VcStatusAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  statusView: slot.forward('statusView'),
  statusAction: slot.forward('statusAction')
};
