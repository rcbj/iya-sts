// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_gnap.ts — /portal/gnap, WHERE A PERSON SEES THE GNAP GRANTS
// THEY GAVE AND ENDS ONE (#432 phase 7, 2026-10-03).
//
// A GNAP grant (RFC 9635) is access a person gave a client instance on the
// approval page — or access a trusted client was allowed to take for them by
// presenting a verified assertion about them. Until this page only the
// client (section 5.4's DELETE) and an administrator (`/admin/gnap`) could
// see or end one.
//
// **A PAGE OF ITS OWN, NOT A SECTION OF `/portal/consents`.** The two were
// weighed. Consents are the OAuth consent register: one `oauthConsent` value
// per (person, application, scope), withdrawn one scope at a time, with
// nothing else to show. A GNAP grant is a different object with a different
// lifetime: a state machine with a resource owner, access rights that are
// objects rather than scope tokens (types, actions, locations, an
// identifier, limits), the tokens issued under it, a lifetime of its own and
// a reason it ended — and its one control ends the WHOLE grant, not a scope.
// The consent register does hold GNAP's remembered approvals, but as digests
// (`gnap:<hash>`, `gnap/CLAUDE.md`) that say nothing a person can read; the
// grant is where the readable rights are. Folding grants into the consents
// page would put two lists with two meanings of "withdraw" under one
// heading, which is the thing the portal's navigation exists to avoid. It
// sits beside Consents under *Your account*, for Consents' reason: not a
// credential, but what this person has let applications do.
//
// **REVOKING IS THE CLIENT'S OWN SECTION 5.4 ACT, PERFORMED FOR THEM** —
// `gnap_grants.ts`'s `revokeGrantBy()`, the one path the client's DELETE and
// the console take: every token issued under the grant stops working, the
// grant is finalized as `revoked`, and CAEP `session-revoked` is sent
// (`gnap_signals.ts`). The page says so above the buttons.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md, OWASP A01). The form names a GRANT, and
// `gnap_console.ts`'s `revokeOwnGrant()` refuses one whose resource owner is
// not the signed-in person (`STS-PORTAL-0163`), the `/portal/keys`
// credential id's arrangement. `manage-own`, CSRF on the POST, and the
// revocation audited as `gnap.grant.revoke` with the person as actor.
//
// **WHAT IS LISTED** is `gnap_console.ts`'s `personGrantsView()` — the same
// view the console's user page and `/admin-api/users?user=` draw — so the
// person and an administrator cannot see different things. Under cells (#98)
// it is this cell's grants, and the page says so when that can leave one
// out (that file's header).
//
// **NO SCRIPT**: a real form per grant, under the service-wide
// `script-src 'none'`. Twenty grants a page.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// as `portal_consents.ts` is, and for its reason. GNAP's view layer is
// required LAZILY: the portal is built at 8a and GNAP at 23d.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_consents.ts`'s context.
interface PortalContext {
  app: {
    get(path: string, handler: (req: Req, res: Res) => unknown): unknown;
    post(path: string, handler: (req: Req, res: Res) => unknown): unknown;
  };
  BASE: string;
  log: {
    debug(message: string): void;
    info(message: string): void;
  };
  esc(value: unknown): string;
  shell(path: string, session: Json, message: unknown, error: unknown,
        body: string): string;
  send(res: Res, status: number, body: string): unknown;
  requireSignIn(req: Req, res: Res, path: string, action: unknown): Json;
  // error-code: none — the portal helper's type, not a call to it.
  refuseShape(res: Res, result: Json): unknown;
  innerCode(result: Json): string;
  baseUrlOf(req: Req): string;
  parseBody(req: Req): Json;
  validation: Json;
  websecurity: Json;
  accessGate: Json;
  audit: Json;
  errorCodes: Json;
  config: { value(key: string): any };
}

interface PortalGnapDeps {
  log: { debug(message: string): void };
  // GNAP's view and action layer, asked for when a page is drawn or a form
  // answered.
  gnapConsole: () => Json;
}

// Grants per page.
const PER_PAGE = 20;

class PortalGnapPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalGnapDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalGnapPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/gnap';
    // `grant` is a grant identifier this service minted (base64url, a
    // cell's stamp included where there is one), checked against the
    // person's own grants, which is the rule that matters.
    this.FORM = vz.object({
      grant: vt.base64url,
      page: vt.opt(vt.integer(1, 100000)),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(300).optional(),
      page: vt.opt(vt.integer(1, 100000))
    });
    ctx.log.debug("Leaving PortalGnapPage.constructor().");
  }

  // Epoch seconds as a reader writes a date.
  private readable(seconds: unknown): string {
    const { log } = this.ctx;
    log.debug("Entering PortalGnapPage.readable().");
    const n = Number(seconds);
    log.debug("Leaving PortalGnapPage.readable().");
    return n > 0
      ? new Date(n * 1000).toISOString().replace('T', ' ')
                                       .replace(/:\d\d(\.\d+)?Z$/, ' UTC')
      : '—';
  }

  // One access right, in words: the type (or reference) and what it names,
  // including any limits it carries.
  private right(one: Json): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalGnapPage.right().");
    if (typeof one === 'string') {
      log.debug("Leaving PortalGnapPage.right(). A reference.");
      return '<code>' + esc(one) + '</code>';
    }
    const parts: string[] = [];
    ['actions', 'locations', 'datatypes', 'privileges'].forEach(
        function (dimension) {
      if (Array.isArray(one[dimension]) && one[dimension].length) {
        parts.push(dimension + ': ' + one[dimension].join(', '));
      }
    });
    if (one.identifier) {
      parts.push('identifier: ' + one.identifier);
    }
    if (one.limits !== undefined) {
      parts.push('limits: ' + JSON.stringify(one.limits));
    }
    log.debug("Leaving PortalGnapPage.right().");
    return '<code>' + esc(one.type || '') + '</code>' +
      (parts.length ? ' — ' + esc(parts.join('; ')) : '');
  }

  // What a finalized grant's reason means, for the person.
  private ended(reason: string): string {
    const { log } = this.ctx;
    log.debug("Entering PortalGnapPage.ended().");
    const words: Record<string, string> = {
      issued: 'finished: its tokens were issued and it can no longer be ' +
              'changed',
      revoked: 'revoked',
      rejected: 'refused',
      expired: 'expired'
    };
    log.debug("Leaving PortalGnapPage.ended().");
    return words[reason] || reason;
  }

  private card(session: Json, row: Json, at: number): string {
    const { log, esc, websecurity } = this.ctx;
    const self = this;
    log.debug("Entering PortalGnapPage.card().");
    const state = row.finalization
      ? 'Ended — ' + this.ended(row.finalization.reason) + ', ' +
        this.readable(row.finalization.at)
      : (row.state === 'approved' ? 'Active' : 'Waiting for approval');
    const tokens = row.tokens.length
      ? '<table><tr><th>Token</th><th>Format</th><th>Expires</th>' +
        '<th>State</th></tr>' + row.tokens.map(function (token: Json) {
          return '<tr><td>' + esc(token.label || '—') + '</td><td><code>' +
            esc(token.format) + '</code>' +
            (token.bearer ? ' <span class="sub">bearer</span>' : '') +
            '</td><td>' + esc(self.readable(token.expiresAt)) + '</td><td>' +
            esc(token.state) + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">No token was issued under it.</p>';
    const revoke = row.revocable
      ? '<form method="post" action="' + esc(this.PATH) + '">' +
        websecurity.field(session.id) +
        '<input type="hidden" name="grant" value="' + esc(row.id) + '">' +
        '<input type="hidden" name="page" value="' + esc(String(at)) + '">' +
        '<button type="submit" class="danger">Revoke this grant</button>' +
        '</form>'
      : '';
    log.debug("Leaving PortalGnapPage.card().");
    return '<div class="card"><h2>' + esc(row.clientName || row.client) +
      '</h2><p class="sub"><code>' + esc(row.client) + '</code> · ' +
      esc(state) + '</p>' +
      '<p>' + (row.rightsAre === 'approved' ? 'May' : 'Asked to') + ':</p>' +
      '<ul>' + (row.rights.map(function (one: Json) {
        return '<li>' + self.right(one) + '</li>';
      }).join('') || '<li>nothing specific</li>') + '</ul>' +
      (row.subjectReleasedAt
        ? '<p class="note">It was also told who you are, ' +
          esc(this.readable(row.subjectReleasedAt)) + '.</p>'
        : '') +
      tokens +
      '<p class="note">Granted ' + esc(this.readable(row.createdAt)) +
      (row.finalization ? ''
        : '; it can be renewed until ' +
          esc(this.readable(row.grantExpiresAt))) + '.</p>' +
      revoke + '</div>';
  }

  private page(session: Json, wanted: number, message: unknown,
               error: unknown): string {
    const { log, esc, shell } = this.ctx;
    const self = this;
    log.debug("Entering PortalGnapPage.page().");
    // THE PERSON IS THE SESSION'S, and nothing else names them.
    const view = this.deps.gnapConsole().personGrantsView(
        String(session.user.username), { per: String(PER_PAGE),
                                         gnapGrantsPage: String(wanted) });
    const paging = view.paging || { page: 1, pages: 1 };
    const at = paging.page;
    const body = view.rows.length
      ? view.rows.map(function (row: Json): string {
          return self.card(session, row, at);
        }).join('')
      : '<div class="card"><p class="sub">You have given no application ' +
        'access through GNAP. When one asks and you allow it, the grant ' +
        'appears here.</p></div>';
    const nav = paging.pages > 1
      ? '<p class="pagenav">' +
        (at > 1
          ? '<a href="' + esc(this.PATH + '?page=' + (at - 1)) +
            '">Previous</a>'
          : '<span class="off">Previous</span>') +
        '<span class="here">Page ' + esc(String(at)) + ' of ' +
        esc(String(paging.pages)) + '</span>' +
        (at < paging.pages
          ? '<a href="' + esc(this.PATH + '?page=' + (at + 1)) + '">Next</a>'
          : '<span class="off">Next</span>') +
        '</p>'
      : '';
    const cells = view.cells && view.cells.multiCell
      ? '<p class="note">' + esc(view.cells.note) + '</p>' : '';
    log.debug("Leaving PortalGnapPage.page(). Page " + at + ".");
    return shell(this.PATH, session, message, error,
      '<div class="card"><p class="sub">The access you have given ' +
      'applications through GNAP, each grant with what it allows and the ' +
      'tokens the application holds under it. <strong>Revoking takes ' +
      'effect at once</strong>: every token issued under the grant stops ' +
      'working, the application cannot renew it or ask anything more of ' +
      'it, and it has to ask you afresh.</p>' + cells + '</div>' +
      body + nav);
  }

  // -------------------------------------------------------------------------
  // GET /portal/gnap
  // -------------------------------------------------------------------------
  private getPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const PATH = this.PATH;
    log.debug('Entering GET ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.READ);
    if (!session) {
      log.debug('Leaving GET ' + PATH + '. Not signed in.');
      return undefined;
    }
    const asked = ctx.validation.check(req, 'query', this.QUERY);
    if (!asked.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(asked) || 'STS-PORTAL-0001');
      log.debug('Leaving GET ' + PATH + '. Malformed.');
      return ctx.refuseShape(res, asked);
    }
    log.debug('Leaving GET ' + PATH + '.');
    return ctx.send(res, 200, this.page(session, asked.value.page || 1,
                                        asked.value.done || null, null));
  }

  // -------------------------------------------------------------------------
  // POST /portal/gnap — `manage-own`: it revokes one of this person's own
  // grants, and every token issued under it.
  // -------------------------------------------------------------------------
  private postPage(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    const PATH = this.PATH;
    log.debug('Entering POST ' + PATH + '.');
    const session = ctx.requireSignIn(req, res, PATH,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving POST ' + PATH + '. Not signed in.');
      return undefined;
    }
    const who = String(session.user.username);
    const posted = ctx.validation.checkParsed(ctx.parseBody(req), 'body',
                                              this.FORM);
    if (!posted.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(posted) || 'STS-PORTAL-0001');
      log.debug('Leaving POST ' + PATH + '. Malformed.');
      return ctx.refuseShape(res, posted);
    }
    const body = posted.value;
    const at = body.page || 1;
    const csrf = ctx.websecurity.checkCsrf(session.id, body);
    if (!csrf.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0083');
      log.debug('Leaving POST ' + PATH + '. CSRF.');
      return ctx.send(res, 403, this.page(session, at, null, csrf.detail));
    }
    // THE PERSON IS THE SESSION'S; the view layer refuses a grant whose
    // resource owner is anybody else.
    const result = this.deps.gnapConsole().revokeOwnGrant(
        who, String(body.grant), { req: req });
    if (!result || !result.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0163');
      log.debug('Leaving POST ' + PATH + '. Nothing of theirs to revoke.');
      return ctx.send(res, 400, this.page(session, at, null,
        'There is no such grant of yours with anything left to revoke. It ' +
        'may already have ended.'));
    }
    const name = result.grant.clientName || result.grant.client;
    log.debug('Leaving POST ' + PATH + '. Revoked.');
    res.redirect(303, PATH + '?page=' + at + '&done=' + encodeURIComponent(
      'Revoked: ' + name + ' no longer has the access you gave it. It asks ' +
      'you again next time.'));
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalGnapPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalGnapPage.registerRoutes().");
  }
}

/**
 * The portal page at /portal/gnap: where a person sees the GNAP grants they
 * gave and revokes one (#432 phase 7).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalGnap {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalGnapDeps) {
    deps.log.debug("Entering PortalGnap.constructor().");
    deps.log.debug("Leaving PortalGnap.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalGnapDeps {
    helpers.log.debug("Entering PortalGnap.defaultDeps().");
    helpers.log.debug("Leaving PortalGnap.defaultDeps().");
    return {
      log: helpers.log,
      gnapConsole: function gnapConsole() {
        helpers.log.debug("Entering gnapConsole().");
        helpers.log.debug("Leaving gnapConsole().");
        return require('../gnap/gnap_console');
      }
    };
  }

  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the page's path
   */
  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalGnap.register().");
    const page = new PortalGnapPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalGnap.register().");
    return { path: page.PATH };
  }
}

const slot = new InstanceSlot<PortalGnap>(
  'portal/portal_gnap',
  () => new PortalGnap(PortalGnap.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The portal page at /portal/gnap, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalGnap: PortalGnap,
  installInstance: (instance: PortalGnap): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
