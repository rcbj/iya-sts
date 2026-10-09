// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_consents.ts — /portal/consents, WHERE A PERSON SEES WHAT
// THEY HAVE AGREED EACH APPLICATION MAY ASK FOR, AND TAKES IT BACK (#172,
// 2026-09-23).
//
// The consent screen writes one `oauthConsent` value per (person,
// application, scope) onto the person's own entry. Until this page nothing
// let the person read that back, and only an administrator could withdraw
// it — at `/admin/consent`, or through `/admin-api`. `/portal/applications`
// is a different question (where this service will sign them in), and says
// nothing about what they have granted.
//
// **WITHDRAWING IS WHAT `/admin/consent` DOES, THROUGH THE SAME FUNCTIONS**:
// `consent.revoke()` for one scope and `consent.revokeApplication()` for
// everything one application holds. So a withdrawal here revokes every token
// that application holds for them under it and records the instant, and a
// refresh token granted before it is refused at the token endpoint even
// after they agree again — `common/consent.ts` argues all three. The page
// says so before the button, because "the application loses access now" is
// the whole of what somebody pressing it wants to know.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md, OWASP A01). The form names an application
// and a scope, which name one of the SIGNED-IN person's own consents, and
// `consent.revoke()` refuses one that is not on their entry
// (`STS-PORTAL-0085`): the `/portal/keys` credential id's arrangement.
//
// **A SCOPE UNDER GLOBAL CONSENT IS LISTED APART, UNDER ADMINISTRATIVE
// CONSENTS (#537)**, with no button: it is not the person's to withdraw — the
// override is an operator's configuration of the application. Until #537
// nothing about the person was ever written and the page said so in a
// sentence; the authorization endpoint now records each scope a global
// consent answered for them (`consent.noteApplied()`), and the section draws
// those that still stand (`consent.appliedConsentsOf()`) — the application
// still carries the global consent, and the person has not also agreed to the
// scope themselves. A sign-in made before #537 recorded nothing.
//
// **NO SCRIPT**: a real form per row and per application, under the
// service-wide `script-src 'none'`. Paged by application, `/portal/
// applications`' way, because a person may have consented to many.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// as `portal_sign_ins.ts` is, and for its reason. The register is required
// LAZILY: the portal is built at 8a, `common/consent` after it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_sign_ins.ts`'s context.
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
  // The portal's translator for a page drawn for this session (#539
  // phase 3): the portal's application and the person's own language.
  translatorFor(session: Json): any;
}

interface PortalConsentsDeps {
  log: { debug(message: string): void };
  // The consent register and the application registry, asked for when a
  // page is drawn or a form answered.
  consent: () => Json;
  applications: () => Json;
}

// Applications per page.
const PER_PAGE = 20;

class PortalConsentsPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalConsentsDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalConsentsPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/consents';
    // `client` has no rule of its own — a client_id may contain anything
    // but a line break and a NUL (`applications.js`) — so it is bounded by
    // length and checked against the person's own entry, which is the rule
    // that matters. `scope` is one RFC 6749 scope token.
    this.FORM = vz.object({
      action: vt.oneOf(['scope', 'application']),
      client: vz.string().min(1).max(512),
      scope: vz.string().max(1024).optional(),
      page: vt.opt(vt.integer(1, 100000)),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(300).optional(),
      page: vt.opt(vt.integer(1, 100000))
    });
    ctx.log.debug("Leaving PortalConsentsPage.constructor().");
  }

  // The person's own consents, one group per application, the application
  // with the newest answer first.
  private groupsOf(session: Json): Json[] {
    const { log } = this.ctx;
    log.debug("Entering PortalConsentsPage.groupsOf().");
    const rows = this.deps.consent().consentsOf(session.user.username) || [];
    const byClient: Record<string, Json> = {};
    rows.forEach(function (one: Json) {
      const group = byClient[one.client] ||
        (byClient[one.client] = { client: one.client, rows: [], newest: '' });
      group.rows.push(one);
      if (String(one.at) > group.newest) {
        group.newest = String(one.at);
      }
    });
    const groups = Object.keys(byClient).map(function (client) {
      return byClient[client];
    }).sort(function (a: Json, b: Json) {
      return String(b.newest).localeCompare(String(a.newest));
    });
    log.debug("Leaving PortalConsentsPage.groupsOf(). " + groups.length +
              " application(s).");
    return groups;
  }

  // A GeneralizedTime as a reader writes a date — in the reader's own
  // language and their locale's way of writing it (#539), still in UTC
  // and saying so (`Translator.date()`). Anything shorter is drawn as it
  // came, as it always was.
  private readable(at: string, t: Json): string {
    const { log } = this.ctx;
    log.debug("Entering PortalConsentsPage.readable().");
    const text = String(at || '');
    log.debug("Leaving PortalConsentsPage.readable().");
    return text.length >= 14
      ? t.date(Date.UTC(Number(text.slice(0, 4)),
                        Number(text.slice(4, 6)) - 1,
                        Number(text.slice(6, 8)),
                        Number(text.slice(8, 10)),
                        Number(text.slice(10, 12))),
               { dateStyle: 'medium', timeStyle: 'short' }) + ' UTC'
      : text;
  }

  private form(session: Json, fields: Record<string, string>,
               label: string): string {
    const { log, esc, websecurity } = this.ctx;
    log.debug("Entering PortalConsentsPage.form().");
    log.debug("Leaving PortalConsentsPage.form().");
    return '<form method="post" action="' + esc(this.PATH) + '" ' +
      'style="display:inline">' + websecurity.field(session.id) +
      Object.keys(fields).map(function (name) {
        return '<input type="hidden" name="' + esc(name) + '" value="' +
          esc(fields[name]) + '">';
      }).join('') +
      '<button type="submit" class="danger">' + esc(label) + '</button>' +
      '</form>';
  }

  private page(session: Json, wanted: number, message: unknown,
               error: unknown): string {
    const { log, esc, shell } = this.ctx;
    const self = this;
    log.debug("Entering PortalConsentsPage.page().");
    const t = this.ctx.translatorFor(session);
    const groups = this.groupsOf(session);
    const pages = Math.max(1, Math.ceil(groups.length / PER_PAGE));
    const at = Math.min(Math.max(1, wanted || 1), pages);
    const shown = groups.slice((at - 1) * PER_PAGE, at * PER_PAGE);
    const applications = this.deps.applications();
    const body = shown.length
      ? shown.map(function (group: Json): string {
          const entry = applications.get(group.client);
          const name = entry && entry.name && entry.name !== group.client
            ? entry.name : group.client;
          return '<div class="card"><h2>' + esc(name) + '</h2>' +
            '<p class="sub"><code>' + esc(group.client) + '</code></p>' +
            '<table><tr><th>' + t.html('portalConsents.agreed') +
            '</th><th>' + t.html('portalConsents.when') + '</th>' +
            '<th></th></tr>' +
            group.rows.map(function (one: Json): string {
              return '<tr><td><code>' + esc(one.scope) + '</code></td><td>' +
                esc(self.readable(one.at, t)) + '</td><td>' +
                self.form(session, { action: 'scope', client: group.client,
                                     scope: one.scope, page: String(at) },
                          t.text('portalConsents.withdraw')) + '</td></tr>';
            }).join('') + '</table><p>' +
            self.form(session, { action: 'application',
                                 client: group.client, page: String(at) },
                      t.text('portalConsents.withdrawAll')) +
            '</p></div>';
        }).join('')
      : '<div class="card"><p class="sub">' + t.html('portalConsents.none') +
        '</p></div>';
    const paging = pages > 1
      ? '<p class="pagenav">' +
        (at > 1
          ? '<a href="' + esc(this.PATH + '?page=' + (at - 1)) +
            '">' + t.html('portalConsents.previous') + '</a>'
          : '<span class="off">' + t.html('portalConsents.previous') +
            '</span>') +
        '<span class="here">' +
        t.html('portalConsents.pageOf', { page: at, pages: pages }) +
        '</span>' +
        (at < pages
          ? '<a href="' + esc(this.PATH + '?page=' + (at + 1)) + '">' +
            t.html('portalConsents.next') + '</a>'
          : '<span class="off">' + t.html('portalConsents.next') +
            '</span>') +
        '</p>'
      : '';
    log.debug("Leaving PortalConsentsPage.page(). Page " + at + ".");
    return shell(this.PATH, session, message, error,
      '<div class="card"><p class="sub">' + t.html('portalConsents.sub') +
      '</p><p class="note">' + t.html('portalConsents.adminNote') +
      '</p></div>' +
      body + paging + this.administrative(session, t));
  }

  // ADMINISTRATIVE CONSENTS (#537): the scopes an application's global
  // consent answered for this person when they signed in to it, grouped by
  // application, newest first. No button: an administrator's consent is not
  // the person's to withdraw. Not paged: an operator configures global consent
  // on a handful of applications, and every row here is one of theirs.
  private administrative(session: Json, t: Json): string {
    const { log, esc } = this.ctx;
    const self = this;
    log.debug("Entering PortalConsentsPage.administrative().");
    const rows = this.deps.consent()
      .appliedConsentsOf(session.user.username) || [];
    const byClient: Record<string, Json> = {};
    rows.forEach(function (one: Json) {
      const group = byClient[one.client] ||
        (byClient[one.client] = { client: one.client, rows: [], newest: '' });
      group.rows.push(one);
      if (String(one.at) > group.newest) {
        group.newest = String(one.at);
      }
    });
    const groups = Object.keys(byClient).map(function (client) {
      return byClient[client];
    }).sort(function (a: Json, b: Json) {
      return String(b.newest).localeCompare(String(a.newest));
    });
    const applications = this.deps.applications();
    const body = groups.length
      ? groups.map(function (group: Json): string {
          const entry = applications.get(group.client);
          const name = entry && entry.name && entry.name !== group.client
            ? entry.name : group.client;
          return '<div class="card"><h3>' + esc(name) + '</h3>' +
            '<p class="sub"><code>' + esc(group.client) + '</code></p>' +
            '<table><tr><th>' + t.html('portalConsents.forEverybody') +
            '</th><th>' + t.html('portalConsents.firstApplied') +
            '</th></tr>' +
            group.rows.map(function (one: Json): string {
              return '<tr><td><code>' + esc(one.scope) + '</code></td><td>' +
                esc(self.readable(one.at, t)) + '</td></tr>';
            }).join('') + '</table></div>';
        }).join('')
      : '<div class="card"><p class="sub">' +
        t.html('portalConsents.adminNone') + '</p></div>';
    log.debug("Leaving PortalConsentsPage.administrative(). " +
              groups.length + " application(s).");
    return '<h2 id="administrative-consents">' +
      t.html('portalConsents.adminHeading') + '</h2>' +
      '<div class="card"><p class="sub">' + t.html('portalConsents.adminSub') +
      '</p></div>' + body;
  }

  // -------------------------------------------------------------------------
  // GET /portal/consents
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
  // POST /portal/consents — `manage-own`: it withdraws this person's own
  // consent, and revokes what was issued under it.
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
    const register = this.deps.consent();
    const client = String(body.client);
    const scope = String(body.scope || '').trim();
    if (body.action === 'scope' && !scope) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0085');
      log.debug('Leaving POST ' + PATH + '. No scope named.');
      return ctx.send(res, 400, this.page(session, at, null,
        'Say which of your answers to withdraw.'));
    }
    // THE PERSON IS THE SESSION'S; the register refuses a consent that is
    // not on their own entry.
    const result = body.action === 'scope'
      ? register.revoke(who, client, scope, who)
      : register.revokeApplication(who, client, who);
    if (!result || !result.ok) {
      ctx.errorCodes.mark(res, 'STS-PORTAL-0085');
      log.debug('Leaving POST ' + PATH + '. Nothing of theirs to withdraw.');
      return ctx.send(res, 400, this.page(session, at, null,
        'There is no such agreement of yours to withdraw. It may already ' +
        'have been withdrawn.'));
    }
    ctx.audit.audit({
      action: 'consent.revoke', actor: who, target: client,
      protocol: 'OAuth 2.0 / OIDC', channel: 'portal',
      detail: (body.action === 'scope'
        ? 'withdrew "' + scope + '"' : 'withdrew every consent (' +
          result.removed + ')') + ' for themselves at ' + PATH + '; ' +
        (result.revoked || 0) + ' token(s) issued under it revoked'
    });
    const entry = this.deps.applications().get(client);
    const name = entry && entry.name ? entry.name : client;
    log.debug('Leaving POST ' + PATH + '. Withdrawn.');
    // In the person's language (#539): the text rides the redirect, and
    // the application's name and the scope are data, parameters.
    const t = ctx.translatorFor(session);
    res.redirect(303, PATH + '?page=' + at + '&done=' + encodeURIComponent(
      body.action === 'scope'
        ? t.text('portalConsents.doneScope', { name: name, scope: scope })
        : t.text('portalConsents.doneApplication', { name: name })));
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalConsentsPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalConsentsPage.registerRoutes().");
  }
}

/**
 * The portal page at /portal/consents: where a person sees what each
 * application may ask for on their behalf and takes it back (#172).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalConsents {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalConsentsDeps) {
    deps.log.debug("Entering PortalConsents.constructor().");
    deps.log.debug("Leaving PortalConsents.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalConsentsDeps {
    helpers.log.debug("Entering PortalConsents.defaultDeps().");
    helpers.log.debug("Leaving PortalConsents.defaultDeps().");
    return {
      log: helpers.log,
      consent: function consent() {
        helpers.log.debug("Entering consent().");
        helpers.log.debug("Leaving consent().");
        return require('../common/consent');
      },
      applications: function applications() {
        helpers.log.debug("Entering applications().");
        helpers.log.debug("Leaving applications().");
        return require('../common/applications');
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
    context.log.debug("Entering PortalConsents.register().");
    const page = new PortalConsentsPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalConsents.register().");
    return { path: page.PATH };
  }
}

const slot = new InstanceSlot<PortalConsents>(
  'portal/portal_consents',
  () => new PortalConsents(PortalConsents.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The portal page at /portal/consents, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalConsents: PortalConsents,
  installInstance: (instance: PortalConsents): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
