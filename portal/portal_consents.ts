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
// **A SCOPE UNDER GLOBAL CONSENT IS NOT LISTED**, because it is not the
// person's to withdraw: nothing about them was ever written, and the
// override is an operator's configuration of the application. The page says
// that in a sentence rather than drawing rows with no button.
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

  // A GeneralizedTime as a reader writes a date.
  private readable(at: string): string {
    const { log } = this.ctx;
    log.debug("Entering PortalConsentsPage.readable().");
    const text = String(at || '');
    log.debug("Leaving PortalConsentsPage.readable().");
    return text.length >= 14
      ? text.slice(0, 4) + '-' + text.slice(4, 6) + '-' + text.slice(6, 8) +
        ' ' + text.slice(8, 10) + ':' + text.slice(10, 12) + ' UTC'
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
            '<table><tr><th>You agreed it may ask for</th><th>When</th>' +
            '<th></th></tr>' +
            group.rows.map(function (one: Json): string {
              return '<tr><td><code>' + esc(one.scope) + '</code></td><td>' +
                esc(self.readable(one.at)) + '</td><td>' +
                self.form(session, { action: 'scope', client: group.client,
                                     scope: one.scope, page: String(at) },
                          'Withdraw') + '</td></tr>';
            }).join('') + '</table><p>' +
            self.form(session, { action: 'application',
                                 client: group.client, page: String(at) },
                      'Withdraw everything for this application') +
            '</p></div>';
        }).join('')
      : '<div class="card"><p class="sub">You have not agreed to anything ' +
        'that is written down. An application asks you the first time it ' +
        'wants something on your behalf, and your answer appears here.</p>' +
        '</div>';
    const paging = pages > 1
      ? '<p class="pagenav">' +
        (at > 1
          ? '<a href="' + esc(this.PATH + '?page=' + (at - 1)) +
            '">Previous</a>'
          : '<span class="off">Previous</span>') +
        '<span class="here">Page ' + esc(String(at)) + ' of ' +
        esc(String(pages)) + '</span>' +
        (at < pages
          ? '<a href="' + esc(this.PATH + '?page=' + (at + 1)) + '">Next</a>'
          : '<span class="off">Next</span>') +
        '</p>'
      : '';
    log.debug("Leaving PortalConsentsPage.page(). Page " + at + ".");
    return shell(this.PATH, session, message, error,
      '<div class="card"><p class="sub">What you have agreed each ' +
      'application may ask this identity provider for on your behalf. ' +
      '<strong>Withdrawing takes effect at once</strong>: every token the ' +
      'application holds for you under what you withdraw stops working — ' +
      'including one that lets it act while you are away ' +
      '(<code>offline_access</code>) — and it cannot renew them even if you ' +
      'agree again later; it has to ask you afresh. Withdrawing one thing ' +
      'ends everything the application was given together with it.</p>' +
      '<p class="note">Some applications are agreed for everybody by ' +
      'whoever runs this service, and you were never asked about those; ' +
      'they are not yours to withdraw here and are not listed.</p></div>' +
      body + paging);
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
    res.redirect(303, PATH + '?page=' + at + '&done=' + encodeURIComponent(
      (body.action === 'scope'
        ? 'Withdrawn: ' + name + ' may no longer ask for ' + scope + '.'
        : 'Withdrawn: ' + name + ' may no longer ask for anything.') +
      ' It asks you again next time.'));
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

class PortalConsents {
  constructor(private readonly deps: PortalConsentsDeps) {
    deps.log.debug("Entering PortalConsents.constructor().");
    deps.log.debug("Leaving PortalConsents.constructor().");
  }

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

export = {
  PortalConsents: PortalConsents,
  installInstance: (instance: PortalConsents): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
