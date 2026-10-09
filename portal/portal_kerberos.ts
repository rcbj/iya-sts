// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_kerberos.ts — /portal/kerberos, WHERE A PERSON SEES THEIR
// KERBEROS PRINCIPAL AND MAKES A KEYTAB FOR IT FROM THEIR OWN PASSWORD (#59,
// 2026-09-22).
//
// A keytab is what a client that cannot type a password — a cron job, a
// script on a server, `kinit -k` — signs in with, and it is exactly as good as
// the password it was made from. This page makes one for the signed-in person
// and for nobody else.
//
// **FROM THE PASSWORD THEY TYPE, AND FROM NOTHING ELSE.** This service never
// reads a stored Kerberos key back out (`kerberos/krb5_person_keys.ts`,
// `personKeytab()`), so the keytab is DERIVED from the password on the form,
// after `credentials.verify()` has checked it, and compared with the key the
// KDC holds before it is handed over. Nothing about the account changes: the
// password stays what it was and so does the kvno, and the keytab stops
// working when the password next changes.
//
// **THE PASSWORD IS ALSO THE RE-AUTHENTICATION.** A signed-in session is not
// enough to export a password-equivalent credential — a browser left open on
// a shared machine would otherwise hand anybody a keytab — so the form asks
// for it, counts a wrong one against the same budget as the password change
// (`password-change`), and audits both answers. `session-held` is the
// declaration `/portal/password` makes, for its reason: this session already
// met whatever second factor the account asks for.
//
// **THE IDENTITY IS THE SESSION'S AND THERE IS NO PARAMETER FOR IT** — the
// portal's rule (portal/CLAUDE.md).
//
// **THE KEYTAB IS SHOWN ON A 200 AND NEVER ON A REDIRECT**, with
// `Cache-Control: no-store`, for `/portal/app-passwords`' reason — and as a
// `data:` link with a `download` attribute beside the base64, the console's
// arrangement, which needs no script: the page is ordinary forms under the
// service-wide `script-src 'none'` (root CLAUDE.md, the CSP section).
//
// **DEVELOPMENT MODE** keys every user from `krb5.userPassword` rather than
// their own password, checks no password here (as it checks none anywhere),
// and so hands over a keytab derived from the password the development KDC
// uses — and the page says so rather than implying it was theirs.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_app_passwords.ts` is, and for its reason.
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS CLASSES (#50) — `portal_app_passwords.ts`'s shape. The
// Kerberos register is required LAZILY: the portal is built at 8a in the
// require order, long before the Kerberos modules (15–17) and the directory
// (21), and requiring the register here would load the principal database
// and the keytab writer out of their order for a page nobody has asked for
// yet.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_app_passwords.ts`'s context.
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

interface PortalKerberosDeps {
  // For the constructor only: a page logs through the portal's context.
  log: { debug(message: string): void };
  credentials: Json;
  // The Kerberos register, asked for when a page is drawn — see the header.
  personKeys: () => Json;
}

class PortalKerberosPage {
  readonly PATH: string;
  private readonly FORM: Json;
  private readonly QUERY: Json;

  constructor(private readonly deps: PortalKerberosDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalKerberosPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.PATH = ctx.BASE + '/kerberos';
    this.FORM = vz.object({
      action: vt.opt(vt.oneOf(['keytab'])),
      current: vz.string().max(1024).optional(),
      csrf_token: vt.opt(vt.token)
    });
    this.QUERY = vz.object({
      done: vz.string().max(200).optional()
    });
    ctx.log.debug("Leaving PortalKerberosPage.constructor().");
  }

  // -------------------------------------------------------------------------
  // THE PAGE. `made` is the keytab the POST just made, or null.
  // -------------------------------------------------------------------------
  private page(session: Json, message: unknown, error: unknown,
               made: Json): string {
    const { log, shell } = this.ctx;
    log.debug("Entering PortalKerberosPage.page().");
    const t = this.ctx.translatorFor(session);
    const who = String(session.user.username);
    const state = this.deps.personKeys().personKerberosState(who);
    const cards: string[] = [];
    if (made) {
      cards.push(this.keytabCard(made, t));
    }
    cards.push(this.stateCard(state, t));
    if (state.kdc && state.person) {
      cards.push(this.formCard(session, state, t));
    }
    log.debug("Leaving PortalKerberosPage.page().");
    return shell(this.PATH, session, message, error, cards.join(''));
  }

  private stateCard(state: Json, t: Json): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalKerberosPage.stateCard().");
    const heading = '<h2>' + t.html('portalKerberos.principalHeading') +
      '</h2>';
    if (!state.kdc) {
      log.debug("Leaving PortalKerberosPage.stateCard(). No KDC.");
      return '<div class="card">' + heading + '<p class="sub">' +
        t.html('portalKerberos.noKdc') + '</p></div>';
    }
    if (!state.person) {
      log.debug("Leaving PortalKerberosPage.stateCard(). Not a principal.");
      return '<div class="card">' + heading + '<p class="sub">' +
        t.html('portalKerberos.notPrincipal') + '</p></div>';
    }
    const keys = state.keys;
    const rows = '<tr><th>' + t.html('portalKerberos.principal') +
      '</th><td><code>' + esc(state.principal) +
      '</code></td></tr>' +
      (state.productKdc
        ? '<tr><th>' + t.html('portalKerberos.kvno') + '</th><td>' +
          (keys && keys.kvno != null
            ? esc(String(keys.kvno)) + (keys.current ? ''
                : t.html('portalKerberos.kvnoNotCurrent'))
            : t.html('portalKerberos.kvnoNone')) + '</td></tr>' +
          '<tr><th>' + t.html('portalKerberos.etypes') + '</th><td>' + (keys
            ? keys.etypes.map(function (one: Json) {
                return '<code>' + esc(one.name) + '</code>';
              }).join(' ')
            : '—') + '</td></tr>'
        : '<tr><th>' + t.html('portalKerberos.keys') + '</th><td>' +
          t.html('portalKerberos.devKeys') + '</td></tr>') +
      (state.disabled
        ? '<tr><th>' + t.html('portalKerberos.account') + '</th><td>' +
          t.html('portalKerberos.disabled') + '</td></tr>'
        : '');
    log.debug("Leaving PortalKerberosPage.stateCard().");
    return '<div class="card">' + heading +
      '<table>' + rows + '</table>' +
      '<p class="note">' + t.html('portalKerberos.keysNote') + '</p></div>';
  }

  private formCard(session: Json, state: Json, t: Json): string {
    const { log, websecurity } = this.ctx;
    log.debug("Entering PortalKerberosPage.formCard().");
    if (state.disabled) {
      log.debug("Leaving PortalKerberosPage.formCard(). Disabled.");
      return '<div class="card"><h2>' +
        t.html('portalKerberos.downloadHeading') + '</h2><p class="sub">' +
        t.html('portalKerberos.disabledNoKeytab') + '</p></div>';
    }
    log.debug("Leaving PortalKerberosPage.formCard().");
    // The command is a parameter (#539): it holds the principal, which is
    // data, and `<file>`, which the parameter's escaping writes as text.
    return '<div class="card"><h2>' +
      t.html('portalKerberos.downloadHeading') + '</h2>' +
      '<p class="sub">' + t.html('portalKerberos.downloadSub',
        { command: 'kinit -k -t <file> ' + state.principal }) + '</p>' +
      '<form method="post" action="' + this.PATH + '">' +
      websecurity.field(session.id) +
      '<input type="hidden" name="action" value="keytab">' +
      '<p><label>' + t.html('portalKerberos.currentPassword') +
      ' <input type="password" ' +
      'name="current" autocomplete="current-password" required></label></p>' +
      '<p><button type="submit">' + t.html('portalKerberos.make') +
      '</button></p>' +
      '</form>' +
      '<p class="note">' + t.html('portalKerberos.downloadNote') + '</p>' +
      '</div>';
  }

  private keytabCard(made: Json, t: Json): string {
    const { log, esc } = this.ctx;
    log.debug("Entering PortalKerberosPage.keytabCard().");
    log.debug("Leaving PortalKerberosPage.keytabCard().");
    const file = String(made.keytabFilename);
    // A warning, not a refusal, though it wears the error box's colour, so
    // it is the catalog's (#539). The commands are parameters: the file
    // name and the principal in them are data.
    return '<div class="card"><h2>' + t.html('portalKerberos.keytabHeading') +
      '</h2>' +
      '<div class="err">' + t.html('portalKerberos.saveNow') + '</div>' +
      '<table><tr><th>' + t.html('portalKerberos.principal') +
      '</th><td><code>' + esc(made.principal) +
      '</code></td></tr><tr><th>' + t.html('portalKerberos.kvno') +
      '</th><td>' +
      esc(String(made.kvno)) + '</td></tr>' +
      '<tr><th>' + t.html('portalKerberos.etypes') + '</th><td>' +
      made.etypes.map(function (etype: unknown) {
        return '<code>' + esc(String(etype)) + '</code>';
      }).join(' ') + '</td></tr></table>' +
      (made.source === 'development'
        ? '<p class="note">' + t.html('portalKerberos.devKeytab') + '</p>'
        : '') +
      '<p><a class="btn" download="' + esc(made.keytabFilename) +
      '" href="data:application/octet-stream;base64,' + esc(made.keytab) +
      '">' + t.html('portalKerberos.save', { file: file }) + '</a></p>' +
      '<p class="note">' + t.html('portalKerberos.pasteNote', {
        decode: 'base64 -d > ' + file,
        list: 'klist -k -e ' + file,
        use: 'kinit -k -t ' + file + ' ' + made.principal }) + '</p>' +
      '<textarea readonly rows="6" name="keytab-base64">' + esc(made.keytab) +
      '</textarea></div>';
  }

  // A refusal drawn on the page, with its code on the response.
  private refused(res: Res, session: Json, status: number, code: string,
                  sentence: unknown): unknown {
    const { log, errorCodes, send } = this.ctx;
    log.debug("Entering PortalKerberosPage.refused(). code=" + code);
    errorCodes.mark(res, code);
    log.debug("Leaving PortalKerberosPage.refused().");
    return send(res, status, this.page(session, null, sentence, null));
  }

  // -------------------------------------------------------------------------
  // GET /portal/kerberos
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
    return ctx.send(res, 200, this.page(session, asked.value.done || null,
                                        null, null));
  }

  // -------------------------------------------------------------------------
  // POST /portal/kerberos — `manage-own`: it exports a credential of this
  // person's.
  // -------------------------------------------------------------------------
  private async postPage(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { credentials } = this.deps;
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
    const csrf = ctx.websecurity.checkCsrf(session.id, body);
    if (!csrf.ok) {
      ctx.audit.record({
        category: 'authentication', action: 'portal.kerberos.csrf',
        errorCode: ctx.innerCode(csrf) || 'STS-PORTAL-0017',
        actor: who, outcome: 'failure',
        summary: 'a keytab download was refused: ' + csrf.reason,
        detail: { address: ctx.websecurity.addressOf(req) }
      });
      log.debug('Leaving POST ' + PATH + '. CSRF.');
      ctx.errorCodes.mark(res, ctx.innerCode(csrf) || 'STS-PORTAL-0017');
      return ctx.send(res, 403, this.page(session, null, csrf.detail, null));
    }
    if (String(body.action || 'keytab') !== 'keytab') {
      log.debug('Leaving POST ' + PATH + '. No such action.');
      return this.refused(res, session, 400, 'STS-PORTAL-0082',
                          'That is not something this page does.');
    }
    // THE PASSWORD CHANGE'S BUDGET, shared: a wrong password here is the same
    // guess as a wrong current password there, and a second budget would be a
    // second set of guesses for whoever found the browser open.
    const allowed = await ctx.websecurity.attemptShared('password-change',
                                                        req, who);
    if (!allowed.ok) {
      log.debug('Leaving POST ' + PATH + '. Rate limited.');
      return this.refused(res, session, 429,
                          ctx.innerCode(allowed) || 'STS-PORTAL-0019',
                          allowed.detail);
    }
    const password = String(body.current || '');
    // In DEVELOPMENT mode `verify()` accepts anything, as it does at
    // `/portal/password` and for its reason; the keytab is then the
    // development KDC's key, not one from this password (see the header).
    const checked = await credentials.verifyAsync(who, password,
      { via: 'the portal keytab download', secondFactor: 'session-held' });
    if (!checked.ok) {
      ctx.audit.record({
        category: 'authentication', action: 'portal.kerberos.refused',
        errorCode: ctx.innerCode(checked) || 'STS-PORTAL-0080',
        actor: who, outcome: 'failure',
        summary: 'a keytab download was refused: the password was not right',
        detail: { reason: checked.reason,
                  address: ctx.websecurity.addressOf(req) }
      });
      log.info('portal: a keytab download for ' + who + ' was refused (' +
               checked.reason + ').');
      log.debug('Leaving POST ' + PATH + '. Wrong password.');
      return this.refused(res, session, 400, 'STS-PORTAL-0080',
                          'Your password is not right.');
    }
    const made = await this.deps.personKeys().personKeytab(who, password,
      { actor: who, via: 'portal' });
    if (!made.ok) {
      ctx.audit.record({
        category: 'authentication', action: 'portal.kerberos.refused',
        errorCode: ctx.errorCodes.codeOf(made) || 'STS-PORTAL-0081',
        actor: who, outcome: 'failure',
        summary: 'a keytab could not be made',
        detail: { errors: made.errors }
      });
      log.debug('Leaving POST ' + PATH + '. The register refused.');
      return this.refused(res, session, 400, 'STS-PORTAL-0081',
                          (made.errors || ['No keytab was made.'])[0]);
    }
    await ctx.websecurity.succeededShared('password-change', req, who);
    ctx.audit.record({
      category: 'authentication', action: 'portal.kerberos.keytab',
      actor: who, target: who, outcome: 'success',
      summary: who + ' made a Kerberos keytab for themselves (kvno ' +
               made.kvno + ')',
      detail: { kvno: made.kvno, etypes: made.etypes, source: made.source,
                address: ctx.websecurity.addressOf(req) }
    });
    log.info('portal: ' + who + ' made themselves a Kerberos keytab at kvno ' +
             made.kvno + '. It was shown once.');
    log.debug('Leaving POST ' + PATH + '. Made.');
    res.set('Cache-Control', 'no-store');
    return ctx.send(res, 200, this.page(session, null, null, made));
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalKerberosPage.registerRoutes().");
    app.get(this.PATH, function (req, res) {
      return self.getPage(req, res);
    });
    app.post(this.PATH, function (req, res) {
      return self.postPage(req, res);
    });
    log.debug("Leaving PortalKerberosPage.registerRoutes().");
  }
}

/**
 * The portal page at /portal/kerberos: where a person sees their Kerberos
 * principal and makes a keytab for it from their own password (#59).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalKerberos {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalKerberosDeps) {
    deps.log.debug("Entering PortalKerberos.constructor().");
    deps.log.debug("Leaving PortalKerberos.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalKerberosDeps {
    helpers.log.debug("Entering PortalKerberos.defaultDeps().");
    helpers.log.debug("Leaving PortalKerberos.defaultDeps().");
    return {
      log: helpers.log,
      credentials: credentials,
      personKeys: function personKeys() {
        helpers.log.debug("Entering personKeys().");
        helpers.log.debug("Leaving personKeys().");
        return require('../kerberos/krb5_person_keys');
      }
    };
  }

  // The portal's call, at the point in its body where the route order is
  // right. Answers the page's path.
  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the page's path
   */
  register(context: PortalContext): { path: string } {
    context.log.debug("Entering PortalKerberos.register().");
    const page = new PortalKerberosPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalKerberos.register().");
    return { path: page.PATH };
  }
}

// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — see
// `portal_certificates.ts`.
const slot = new InstanceSlot<PortalKerberos>(
  'portal/portal_kerberos',
  () => new PortalKerberos(PortalKerberos.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The portal page at /portal/kerberos, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalKerberos: PortalKerberos,
  installInstance: (instance: PortalKerberos): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
