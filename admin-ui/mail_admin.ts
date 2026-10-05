// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mail_admin.ts
//
// ===========================================================================
// THE MAIL CHANNEL'S TWO CONSOLE PAGES (#63, 2026-09-22), and what the
// management API mirrors of them (rule 7).
//
//   * **/admin/mail** — Server configuration → Mail. Which transport this
//     realm sends through and whether it could be built (never a secret:
//     where each one is configured to be is `/admin/secrets`), where a mailed
//     link points, a TEST MESSAGE, the realm's own wording of each message,
//     and the `Mail` settings group (`SETTING_HOMES`). A realm's settings are
//     its override of the service's, so a realm administrator edits their own
//     realm's transport and no other.
//   * **/admin/mail/outbox** — Monitoring → Mail. The outbox: what was
//     queued, for whom, what became of it, the dead letters with a Retry, and
//     — in development only — a captured message's body, which is the whole
//     point of the capture transport.
//
// **A TEST MESSAGE GOES TO A DIRECTORY ENTRY**, the signed-in administrator's
// own unless another person is named, and never to an address typed on the
// form: the channel has no parameter that takes an address
// (`common/mail.ts`, header point 5), and a console form that took one would
// be an open relay with a login.
//
// Filed under two sections for the console's filing rule (a page goes where
// the question it answers is asked): *how is this service configured to send
// mail* and *what did it send*.
// ===========================================================================

import admin = require('./admin');
import adminViews = require('../admin-core/admin_views');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import mail = require('../common/mail');
import mailUses = require('../common/mail_uses');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import MailOutboxPage = require('./web_mail_outbox');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import MailPage = require('./web_mail');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

/**
 * Server configuration → Mail: the realm's transport, a test message, the
 * realm's wording of each message and the `Mail` settings.
 */
const PAGE = '/admin/mail';
/**
 * Monitoring → Mail: the outbox, what became of each message, and the dead
 * letters with a Retry.
 */
const OUTBOX = '/admin/mail/outbox';

// The actions each page takes, for the sentence an unknown one is answered
// with (the parity jobs read the list back out of it).
/**
 * The actions the settings page takes.
 */
const SETTINGS_ACTIONS = ['test', 'verify', 'save-template',
                          'reset-template'];
/**
 * The actions the outbox page takes.
 */
const OUTBOX_ACTIONS = ['retry'];

interface MailAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  mail: typeof mail;
  mailUses: typeof mailUses;
  parseBody: typeof helpers.parseBody;
}

/**
 * The mail channel's two console pages, and the views and actions the
 * management API mirrors of them (rule 7).
 */
class MailAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;
  /**
   * See the module's `OUTBOX`.
   */
  static readonly OUTBOX = OUTBOX;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console and the mail channel
   */
  constructor(private readonly deps: MailAdminDeps) {
    deps.log.debug("Entering MailAdmin.constructor().");
    deps.log.debug("Leaving MailAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): MailAdminDeps {
    helpers.log.debug("Entering MailAdmin.defaultDeps().");
    helpers.log.debug("Leaving MailAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      adminViews: adminViews,
      errorCodes: errorCodes,
      mail: mail,
      mailUses: mailUses,
      parseBody: helpers.parseBody
    };
  }

  // Who is acting: the console session's person, or '' for an API caller.
  private actorOf(req: Req): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering MailAdmin.actorOf().");
    let who = '';
    try {
      const state: Json = adminViews.gateStateFor(req);
      who = String((state && state.username) || '');
    } catch (e) {
      log.debug("Caught in MailAdmin.actorOf(): " + ((e && e.message) || e));
      who = '';
    }
    log.debug("Leaving MailAdmin.actorOf().");
    return who;
  }

  private refuse(code: string, why: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering MailAdmin.refuse(). " + code);
    log.debug("Leaving MailAdmin.refuse().");
    return errorCodes.mark({ ok: false, errors: [why] }, code);
  }

  // -------------------------------------------------------------------------
  // /admin/mail — the JSON both surfaces answer. `?template=<id>&lang=<tag>`
  // is the one message's drill-down.
  // -------------------------------------------------------------------------
  /**
   * Builds `/admin/mail`'s view: the channel's status, the message templates
   * and the settings, or one template when the query names `template` and
   * `lang`.
   *
   * @param req - the request
   * @param query - the query's values
   * @returns the view
   */
  settingsView(req: Req, query?: Json): Json {
    const { log, admin, mail } = this.deps;
    log.debug("Entering MailAdmin.settingsView().");
    const q = query || {};
    const out: Json = Object.assign({}, mail.status(), {
      templates: mail.listTemplates(),
      settings: admin.configSettingsJson(PAGE)
    });
    if (q.template) {
      out.template = mail.templateView(String(q.template),
                                       String(q.lang || 'en'));
    }
    log.debug("Leaving MailAdmin.settingsView().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE SETTINGS PAGE'S ACTIONS: `test`, `save-template`, `reset-template`.
  // `actor` is who pressed it (the console's person, or '' for an API
  // token), `via` which surface.
  // -------------------------------------------------------------------------
  /**
   * Takes one of the settings page's actions: `test`, `verify`, `save-template`
   * or `reset-template`.
   *
   * A test message goes to a person in the realm's directory, at their own
   * address; it is never sent to an address the request supplies.
   * @param body - the action and its fields
   * @param actor - who pressed it; '' for an API token
   * @param via - which surface asked
   * @returns `ok` with a message, or a refusal carrying its error code
   */
  settingsAction(body: Json, actor: string, via: string): Json {
    const { log, mail } = this.deps;
    log.debug("Entering MailAdmin.settingsAction().");
    const b = body || {};
    const action = String(b.action || '');
    if (SETTINGS_ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving MailAdmin.settingsAction(). Unknown.");
      return this.refuse('STS-MAIL-0025', 'Unknown action "' + action +
        '". The four are: ' + SETTINGS_ACTIONS.join(', ') + '.');
    }
    if (action === 'test') {
      const who = String(b.user || actor || '').trim();
      if (!who) {
        log.debug("Leaving MailAdmin.settingsAction(). Nobody to send to.");
        return this.refuse('STS-MAIL-0027', 'Name the person to send the ' +
          'test message to in `user` — a person in this realm\'s ' +
          'directory, whose own address it goes to. It is never an address.');
      }
      const person = mail.recipient(who);
      if (!person || !person.address) {
        log.debug("Leaving MailAdmin.settingsAction(). No address.");
        return this.refuse('STS-MAIL-0027', (person ? who + '\'s entry has ' +
          'no mail attribute' : 'There is no "' + who + '" in this realm\'s ' +
          'directory') + ', so a test message has nowhere to go.');
      }
      const sent = mail.send({ username: who, template: 'test-message',
        values: { username: actor || who,
                  when: new Date().toISOString(),
                  transport: mail.effectiveTransport() },
        via: via, actor: actor });
      if (!sent.ok) {
        log.debug("Leaving MailAdmin.settingsAction(). Not queued.");
        return this.refuse((sent.refused[0] && sent.refused[0].code) ||
                           'STS-MAIL-0001', 'The test message was not ' +
                           'queued: ' + String(sent.error || '') + '.');
      }
      log.debug("Leaving MailAdmin.settingsAction(). Test queued.");
      return { ok: true, message: sent.queued[0]
        ? 'A test message to ' + sent.queued[0].to + ' was queued through ' +
          'the ' + sent.queued[0].transport + ' transport. The outbox ' +
          '(Monitoring → Mail) shows where it got to.'
        : 'A test message was queued.',
        message_id: sent.queued[0] ? sent.queued[0].id : '' };
    }
    if (action === 'verify') {
      // A VERIFICATION LINK TO A PERSON'S OWN ADDRESS, sent by an
      // administrator — the person's own button is on /portal/email. It is
      // the same link, spent by the person at /portal/verify-email; the
      // administrator never sees it.
      const who = String(b.user || '').trim();
      if (!who) {
        log.debug("Leaving MailAdmin.settingsAction(). verify: nobody.");
        return this.refuse('STS-MAIL-0012', 'Name the person whose address ' +
                           'to verify in `user`.');
      }
      if (!mail.available()) {
        log.debug("Leaving MailAdmin.settingsAction(). verify: no mail.");
        return this.refuse('STS-MAIL-0032', 'This realm has no mail ' +
                           'transport, so no verification link can be sent.');
      }
      log.debug("Leaving MailAdmin.settingsAction(). verify.");
      return this.deps.mailUses.startVerification(who, via, actor || via);
    }
    const id = String(b.template || '');
    const lang = String(b.lang || '');
    if (action === 'save-template') {
      log.debug("Leaving MailAdmin.settingsAction(). save-template.");
      return mail.saveTemplate(id, lang, { subject: b.subject, text: b.text,
                                           html: b.html }, actor || via);
    }
    log.debug("Leaving MailAdmin.settingsAction(). reset-template.");
    return mail.resetTemplate(id, lang, actor || via);
  }

  // -------------------------------------------------------------------------
  // /admin/mail/outbox — the JSON both surfaces answer. `state` and `q`
  // filter; `message=<id>` is one message's drill-down, with its body only
  // when it was CAPTURED (development).
  // -------------------------------------------------------------------------
  /**
   * Builds `/admin/mail/outbox`'s view, filtered by `state` and `q`, or one
   * message when the query names `message`; its body only when it was captured
   * (development).
   *
   * @param req - the request
   * @param query - the query's values
   * @returns the view
   */
  outboxView(req: Req, query?: Json): Json {
    const { log, adminViews, mail } = this.deps;
    log.debug("Entering MailAdmin.outboxView().");
    const q = query || {};
    const state = mail.STATES.indexOf(String(q.state || '')) >= 0
      ? String(q.state) : '';
    const rows = mail.list({ state: state, q: String(q.q || '') });
    const paged = adminViews.pagedRows(q, rows, { noun: 'messages' });
    const out: Json = {
      realm: mail.status().realm,
      transport: mail.effectiveTransport(),
      counts: mail.counts(),
      state: state,
      q: String(q.q || ''),
      rows: paged.shown,
      rowsPaging: adminViews.pagingJson(paged.paging)
    };
    if (q.message) {
      out.message = mail.message(String(q.message));
    }
    Object.defineProperty(out, 'paging', { value: paged.paging,
                                           enumerable: false });
    log.debug("Leaving MailAdmin.outboxView(). " + rows.length + " row(s).");
    return out;
  }

  /**
   * Takes the outbox page's one action, `retry`, on a dead letter.
   *
   * @param body - `action` and the `message` to retry
   * @param actor - who pressed it; '' for an API token
   * @returns the channel's answer to the retry, or a refusal
   */
  outboxAction(body: Json, actor: string): Json {
    const { log, mail } = this.deps;
    log.debug("Entering MailAdmin.outboxAction().");
    const b = body || {};
    const action = String(b.action || '');
    if (OUTBOX_ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving MailAdmin.outboxAction(). Unknown.");
      return this.refuse('STS-MAIL-0025', 'Unknown action "' + action +
        '". The one is: ' + OUTBOX_ACTIONS.join(', ') + '.');
    }
    const id = String(b.message || b.id || '').trim();
    if (!id) {
      log.debug("Leaving MailAdmin.outboxAction(). No message.");
      return this.refuse('STS-MAIL-0018', 'Name the dead letter to retry in ' +
                         '`message`.');
    }
    log.debug("Leaving MailAdmin.outboxAction().");
    return mail.retry(id, actor || 'the management API');
  }

  // DRAWN BY `web_mail.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private settingsBody(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering MailAdmin.settingsBody().");
    const drawn = MailPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving MailAdmin.settingsBody().");
    return drawn;
  }

  // DRAWN BY `web_mail_outbox.ts` (#446): this page is converted for the
  // static console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private outboxBody(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering MailAdmin.outboxBody().");
    const drawn = MailOutboxPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving MailAdmin.outboxBody().");
    return drawn;
  }

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering MailAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      const json = self.settingsView(req, req.query);
      if (json.template || (req.query && req.query.template)) {
        if (!json.template) {
          errorCodes.mark(res, 'STS-MAIL-0017');
        }
        admin.respond(req, res, json, 'Mail — ' + String(req.query.template),
                      PAGE,
                      admin.messagesOf(req) + self.settingsBody(req, json),
                      admin.upTo(PAGE, String(req.query.template), {}));
        log.debug('Leaving GET ' + PAGE + '. A template.');
        return;
      }
      admin.respond(req, res, json, 'Mail', PAGE,
                    admin.messagesOf(req) + self.settingsBody(req, json));
      log.debug('Leaving GET ' + PAGE + '.');
    });
    app.post(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + PAGE + '.');
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-MAIL-0026');
        admin.respondToAction(req, res, PAGE, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + PAGE + '. Read-only.');
        return;
      }
      const result = self.settingsAction(parseBody(req), self.actorOf(req),
                                         'the admin console');
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-MAIL-0025');
      }
      admin.respondToAction(req, res, PAGE, result);
      log.debug('Leaving POST ' + PAGE + '.');
    });
    app.get(OUTBOX, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + OUTBOX + '.');
      const json = self.outboxView(req, req.query);
      if (req.query && req.query.message) {
        if (!json.message) {
          errorCodes.mark(res, 'STS-MAIL-0018');
        }
        admin.respond(req, res, json, 'Mail — message', OUTBOX,
                      admin.messagesOf(req) + self.outboxBody(req, json),
                      admin.upTo(OUTBOX, 'Message', {}));
        log.debug('Leaving GET ' + OUTBOX + '. One message.');
        return;
      }
      admin.respond(req, res, json, 'Mail outbox', OUTBOX,
                    admin.messagesOf(req) + self.outboxBody(req, json));
      log.debug('Leaving GET ' + OUTBOX + '.');
    });
    app.post(OUTBOX, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + OUTBOX + '.');
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-MAIL-0026');
        admin.respondToAction(req, res, OUTBOX, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + OUTBOX + '. Read-only.');
        return;
      }
      const result = self.outboxAction(parseBody(req), self.actorOf(req));
      if (!result.ok) {
        errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-MAIL-0025');
      }
      admin.respondToAction(req, res, OUTBOX, result);
      log.debug('Leaving POST ' + OUTBOX + '.');
    });
    log.debug("Leaving MailAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<MailAdmin>(
  'admin-ui/mail_admin',
  () => new MailAdmin(MailAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The mail channel's two console pages, `/admin/mail` and `/admin/mail/outbox`,
 * and what the management API mirrors of them (rule 7).
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  MailAdmin: MailAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: MailAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  OUTBOX: OUTBOX,
  SETTINGS_ACTIONS: SETTINGS_ACTIONS,
  OUTBOX_ACTIONS: OUTBOX_ACTIONS,
  // For `mgmt-api/admin_api.ts` (rule 7).
  settingsView: slot.forward('settingsView'),
  settingsAction: slot.forward('settingsAction'),
  outboxView: slot.forward('outboxView'),
  outboxAction: slot.forward('outboxAction')
};
