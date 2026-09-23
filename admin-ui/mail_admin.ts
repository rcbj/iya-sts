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

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

const PAGE = '/admin/mail';
const OUTBOX = '/admin/mail/outbox';

// The actions each page takes, for the sentence an unknown one is answered
// with (the parity jobs read the list back out of it).
const SETTINGS_ACTIONS = ['test', 'verify', 'save-template',
                          'reset-template'];
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

class MailAdmin {
  static readonly PAGE = PAGE;
  static readonly OUTBOX = OUTBOX;

  constructor(private readonly deps: MailAdminDeps) {
    deps.log.debug("Entering MailAdmin.constructor().");
    deps.log.debug("Leaving MailAdmin.constructor().");
  }

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

  // -------------------------------------------------------------------------
  // THE HTML
  // -------------------------------------------------------------------------
  private settingsHtml(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering MailAdmin.settingsHtml().");
    const esc = admin.esc.bind(admin);
    const canWrite = admin.mayWrite(req);
    const problem = json.buildProblem;
    const relay = json.relay;
    const status = '<table class="grid"><tbody>' +
      '<tr><th>Transport</th><td><strong>' + esc(json.transport) +
      '</strong> (<code>mail.transport</code> is <code>' +
      esc(json.setting) + '</code>; this realm is in ' + esc(json.mode) +
      ' mode)' + (json.transport === 'capture'
        ? '<br><small>Development: every message is KEPT and shown on ' +
          '<a href="' + OUTBOX + '">Monitoring &rarr; Mail</a>, not sent.' +
          '</small>' : '') + (json.transport === 'off'
        ? '<br><small>Nothing is sent: a message is refused as it is ' +
          'queued (STS-MAIL-0001).</small>' : '') + '</td></tr>' +
      (relay ? '<tr><th>Relay</th><td><code>' + esc(relay.host) + ':' +
        esc(relay.port) + '</code>, ' + esc(relay.tls) + ', AUTH ' +
        esc(relay.auth) + ', DKIM ' + esc(relay.dkim) + '</td></tr>' : '') +
      '<tr><th>Built</th><td>' + (problem
        ? '<strong>NO</strong> — ' + esc(problem.code) + ': ' +
          esc(problem.why) + ' <small>(' + esc(problem.at) + ')</small>'
        : 'no failure recorded in this process') + '</td></tr>' +
      '<tr><th>From</th><td><code>' + esc(json.from) + '</code></td></tr>' +
      '<tr><th>Links point at</th><td>' + (json.linkBase
        ? '<code>' + esc(json.linkBase) + '</code>' +
          (json.linkBasePinned ? '' : ' <small>(the listener\'s configured ' +
            'address: <code>global.publicBaseUrl</code> is empty, which ' +
            'product mode refuses)</small>')
        : '<strong>nowhere</strong> — set <code>global.publicBaseUrl</code>; ' +
          'a message with a link is refused until then (STS-MAIL-0015)') +
      '</td></tr><tr><th>Self-service reset</th><td>' +
      (json.selfServiceReset ? 'offered where a transport is available' :
        'off') + '</td></tr><tr><th>Security notices</th><td>' +
      (json.securityNotices ? 'on' : 'off') + '</td></tr></tbody></table>';
    // WITH NO WORKING TRANSPORT THE TWO FORMS ARE DRAWN DISABLED, WITH THE
    // REASON (#64: "these features should be greyed out in the admin
    // console"), rather than left out as they were until then — a control
    // that vanished reads as one this service does not have. `configRow()`'s
    // pattern on /admin/config.
    const off = json.available ? '' : ' disabled';
    const why = json.available ? ''
      : admin.warn('<strong>This realm cannot send mail</strong>' +
          (json.buildProblem ? ' — ' + esc(json.buildProblem.why ||
                                           json.buildProblem) : '') +
          '. Configure a transport below; until then these forms, the ' +
          'emailed sign-in mechanisms on <a href="/admin/policies#authn">' +
          'Policies</a> and self-service reset are off.');
    const test = canWrite
      ? '<h2>Send a test message</h2>' + why +
        admin.note('To your own entry\'s address, or to another person in ' +
                   'this realm by username. Never to an address.') +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="test">' +
        '<div class="formrow"><label for="mail-test-user">Person</label>' +
        '<input type="text" id="mail-test-user" name="user" size="24" ' +
        'maxlength="256" placeholder="yourself"' + off + '><button ' +
        'type="submit"' + off + '>Send a test message</button></div>' +
        '</form>' +
        '<h2>Verify a person\'s address</h2>' +
        admin.note('Sends a single-use verification link to the address on ' +
                   'their entry; they follow it. You never see it. A person ' +
                   'can send themselves one from <code>/portal/email</code>.') +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="verify">' +
        '<div class="formrow"><label for="mail-verify-user">Person</label>' +
        '<input type="text" id="mail-verify-user" name="user" size="24" ' +
        'maxlength="256" required' + off + '><button type="submit"' + off +
        '>Send a verification link</button></div></form>'
      : '';
    const templates = '<h2>Messages</h2>' +
      admin.note('Every message this service sends, in English, and the ' +
                 'languages this realm has written its own wording in. A ' +
                 'person\'s <code>preferredLanguage</code> chooses. A link ' +
                 'is a placeholder whose value is this service\'s own; a ' +
                 'template that writes an address, loads an image or runs ' +
                 'anything is refused when it is saved.') +
      '<table class="grid"><thead><tr><th>Message</th><th>Category</th>' +
      '<th>Placeholders</th><th>This realm\'s wording</th></tr></thead>' +
      '<tbody>' + json.templates.map(function (t: Json): string {
        return '<tr><td><a href="' + PAGE + '?template=' +
          encodeURIComponent(t.id) + '&amp;lang=en"><code>' + esc(t.id) +
          '</code></a><br><small>' + esc(t.title) + '</small></td><td>' +
          esc(t.category) + '</td><td><small>' +
          t.values.concat(t.links).map(function (n: string): string {
            return '{{' + esc(n) + '}}';
          }).join(' ') + '</small></td><td>' + (t.languages.length
            ? t.languages.map(function (l: string): string {
                return '<a href="' + PAGE + '?template=' +
                  encodeURIComponent(t.id) + '&amp;lang=' +
                  encodeURIComponent(l) + '">' + esc(l) + '</a>';
              }).join(' ') : 'built-in only') + '</td></tr>';
      }).join('') + '</tbody></table>';
    log.debug("Leaving MailAdmin.settingsHtml().");
    return status + test + templates +
      (json.confinedToRealm ? '' : '<h2>Settings</h2>' +
       admin.configFormsFor(PAGE));
  }

  private templateHtml(req: Req, t: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering MailAdmin.templateHtml().");
    const esc = admin.esc.bind(admin);
    const canWrite = admin.mayWrite(req);
    const field = function (name: string, label: string, value: string,
                            rows: number): string {
      log.debug("Entering field(). " + name);
      log.debug("Leaving field().");
      return '<div class="formrow"><label for="mail-t-' + name + '">' +
        label + '</label>' + (rows > 1
          ? '<textarea id="mail-t-' + name + '" name="' + name + '" rows="' +
            rows + '" cols="90">' + esc(value) + '</textarea>'
          : '<input type="text" id="mail-t-' + name + '" name="' + name +
            '" size="90" maxlength="250" value="' + esc(value) + '">') +
        '</div>';
    };
    const form = '<form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="save-template">' +
      '<input type="hidden" name="template" value="' + esc(t.id) + '">' +
      '<div class="formrow"><label for="mail-t-lang">Language</label>' +
      '<input type="text" id="mail-t-lang" name="lang" size="10" ' +
      'maxlength="35" value="' + esc(t.lang) + '"></div>' +
      field('subject', 'Subject', t.subject, 1) +
      field('text', 'Text part', t.text, 10) +
      field('html', 'HTML part', t.html, 10) +
      (canWrite ? '<div class="formrow"><button type="submit">Save this ' +
                  'realm\'s wording</button></div>' : '') + '</form>' +
      (canWrite && t.own
        ? '<form method="post" action="' + PAGE + '">' +
          '<input type="hidden" name="action" value="reset-template">' +
          '<input type="hidden" name="template" value="' + esc(t.id) + '">' +
          '<input type="hidden" name="lang" value="' + esc(t.lang) + '">' +
          '<button type="submit" class="danger">Put back the built-in ' +
          'wording</button></form>' : '');
    log.debug("Leaving MailAdmin.templateHtml().");
    return admin.note('<strong>' + esc(t.title) + '</strong>, a ' +
      esc(t.category) + ' message. ' + (t.own ? 'This realm has its own ' +
      'wording in <code>' + esc(t.lang) + '</code>.' : 'This is the ' +
      'built-in wording; saving it makes it this realm\'s own in the ' +
      'language you name.') + ' Placeholders: ' +
      t.values.concat(t.links).map(function (n: string): string {
        return '<code>{{' + esc(n) + '}}</code>';
      }).join(' ') + (t.links.length ? '; ' + t.links.map(function (n:
                                                                   string) {
        return '<code>{{' + esc(n) + '}}</code>';
      }).join(', ') + ' is a link, and the text part must carry it.' : '.')) +
      form;
  }

  private outboxHtml(req: Req, json: Json): string {
    const { log, admin, adminViews } = this.deps;
    log.debug("Entering MailAdmin.outboxHtml().");
    const esc = admin.esc.bind(admin);
    const canWrite = admin.mayWrite(req);
    const c = json.counts;
    const tiles = '<div class="tiles">' +
      admin.tile(String(c.pending), 'pending') +
      admin.tile(String(c.sent), 'sent') +
      admin.tile(String(c.captured), 'captured') +
      admin.tile(String(c.dead), 'dead letters') + '</div>';
    const filters = '<form method="get" action="' + OUTBOX + '" ' +
      'class="inline"><label for="mail-state">State</label>' +
      '<select id="mail-state" name="state"><option value="">all</option>' +
      ['pending', 'sent', 'captured', 'dead'].map(function (s) {
        return '<option value="' + s + '"' + (json.state === s ? ' selected'
          : '') + '>' + (s === 'dead' ? 'dead letters' : s) + '</option>';
      }).join('') + '</select> <input type="text" name="q" size="24" ' +
      'placeholder="person, address, message, code" value="' + esc(json.q) +
      '"> <button type="submit">Show</button></form>';
    const params: Json = Object.assign({}, adminViews.pageParamsOf(
      { state: json.state, q: json.q }));
    const nav = admin.pageNavPair(OUTBOX, params, json.paging);
    const rows = json.rows.map(function (r: Json): string {
      return '<tr><td><small>' + esc(r.queuedAt) + '</small></td><td>' +
        '<a href="' + OUTBOX + '?message=' + encodeURIComponent(r.id) + '">' +
        esc(r.template) + '</a><br><small>' + esc(r.category) +
        '</small></td><td>' + esc(r.username) + '<br><small><code>' +
        esc(r.to) + '</code></small></td><td><strong>' + esc(r.state) +
        '</strong> <small>via ' + esc(r.transport) + ', ' + r.attempts +
        ' attempt(s)</small>' + (r.errorCode ? '<br><small>' +
          esc(r.errorCode) + ': ' + esc(r.why) + '</small>' : '') +
        '</td><td>' + (r.state === 'dead' && canWrite
          ? '<form method="post" action="' + OUTBOX + '" class="inline">' +
            '<input type="hidden" name="action" value="retry">' +
            '<input type="hidden" name="message" value="' + esc(r.id) + '">' +
            '<button type="submit">Retry</button></form>' : '') +
        '</td></tr>';
    }).join('');
    log.debug("Leaving MailAdmin.outboxHtml().");
    return tiles + admin.note('Every message this realm queued: to whom, ' +
      'which message, and what became of it. A SENT message keeps no body. ' +
      'A dead letter keeps its body until it is retried or retention ' +
      '(<code>mail.retentionS</code>) removes it; Retry sends it again to ' +
      'the address the entry holds now.', 'What this page is') + filters +
      nav.head + '<table class="grid"><thead><tr><th>Queued</th><th>' +
      'Message</th><th>To</th><th>State</th><th></th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="5">Nothing has been queued here.</td>' +
       '</tr>') + '</tbody></table>' + nav.foot;
  }

  private messageHtml(m: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering MailAdmin.messageHtml().");
    const esc = admin.esc.bind(admin);
    const facts = ['id', 'state', 'username', 'to', 'from', 'subject',
                   'template', 'category', 'lang', 'transport', 'attempts',
                   'generation', 'errorCode', 'why', 'providerId',
                   'messageId', 'via', 'actor', 'queuedAt', 'lastAttemptAt',
                   'finishedAt'];
    log.debug("Leaving MailAdmin.messageHtml().");
    return '<table class="grid"><tbody>' + facts.map(function (k) {
      return '<tr><th>' + k + '</th><td>' + esc(String(m[k] === undefined
        ? '' : m[k])) + '</td></tr>';
    }).join('') + '</tbody></table>' + (m.text !== undefined
      ? '<h2>The captured message</h2>' + admin.note('Development only: ' +
          'the capture transport kept it instead of sending it. Links in it ' +
          'work.') + '<h3>Text part</h3><pre>' + esc(m.text) + '</pre>' +
        '<h3>HTML part, as source</h3><pre>' + esc(m.html) + '</pre>'
      : admin.note('No body is shown: a message that was sent keeps none, ' +
                   'and a pending or dead one\'s is not drawn here.'));
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
                      PAGE, admin.messagesOf(req) + (json.template
                        ? self.templateHtml(req, json.template)
                        : admin.warn('There is no such message.')),
                      admin.upTo(PAGE, String(req.query.template), {}));
        log.debug('Leaving GET ' + PAGE + '. A template.');
        return;
      }
      admin.respond(req, res, json, 'Mail', PAGE,
                    admin.messagesOf(req) + self.settingsHtml(req, json));
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
                      admin.messagesOf(req) + (json.message
                        ? self.messageHtml(json.message)
                        : admin.warn('There is no such message in this ' +
                                     'realm\'s outbox.')),
                      admin.upTo(OUTBOX, 'Message', {}));
        log.debug('Leaving GET ' + OUTBOX + '. One message.');
        return;
      }
      admin.respond(req, res, json, 'Mail outbox', OUTBOX,
                    admin.messagesOf(req) + self.outboxHtml(req, json));
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  MailAdmin: MailAdmin,
  installInstance: (instance: MailAdmin): void => slot.install(instance),
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
