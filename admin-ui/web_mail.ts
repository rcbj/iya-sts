// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_mail.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → MAIL, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Mail from the answer of `GET /admin-api/mail`: the channel this realm
// sends through, its test and verification, the message templates or one of
// them, and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `MailAdmin`'s in `admin-ui/mail_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Server configuration → Mail: the realm's transport, a test message, the
 * realm's wording of each message and the `Mail` settings.
 */
const PAGE = '/admin/mail';

/**
 * Monitoring → Mail outbox, which the templates' pages link to.
 */
const OUTBOX = '/admin/mail/outbox';

/**
 * Draws Mail from the answer of `GET /admin-api/mail`: the channel this realm
 * sends through, its test and verification, the message templates or one of
 * them, and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class MailPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return MailPage.settingsBody(ctx, view);
  }

  // -------------------------------------------------------------------------
  // THE HTML
  // -------------------------------------------------------------------------
  static settingsHtml(ctx: Json, json: Json): string {
    const esc = kit.esc.bind(kit);
    const canWrite = ctx.write;
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
      : kit.warn('<strong>This realm cannot send mail</strong>' +
          (json.buildProblem ? ' — ' + esc(json.buildProblem.why ||
                                           json.buildProblem) : '') +
          '. Configure a transport below; until then these forms, the ' +
          'emailed sign-in mechanisms on <a href="/admin/policies#authn">' +
          'Policies</a> and self-service reset are off.');
    const test = canWrite
      ? '<h2>Send a test message</h2>' + why +
        kit.note('To your own entry\'s address, or to another person in ' +
                   'this realm by username. Never to an address.') +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="test">' +
        '<div class="formrow"><label for="mail-test-user">Person</label>' +
        '<input type="text" id="mail-test-user" name="user" size="24" ' +
        'maxlength="256" placeholder="yourself"' + off + '><button ' +
        'type="submit"' + off + '>Send a test message</button></div>' +
        '</form>' +
        '<h2>Verify a person\'s address</h2>' +
        kit.note('Sends a single-use verification link to the address on ' +
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
      kit.note('Every message this service sends, in English, and the ' +
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
    return status + test + templates +
      (json.confinedToRealm ? '' : '<h2>Settings</h2>' +
       SettingsForms.forms(json.settings, PAGE));
  }

  static templateHtml(ctx: Json, t: Json): string {
    const esc = kit.esc.bind(kit);
    const canWrite = ctx.write;
    const field = function (name: string, label: string, value: string,
                            rows: number): string {
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
    return kit.note('<strong>' + esc(t.title) + '</strong>, a ' +
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

  /**
   * Registers the two pages and their actions.
   *
   * @param app - the shared express app
   */
  // THE TWO PAGES' BODIES (#446), each one method so that it can be one
  // renderer: Server configuration → Mail (the settings, or one message's
  // template when the query names it) and Monitoring → Mail outbox (the
  // list, or one message). Which of the two each draws is in the view.
  /**
   * Draws Server configuration → Mail: the channel and its settings, or one
   * template.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view from `settingsView()`
   * @returns the body as HTML
   */
  static settingsBody(ctx: Json, json: Json): string {
    if (json.template || (ctx.query && ctx.query.template)) {
      return json.template ? this.templateHtml(ctx, json.template)
        : kit.warn('There is no such message.');
    }
    return this.settingsHtml(ctx, json);
  }
}

export = MailPage;
