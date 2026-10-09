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
    const t = ctx.t;
    const esc = kit.esc.bind(kit);
    const canWrite = ctx.write;
    const problem = json.buildProblem;
    const relay = json.relay;
    const status = '<table class="grid"><tbody>' +
      '<tr><th>' + t.html('consoleMail.status.transport') +
      '</th><td><strong>' + esc(json.transport) +
      '</strong> ' + t.html('consoleMail.status.transportSetting',
        { setting: json.setting, mode: json.mode }) +
      (json.transport === 'capture'
        ? '<br><small>' + t.html('consoleMail.status.captureBefore') +
          '<a href="' + OUTBOX + '">' +
          t.html('consoleMail.status.captureLink') + '</a>' +
          t.html('consoleMail.status.captureAfter') +
          '</small>' : '') + (json.transport === 'off'
        ? '<br><small>' + t.html('consoleMail.status.off') +
          '</small>' : '') + '</td></tr>' +
      (relay ? '<tr><th>' + t.html('consoleMail.status.relay') +
        '</th><td><code>' + esc(relay.host) + ':' +
        esc(relay.port) + '</code>, ' + esc(relay.tls) + ', AUTH ' +
        esc(relay.auth) + ', DKIM ' + esc(relay.dkim) + '</td></tr>' : '') +
      '<tr><th>' + t.html('consoleMail.status.built') + '</th><td>' +
      (problem
        ? t.html('consoleMail.status.builtNo') + ' — ' + esc(problem.code) +
          ': ' + esc(problem.why) + ' <small>(' + esc(problem.at) +
          ')</small>'
        : t.html('consoleMail.status.builtOk')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleMail.status.from') + '</th><td><code>' +
      esc(json.from) + '</code></td></tr>' +
      '<tr><th>' + t.html('consoleMail.status.links') + '</th><td>' +
      (json.linkBase
        ? '<code>' + esc(json.linkBase) + '</code>' +
          (json.linkBasePinned ? '' : ' <small>' +
            t.html('consoleMail.status.linksUnpinned') + '</small>')
        : t.html('consoleMail.status.linksNowhere')) +
      '</td></tr><tr><th>' + t.html('consoleMail.status.reset') +
      '</th><td>' +
      (json.selfServiceReset ? t.html('consoleMail.status.resetOffered') :
        t.html('consoleMail.status.offWord')) + '</td></tr><tr><th>' +
      t.html('consoleMail.status.notices') + '</th><td>' +
      (json.securityNotices ? t.html('consoleMail.status.onWord')
        : t.html('consoleMail.status.offWord')) +
      '</td></tr></tbody></table>';
    // WITH NO WORKING TRANSPORT THE TWO FORMS ARE DRAWN DISABLED, WITH THE
    // REASON (#64: "these features should be greyed out in the admin
    // console"), rather than left out as they were until then — a control
    // that vanished reads as one this service does not have. `configRow()`'s
    // pattern on /admin/config.
    //
    // The sentence is split around its link (#539): a catalog message
    // cannot carry an anchor. The build problem's own text is the view's
    // and stays as it comes.
    const off = json.available ? '' : ' disabled';
    const why = json.available ? ''
      : kit.warn(t.html('consoleMail.cannot.head') +
          (json.buildProblem ? ' — ' + esc(json.buildProblem.why ||
                                           json.buildProblem) : '') +
          t.html('consoleMail.cannot.before') +
          '<a href="/admin/policies#authn">' +
          t.html('consoleMail.cannot.link') + '</a>' +
          t.html('consoleMail.cannot.after'));
    const test = canWrite
      ? '<h2>' + t.html('consoleMail.test.heading') + '</h2>' + why +
        kit.note(t.html('consoleMail.test.note')) +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="test">' +
        '<div class="formrow"><label for="mail-test-user">' +
        t.html('consoleMail.test.person') + '</label>' +
        '<input type="text" id="mail-test-user" name="user" size="24" ' +
        'maxlength="256" placeholder="' +
        esc(t.text('consoleMail.test.yourself')) + '"' + off + '><button ' +
        'type="submit"' + off + '>' + t.html('consoleMail.test.heading') +
        '</button></div>' +
        '</form>' +
        '<h2>' + t.html('consoleMail.verify.heading') + '</h2>' +
        kit.note(t.html('consoleMail.verify.note')) +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="verify">' +
        '<div class="formrow"><label for="mail-verify-user">' +
        t.html('consoleMail.test.person') + '</label>' +
        '<input type="text" id="mail-verify-user" name="user" size="24" ' +
        'maxlength="256" required' + off + '><button type="submit"' + off +
        '>' + t.html('consoleMail.verify.button') + '</button></div></form>'
      : '';
    // THE LANGUAGES EACH MESSAGE HAS A BUILT-IN TRANSLATION IN (#539),
    // beside the ones this realm wrote its own wording in: the view's
    // `builtInLanguages`, a short list in the same cell. A view without the
    // member (an older server) draws the cell as it always did.
    const templates = '<h2>' + t.html('consoleMail.templates.heading') +
      '</h2>' +
      kit.note(t.html('consoleMail.templates.note')) +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleMail.templates.message') + '</th><th>' +
      t.html('consoleMail.templates.category') + '</th>' +
      '<th>' + t.html('consoleMail.templates.placeholders') + '</th><th>' +
      t.html('consoleMail.templates.wording') + '</th></tr></thead>' +
      '<tbody>' + json.templates.map(function (tpl: Json): string {
        const builtIn = Array.isArray(tpl.builtInLanguages) &&
          tpl.builtInLanguages.length
          ? '<br><small>' + t.html('consoleMail.templates.builtIn',
              { languages: tpl.builtInLanguages.join(' ') }) + '</small>'
          : '';
        return '<tr><td><a href="' + PAGE + '?template=' +
          encodeURIComponent(tpl.id) + '&amp;lang=en"><code>' +
          esc(tpl.id) + '</code></a><br><small>' + esc(tpl.title) +
          '</small></td><td>' +
          esc(tpl.category) + '</td><td><small>' +
          tpl.values.concat(tpl.links).map(function (n: string): string {
            return '{{' + esc(n) + '}}';
          }).join(' ') + '</small></td><td>' + (tpl.languages.length
            ? tpl.languages.map(function (l: string): string {
                return '<a href="' + PAGE + '?template=' +
                  encodeURIComponent(tpl.id) + '&amp;lang=' +
                  encodeURIComponent(l) + '">' + esc(l) + '</a>';
              }).join(' ') : t.html('consoleMail.templates.builtInOnly')) +
          builtIn + '</td></tr>';
      }).join('') + '</tbody></table>';
    return status + test + templates +
      (json.confinedToRealm ? '' : '<h2>' +
       t.html('consoleMail.settings') + '</h2>' +
       SettingsForms.forms(json.settings, PAGE, undefined, t));
  }

  // `tpl` is the one template the view answered; `t` is the translator
  // (#539), so the template is no longer called `t` here.
  static templateHtml(ctx: Json, tpl: Json): string {
    const t = ctx.t;
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
      '<input type="hidden" name="template" value="' + esc(tpl.id) + '">' +
      '<div class="formrow"><label for="mail-t-lang">' +
      t.html('consoleMail.template.language') + '</label>' +
      '<input type="text" id="mail-t-lang" name="lang" size="10" ' +
      'maxlength="35" value="' + esc(tpl.lang) + '"></div>' +
      field('subject', t.html('consoleMail.template.subject'),
            tpl.subject, 1) +
      field('text', t.html('consoleMail.template.text'), tpl.text, 10) +
      field('html', t.html('consoleMail.template.html'), tpl.html, 10) +
      (canWrite ? '<div class="formrow"><button type="submit">' +
                  t.html('consoleMail.template.save') +
                  '</button></div>' : '') + '</form>' +
      (canWrite && tpl.own
        ? '<form method="post" action="' + PAGE + '">' +
          '<input type="hidden" name="action" value="reset-template">' +
          '<input type="hidden" name="template" value="' + esc(tpl.id) +
          '">' +
          '<input type="hidden" name="lang" value="' + esc(tpl.lang) + '">' +
          '<button type="submit" class="danger">' +
          t.html('consoleMail.template.reset') + '</button></form>' : '');
    return kit.note(t.html('consoleMail.template.intro',
      { title: tpl.title, category: tpl.category }) + ' ' +
      (tpl.own ? t.html('consoleMail.template.own', { lang: tpl.lang })
        : t.html('consoleMail.template.builtIn')) + ' ' +
      t.html('consoleMail.template.placeholders') + ' ' +
      tpl.values.concat(tpl.links).map(function (n: string): string {
        return '<code>{{' + esc(n) + '}}</code>';
      }).join(' ') + (tpl.links.length ? '; ' + tpl.links.map(function (n:
                                                                   string) {
        return '<code>{{' + esc(n) + '}}</code>';
      }).join(', ') + ' ' + t.html('consoleMail.template.isLink') : '.')) +
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
