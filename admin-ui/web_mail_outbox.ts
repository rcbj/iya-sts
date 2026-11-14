// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_mail_outbox.ts
//
// ---------------------------------------------------------------------------
// MONITORING → MAIL OUTBOX, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Mail outbox from the answer of `GET /admin-api/mail/outbox`: what this
// realm has queued, sent, captured and given up on, and one message.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `MailAdmin`'s in `admin-ui/mail_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Monitoring → Mail: the outbox, what became of each message, and the dead
 * letters with a Retry.
 */
const OUTBOX = '/admin/mail/outbox';

/**
 * Draws Mail outbox from the answer of `GET /admin-api/mail/outbox`: what this
 * realm has queued, sent, captured and given up on, and one message.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class MailOutboxPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return MailOutboxPage.outboxBody(ctx, view);
  }

  static outboxHtml(ctx: Json, json: Json): string {
    const t = ctx.t;
    const esc = kit.esc.bind(kit);
    const canWrite = ctx.write;
    const c = json.counts;
    // The four states' names, as the tiles and the filter both draw them
    // (#539): the option's VALUE stays the state's own name.
    const stateName = {
      pending: t.text('consoleMailOutbox.state.pending'),
      sent: t.text('consoleMailOutbox.state.sent'),
      captured: t.text('consoleMailOutbox.state.captured'),
      dead: t.text('consoleMailOutbox.state.dead')
    };
    const tiles = '<div class="tiles">' +
      kit.tile(String(c.pending), stateName.pending) +
      kit.tile(String(c.sent), stateName.sent) +
      kit.tile(String(c.captured), stateName.captured) +
      kit.tile(String(c.dead), stateName.dead) + '</div>';
    const filters = '<form method="get" action="' + OUTBOX + '" ' +
      'class="inline"><label for="mail-state">' +
      t.html('consoleMailOutbox.filter.state') + '</label>' +
      '<select id="mail-state" name="state"><option value="">' +
      t.html('consoleMailOutbox.filter.all') + '</option>' +
      ['pending', 'sent', 'captured', 'dead'].map(function (s) {
        return '<option value="' + s + '"' + (json.state === s ? ' selected'
          : '') + '>' + esc(stateName[s]) + '</option>';
      }).join('') + '</select> <input type="text" name="q" size="24" ' +
      'placeholder="' + esc(t.text('consoleMailOutbox.filter.placeholder')) +
      '" value="' + esc(json.q) +
      '"> <button type="submit">' + t.html('consoleMailOutbox.filter.show') +
      '</button></form>';
    const params: Json = Object.assign({}, kit.pageParamsOf(
      { state: json.state, q: json.q }));
    const nav = kit.pageNavPair(OUTBOX, params, json.rowsPaging);
    const rows = json.rows.map(function (r: Json): string {
      return '<tr><td><small>' + esc(r.queuedAt) + '</small></td><td>' +
        '<a href="' + OUTBOX + '?message=' + encodeURIComponent(r.id) + '">' +
        esc(r.template) + '</a><br><small>' + esc(r.category) +
        '</small></td><td>' + esc(r.username) + '<br><small><code>' +
        esc(r.to) + '</code></small></td><td><strong>' + esc(r.state) +
        '</strong> <small>' + t.html('consoleMailOutbox.row.via',
          { transport: r.transport, attempts: r.attempts }) + '</small>' +
        (r.errorCode ? '<br><small>' +
          esc(r.errorCode) + ': ' + esc(r.why) + '</small>' : '') +
        '</td><td>' + (r.state === 'dead' && canWrite
          ? '<form method="post" action="' + OUTBOX + '" class="inline">' +
            '<input type="hidden" name="action" value="retry">' +
            '<input type="hidden" name="message" value="' + esc(r.id) + '">' +
            '<button type="submit">' + t.html('consoleMailOutbox.row.retry') +
            '</button></form>' : '') +
        '</td></tr>';
    }).join('');
    return tiles + kit.note(t.html('consoleMailOutbox.note.what'),
                            t.text('consoleMailOutbox.note.whatLabel')) +
      filters + nav.head + '<table class="grid"><thead><tr><th>' +
      t.html('consoleMailOutbox.th.queued') + '</th><th>' +
      t.html('consoleMailOutbox.th.message') + '</th><th>' +
      t.html('consoleMailOutbox.th.to') + '</th><th>' +
      t.html('consoleMailOutbox.th.state') +
      '</th><th></th></tr></thead><tbody>' +
      (rows || '<tr><td colspan="5">' +
       t.html('consoleMailOutbox.empty') + '</td>' +
       '</tr>') + '</tbody></table>' + nav.foot;
  }

  // The facts' names are the row's own member names and stay as they are;
  // `t` is the page's translator, given by the caller (#539).
  static messageHtml(m: Json, t: Json): string {
    const esc = kit.esc.bind(kit);
    const facts = ['id', 'state', 'username', 'to', 'from', 'subject',
                   'template', 'category', 'lang', 'transport', 'attempts',
                   'generation', 'errorCode', 'why', 'providerId',
                   'messageId', 'via', 'actor', 'queuedAt', 'lastAttemptAt',
                   'finishedAt'];
    return '<table class="grid"><tbody>' + facts.map(function (k) {
      return '<tr><th>' + k + '</th><td>' + esc(String(m[k] === undefined
        ? '' : m[k])) + '</td></tr>';
    }).join('') + '</tbody></table>' + (m.text !== undefined
      ? '<h2>' + t.html('consoleMailOutbox.captured.heading') + '</h2>' +
        kit.note(t.html('consoleMailOutbox.captured.note')) + '<h3>' +
        t.html('consoleMailOutbox.captured.text') + '</h3><pre>' +
        esc(m.text) + '</pre>' +
        '<h3>' + t.html('consoleMailOutbox.captured.html') + '</h3><pre>' +
        esc(m.html) + '</pre>'
      : kit.note(t.html('consoleMailOutbox.noBody')));
  }

  /**
   * Draws Monitoring → Mail outbox: the list, or one message.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view from `outboxView()`
   * @returns the body as HTML
   */
  static outboxBody(ctx: Json, json: Json): string {
    if (ctx.query && ctx.query.message) {
      return json.message ? this.messageHtml(json.message, ctx.t)
        : kit.warn('There is no such message in this ' +
                     'realm\'s outbox.');
    }
    return this.outboxHtml(ctx, json);
  }
}

export = MailOutboxPage;
