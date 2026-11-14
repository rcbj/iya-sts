// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: web_broadcast.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → BROADCAST ANNOUNCEMENT (#1086), drawn from
// `GET /admin-api/broadcast`.
//
// One form: the message, a checkbox per application (all ticked), and — for
// a service administrator in the default realm — whether it goes to this
// realm or every realm. It posts `action=send` to `/admin/broadcast`, which
// the runtime sends to `POST /admin-api/broadcast/send` (rule 7); the answer
// comes back as the page's notice or refusal, the shape every action here
// has. What it SENDS is `ssf.broadcastAnnouncement()`'s business; what the
// people signed in SEE is `common/web_announcements.ts`'s.
//
// A static utility class, on `web_kit.ts`'s terms: it holds no state, logs
// nothing, and is bundled for a browser.
// ---------------------------------------------------------------------------
import WebKit = require('./web_kit');

type Json = any;

const PAGE = '/admin/broadcast';

/**
 * Draws the Broadcast Announcement page from its view.
 */
class BroadcastPage {
  /**
   * Draws the page's body.
   *
   * @param view - `GET /admin-api/broadcast`'s answer
   * @param ctx - the render context, whose translator draws the words
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const c = ctx || WebKit.context();
    const t = c.t;
    const esc = WebKit.esc.bind(WebKit);
    const v = view || {};
    const off = c.write && v.ready ? '' : ' disabled';
    const surfaces = (Array.isArray(v.surfaces) ? v.surfaces : [])
      .map(function (one: Json): string {
        const id = 'broadcast-surface-' + esc(one.id);
        return '<label for="' + id + '"><input type="checkbox" id="' + id +
          '" name="surfaces" value="' + esc(one.id) + '" checked' + off +
          '> ' + esc(one.label) + '</label> ';
      }).join('');
    const scope = v.everyRealm
      ? '<fieldset class="broadcast-scope"><legend>' +
        t.html('consoleBroadcast.scope.legend') + '</legend>' +
        '<label for="broadcast-scope-realm"><input type="radio" ' +
        'id="broadcast-scope-realm" name="everyRealm" value="false" checked' +
        off + '> ' + t.html('consoleBroadcast.scope.realm',
                            { realm: v.realm }) + '</label> ' +
        '<label for="broadcast-scope-every"><input type="radio" ' +
        'id="broadcast-scope-every" name="everyRealm" value="true"' + off +
        '> ' + t.html('consoleBroadcast.scope.every',
                      { count: Number(v.realmCount) || 1 }) +
        '</label></fieldset>'
      : '<p>' + t.html('consoleBroadcast.scope.only',
                       { realm: v.realm }) + '</p>';
    const notReady = v.ready ? ''
      : WebKit.warn(t.html('consoleBroadcast.notReady') + ' ' +
                    esc(v.why || ''));
    const readOnly = c.write ? ''
      : WebKit.note(t.html('consoleBroadcast.readOnly'));
    return WebKit.note(t.html('consoleBroadcast.about',
                              { seconds: Math.round(
                                (Number(v.pollMs) || 5000) / 1000) })) +
      notReady + readOnly +
      '<form method="post" action="' + PAGE + '" id="broadcast-form">' +
      '<input type="hidden" name="action" value="send">' +
      '<div class="formrow"><label for="broadcast-message">' +
      t.html('consoleBroadcast.message') + '</label>' +
      '<textarea id="broadcast-message" name="message" rows="4" cols="60" ' +
      'maxlength="' + (Number(v.maxChars) || 500) + '" required' + off +
      '></textarea></div>' +
      '<p class="hint">' + t.html('consoleBroadcast.maxChars',
                                  { max: Number(v.maxChars) || 500 }) +
      '</p>' +
      '<fieldset class="broadcast-surfaces"><legend>' +
      t.html('consoleBroadcast.surfaces') + '</legend>' + surfaces +
      '</fieldset>' + scope +
      '<div class="formrow"><button type="submit" id="broadcast-send"' + off +
      '>' + t.html('consoleBroadcast.send') + '</button></div></form>' +
      '<p><a href="/admin/ssf">' + t.html('consoleBroadcast.streamsLink') +
      '</a></p>';
  }
}

export = BroadcastPage;
