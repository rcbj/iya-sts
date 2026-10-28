// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: web_post_login_campaigns.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → POST-LOGIN CAMPAIGNS (#1111), drawn from
// `GET /admin-api/post-login-campaigns`.
//
// Two tabs. **Campaigns**: every campaign of the realm with its state, its
// numbers, what its runs have done so far, and a Pause, Resume or End
// button where the state allows one. **Start**: the form — the activity, an
// optional group, the reminder interval, the most mails per person and how
// many people a run reads. Each posts to `/admin/post-login-campaigns`,
// which the runtime sends to `POST /admin-api/post-login-campaigns/<action>`
// (rule 7); the answer comes back as the page's notice or refusal.
//
// THIS PAGE IS THE CONTROLS, NOT THE REPORT (rcbj on #1110): who was mailed
// and where each person stands is the reports application's
// `postLoginProgress` source, and the page links there rather than drawing
// a second copy.
//
// A static utility class, on `web_kit.ts`'s terms: it holds no state, logs
// nothing, and is bundled for a browser.
// ---------------------------------------------------------------------------
import WebKit = require('./web_kit');

type Json = any;

const PAGE = '/admin/post-login-campaigns';

/**
 * Draws Directory → Post-login campaigns from its view.
 */
class PostLoginCampaignsPage {
  /**
   * Draws the page's body.
   *
   * @param view - `GET /admin-api/post-login-campaigns`'s answer
   * @param ctx - the render context: the translator, and whether the
   *   reader may write
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const c = ctx || WebKit.context();
    const t = c.t;
    const v = view || {};
    const self = PostLoginCampaignsPage;
    const warnings = (v.mailAvailable ? ''
      : WebKit.warn(t.html('consolePostLoginCampaigns.noMail'))) +
      (v.activityEnabled ? ''
        : WebKit.warn(t.html('consolePostLoginCampaigns.noActivity')));
    return WebKit.note(t.html('consolePostLoginCampaigns.about', {
      minutes: Number(v.everyMinutes) || 10 })) + warnings +
      '<p><a href="/report/sources/postLoginProgress">' +
      t.html('consolePostLoginCampaigns.reportLink') + '</a></p>' +
      '<h2 data-tab="campaigns">' +
      t.html('consolePostLoginCampaigns.campaigns') + '</h2>' +
      self.list(v, c) +
      '<h2 data-tab="start">' + t.html('consolePostLoginCampaigns.start') +
      '</h2>' + self.startForm(v, c);
  }

  // A state in the reader's words.
  private static stateWord(t: Json, state: string): string {
    const known = ['running', 'paused', 'ended'];
    return known.indexOf(state) >= 0
      ? t.html('consolePostLoginCampaigns.state.' + state)
      : WebKit.esc(state);
  }

  // One act's button, a form of its own posting `action` and `id`.
  private static actButton(t: Json, act: string, id: string): string {
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + act + '">' +
      '<input type="hidden" name="id" value="' + WebKit.esc(id) + '">' +
      '<button type="submit"' + (act === 'end' ? ' class="danger"' : '') +
      '>' + t.html('consolePostLoginCampaigns.act.' + act) +
      '</button></form>';
  }

  // The Campaigns tab.
  private static list(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PostLoginCampaignsPage;
    const list = Array.isArray(v.campaigns) ? v.campaigns : [];
    if (!list.length) {
      return WebKit.note(t.html('consolePostLoginCampaigns.none'));
    }
    const rows = list.map(function (one: Json): string {
      const run = one.run || {};
      const acts = !ctx.write ? ''
        : one.state === 'running'
          ? self.actButton(t, 'pause', one.id) +
            self.actButton(t, 'end', one.id)
          : one.state === 'paused'
            ? self.actButton(t, 'resume', one.id) +
              self.actButton(t, 'end', one.id)
            : '';
      return '<tr><td><code>' + WebKit.esc(one.id) + '</code></td><td>' +
        self.stateWord(t, one.state) + '</td><td><code>' +
        WebKit.esc(one.activity) + '</code></td><td>' +
        (one.group ? '<code>' + WebKit.esc(one.group) + '</code>'
                   : t.html('consolePostLoginCampaigns.everybody')) +
        '</td><td>' + t.html('consolePostLoginCampaigns.numbers', {
          interval: Number(one.intervalDays) || 0,
          max: Number(one.maxMails) || 0,
          perRun: Number(one.perRun) || 0 }) + '</td><td>' +
        t.html('consolePostLoginCampaigns.done', {
          passes: Number(run.passes) || 0, read: Number(run.read) || 0,
          mailed: Number(run.mailed) || 0,
          refused: Number(run.refused) || 0 }) +
        (run.lastRunAt ? '<br><small>' + WebKit.esc(run.lastRunAt) +
                         '</small>' : '') + '</td><td>' +
        WebKit.esc(one.startedBy || '') + '<br><small>' +
        WebKit.esc(one.startedAt || '') + '</small></td><td>' + acts +
        '</td></tr>';
    }).join('');
    return WebKit.wideTable(t.text('consolePostLoginCampaigns.campaigns'),
      '<table><tr><th>' + t.html('consolePostLoginCampaigns.id') +
      '</th><th>' + t.html('consolePostLoginCampaigns.stateHeading') +
      '</th><th>' + t.html('consolePostLoginCampaigns.activity') +
      '</th><th>' + t.html('consolePostLoginCampaigns.group') +
      '</th><th>' + t.html('consolePostLoginCampaigns.settings') +
      '</th><th>' + t.html('consolePostLoginCampaigns.progress') +
      '</th><th>' + t.html('consolePostLoginCampaigns.startedBy') +
      '</th><th></th></tr>' + rows + '</table>');
  }

  // A number field of the start form, bounded as the API bounds it.
  private static numberField(t: Json, name: string, bound: Json): string {
    const b = bound || {};
    return '<div class="formrow"><label for="plc-' + name + '">' +
      t.html('consolePostLoginCampaigns.field.' + name) + '</label>' +
      '<input type="number" id="plc-' + name + '" name="' + name +
      '" min="' + (Number(b.min) || 1) + '" max="' + (Number(b.max) || 1) +
      '" value="' + (Number(b.dflt) || 1) + '" required></div>';
  }

  // The Start tab: the form, drawn only for a reader who may write.
  private static startForm(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PostLoginCampaignsPage;
    if (!ctx.write) {
      return WebKit.note(t.html('consolePostLoginCampaigns.readOnly'));
    }
    const limits = v.limits || {};
    const activities = (Array.isArray(v.activities) ? v.activities : [])
      .map(function (one: string): string {
        return '<option value="' + WebKit.esc(one) + '">' +
          WebKit.esc(one) + '</option>';
      }).join('');
    return '<form method="post" action="' + PAGE + '" id="plc-start">' +
      '<input type="hidden" name="action" value="start">' +
      '<div class="formrow"><label for="plc-activity">' +
      t.html('consolePostLoginCampaigns.activity') + '</label>' +
      '<select id="plc-activity" name="activity">' + activities +
      '</select></div>' +
      '<div class="formrow"><label for="plc-group">' +
      t.html('consolePostLoginCampaigns.group') + '</label>' +
      '<input id="plc-group" name="group" maxlength="1024"></div>' +
      '<p class="hint">' + t.html('consolePostLoginCampaigns.groupHint') +
      '</p>' +
      self.numberField(t, 'intervalDays', limits.intervalDays) +
      self.numberField(t, 'maxMails', limits.maxMails) +
      self.numberField(t, 'perRun', limits.perRun) +
      WebKit.note(t.html('consolePostLoginCampaigns.startNote')) +
      '<div class="formrow"><button type="submit">' +
      t.html('consolePostLoginCampaigns.startButton') +
      '</button></div></form>';
  }
}

export = PostLoginCampaignsPage;
