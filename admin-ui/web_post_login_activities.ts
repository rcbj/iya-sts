// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: web_post_login_activities.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → POST-LOGIN ACTIVITIES (#1111, #1123), drawn from
// `GET /admin-api/post-login-activities`.
//
// WHAT A STARTED ACTIVITY DOES IS SAID ON BOTH TABS (#1126): it asks its
// people at sign-in (the `signIn` note above the list, `about`) and mails
// them (`about`, `startNote`), and the policy being off no longer draws a
// warning, because it no longer stops either.
//
// Two tabs. **Activities**: every post-login activity started in the realm
// with its state, its groups, its numbers, what its runs have done so far,
// and a Pause, Resume or End button where the state allows one. **Start an
// activity**: the groups chosen so far, a group search, and the form — the
// activity, the reminder interval, the most mails per person and how many
// people a run reads. Each form posts to `/admin/post-login-activities`,
// which the runtime sends to `POST /admin-api/post-login-activities/<action>`
// (rule 7); the answer comes back as the page's notice or refusal.
//
// THE GROUPS ARE CHOSEN BY SEARCH, SEVERAL AT ONCE (#1123, rcbj). The search
// is `kit.chooserPane()` — the RBAC person chooser's, the delegation
// choosers', the applications grant chooser's — drawn from a SLICE the view
// cut (`groupChooser.pane`: twenty from the clamped `groupfrom`), because a
// realm's groups are a catalogue too big to send whole. A result is a LINK
// back to this page that ADDS the group to the list; the list is the page's
// own query parameter `groups`, its DNs separated by `;` (a DN escapes one
// inside a value; `common/post_login_activities.ts` argues the separator),
// so it survives the search,
// its paging and a reload with no state held anywhere, as `grantto` and
// `person` do on the pages that pick one thing. Each chosen group has a
// Remove link (the same list without it), and the start form carries the
// list as one hidden `groups` field per group, which `shapeFields()` folds
// into the operation's `groups` array. No group chosen is the whole realm.
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

const PAGE = '/admin/post-login-activities';

// The chosen list's id: the fragment a pick or a removal lands on. It is
// inside the Start tab, which the stylesheet shows for a target inside it
// (`:has(:target)`), so the tab stays open (#1084's reason).
const LIST_ANCHOR = 'pla-groups';

/**
 * Draws Directory → Post-login activities from its view.
 */
class PostLoginActivitiesPage {
  /**
   * Draws the page's body.
   *
   * @param view - `GET /admin-api/post-login-activities`'s answer
   * @param ctx - the render context: the translator, the page's query and
   *   whether the reader may write
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const c = ctx || WebKit.context();
    const t = c.t;
    const v = view || {};
    const self = PostLoginActivitiesPage;
    // No warning about the policy being off (#1126): a running started
    // activity asks its own people at sign-in whatever the policy says, so
    // `activityEnabled` no longer decides whether starting one does
    // anything. Without a transport it still mails nobody.
    const warnings = v.mailAvailable ? ''
      : WebKit.warn(t.html('consolePostLoginActivities.noMail'));
    return WebKit.note(t.html('consolePostLoginActivities.about', {
      minutes: Number(v.everyMinutes) || 10 })) + warnings +
      '<p><a href="/report/sources/postLoginProgress">' +
      t.html('consolePostLoginActivities.reportLink') + '</a></p>' +
      '<h2 data-tab="activities">' +
      t.html('consolePostLoginActivities.activities') + '</h2>' +
      WebKit.note(t.html('consolePostLoginActivities.signIn')) +
      self.list(v, c) +
      '<h2 data-tab="start">' + t.html('consolePostLoginActivities.start') +
      '</h2>' + self.startForm(v, c);
  }

  // A state in the reader's words. Each key is written out whole, so the
  // catalog check (`tests/i18n_catalogs.js`) can find it.
  private static stateWord(t: Json, state: string): string {
    const words: Record<string, string> = {
      running: 'consolePostLoginActivities.state.running',
      paused: 'consolePostLoginActivities.state.paused',
      ended: 'consolePostLoginActivities.state.ended'
    };
    return words[state] ? t.html(words[state]) : WebKit.esc(state);
  }

  // One act's button, a form of its own posting `action` and `id`.
  private static actButton(t: Json, act: string, id: string): string {
    const words: Record<string, string> = {
      pause: 'consolePostLoginActivities.act.pause',
      resume: 'consolePostLoginActivities.act.resume',
      end: 'consolePostLoginActivities.act.end'
    };
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + act + '">' +
      '<input type="hidden" name="id" value="' + WebKit.esc(id) + '">' +
      '<button type="submit"' + (act === 'end' ? ' class="danger"' : '') +
      '>' + t.html(words[act]) + '</button></form>';
  }

  // A started activity's groups, a DN a line, or everybody.
  private static groupsCell(t: Json, groups: Json): string {
    const list = Array.isArray(groups) ? groups : [];
    if (!list.length) {
      return t.html('consolePostLoginActivities.everybody');
    }
    return list.map(function (dn: string): string {
      return '<code>' + WebKit.esc(dn) + '</code>';
    }).join('<br>');
  }

  // The Activities tab.
  private static list(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PostLoginActivitiesPage;
    const list = Array.isArray(v.started) ? v.started : [];
    if (!list.length) {
      return WebKit.note(t.html('consolePostLoginActivities.none'));
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
        self.groupsCell(t, one.groups) +
        '</td><td>' + t.html('consolePostLoginActivities.numbers', {
          interval: Number(one.intervalDays) || 0,
          max: Number(one.maxMails) || 0,
          perRun: Number(one.perRun) || 0 }) + '</td><td>' +
        t.html('consolePostLoginActivities.done', {
          passes: Number(run.passes) || 0, read: Number(run.read) || 0,
          mailed: Number(run.mailed) || 0,
          refused: Number(run.refused) || 0 }) +
        (run.lastRunAt ? '<br><small>' + WebKit.esc(run.lastRunAt) +
                         '</small>' : '') + '</td><td>' +
        WebKit.esc(one.startedBy || '') + '<br><small>' +
        WebKit.esc(one.startedAt || '') + '</small></td><td>' + acts +
        '</td></tr>';
    }).join('');
    return WebKit.wideTable(t.text('consolePostLoginActivities.activities'),
      '<table><tr><th>' + t.html('consolePostLoginActivities.id') +
      '</th><th>' + t.html('consolePostLoginActivities.stateHeading') +
      '</th><th>' + t.html('consolePostLoginActivities.activity') +
      '</th><th>' + t.html('consolePostLoginActivities.groups') +
      '</th><th>' + t.html('consolePostLoginActivities.settings') +
      '</th><th>' + t.html('consolePostLoginActivities.progress') +
      '</th><th>' + t.html('consolePostLoginActivities.startedBy') +
      '</th><th></th></tr>' + rows + '</table>');
  }

  // A number field of the start form, bounded as the API bounds it.
  private static numberField(t: Json, name: string, bound: Json): string {
    const b = bound || {};
    const words: Record<string, string> = {
      intervalDays: 'consolePostLoginActivities.field.intervalDays',
      maxMails: 'consolePostLoginActivities.field.maxMails',
      perRun: 'consolePostLoginActivities.field.perRun'
    };
    return '<div class="formrow"><label for="pla-' + name + '">' +
      t.html(words[name]) + '</label>' +
      '<input type="number" id="pla-' + name + '" name="' + name +
      '" min="' + (Number(b.min) || 1) + '" max="' + (Number(b.max) || 1) +
      '" value="' + (Number(b.dflt) || 1) + '" required></div>';
  }

  /**
   * This page's URL with the chosen groups set to `groups`, the rest of the
   * query kept and the search's offset dropped, landing on the list.
   *
   * @param query - the page's query
   * @param groups - the group DNs the link chooses
   * @returns the href
   */
  static withGroups(query: Json, groups: string[]): string {
    const carried = WebKit.pageParamsOf(query);
    delete carried.groupfrom;
    return PAGE + WebKit.queryWith(carried,
      { groups: groups.join(';') }) + '#' + LIST_ANCHOR;
  }

  // The groups chosen so far: a table with a Remove each, or the note that
  // no group means everybody.
  private static chosenList(chosen: Json[], ctx: Json): string {
    const t = ctx.t;
    const self = PostLoginActivitiesPage;
    const dns = chosen.map(function (g: Json): string {
      return String(g.dn);
    });
    if (!chosen.length) {
      return '<div id="' + LIST_ANCHOR + '">' +
        WebKit.note(t.html('consolePostLoginActivities.noGroups')) +
        '</div>';
    }
    const rows = chosen.map(function (g: Json, i: number): string {
      const rest = dns.filter(function (dn: string, j: number): boolean {
        return j !== i;
      });
      return '<tr><td>' + (g.found
        ? WebKit.esc(g.cn || g.dn)
        : '<span class="state-revoked">' +
          t.html('consolePostLoginActivities.noSuchGroup') + '</span>') +
        '</td><td><code>' + WebKit.esc(g.dn) + '</code></td><td><a href="' +
        WebKit.esc(self.withGroups(ctx.query, rest)) + '">' +
        t.html('consolePostLoginActivities.remove') + '</a></td></tr>';
    }).join('');
    return '<div id="' + LIST_ANCHOR + '">' +
      WebKit.wideTable(t.text('consolePostLoginActivities.chosenGroups'),
        '<table><tr><th>' + t.html('consolePostLoginActivities.groupName') +
        '</th><th>DN</th><th></th></tr>' + rows + '</table>') +
      '<p class="note"><a href="' +
      WebKit.esc(self.withGroups(ctx.query, [])) + '">' +
      t.html('consolePostLoginActivities.clearGroups') + '</a></p></div>';
  }

  // The Start tab: the chosen groups, the group search and the form, drawn
  // only for a reader who may write.
  private static startForm(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PostLoginActivitiesPage;
    if (!ctx.write) {
      return WebKit.note(t.html('consolePostLoginActivities.readOnly'));
    }
    const limits = v.limits || {};
    const chooser = v.groupChooser || {};
    const chosen: Json[] = Array.isArray(chooser.chosen) ? chooser.chosen
                                                         : [];
    const pane = chooser.pane || { matched: 0, from: 0, shown: [] };
    const dns = chosen.map(function (g: Json): string {
      return String(g.dn);
    });
    const max = Number(limits.groups && limits.groups.max) || 50;
    const search = dns.length >= max
      ? WebKit.note(t.html('consolePostLoginActivities.groupsFull',
                           { max: max }))
      : WebKit.chooserPane({
        here: { path: PAGE, query: ctx.query },
        param: 'groupq', fromParam: 'groupfrom',
        label: t.text('consolePostLoginActivities.findGroup'),
        placeholder: t.text('consolePostLoginActivities.findPlaceholder'),
        slice: { matched: Number(pane.matched) || 0,
                 from: Number(pane.from) || 0 },
        entries: (Array.isArray(pane.shown) ? pane.shown : [])
          .map(function (g: Json): Json {
            return {
              key: String(g.dn).toLowerCase(),
              names: [g.cn, g.dn],
              label: g.cn || g.dn,
              detail: g.dn,
              href: self.withGroups(ctx.query, dns.concat([String(g.dn)]))
            };
          }),
        selectedKey: '',
        nothing: Number(pane.total)
          ? t.text('consolePostLoginActivities.noGroupMatches')
          : t.text('consolePostLoginActivities.noGroupsAtAll')
      }, t);
    const activities = (Array.isArray(v.activities) ? v.activities : [])
      .map(function (one: string): string {
        return '<option value="' + WebKit.esc(one) + '">' +
          WebKit.esc(one) + '</option>';
      }).join('');
    const hiddenGroups = dns.map(function (dn: string): string {
      return '<input type="hidden" name="groups" value="' +
        WebKit.esc(dn) + '">';
    }).join('');
    return '<h3>' + t.html('consolePostLoginActivities.groups') + '</h3>' +
      '<p class="hint">' + t.html('consolePostLoginActivities.groupsHint') +
      '</p>' + self.chosenList(chosen, ctx) + search +
      '<form method="post" action="' + PAGE + '" id="pla-start">' +
      '<input type="hidden" name="action" value="start">' + hiddenGroups +
      '<div class="formrow"><label for="pla-activity">' +
      t.html('consolePostLoginActivities.activity') + '</label>' +
      '<select id="pla-activity" name="activity">' + activities +
      '</select></div>' +
      self.numberField(t, 'intervalDays', limits.intervalDays) +
      self.numberField(t, 'maxMails', limits.maxMails) +
      self.numberField(t, 'perRun', limits.perRun) +
      WebKit.note(t.html('consolePostLoginActivities.startNote')) +
      '<div class="formrow"><button type="submit">' +
      t.html('consolePostLoginActivities.startButton') +
      '</button></div></form>';
  }
}

export = PostLoginActivitiesPage;
