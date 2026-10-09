// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_audit.ts
//
// ---------------------------------------------------------------------------
// AUDIT → AUDIT LOG, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws the Audit log from the answer of `GET /admin-api/audit`: what was
// done, by whom, from where and with what outcome, filtered and paged, and the
// settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/audit` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws the Audit log from the answer of `GET /admin-api/audit`: what was
 * done, by whom, from where and with what outcome, filtered and paged, and the
 * settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class AuditPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its catalog's (#539); what the view answered —
    // the category labels and their explanations, every row's summary —
    // is drawn as it came.
    const t = ctx.t;
    const paging = json.paging;
    const summary = json;
    const known = json.knownActors;
    // What every paging link carries with it. The page number is not in here
    // — kit.pageNavPair() supplies that per link — for the reason the tokens
    // page
    // gives: a "next" that dropped the filter would be page 2 of a different
    // list.
    const filterParams = { category: (json.filter.category || ''),
                           action: (json.filter.action || ''),
                           outcome: (json.filter.outcome || ''),
                           actor: (json.filter.actor || ''),
                           q: (json.filter.q || ''),
                             code: (json.filter.code || ''),
                           address: (json.filter.address || ''),
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/audit', filterParams, paging);

    const rows = json.events.map(function (row) {
      return AuditPage.auditRow(row, known, t);
    }).join('');

    const categoryOptions = ['<option value=""' +
                             ((json.filter.category || '') ? '' : ' ' +
        'selected') +
                             '>' + t.html('consoleAudit.anyCategory') +
                             '</option>']
      .concat(json.categories.map(function (entry) {
        return '<option value="' + kit.esc(entry.category) + '"' +
               (entry.category === (json.filter.category || '')
                 ? ' selected' : '') +
               '>' +
               kit.esc(entry.label) + ' (' +
               (summary.byCategory[entry.category] || 0) + ')</option>';
      })).join('');

    // Grouped by category, and built from the SAME table the category select
    // is, so the two cannot come to disagree about which action belongs where
    // — which they would, being two hand-written lists of the same
    // twenty-four strings.
    const actionOptions = '<option value=""' +
      ((json.filter.action || '') ? '' : ' ' +
        'selected') +
      '>' + t.html('consoleAudit.anyAction') + '</option>' +
      json.categories.map(function (entry) {
        const inGroup = json.actions.filter(function (a) {
          return a.category === entry.category;
        });
        return '<optgroup label="' + kit.esc(entry.label) + '">' +
               inGroup.map(function (a) {
          return '<option value="' + kit.esc(a.action) + '"' +
                 (a.action === (json.filter.action || '') ? ' selected' : '') +
                   '>' +
                 kit.esc(a.action) + ' (' +
                 (summary.byAction[a.action] || 0) +
                 ')</option>';
        }).join('') + '</optgroup>';
      }).join('');

    const outcomeOptions = ['<option value=""' +
                            ((json.filter.outcome || '') ? '' : ' ' +
        'selected') +
                            '>' + t.html('consoleAudit.anyOutcome') +
                            '</option>']
      .concat(json.outcomes.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
               (name === (json.filter.outcome || '') ? ' selected' : '') + '>' +
               kit.esc(name) +
               ' (' + (summary.byOutcome[name] || 0) + ')</option>';
      })).join('');

    const perOptions = kit.perPageOptions(paging.perPage);

    const f = json.filter;
    const filtering = f.category || f.action || f.outcome || f.actor ||
                      f.q || f.code || f.address || '';

    const inner = '<div class="tiles">' +
        kit.tile(summary.held, t.text('consoleAudit.tileHeld')) +
        kit.tile(summary.recorded, t.text('consoleAudit.tileRecorded')) +
        kit.tile(summary.dropped, t.text('consoleAudit.tileDropped')) +
        kit.tile(summary.byCategory.directory || 0,
                 t.text('consoleAudit.tileDirectory')) +
        kit.tile(summary.byCategory.authentication || 0,
                 t.text('consoleAudit.tileAuthentications')) +
        kit.tile(summary.byCategory.session || 0,
                 t.text('consoleAudit.tileSessions')) +
      '</div>' +

      kit.note(t.html('consoleAudit.history')) +

      kit.note(t.html('consoleAudit.noCredential')) +

      kit.note(t.html('consoleAudit.severalRows')) +

      kit.note(t.html('consoleAudit.observesItself')) +

      '<h2>' + t.html('consoleAudit.whatHappened') + '</h2>' +
      // No `page` input in this form, deliberately: changing a filter or the
      // page size returns to page 1. Carrying the old page number over would
      // land somebody on page 6 of a two-page result and the clamp in
      // pagingOf() would then move them again, which reads as the form
      // ignoring them.
      '<form method="get" action="/admin/audit"><div ' +
        'class="formrow"><label for="category">' +
        t.html('consoleAudit.category') + '</label><select ' +
        'id="category" name="category">' +
          categoryOptions + '</select>' +
        '<label for="action">' + t.html('consoleAudit.action') +
        '</label><select id="action" ' +
        'name="action">' +
          actionOptions + '</select>' +
        '<label for="outcome">' + t.html('consoleAudit.outcome') +
        '</label><select id="outcome" ' +
        'name="outcome">' +
          outcomeOptions + '</select>' +
        '<label for="per">' + t.html('consoleAudit.perPage') +
        '</label><select id="per" name="per">' +
      perOptions +
          '</select>' +
      '</div><div class="formrow">' +
        '<label for="actor">' + t.html('consoleAudit.actor') + '</label>' +
        '<input type="text" id="actor" name="actor" size="20" value="' +
          kit.esc((json.filter.actor || '')) + '" placeholder="alice">' +
        '<label for="q">' + t.html('consoleAudit.text') + '</label>' +
        '<input type="text" id="q" name="q" size="30" value="' +
      kit.esc((json.filter.q || '')) +
          '" placeholder="' +
          kit.esc(t.text('consoleAudit.textPlaceholder')) + '">' +
        '<label for="code">' + t.html('consoleAudit.errorCode') +
        '</label>' +
        '<input type="text" id="code" name="code" size="16" value="' +
          kit.esc((json.filter.code || '')) + '" placeholder="STS-OAUTH">' +
        '<label for="address">' + t.html('consoleAudit.from') + '</label>' +
        '<input type="text" id="address" name="address" size="16" ' +
          'value="' + kit.esc((json.filter.address || '')) +
          '" placeholder="10.0.0.">' +
        '<button class="secondary">' + t.html('consoleAudit.filter') +
        '</button>' +
        (filtering ? ' <a href="/admin/audit">' +
          t.html('consoleAudit.clear') + '</a>' : '') +
      '</div></form>' +
      // The link to Error codes is markup, so it sits between two messages.
      kit.note(t.html('consoleAudit.filterNoteHead') +
      ' <a href="/admin/error-codes">' + t.html('consoleAudit.errorCodes') +
      '</a> ' + t.html('consoleAudit.filterNoteTail')) +
      nav.head +
      '<table><tr><th class="num">#</th><th>' +
      t.html('consoleAudit.when') + '</th><th>' +
      t.html('consoleAudit.category') + '</th><th>' +
      t.html('consoleAudit.action') + '</th><th>' +
      t.html('consoleAudit.outcome') + '</th><th>' +
      t.html('consoleAudit.actor') + '</th><th>' +
      t.html('consoleAudit.from') + '</th>' +
      '<th>' + t.html('consoleAudit.target') + '</th><th>' +
      t.html('consoleAudit.whatHappened') + '</th><th>' +
      t.html('consoleAudit.detail') + '</th></tr>' +
      (rows || '<tr><td colspan="10">' +
        t.html('consoleAudit.nothingMatches') + '</td></tr>') +
      '</table>' +
      nav.foot +

      kit.note(t.html('consoleAudit.rowsMatch',
                      { n: String(json.matched) }) +
      (paging.pages > 1
        ? t.html('consoleAudit.rowsOnPage',
                 { first: String(paging.firstRow),
                   last: String(paging.lastRow),
                   page: String(paging.page),
                   pages: String(paging.pages) })
        : '') +
      t.html('consoleAudit.heldOf',
             { held: String(summary.held),
               recorded: String(summary.recorded) }) +
      (summary.dropped
        ? t.html('consoleAudit.someDropped',
                 { dropped: String(summary.dropped),
                   max: String(summary.maxEvents) })
        : t.html('consoleAudit.noneDropped',
                 { max: String(summary.maxEvents) }))) +

      kit.note(t.html('consoleAudit.seqNote')) +

      '<h3>' + t.html('consoleAudit.whereRowsComeFrom') + '</h3>' +
      kit.note(t.html('consoleAudit.sixCategories')) +
      '<ul>' + json.categories.map(function (entry) {
        // The label, the category and the count stay on the row and the
        // paragraph explaining the category folds under them, which is the
        // shape every legend on this console now has.
        return '<li><strong>' + kit.esc(entry.label) + '</strong> (<code>' +
               kit.esc(entry.category) +
               '</code>, ' + (summary.byCategory[entry.category] || 0) +
               ') ' +
               kit.note(kit.esc(entry.what)) + '</li>';
      }).join('') + '</ul>' +

      kit.note(t.html('consoleAudit.fromNote')) +

      kit.note(t.html('consoleAudit.inMemory')) +

      // THE TWO SETTINGS ARE ON THIS PAGE NOW rather than being described
      // here and typed in somewhere else. `audit.protocolCalls` is the reason
      // this one matters: it is the noisy category, and somebody turning it
      // off is doing it BECAUSE they are looking at this page and cannot read
      // it.
      SettingsForms.forms(json.settings, '/admin/audit', undefined,
                          t) +
      // Each link to the metrics page is markup, so it sits between two
      // messages.
      kit.note(t.html('consoleAudit.protocolCallsHead',
                      { state: summary.protocolCalls ? 'on' : 'off' }) +
      ' <a href="/admin/metrics">' + t.html('consoleAudit.theMetricsPage') +
      '</a> ' + t.html('consoleAudit.protocolCallsTail',
                       { max: String(summary.maxEvents) })) +

      kit.note(t.html('consoleAudit.healthcheckHead') + ' <a ' +
      'href="/admin/metrics">' + t.html('consoleAudit.metricsPageStart') +
      '</a> ' + t.html('consoleAudit.healthcheckTail')) +

      kit.note(t.html('consoleAudit.paging',
                      { max: String(kit.MAX_ROWS) }));

    return inner;
  }

  /**
   * Draws one row of the audit log table.
   *
   * @param row - an audit row
   * @param known - the usernames this console has seen, as object keys
   * @param t - the page's translator; the default (English in node) when
   *   omitted, which is how `admin.ts` calls it
   * @returns a <tr> as HTML
   */
  static auditRow(row, known, t?) {
    t = t || kit.context().t;
    return '<tr>' +
      '<td class="num">' + kit.esc(row.seq) + '</td>' +
      '<td>' + kit.esc(kit.whenText(row.at)) + '</td>' +
      '<td>' + kit.esc(row.category) + '</td>' +
      '<td><code>' + kit.esc(row.action) + '</code></td>' +
      '<td>' + AuditPage.outcomeCell(row.outcome) +
        (row.errorCode ? '<br><a href="/admin/audit?code=' +
                         encodeURIComponent(row.errorCode) + '"><code>' +
                         kit.esc(row.errorCode) + '</code></a>' : '') +
                             '</td>' +
      '<td class="who">' + AuditPage.auditActorCell(row, known, t) + '</td>' +
      '<td class="who">' + AuditPage.auditAddressCell(row, t) + '</td>' +
      '<td class="who">' +
      (row.target ? '<code>' + kit.esc(row.target) + '</code>'
                                       : '<span class="state-none">—</span>') +
        (row.channel ? '<br><span class="state-none">' + kit.esc(row.channel) +
                       (row.protocol ? ' — ' + kit.esc(row.protocol) : '') +
                       '</span>' : '') +
      '</td>' +
      '<td>' + kit.esc(row.summary) + '</td>' +
      '<td class="who">' + AuditPage.auditDetailCell(row.detail) + '</td>' +
      '</tr>';
  }

  // Who did it. The console key links to their page where this service has seen
  // them authenticate, following the same three-state rule the groups page uses
  // — a name it knows, a name it could file somebody under but never has, and
  // no name at all. The PRESENTED form is shown underneath when it differs,
  // because the collapse from `uid=alice,ou=users,dc=example,dc=com` to `alice`
  // is a thing an auditor has to be able to see rather than take on trust.
  /**
   * Draws who did an audited act.
   *
   * The actor links to their user page when the console knows them, and
   * the presented form is shown underneath when it differs.
   *
   * @param row - an audit row
   * @param known - the usernames this console has seen, as object keys
   * @param t - the page's translator
   * @returns the cell's content as HTML
   */
  static auditActorCell(row, known, t) {
    if (!row.actor && !row.actorForm) {
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleAudit.noActorTitle')) + '">—</span>';
    }
    const parts = [];
    if (row.actor) {
      parts.push(known[row.actor]
        ? '<a href="' +
          kit.esc('/admin/users' + kit.queryWith({ user: row.actor }, {})) +
          '">' + kit.esc(row.actor) + '</a>'
        : '<span class="state-none" title="' +
          kit.esc(t.text('consoleAudit.neverHereTitle')) + '">' +
          kit.esc(row.actor) + ' ' + t.html('consoleAudit.neverHere') +
          '</span>');
    }
    if (row.actorForm && row.actorForm !== row.actor) {
      parts.push('<code>' + kit.esc(row.actorForm) + '</code>');
    }
    return parts.join('<br>');
  }

  // WHERE THE ACT CAME FROM (2026-09-18): the client's address, linked to
  // every row from it. A dash where nobody sent it — a timer, an expiry, a
  // background delivery, a seed at start-up — or where it came over a Unix
  // socket, which has no address; the tooltip says which that can be.
  /**
   * Draws an audit row's client address as a link to its other rows.
   *
   * @param row - an audit row
   * @param t - the page's translator
   * @returns the link as HTML, or a dash when no address was recorded
   */
  static auditAddressCell(row, t) {
    if (!row.address) {
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleAudit.noAddressTitle')) + '">—</span>';
    }
    return '<a href="/admin/audit?address=' +
           encodeURIComponent(row.address) + '"><code>' +
           kit.esc(row.address) + '</code></a>';
  }

  // The detail object as one cell. Rendered as `key=value` pairs rather than as
  // JSON because the column is narrow and a reader is scanning for one fact,
  // not parsing a document; `?format=json` has the object itself for anything
  // that is not a person.
  /**
   * Draws an audit row's detail object as key=value pairs.
   *
   * @param detail - the row's detail object
   * @returns the pairs as HTML, or a dash when there are none
   */
  static auditDetailCell(detail) {
    const keys = Object.keys(detail || {});
    if (!keys.length) {
      return '<span class="state-none">—</span>';
    }
    return keys.map(function (key) {
      return '<code>' + kit.esc(key) + '=' + kit.esc(detail[key]) + '</code>';
    }).join(' ');
  }

  // The outcome, in the same three colours the token states use — so that a
  // page somebody has learned to skim once reads the same way here. `refused`
  // is amber rather than red on purpose: it is this service working correctly
  // and saying no, which is most of what a debugger of a protocol client wants
  // to see, and painting it as a failure would bury the 5xx rows that are one.
  /**
   * Draws an audit outcome in the state colours.
   *
   * @param outcome - `success`, `refused` or another outcome
   * @returns a <span> as HTML
   */
  static outcomeCell(outcome) {
    const cls = outcome === 'success' ? 'state-valid'
              : (outcome === 'refused' ? 'state-expired' : 'state-revoked');
    return '<span class="' + cls + '">' + kit.esc(outcome) + '</span>';
  }
}

export = AuditPage;
