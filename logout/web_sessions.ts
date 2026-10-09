// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_sessions.ts
//
// ---------------------------------------------------------------------------
// MONITORING → SESSIONS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Sessions from the answer of `GET /admin-api/sessions`: every live
// session in every protocol family, filtered and paged, with the controls that
// end them, and those that authenticated nobody.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/sessions` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws Sessions from the answer of `GET /admin-api/sessions`: every live
 * session in every protocol family, filtered and paged, with the controls that
 * end them, and those that authenticated nobody.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SessionsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its translator's (#539 phase 6); a row's rule,
    // its reason and its detail come from the view and are drawn as they
    // come, and the not-installed box is an error and stays English.
    const t = ctx.t;

    if (!json.installed) {
      const inner = '<div class="err"><strong>The logout reader is not ' +
        'installed in ' +
        'this process</strong>, so nothing here can say what is live. ' +
        'Every row on this page is read from ' +
        '<code>logout/logout.ts</code>, which is the one model of what a ' +
        'session IS across protocol families.</div>';
      return inner;
    }

    const nowMs = json.at;
    const paging = json.paging;
    // What every paging link carries with it. The page number is not in here
    // — kit.pageNavPair() supplies that per link — and neither is `format`,
    // because JSON has no links in it.
    const filterParams = { q: (json.filter.q || ''),
      protocol: (json.filter.protocol || ''),
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/sessions', filterParams, paging);
    // Where a Revoke sends the reader back to: THIS page of THIS filter,
    // because the row above and below the one they ended is what they were
    // reading.
    const back = kit.queryWith(filterParams, { page: paging.page });

    const protocolOptions = ['<option value=""' +
        ((json.filter.protocol || '') ? '' : ' selected') +
          '>' + t.html('consoleSessions.anyProtocol') + '</option>']
      .concat(json.protocols.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
               (name === (json.filter.protocol || '') ? ' selected' : '') +
                 '>' +
               kit.esc(name) + '</option>';
      })).join('');

    const rows = json.sessions.length
      ? json.sessions.map(function (row) {
          return SessionsPage.sessionRow(t, row, nowMs, ctx.write, back);
        }).join('')
      : '<tr><td colspan="8">' +
        (json.held
          ? t.html('consoleSessions.nothingMatches', { n: json.held })
          : t.html('consoleSessions.nothingSignedIn')) +
        '</td></tr>';

    const thead = '<tr><th>' + t.html('consoleSessions.thKind') +
      '</th><th>' + t.html('consoleSessions.thProtocol') + '</th><th>' +
      t.html('consoleSessions.thWho') + '</th><th>' +
      t.html('consoleSessions.thSince') + '</th>' +
      '<th>' + t.html('consoleSessions.thExpires') + '</th><th>' +
      t.html('consoleSessions.thCarries') + '</th><th>' +
      t.html('consoleSessions.thCredentials') + '</th><th></th></tr>';

    // A link carries an href, which a message may not: each sentence around
    // one is split into messages with the anchor in the code.
    const inner = kit.note(t.html('consoleSessions.leadBefore') +
      '<a href="/admin/tokens">' + t.html('consoleSessions.leadTokens') +
      '</a>' + t.html('consoleSessions.leadAfter')) +

      '<div class="tiles">' +
      kit.tile(json.held, t.text('consoleSessions.tileLive')) +
      kit.tile(json.heldByKind.session || 0,
               t.text('consoleSessions.tileBrowser')) +
      kit.tile(json.heldByKind.krb5 || 0,
               t.text('consoleSessions.tileKerberos')) +
      kit.tile(json.heldByKind.ldap || 0, t.text('consoleSessions.tileLdap')) +
      // The fifth tile is a SLICE of the first four rather than a fifth kind,
      // so the four above it still add up to `live sessions` and this one
      // does not join that sum. It earns a tile anyway: it is the number
      // somebody scans this page for, and a zero here is as informative as a
      // non-zero.
      kit.tile(json.unauthenticatedHeld,
               t.text('consoleSessions.tileUnauthenticated')) +
      '</div>' +

      kit.note(t.html('consoleSessions.threeKinds')) +
      '<ul><li>' + t.html('consoleSessions.kindBrowser') + '</li><li>' +
      t.html('consoleSessions.kindKerberos') + '</li><li>' +
      t.html('consoleSessions.kindLdap') + '</li></ul>' +

      kit.warn(t.html('consoleSessions.revokeBefore') +
      '<a href="/logout">' + t.html('consoleSessions.revokeLink') + '</a>' +
      t.html('consoleSessions.revokeAfter')) +

      '<h2>' + t.html('consoleSessions.hLive') + '</h2>' +
      // No `page` input in this form, and that is the point: changing the
      // filter or the page size sends the reader back to page 1. Carrying the
      // old page number over would land somebody on page 6 of a two-page
      // result.
      '<form method="get" action="/admin/sessions"><div class="formrow">' +
        '<label for="q">' + t.html('consoleSessions.search') + '</label>' +
        '<input type="text" id="q" name="q" size="28" value="' +
        kit.esc((json.filter.q || '')) +
          '" placeholder="' +
        kit.esc(t.text('consoleSessions.searchPlaceholder')) + '">' +
        '<label for="protocol">' + t.html('consoleSessions.protocol') +
        '</label>' +
        '<select id="protocol" name="protocol">' + protocolOptions +
        '</select><label for="per">' + t.html('consoleSessions.perPage') +
        '</label><select id="per" ' +
        'name="per">' + kit.perPageOptions(paging.perPage) +
        '</select>' +
        '<button class="secondary">' + t.html('consoleSessions.filter') +
        '</button>' +
        ((json.filter.q || '') || (json.filter.protocol || '')
          ? ' <a href="/admin/sessions">' + t.html('consoleSessions.clear') +
            '</a>' : '') +
      '</div></form>' +
      kit.note(t.html('consoleSessions.searchNote')) +
      nav.head +
      '<table>' + thead +
      rows + '</table>' +
      nav.foot +
      kit.note(t.html('consoleSessions.matched', { n: json.matched }) +
      (paging.pages > 1
        ? t.html('consoleSessions.rowsOnPage', {
            first: paging.firstRow, last: paging.lastRow,
            page: paging.page, pages: paging.pages })
        : '') +
      t.html('consoleSessions.liveInTotal', { held: json.held })) +

      // ---------------------------------------------------------------------
      // THE UNAUTHENTICATED SESSIONS (2026-09-05).
      //
      // A section rather than a column, for the reason `sessionsView()`
      // gives: the answer is almost always "none", and a column that says the
      // same thing on every row for weeks stops being read.
      //
      // It draws whether or not the setting that CREATES these is on, and
      // that is deliberate — a service that had the setting on this morning
      // and off now may still be holding sessions it minted then, and a
      // section that disappeared with the setting would hide exactly those.
      // What changes with the setting is the sentence, not the presence.
      // ---------------------------------------------------------------------
      '<h2>' + t.html('consoleSessions.hUnauthenticated') + '</h2>' +

      kit.note(t.html('consoleSessions.unauthLead')) +

      kit.note(t.html('consoleSessions.rolesBefore') + '<a ' +
      'href="/admin/roles">' + t.html('consoleSessions.rolesLink') + '</a>' +
      t.html('consoleSessions.rolesAfter')) +

      (json.unauthenticatedKept
        ? kit.note(t.html('consoleSessions.onBefore') +
          '<a href="/admin/roles">' + t.html('consoleSessions.turnOff') +
          '</a>' + t.html('consoleSessions.onAfter'))
        : kit.warn(t.html('consoleSessions.offBefore') + '<a ' +
          'href="/admin/roles">' + t.html('consoleSessions.turnOn') +
          '</a>' + t.html('consoleSessions.offAfter'))) +

      (json.unauthenticatedHeld
        ? '<table>' + thead +
          json.unauthenticatedSessions.map(function (row) {
            return SessionsPage.sessionRow(t, row, nowMs, ctx.write, back);
          }).join('') + '</table>' +
          kit.note(t.html('consoleSessions.unauthCount', {
            n: json.unauthenticatedHeld, held: json.held }))
        : kit.note(t.html('consoleSessions.unauthNone'))) +

      kit.note('<a href="/admin/logout">' +
      t.html('consoleSessions.linkLogout') + '</a>' +
      t.html('consoleSessions.linkLogoutAfter') + ' &middot; <a ' +
      'href="/admin/tokens">' + t.html('consoleSessions.linkTokens') +
      '</a> &middot; <a href="/admin/caep-sessions">' +
      t.html('consoleSessions.linkCaep') + '</a>' +
      t.html('consoleSessions.linkCaepAfter') + ' &middot; ' +
      '<a href="/admin/metrics">' + t.html('consoleSessions.linkMetrics') +
      '</a> &middot; <a ' +
      'href="/admin/sessions?format=json">' +
      t.html('consoleSessions.linkJson') + '</a> &middot; ' +
      '<a href="/admin-api/sessions">' + t.html('consoleSessions.linkApi') +
      '</a>');

    return inner;
  }

  /**
   * Draws one row of the sessions page, with its Revoke form.
   *
   * The form is drawn only for a terminable row and a holder of Admin
   * Write; otherwise the cell says why not.
   *
   * @param t - the page's translator (#539)
   * @param row - a live-session row from logout.ts
   * @param nowMs - the current time in milliseconds
   * @param canWrite - whether the reader holds Admin Write
   * @param back - the list state the form posts as `back`
   * @returns a <tr> as HTML
   */
  static sessionRow(t, row, nowMs, canWrite, back) {
    const revoke = row.terminable && canWrite
      ? '<form method="post" action="/admin/sessions">' +
        '<input type="hidden" name="action" value="revoke">' +
        '<input type="hidden" name="key" value="' + kit.esc(row.key) + '">' +
        '<input type="hidden" name="select" value="' + kit.esc(row.id) + '">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<button class="danger"' +
        (row.why ? ' title="' + kit.esc(row.why) + '"' : '') +
        '>' + t.html('consoleSessions.revoke') + '</button></form>'
      : (canWrite
          ? '<span class="state-none" title="' + kit.esc(row.why) +
            '">' + t.html('consoleSessions.cannot') + '</span>'
          : '<span class="state-none" title="' +
            kit.esc(t.text('consoleSessions.needsWrite')) +
            '">—</span>');
    const out = '<tr>' +
      '<td>' + kit.esc(row.kind) +
      '<div class="sub">' + kit.shortened(row.handle, 28) + '</div></td>' +
      '<td>' + kit.esc(row.protocol) +
      (row.acr ? '<div class="sub">acr ' + kit.esc(row.acr) +
        (row.amr.length ? ', amr ' + kit.esc(row.amr.join(' ')) : '') +
        '</div>' :
       '') +
      '</td>' +
      '<td>' + kit.esc(row.username || t.text('consoleSessions.unknown')) +
      (row.sub ? '<div class="sub"><code>' + kit.esc(row.sub) +
       '</code></div>' :
       '') +
      '</td>' +
      '<td class="sub">' +
      (row.startedAt ? kit.esc(kit.whenText(row.startedAt))
                     : '<span title="' +
                       kit.esc(t.text('consoleSessions.notRecordedTitle')) +
                       '">' + t.html('consoleSessions.notRecorded') +
                       '</span>') +
      '</td>' +
      SessionsPage.sessionExpiryCell(t, row, nowMs) +
      '<td class="sub">' + kit.esc(row.detail || '—') + '</td>' +
      SessionsPage.sessionCredentialsCell(t, row) +
      '<td>' + revoke + '</td>' +
      '</tr>';
    return out;
  }

  // WHAT CAME OUT OF THIS SESSION, as a link into /admin/tokens.
  //
  // Only a browser sign-on session has a join: a token records the `sessionId`
  // it was issued under, and nothing else here does. A Kerberos row therefore
  // links to its FAMILY — the TGT on this row is in that table and this service
  // keeps no handle on one, which is a fact about Kerberos rather than a gap —
  // and an LDAP connection links nowhere at all, because a bind issues no
  // credential.
  /**
   * Draws where to find what a session issued.
   *
   * A browser session links to its tokens, a Kerberos row to the ticket
   * table, and an LDAP connection to nothing.
   *
   * @param t - the page's translator (#539)
   * @param row - a live-session row from logout.ts
   * @returns a <td> as HTML
   */
  static sessionCredentialsCell(t, row) {
    if (row.family === 'session') {
      return '<td><a href="' + kit.esc('/admin/tokens' +
        kit.queryWith({ session: row.sessionId }, {})) +
        '" title="' + kit.esc(t.text('consoleSessions.issuedOnItTitle')) +
        '">' + t.html('consoleSessions.issuedOnIt') + '</a></td>';
    }
    if (row.family === 'krb5') {
      return '<td><a href="' + kit.esc('/admin/tokens' +
        kit.queryWith({ family: 'ticket' }, {})) +
        '" title="' + kit.esc(t.text('consoleSessions.ticketTableTitle')) +
        '">' + t.html('consoleSessions.ticketTable') + '</a></td>';
    }
    if (row.family === 'gnap') {
      // A GNAP GRANT (#432): its tokens are in GNAP's own store, listed with
      // the grant on Protocols → GNAP.
      return '<td><a href="' + kit.esc('/admin/gnap' +
        kit.queryWith({ state: 'approved' }, {})) +
        '" title="' + kit.esc(t.text('consoleSessions.grantListTitle')) +
        '">' + t.html('consoleSessions.grantList') + '</a></td>';
    }
    return '<td class="sub" title="' +
           kit.esc(t.text('consoleSessions.noneTitle')) + '">' +
           t.html('consoleSessions.none') + '</td>';
  }

  // WHEN THIS SESSION ENDS, AND HOW THAT IS WORKED OUT. Several answers rather
  // than one, because the kinds are genuinely different and a column that
  // showed only a timestamp would be read as one rule with several values. The
  // rule is the row's `expiryRule`, which `logout.ts`'s SESSION_EXPIRY_RULES
  // writes.
  /**
   * Draws when a session ends, with the rule for its kind as the title.
   *
   * A session with no expiry says so; one under five minutes is marked.
   *
   * @param t - the page's translator (#539)
   * @param row - a live-session row from logout.ts
   * @param nowMs - the current time in milliseconds
   * @returns a <td> as HTML
   */
  static sessionExpiryCell(t, row, nowMs) {
    const rule = row.expiryRule || '';
    if (!row.expiresAt) {
      return '<td class="sub" title="' + kit.esc(rule) + '">' +
        t.html('consoleSessions.noExpiry') + '<div class="sub">' +
        t.html('consoleSessions.noExpiryNote') + '</div></td>';
    }
    const left = row.expiresAt - nowMs;
    if (left <= 0) {
      // Live rows only reach here in a race — the list was built a moment ago —
      // and saying so is better than a negative countdown.
      return '<td class="state-expired" title="' + kit.esc(rule) +
             '">' + t.html('consoleSessions.expired') +
        '<div class="sub">' + kit.esc(kit.whenText(row.expiresAt)) +
        '</div></td>';
    }
    return '<td' + (left < 5 * 60 * 1000 ? ' class="state-expired"' : '') +
      ' title="' + kit.esc(rule) + '">' +
      t.html('consoleSessions.inDuration',
             { duration: kit.durationText(left) }) +
      '<div class="sub">' + kit.esc(kit.whenText(row.expiresAt)) +
      '</div></td>';
  }
}

export = SessionsPage;
