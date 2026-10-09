// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_logout.ts
//
// ---------------------------------------------------------------------------
// SIGN-OUT, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/logout` from the answer of `GET /admin-api/logout`: the
// lookup, or everything an identity holds live across every family and the
// controls that end it, and the back-channel deliveries.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `method:logoutView` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws `/admin/logout` from the answer of `GET /admin-api/logout`: the
 * lookup, or everything an identity holds live across every family and the
 * controls that end it, and the back-channel deliveries.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class LogoutPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    // The page's words are its translator's (#539 phase 6); a family's label,
    // prose and specification come from the view and are drawn as they
    // come, and the no-reader box is an error and stays English.
    const t = ctx.t;
    const wantedUser = json.user;
    const mayWrite = ctx.write;
    const params = kit.pageParamsOf(ctx.query);
    const back = kit.queryWith(params, {});
    const families = json.families || [];
    const yesNo = function (yes) {
      return yes ? t.html('consoleLogout.yes') : '<span ' +
        'class="state-none">' + t.html('consoleLogout.no') + '</span>';
    };

    let inner;
    if (!wantedUser) {
      // No name is not an error and not a 404: this page is a lookup, and the
      // list of everybody is /admin/users' job rather than a second copy here.
      inner = (json.hasReader ? '' : LogoutPage.logoutNoReaderNote()) +
        kit.note(t.html('consoleLogout.lookupLead')) +
        '<form method="get" action="/admin/logout"><label>' +
        t.html('consoleLogout.identity') + ' <input ' +
        'name="user" value="" placeholder="alice"></label> <button ' +
        'type="submit">' + t.html('consoleLogout.look') +
        '</button></form><h2>' + t.html('consoleLogout.hReaches') +
        '</h2><table><thead><tr><th>' + t.html('consoleLogout.thFamily') +
        '</th><th>' + t.html('consoleLogout.thProtocol') + '</th><th>' +
        t.html('consoleLogout.thCanEnd') + '</th><th>' +
        t.html('consoleLogout.thWhat') + '</th></tr></thead><tbody>' +
        families.map(function (family) {
          return '<tr><td>' + kit.esc(family.label) + '</td><td>' +
            kit.esc(family.protocol) + '</td><td>' +
            yesNo(family.terminable) + '</td>' +
            // The family's prose is a paragraph on most rows and it is the same
            // prose logout.ts owns (see FAMILIES over there) — so it folds here
            // rather than being shortened, which would have made this file the
            // second place it is written.
            '<td class="sub">' + kit.note(kit.esc(family.what)) + '<em>' +
              kit.esc(
                family.spec) +
            '</em></td></tr>';
        }).join('') + '</tbody></table>' +
        kit.note(t.html('consoleLogout.cannotBeEnded')) +
        kit.note(t.html('consoleLogout.themselves')) +
        LogoutPage.backchannelDeliveriesSection(t, json, mayWrite, back, '') +
        // ON THE LOOKUP PAGE AND NOT ON THE PER-PERSON ONE. These four decide
        // what a logout REACHES, which is a question about the feature; the
        // drill-down is about one person, and a form there would invite
        // somebody to change the rules for everybody while looking at one of
        // them.
        SettingsForms.forms(json.settings, '/admin/logout', undefined, t);
    } else if (!json.known) {
      inner = LogoutPage.logoutNoReaderNote();
    } else {
      const inventory = json;
      const wantedFamily = json.family;
      const canWrite = json.canWrite;
      const summary = '<table><thead><tr><th>' +
        t.html('consoleLogout.thFamily') + '</th><th>' +
        t.html('consoleLogout.thLive') + '</th><th>' +
        t.html('consoleLogout.thEndable') + '</th><th>' +
        t.html('consoleLogout.thProtocol') + '</th></tr></thead><tbody>' +
        inventory.families.map(function (family) {
          return '<tr><td><a href="' +
            kit.esc('/admin/logout' +
                     kit.queryWith(params, { user: wantedUser,
                       family: family.id,
                                                           page: '' })) + '">' +
            kit.esc(family.label) + '</a></td>' +
            '<td>' + family.held +
            (family.notListed ? t.html('consoleLogout.notListed',
                                       { n: family.notListed }) : '') +
            '</td>' +
            '<td>' + yesNo(family.terminable) +
            '</td><td ' +
            'class="sub">' + kit.esc(family.protocol) + '</td></tr>';
        }).join('') + '</tbody></table>';

      inner = kit.note(t.html('consoleLogout.inventory', {
          total: inventory.total, user: wantedUser,
          families: inventory.families.filter(function (f) {
            return f.held;
          }).length,
          key: json.key, realm: json.kerberosRealm })) +
        summary +
        (canWrite
          ? '<form method="post" action="/admin/logout">' +
            '<input type="hidden" name="action" value="global">' +
            '<input type="hidden" name="user" value="' + kit.esc(wantedUser) +
            '">' +
            LogoutPage.logoutBackField(back) +
            '<p><button type="submit">' +
            t.html('consoleLogout.globalLogout') + '</button> <span ' +
            'class="sub">' + t.html('consoleLogout.globalLogoutNote') +
            '</span></p></form>'
          : kit.note(t.html('consoleLogout.needsWrite'))) +
        '<h2>' + t.html('consoleLogout.hLiveItems') +
        (wantedFamily ? ' — ' + kit.esc(wantedFamily) : '') +
        '</h2>' +
        kit.perPageForm('/admin/logout', 'family', wantedFamily,
                         json.paging.perPage,
                         t.html('consoleLogout.perPageNote'),
                         { user: wantedUser }) +
        (json.rows.length
          ? '<table><thead><tr><th>' + t.html('consoleLogout.thFamily') +
            '</th><th>' + t.html('consoleLogout.thWhatShort') + '</th><th>' +
            t.html('consoleLogout.thKind') + '</th><th>' +
            t.html('consoleLogout.thSince') + '</th><th>' +
            t.html('consoleLogout.thUntil') + '</th><th>' +
            t.html('consoleLogout.thEnd') + '</th></tr></thead><tbody>' +
            json.rows.map(function (r) { return LogoutPage.logoutRowHtml(t,
              r, canWrite,
                back); })
                    .join('') +
            '</tbody></table>' +
            kit.pageNavPair('/admin/logout', params, json.paging).head
          : kit.note(wantedFamily ? t.html('consoleLogout.nothingLiveFamily')
                                  : t.html('consoleLogout.nothingLive'))) +
        (canWrite
          ? '<h2>' + t.html('consoleLogout.hUndo') + '</h2>' +
            kit.note(t.html('consoleLogout.undoLead')) +
            // DEVELOPMENT ONLY (#111): refused in product by the action, and
            // so not offered there — a note says why in its place.
            (json.opensTestControls
              ? '<form method="post" action="/admin/logout">' +
                '<input type="hidden" name="action" ' +
                'value="restore-kerberos">' +
                '<input type="hidden" name="user" value="' +
                kit.esc(wantedUser) + '">' +
                LogoutPage.logoutBackField(back) +
                '<p><button type="submit">' +
                t.html('consoleLogout.clearKerberos') + '</button> <span ' +
                'class="sub">' + t.html('consoleLogout.clearKerberosNote') +
                '</span></p></form>'
              : kit.note(t.html('consoleLogout.clearKerberosProduct'))) +
            '<form method="post" ' +
            'action="/admin/logout"><input type="hidden" name="action" ' +
            'value="restore-token"><input type="hidden" name="user" ' +
            'value="' + kit.esc(wantedUser) + '">' +
            LogoutPage.logoutBackField(back) +
            '<p><label>' + t.html('consoleLogout.restoreByJti') +
            ' <input name="jti" ' +
            'placeholder="jti"></label> <button ' +
              'type="submit">' + t.html('consoleLogout.restore') +
            '</button> ' +
            '<span class="sub">' + t.html('consoleLogout.restoreNote') +
            '</span></p></form>'
          : '') +
        LogoutPage.backchannelDeliveriesSection(t, json, canWrite, back,
          wantedUser);
    }

    return inner;
  }

  // ---------------------------------------------------------------------------
  // THE BACK-CHANNEL LOGOUT DELIVERIES AND THEIR DEAD LETTERS (2026-09-17,
  // #36; the cluster-wide, paged list and the retry the same day).
  //
  // A sign-out answers before its Logout Tokens are sent, so every result
  // says `pending`; this is where each one is seen to have been accepted or
  // not. On both halves of the page — the lookup and one person — because a
  // delivery is not only one person's: an operator asking "is the relying
  // party getting these?" has nobody in particular in mind. The rows are the
  // SHARED store's (`oauth-oidc/backchannel_logout.ts`, header point 3), so
  // this node lists every node's deliveries. Filtered by state and a search,
  // paged on `backchannelDeliveriesPage`; a DEAD row carries a Retry button
  // for a holder of Admin Write, which posts `retry-backchannel` — the same
  // action `POST /admin-api/logout/retry-backchannel` calls.
  // ---------------------------------------------------------------------------
  /**
   * Draws the back-channel Logout Token deliveries section.
   *
   * Counts, a state and search filter, and a paged table; a dead letter
   * gets a Retry form for a holder of Admin Write.
   *
   * @param t - the page's translator (#539)
   * @param view - the view from adminViews.logoutJson()
   * @param canWrite - optional; whether the reader holds Admin Write
   * @param back - optional; the list state the Retry form posts as `back`
   * @param wantedUser - optional; the identity the page is about
   * @returns the section as HTML
   */
  static backchannelDeliveriesSection(t, view, canWrite?, back?,
                                      wantedUser?) {
    const v = view || {};
    const list = Array.isArray(v.backchannelDeliveries)
      ? v.backchannelDeliveries : [];
    const counts = v.backchannelCounts || { pending: 0, sent: 0, dead: 0 };
    const state = String(v.deliveryState || '');
    // The audit link carries an href, which a message may not, so the
    // paragraph around it is two messages with the anchor in the code.
    const heading = '<h2 id="backchannel">' +
      t.html('consoleLogout.hBackchannel') + '</h2>' +
      kit.note(t.html('consoleLogout.backchannelLead', {
        pending: counts.pending, sent: counts.sent, dead: counts.dead }) +
        '<a href="/admin/audit">' + t.html('consoleLogout.auditLink') +
        '</a>' + t.html('consoleLogout.backchannelLeadEnd')) +
      '<form method="get" action="/admin/logout#backchannel"><div ' +
      'class="formrow">' +
      (wantedUser ? '<input type="hidden" name="user" value="' +
                    kit.esc(wantedUser) + '">' : '') +
      '<label for="deliveryState">' + t.html('consoleLogout.state') +
      '</label><select id="deliveryState" ' +
      'name="deliveryState"><option value="">' +
      t.html('consoleLogout.any') + '</option>' +
      ['pending', 'sent', 'dead'].map(function (one) {
        return '<option value="' + one + '"' +
               (one === state ? ' selected' : '') + '>' +
               (one === 'dead' ? t.html('consoleLogout.optionDead')
                 : one === 'sent' ? t.html('consoleLogout.optionSent')
                   : t.html('consoleLogout.optionPending')) + '</option>';
      }).join('') + '</select><label for="deliveryq">' +
      t.html('consoleLogout.search') + '</label>' +
      '<input id="deliveryq" name="deliveryq" value="' +
      kit.esc(v.deliveryq || '') + '" placeholder="' +
      kit.esc(t.text('consoleLogout.searchPlaceholder')) + '">' +
      '<button class="secondary">' + t.html('consoleLogout.filter') +
      '</button></div></form>';
    if (!list.length) {
      return heading + kit.note(state || v.deliveryq
        ? t.html('consoleLogout.noDeliveryMatches')
        : t.html('consoleLogout.noneYet'));
    }
    const paging = (v.deliveriesPg && v.deliveriesPg.paging) || null;
    const params = Object.assign({}, kit.pageParamsOf({}), wantedUser
      ? { user: wantedUser } : {}, { deliveryState: state,
                                     deliveryq: v.deliveryq || '' });
    const nav = paging
      ? kit.pageNavPair('/admin/logout', params, paging) : { head: '' };
    return heading + nav.head +
      '<table><thead><tr><th>' + t.html('consoleLogout.thQueued') +
      '</th><th>' + t.html('consoleLogout.thClient') + '</th><th>' +
      t.html('consoleLogout.thSession') + '</th>' +
      '<th>' + t.html('consoleLogout.thState') + '</th><th>' +
      t.html('consoleLogout.thWhy') + '</th><th></th></tr></thead><tbody>' +
      list.map(function (row) {
        const retry = row.state === 'dead' && canWrite
          ? '<form method="post" action="/admin/logout" ' +
            'style="display:inline">' +
            '<input type="hidden" name="action" value="retry-backchannel">' +
            '<input type="hidden" name="delivery" value="' +
            kit.esc(row.id) + '">' +
            '<input type="hidden" name="user" value="' +
            kit.esc(wantedUser || '') + '">' +
            LogoutPage.logoutBackField(back || kit.queryWith(params, {})) +
            '<button type="submit">' + t.html('consoleLogout.retry') +
            '</button></form>'
          : '';
        // The state is the store's word, drawn as it comes, except a dead
        // letter, which the page has always named in words of its own.
        return '<tr><td class="sub">' + kit.esc(row.queuedAt) + '</td>' +
          '<td><code>' + kit.esc(row.clientId) + '</code><br><span ' +
          'class="sub">' + kit.esc(row.uri) + '</span></td>' +
          '<td class="sub">' + kit.esc(row.sessionId) +
          (row.trigger && row.trigger !== 'sign-out'
            ? '<br>' + kit.esc(row.trigger) : '') + '</td>' +
          '<td>' + (row.state === 'dead'
            ? t.html('consoleLogout.deadLetter') : kit.esc(row.state)) +
          (row.attempts ? '<br><span class="sub">' +
                          t.html('consoleLogout.attempts',
                                 { n: row.attempts }) +
                          (row.status ? ', HTTP ' + row.status : '') +
                          (row.generation > 1
                            ? t.html('consoleLogout.retryN',
                                     { n: row.generation - 1 }) : '') +
                          '</span>' : '') +
          (row.encrypted ? '<br><span class="sub">' +
                           t.html('consoleLogout.encrypted',
                                  { alg: row.encrypted }) + '</span>' : '') +
          '</td>' +
      '<td class="sub">' + (row.errorCode
            ? '<code>' + kit.esc(row.errorCode) + '</code> ' : '') +
          kit.esc(row.why || row.via || '') + '</td><td>' + retry +
          '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  // One row of the flattened table. The family is a COLUMN here where /logout
  // makes it a heading, because this table is filtered and paged across
  // families and a heading that appeared and vanished with the filter would be
  // worse than a column that is always there. The opaque `back` field every
  // form on this page carries, so that ending one item does not cost the reader
  // their place in the list. Three other pages here build the same input as a
  // local `const`; this is a function because six forms on this one page need
  // it and a sixth hand-written copy is the one that would forget. It is
  // REBUILT by kit.listViewFromBack() on the way in and never echoed — the
  // guarantee that keeps a hand-written `back` from reaching anything but
  // another page of this same list.
  /**
   * Draws the hidden `back` input every form on the sign-out page carries.
   *
   * @param back - the list state, as a query string
   * @returns an <input> as HTML
   */
  static logoutBackField(back) {
    return '<input type="hidden" name="back" value="' + kit.esc(back) + '">';
  }

  /**
   * Draws the error shown when the logout module has not filled its slot.
   *
   * @returns the note as HTML
   */
  static logoutNoReaderNote() {
    return '<div class="err"><strong>The logout module is not loaded in this ' +
      'process.</strong> That is a require-order fault rather than a ' +
      'configuration one: <code>logout/logout.ts</code> fills this ' +
      'console\'s slot at its own require time, and <code>server.js</code> ' +
      'requires it second to last. Nothing else on this console is ' +
      'affected.</div>';
  }

  /**
   * Draws one row of the sign-out page's table, with its End form.
   *
   * @param t - the page's translator (#539)
   * @param row - an inventory row from logout.ts
   * @param canWrite - whether the reader holds Admin Write
   * @param back - the list state the form posts as `back`
   * @returns a <tr> as HTML
   */
  static logoutRowHtml(t, row, canWrite, back) {
    const button = row.terminable && canWrite
      ? '<form method="post" action="/admin/logout" style="display:inline">' +
        '<input type="hidden" name="action" value="end">' +
        '<input type="hidden" name="user" value="' + kit.esc(row.user) + '">' +
        '<input type="hidden" name="select" value="' + kit.esc(row.id) + '">' +
        LogoutPage.logoutBackField(back) +
        '<button type="submit">' + t.html('consoleLogout.end') +
        '</button></form>'
      : (row.terminable ? '<span class="state-none">—</span>'
                        : '<span class="state-none" title="' +
                          kit.esc(row.why) +
                          '">' + t.html('consoleLogout.cannot') + '</span>');
    return '<tr><td>' + kit.esc(row.family) + '</td>' +
      // kit.shortened() emits its OWN <code title=…> wrapper — the title is how
      // the
      // full value stays recoverable — so it must NOT be escaped or wrapped
      // again: kit.esc() around it prints the tags, which is what this cell
      // did.
      '<td>' + kit.shortened(row.label, 44) + '<br><span class="sub">' +
      kit.esc(row.detail) + '</span>' +
      (row.terminable ? '' :
       '<br><span class="sub">' + kit.esc(row.why) + '</span>') + '</td><td>' +
      kit.esc(row.kind) + '</td><td ' +
      'class="sub">' + kit.esc(kit.whenText(row.startedAt)) + '</td>' +
      '<td class="sub">' + kit.esc(kit.whenText(row.expiresAt)) + '</td>' +
      '<td>' + button + '</td></tr>';
  }
}

export = LogoutPage;
