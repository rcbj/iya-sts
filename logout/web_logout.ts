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
    const wantedUser = json.user;
    const mayWrite = ctx.write;
    const params = kit.pageParamsOf(ctx.query);
    const back = kit.queryWith(params, {});
    const families = json.families || [];

    let inner;
    if (!wantedUser) {
      // No name is not an error and not a 404: this page is a lookup, and the
      // list of everybody is /admin/users' job rather than a second copy here.
      inner = (json.hasReader ? '' : LogoutPage.logoutNoReaderNote()) +
        kit.note('Name an identity to see everything this service is still ' +
        'holding for them — every browser sign-on session, every token it ' +
        'can still revoke, every outstanding code, every directory ' +
        'connection bound as them, and the Kerberos sign-out instant — and ' +
        'to end any of it.') +
        '<form method="get" action="/admin/logout"><label>Identity <input ' +
        'name="user" value="" placeholder="alice"></label> <button ' +
        'type="submit">Look</button></form><h2>What a logout ' +
        'reaches</h2><table><thead><tr><th>Family</th><th>Protocol</th><th>' +
        'Can ' +
        'it be ended?</th><th>What it is</th></tr></thead><tbody>' +
        families.map(function (family) {
          return '<tr><td>' + kit.esc(family.label) + '</td><td>' +
            kit.esc(family.protocol) + '</td><td>' +
            (family.terminable ? 'yes' : '<span ' +
                                                  'class="state-none">no' +
                                                  '</span>') + '</td>' +
            // The family's prose is a paragraph on most rows and it is the same
            // prose logout.ts owns (see FAMILIES over there) — so it folds here
            // rather than being shortened, which would have made this file the
            // second place it is written.
            '<td class="sub">' + kit.note(kit.esc(family.what)) + '<em>' +
              kit.esc(
                family.spec) +
            '</em></td></tr>';
        }).join('') + '</tbody></table>' +
        kit.note('The families that cannot be ended are listed on purpose. ' +
        'Nothing consults this service when a SAML assertion, a Kerberos ' +
        'service ticket or an X509-SVID is presented, so there is no ' +
        'revocation any issuer could perform — and a page that hid them ' +
        'would make a global logout look complete when it is not.') +
        kit.note('A person signing THEMSELVES out uses ' +
        '<code>/logout</code>, which needs no console role and is where the ' +
        'front-channel notifications actually load: those are iframes in the ' +
        'signed-out person\'s own browser, and this console is not that ' +
        'browser. The back-channel Logout Tokens are different — this ' +
        'service sends them, whichever door the sign-out came through — and ' +
        'the list below is where each one ended up.') +
        LogoutPage.backchannelDeliveriesSection(json, mayWrite, back, '') +
        // ON THE LOOKUP PAGE AND NOT ON THE PER-PERSON ONE. These four decide
        // what a logout REACHES, which is a question about the feature; the
        // drill-down is about one person, and a form there would invite
        // somebody to change the rules for everybody while looking at one of
        // them.
        SettingsForms.forms(json.settings, '/admin/logout');
    } else if (!json.known) {
      inner = LogoutPage.logoutNoReaderNote();
    } else {
      const inventory = json;
      const wantedFamily = json.family;
      const canWrite = json.canWrite;
      const summary = '<table><thead><tr><th>Family</th><th>Live</th><th>' +
                      'Endable</th><th>Protocol</th></tr></thead><tbody>' +
        inventory.families.map(function (family) {
          return '<tr><td><a href="' +
            kit.esc('/admin/logout' +
                     kit.queryWith(params, { user: wantedUser,
                       family: family.id,
                                                           page: '' })) + '">' +
            kit.esc(family.label) + '</a></td>' +
            '<td>' + family.held +
            (family.notListed ? ' (' + family.notListed + ' ' +
                'not listed)' : '') +
            '</td>' +
            '<td>' + (family.terminable ? 'yes' : '<span ' +
                                                  'class="state-none">no' +
                                                  '</span>') +
            '</td><td ' +
            'class="sub">' + kit.esc(family.protocol) + '</td></tr>';
        }).join('') + '</tbody></table>';

      inner = kit.note('<strong>' + inventory.total +
        '</strong> live item(s) for ' +
          '<code>' +
        kit.esc(wantedUser) + '</code>, in ' +
        inventory.families.filter(function (f) { return f.held; }).length +
          ' ' +
        'family/families. Filed under the key ' +
        '<code>' + kit.esc(json.key) + '</code>, which is what folds ' +
                                                       '<code>' +
        kit.esc(wantedUser) + '</code>, <code>' + kit.esc(wantedUser) + '@' +
        kit.esc(json.kerberosRealm) + '</code> and a <code>urn:</code> ' +
                                         'subject into one person.') +
        summary +
        (canWrite
          ? '<form method="post" action="/admin/logout">' +
            '<input type="hidden" name="action" value="global">' +
            '<input type="hidden" name="user" value="' + kit.esc(wantedUser) +
            '">' +
            LogoutPage.logoutBackField(back) +
            '<p><button type="submit">Global logout — end everything ' +
            'above</button> <span class="sub">Everything endable, in every ' +
            'family, in one act. What cannot be ended is reported rather ' +
              'than ' +
            'skipped silently.</span></p></form>'
          : kit.note('Ending anything needs the Admin Write role.')) +
        '<h2>Live items' + (wantedFamily ? ' — ' + kit.esc(wantedFamily) : '') +
        '</h2>' +
        kit.perPageForm('/admin/logout', 'family', wantedFamily,
                         json.paging.perPage,
                         'Filter by family, and choose how many rows a page ' +
                         'holds.',
                         { user: wantedUser }) +
        (json.rows.length
          ? '<table><thead><tr><th>Family</th><th>What</th><th>Kind</th><th>' +
            'Since</th><th>Until</th><th>End</th></tr></thead><tbody>' +
            json.rows.map(function (r) { return LogoutPage.logoutRowHtml(r,
              canWrite,
                back); })
                    .join('') +
            '</tbody></table>' +
            kit.pageNavPair('/admin/logout', params, json.paging).head
          : kit.note('Nothing live' + (wantedFamily ? ' in that family' : '') +
                      '.')) +
        (canWrite
          ? '<h2>Undo — both NON-SPEC</h2>' +
            kit.note('Neither of these is an operation any real deployment ' +
            'could offer, and they are here for the reason /admin/tokens\' ' +
            'restore button is: having to restart this service to get back ' +
              'to ' +
            'a working credential turns a two-second test into a two-minute ' +
            'one.') +
            // DEVELOPMENT ONLY (#111): refused in product by the action, and
            // so not offered there — a note says why in its place.
            (json.opensTestControls
              ? '<form method="post" action="/admin/logout">' +
                '<input type="hidden" name="action" ' +
                'value="restore-kerberos">' +
                '<input type="hidden" name="user" value="' +
                kit.esc(wantedUser) + '">' +
                LogoutPage.logoutBackField(back) +
                '<p><button type="submit">Clear the Kerberos sign-out ' +
                'instant</button> <span class="sub">Tickets issued before it ' +
                'are accepted again. Development mode only. A fresh AS-REQ ' +
                'does NOT do this: it gets a newer ticket and the older ones ' +
                'stay refused.</span></p></form>'
              : kit.note('Clearing a Kerberos sign-out instant is a ' +
                'development-only test control and is not offered in product ' +
                'mode: the instant stands until the latest a ticket from ' +
                'before it could still be valid.')) +
            '<form method="post" ' +
            'action="/admin/logout"><input type="hidden" name="action" ' +
            'value="restore-token"><input type="hidden" name="user" ' +
            'value="' + kit.esc(wantedUser) + '">' +
            LogoutPage.logoutBackField(back) +
            '<p><label>Restore a token by jti <input name="jti" ' +
            'placeholder="jti"></label> <button ' +
              'type="submit">Restore</button> ' +
            '<span class="sub">RFC 7009 has no such operation: a resource ' +
            'server may already have cached the refusal.</span></p></form>'
          : '') +
        LogoutPage.backchannelDeliveriesSection(json, canWrite, back,
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
   * @param view - the view from adminViews.logoutJson()
   * @param canWrite - optional; whether the reader holds Admin Write
   * @param back - optional; the list state the Retry form posts as `back`
   * @param wantedUser - optional; the identity the page is about
   * @returns the section as HTML
   */
  static backchannelDeliveriesSection(view, canWrite?, back?, wantedUser?) {
    const v = view || {};
    const list = Array.isArray(v.backchannelDeliveries)
      ? v.backchannelDeliveries : [];
    const counts = v.backchannelCounts || { pending: 0, sent: 0, dead: 0 };
    const state = String(v.deliveryState || '');
    const heading = '<h2 id="backchannel">Back-channel Logout Tokens</h2>' +
      kit.note('<strong>' + counts.pending + '</strong> pending, <strong>' +
        counts.sent + '</strong> sent, <strong>' + counts.dead + '</strong> ' +
        'dead letter(s) in this realm, across every node. A relying party ' +
        'that is down is retried with backoff by whichever node gets there ' +
        'first, across restarts; one that never accepts — or answers 400, ' +
        'or is refused by the outbound policy — is a DEAD LETTER, sent again ' +
        'only when somebody presses Retry. Each final outcome is also a ' +
        '<code>logout.backchannel</code> row on <a href="/admin/audit">the ' +
        'audit log</a>.') +
      '<form method="get" action="/admin/logout#backchannel"><div ' +
      'class="formrow">' +
      (wantedUser ? '<input type="hidden" name="user" value="' +
                    kit.esc(wantedUser) + '">' : '') +
      '<label for="deliveryState">State</label><select id="deliveryState" ' +
      'name="deliveryState"><option value="">any</option>' +
      ['pending', 'sent', 'dead'].map(function (one) {
        return '<option value="' + one + '"' +
               (one === state ? ' selected' : '') + '>' +
               (one === 'dead' ? 'dead letters' : one) + '</option>';
      }).join('') + '</select><label for="deliveryq">Search</label>' +
      '<input id="deliveryq" name="deliveryq" value="' +
      kit.esc(v.deliveryq || '') + '" placeholder="client, session, code">' +
      '<button class="secondary">Filter</button></div></form>';
    if (!list.length) {
      return heading + kit.note(state || v.deliveryq
        ? 'No delivery matches.'
        : 'None yet. A sign-out — or an expiry, while ' +
          '<code>oauth2.backchannelLogoutOnExpiry</code> is on — sends one ' +
            'to ' +
          'every relying party on the ending session that registered a ' +
          '<code>backchannel_logout_uri</code>, while ' +
          '<code>oauth2.backchannelLogout</code> is on.');
    }
    const paging = (v.deliveriesPg && v.deliveriesPg.paging) || null;
    const params = Object.assign({}, kit.pageParamsOf({}), wantedUser
      ? { user: wantedUser } : {}, { deliveryState: state,
                                     deliveryq: v.deliveryq || '' });
    const nav = paging
      ? kit.pageNavPair('/admin/logout', params, paging) : { head: '' };
    return heading + nav.head +
      '<table><thead><tr><th>Queued</th><th>Client</th><th>Session</th>' +
      '<th>State</th><th>Why</th><th></th></tr></thead><tbody>' +
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
            '<button type="submit">Retry</button></form>'
          : '';
        return '<tr><td class="sub">' + kit.esc(row.queuedAt) + '</td>' +
          '<td><code>' + kit.esc(row.clientId) + '</code><br><span ' +
          'class="sub">' + kit.esc(row.uri) + '</span></td>' +
          '<td class="sub">' + kit.esc(row.sessionId) +
          (row.trigger && row.trigger !== 'sign-out'
            ? '<br>' + kit.esc(row.trigger) : '') + '</td>' +
          '<td>' + kit.esc(row.state === 'dead' ? 'dead letter' : row.state) +
          (row.attempts ? '<br><span class="sub">' + row.attempts +
                          ' attempt(s)' +
                          (row.status ? ', HTTP ' + row.status : '') +
                          (row.generation > 1
                            ? ', retry ' + (row.generation - 1) : '') +
                          '</span>' : '') +
          (row.encrypted ? '<br><span class="sub">encrypted ' +
                           kit.esc(row.encrypted) + '</span>' : '') +
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
   * @param row - an inventory row from logout.ts
   * @param canWrite - whether the reader holds Admin Write
   * @param back - the list state the form posts as `back`
   * @returns a <tr> as HTML
   */
  static logoutRowHtml(row, canWrite, back) {
    const button = row.terminable && canWrite
      ? '<form method="post" action="/admin/logout" style="display:inline">' +
        '<input type="hidden" name="action" value="end">' +
        '<input type="hidden" name="user" value="' + kit.esc(row.user) + '">' +
        '<input type="hidden" name="select" value="' + kit.esc(row.id) + '">' +
        LogoutPage.logoutBackField(back) +
        '<button type="submit">End</button></form>'
      : (row.terminable ? '<span class="state-none">—</span>'
                        : '<span class="state-none" title="' +
                          kit.esc(row.why) +
                          '">cannot</span>');
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
