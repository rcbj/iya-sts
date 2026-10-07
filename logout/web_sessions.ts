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
          '>any protocol</option>']
      .concat(json.protocols.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
               (name === (json.filter.protocol || '') ? ' selected' : '') +
                 '>' +
               kit.esc(name) + '</option>';
      })).join('');

    const rows = json.sessions.length
      ? json.sessions.map(function (row) {
          return SessionsPage.sessionRow(row, nowMs, ctx.write, back);
        }).join('')
      : '<tr><td colspan="8">' +
        (json.held
          ? 'Nothing matches. ' + json.held + ' session(s) are live ' +
            'under other names or other protocols.'
          : 'Nothing is signed in. Sign somebody in &mdash; an OIDC flow, ' +
            'a SAML 2.0 sign-in, an <code>ldapsearch</code> that binds, a ' +
            '<code>kinit</code> &mdash; and a row appears here.') +
        '</td></tr>';

    const inner = kit.note('<strong>Every session this service is holding ' +
      'right ' +
      'now</strong>, across the three protocols that have one. A session ' +
      'is state THIS SERVICE holds that makes somebody currently ' +
      'authenticated; a token, an assertion, a ticket and an SVID are ' +
      'things it has HANDED OUT, they outlive every session here, and they ' +
      'are <a href="/admin/tokens">Tokens</a>. Keeping the two apart is ' +
      'the whole point of a page of each.') +

      '<div class="tiles">' +
      kit.tile(json.held, 'live sessions') +
      kit.tile(json.heldByKind.session || 0, 'browser sign-on') +
      kit.tile(json.heldByKind.krb5 || 0, 'Kerberos TGTs') +
      kit.tile(json.heldByKind.ldap || 0, 'LDAP connections') +
      // The fifth tile is a SLICE of the first four rather than a fifth kind,
      // so the four above it still add up to `live sessions` and this one
      // does not join that sum. It earns a tile anyway: it is the number
      // somebody scans this page for, and a zero here is as informative as a
      // non-zero.
      kit.tile(json.unauthenticatedHeld, 'unauthenticated') +
      '</div>' +

      kit.note('<strong>The three are not variants of one thing and their ' +
      'expiries are worked out differently</strong>, which is why the ' +
      'Expires column carries the rule as well as the time &mdash; hover ' +
      'it on any row:') +
      '<ul><li><strong>The browser sign-on session</strong> &mdash; the ' +
      'cookie from <code>/authn/login</code>, which OAuth 2.0 / OIDC, ' +
      'WS-Federation, SAML 2.0, SAML 1.1 and this console all read. It ' +
      'expires at an ABSOLUTE instant fixed when it was created ' +
      '(<code>authn.sessionLifetimeS</code>) and <strong>using it does not ' +
      'extend it</strong>. An idle timeout ' +
      '(<code>authn.sessionIdleTimeoutS</code>) ends it earlier when it ' +
      'goes unused; it is off by default, and then a session in constant ' +
      'use dies at the same moment as one nobody has touched. The ' +
      '<em>Carries</em> column is what has signed in ON it, which is what ' +
      'makes ending one reach further than it looks.</li><li><strong>The ' +
      'Kerberos ticket-granting ticket</strong> &mdash; a TGT IS the ' +
      'Kerberos session and a service ticket is one use of it. It expires ' +
      'at the <code>endtime</code> the KDC sealed INTO the ticket, and ' +
      'nothing here can move it or take it back: a ticket is valid because ' +
      'it decrypts and its endtime has not passed. Short lifetimes are the ' +
      'whole of Kerberos\'s revocation model.</li><li><strong>The LDAP ' +
      'connection</strong> &mdash; RFC 4511 section 4.2 makes a Bind the ' +
      'authorization state of a CONNECTION, so in LDAP the connection is ' +
      'the session and closing it is the only sign-out the protocol has. ' +
      'It has <strong>no expiry at all</strong>: it lasts until the next ' +
      'Bind, an Unbind, or the socket closing.</li></ul>' +

      kit.warn('<strong>Revoke is not one act either.</strong> On a ' +
      'browser session it ends that session and everything hanging off it ' +
      '&mdash; the relying parties are notified, the refresh tokens issued ' +
      'on it are revoked. On an LDAP row it closes the socket, which the ' +
      'client sees as its connection dropping mid-conversation. On a ' +
      'Kerberos row <strong>it does more than the row it is on</strong>: ' +
      'it stamps a sign-out instant on the PRINCIPAL, so every ' +
      'ticket-granting ticket that principal authenticated before now is ' +
      'refused &mdash; and it still reaches no service ticket already in a ' +
      'cache, because accepting one never contacts this KDC. Every button ' +
      'carries its own sentence; hover it before pressing it. All three go ' +
      'through the same termination <a href="/logout">the ' +
      'protocol-independent sign-out</a> performs, so they write the same ' +
      'audit row and honour the same two settings.') +

      '<h2>Live sessions</h2>' +
      // No `page` input in this form, and that is the point: changing the
      // filter or the page size sends the reader back to page 1. Carrying the
      // old page number over would land somebody on page 6 of a two-page
      // result.
      '<form method="get" action="/admin/sessions"><div class="formrow">' +
        '<label for="q">Search</label>' +
        '<input type="text" id="q" name="q" size="28" value="' +
        kit.esc((json.filter.q || '')) +
          '" placeholder="a username, a subject, ' +
        'a DN or a session id">' +
        '<label for="protocol">Protocol</label>' +
        '<select id="protocol" name="protocol">' + protocolOptions +
        '</select><label for="per">Per page</label><select id="per" ' +
        'name="per">' + kit.perPageOptions(paging.perPage) +
        '</select>' +
        '<button class="secondary">Filter</button>' +
        ((json.filter.q || '') || (json.filter.protocol || '')
          ? ' <a href="/admin/sessions">clear</a>' : '') +
      '</div></form>' +
      kit.note('The search matches the username, the subject, the session ' +
      'id, the bind DN and the principal name together, because a reader ' +
      'arrives holding exactly one of those. The protocol is the one the ' +
      'sign-in came THROUGH and not the only one the session serves: every ' +
      'browser family here reads the same session, so a row saying ' +
      '<code>SAML 2.0</code> may well be carrying OIDC relying parties too ' +
      '&mdash; which is what the <em>Carries</em> column says.') +
      nav.head +
      '<table><tr><th>Kind</th><th>Protocol</th><th>Who</th><th>Since</th>' +
      '<th>Expires</th><th>Carries</th><th>Credentials</th><th></th></tr>' +
      rows + '</table>' +
      nav.foot +
      kit.note(json.matched + ' row(s) match' +
      (paging.pages > 1
        ? ', of which rows ' + paging.firstRow + '&ndash;' + paging.lastRow +
          ' are on this page (' + paging.page + ' of ' + paging.pages + ')'
        : '') +
      '; ' + json.held + ' live in total. Newest first. Everything ' +
      'here is read live from the module that owns it every time this page ' +
      'is drawn &mdash; there is no cache, deliberately, because a cached ' +
      'answer to <em>is this still live</em> would be the half a reader is ' +
      'about to press a button on.') +

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
      '<h2>Unauthenticated sessions</h2>' +

      kit.note('<strong>A session where nobody authenticated.</strong> ' +
      'Somebody pressed <em>Continue without signing in</em> at ' +
      '<code>/authn/login</code>, so this service holds a real session for ' +
      'them &mdash; it has a cookie, it satisfies a flow already in ' +
      'progress, and tokens can be issued on it &mdash; and it records ' +
      'that no credential was ever checked. They are the ' +
      '<code>anonymous</code> principal, which is one directory entry ' +
      'however many of these there are.') +

      kit.note('<strong>This is the only place the difference between two ' +
      'of the built-in roles is visible.</strong> Every session in the ' +
      'table above holds <code>EVERYBODY</code> <em>and</em> ' +
      '<code>ALL_AUTHENTICATED_USERS</code>; every session in this one ' +
      'holds <code>EVERYBODY</code> and ' +
      '<code>ALL_UNAUTHENTICATED_USERS</code> instead. So an application ' +
      'whose <code>appRequiredRole</code> is ' +
      '<code>ALL_AUTHENTICATED_USERS</code> refuses these with ' +
      '<code>access_denied</code>, and one that names no role at all ' +
      '&mdash; which requires <code>EVERYBODY</code> &mdash; does not. <a ' +
      'href="/admin/roles">The role register</a> is where that is ' +
      'configured.') +

      (json.unauthenticatedKept
        ? kit.note('<strong><code>authn.unauthenticatedSessions</code> is ' +
          'ON</strong> in this realm, so the sign-in screen is offering ' +
          'the third button. <a href="/admin/roles">Turn it off</a> and no ' +
          'new ones can be started; any already here stay until they ' +
          'expire or are ended.')
        : kit.warn('<strong><code>authn.unauthenticatedSessions</code> is ' +
          'OFF</strong> in this realm, so no new ones can be started and ' +
          'this section will stay empty. It is off by default because it ' +
          'puts a third button on every sign-in screen in the service. <a ' +
          'href="/admin/roles">Turn it on</a> to make ' +
          '<code>ALL_UNAUTHENTICATED_USERS</code> reachable.')) +

      (json.unauthenticatedHeld
        ? '<table><tr><th>Kind</th><th>Protocol</th><th>Who</th><th>Since' +
          '</th>' +
          '<th>Expires</th><th>Carries</th><th>Credentials</th><th></th>' +
          '</tr>' +
          json.unauthenticatedSessions.map(function (row) {
            return SessionsPage.sessionRow(row, nowMs, ctx.write, back);
          }).join('') + '</table>' +
          kit.note(json.unauthenticatedHeld + ' unauthenticated ' +
            'session(s), of ' +
          json.held + ' live. <strong>Not filtered and not ' +
          'paged</strong>, unlike the table above &mdash; the question ' +
          'this section answers is about the whole service, and a search ' +
          'box somebody had left set could hide the one row that matters.')
        : kit.note('<strong>None.</strong> Every session this service is ' +
          'holding right now had a credential accepted for it.')) +

      kit.note('<a href="/admin/logout">What ONE person is still signed ' +
      'into</a>, which is this question asked the other way round and ' +
      'reaches seven more families &middot; <a href="/admin/tokens">what ' +
      'has been issued</a> &middot; <a href="/admin/caep-sessions">what ' +
      'has been SAID about these sessions</a> over Shared Signals &middot; ' +
      '<a href="/admin/metrics">the counts</a> &middot; <a ' +
      'href="/admin/sessions?format=json">this page as JSON</a> &middot; ' +
      '<a href="/admin-api/sessions">the same over the management API</a>');

    return inner;
  }

  /**
   * Draws one row of the sessions page, with its Revoke form.
   *
   * The form is drawn only for a terminable row and a holder of Admin
   * Write; otherwise the cell says why not.
   *
   * @param row - a live-session row from logout.ts
   * @param nowMs - the current time in milliseconds
   * @param canWrite - whether the reader holds Admin Write
   * @param back - the list state the form posts as `back`
   * @returns a <tr> as HTML
   */
  static sessionRow(row, nowMs, canWrite, back) {
    const revoke = row.terminable && canWrite
      ? '<form method="post" action="/admin/sessions">' +
        '<input type="hidden" name="action" value="revoke">' +
        '<input type="hidden" name="key" value="' + kit.esc(row.key) + '">' +
        '<input type="hidden" name="select" value="' + kit.esc(row.id) + '">' +
        '<input type="hidden" name="back" value="' + kit.esc(back) + '">' +
        '<button class="danger"' +
        (row.why ? ' title="' + kit.esc(row.why) + '"' : '') +
        '>Revoke</button></form>'
      : (canWrite
          ? '<span class="state-none" title="' + kit.esc(row.why) +
            '">cannot</span>'
          : '<span class="state-none" title="' +
            kit.esc('Ending a session needs the Admin Write role.') +
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
      '<td>' + kit.esc(row.username || '(unknown)') +
      (row.sub ? '<div class="sub"><code>' + kit.esc(row.sub) +
       '</code></div>' :
       '') +
      '</td>' +
      '<td class="sub">' +
      (row.startedAt ? kit.esc(kit.whenText(row.startedAt))
                     : '<span title="' +
                       kit.esc('Nothing recorded when this one ' +
                       'started. A connection bound before this service ' +
                       'began stamping the instant reads this way.') +
                       '">not ' +
                           'recorded</span>') +
      '</td>' +
      SessionsPage.sessionExpiryCell(row, nowMs) +
      '<td class="sub">' + kit.esc(row.detail || '—') + '</td>' +
      SessionsPage.sessionCredentialsCell(row) +
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
   * @param row - a live-session row from logout.ts
   * @returns a <td> as HTML
   */
  static sessionCredentialsCell(row) {
    if (row.family === 'session') {
      return '<td><a href="' + kit.esc('/admin/tokens' +
        kit.queryWith({ session: row.sessionId }, {})) +
        '" title="' + kit.esc('Every credential issued under this session') +
        '">issued on it</a></td>';
    }
    if (row.family === 'krb5') {
      return '<td><a href="' + kit.esc('/admin/tokens' +
        kit.queryWith({ family: 'ticket' }, {})) +
        '" title="' + kit.esc('Every Kerberos ticket this KDC has minted. ' +
          'There is no per-session link: a ticket carries no identifier this ' +
          'service keeps a handle on.') + '">the ticket table</a></td>';
    }
    if (row.family === 'gnap') {
      // A GNAP GRANT (#432): its tokens are in GNAP's own store, listed with
      // the grant on Protocols → GNAP.
      return '<td><a href="' + kit.esc('/admin/gnap' +
        kit.queryWith({ state: 'approved' }, {})) +
        '" title="' + kit.esc('The grants this authorization server holds, ' +
          'with the tokens each issued') + '">the grant list</a></td>';
    }
    return '<td class="sub" title="' +
           kit.esc('A Bind issues no credential. It sets the authorization ' +
      'state of a connection, and that state is this row.') + '">none</td>';
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
   * @param row - a live-session row from logout.ts
   * @param nowMs - the current time in milliseconds
   * @returns a <td> as HTML
   */
  static sessionExpiryCell(row, nowMs) {
    const rule = row.expiryRule || '';
    if (!row.expiresAt) {
      return '<td class="sub" title="' + kit.esc(rule) + '"><strong>no ' +
        'expiry</strong><div class="sub">it ends when something ends ' +
        'it</div></td>';
    }
    const left = row.expiresAt - nowMs;
    if (left <= 0) {
      // Live rows only reach here in a race — the list was built a moment ago —
      // and saying so is better than a negative countdown.
      return '<td class="state-expired" title="' + kit.esc(rule) +
             '">expired' +
        '<div class="sub">' + kit.esc(kit.whenText(row.expiresAt)) +
        '</div></td>';
    }
    return '<td' + (left < 5 * 60 * 1000 ? ' class="state-expired"' : '') +
      ' title="' + kit.esc(rule) + '">in ' +
      kit.esc(kit.durationText(left)) +
      '<div class="sub">' + kit.esc(kit.whenText(row.expiresAt)) +
      '</div></td>';
  }
}

export = SessionsPage;
