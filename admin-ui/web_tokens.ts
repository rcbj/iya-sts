// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_tokens.ts
//
// ---------------------------------------------------------------------------
// MONITORING → TOKENS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Tokens from the answer of `GET /admin-api/tokens`: every issuance this
// service remembers, one row per set, filtered and paged, with the controls
// that revoke.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/tokens` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

// The legend for the above, on the page, because a reader cannot see the
// comment this file opens the section with and a table whose columns shift
// meaning between rows has to say so where the rows are.
const COLUMN_LEGEND =
  '<table><tr><th>Column</th><th>A JWT</th><th>A SAML assertion</th><th>A ' +
  'Kerberos ticket</th></tr><tr><td>Contents</td><td>every credential the ' +
  'reply carried, in the order they were minted — one row, however many that ' +
  'is</td><td colspan="2">one credential: these protocols issue one thing ' +
  'per act, so the cell is the kind and nothing ' +
  'else</td></tr><tr><td>State</td><td>the state every member shares, or ' +
  '<em>mixed</em> when they differ — which they usually do, since an access ' +
  'token and the refresh token beside it have very different lifetimes. ' +
  'Hover for the breakdown</td><td colspan="2">the one credential\'s own ' +
  'state</td></tr><tr><td>Expires</td><td>the first member to go, then the ' +
  'last — a set comes apart before it is finished, and the earlier instant ' +
  'is the one a refused call is about</td><td colspan="2">its ' +
  '<code>NotOnOrAfter</code> / its ' +
  '<code>endtime</code></td></tr><tr><td>User</td><td><code>username</code>, ' +
  'as typed at the sign-in screen</td><td colspan="2">nothing: each of these ' +
  'has one name, and it is in ' +
  'Subject</td></tr><tr><td>Subject</td><td><code>sub</code></td><td>the ' +
  '<code>NameID</code></td><td>the client principal, ' +
  '<code>name@REALM</code></td></tr><tr><td>Client, audience or ' +
  'service</td><td><code>client_id</code> (or <code>azp</code>, or the ' +
  '<code>aud</code>)</td><td>the <code>AudienceRestriction</code>, or ' +
  '<em>unrestricted</em> when WS-Trust was given no ' +
  '<code>AppliesTo</code></td><td>the service the ticket is for; hover for ' +
  'the realm that issued it</td></tr><tr><td>Detail</td><td>the ACCESS ' +
  'TOKEN\'s <code>scope</code>. The refresh token beside it deliberately ' +
  'carries a different one — what was <em>authorized</em>, rather than what ' +
  'this token can do — so the two disagree by design, and the set page shows ' +
  'each. A scope that became the audience is not on either</td><td>whether ' +
  'the signature was written — an assertion that failed to sign still went ' +
  'out</td><td>the enc-type it was sealed with</td></tr><tr><td>Presented ' +
  'as</td><td>Bearer, or DPoP when <code>cnf.jkt</code> binds it to a ' +
  'key</td><td>bearer <code>SubjectConfirmation</code>; there is no ' +
  'holder-of-key form here</td><td>in a TGS-REQ (a TGT) or an AP-REQ (a ' +
  'service ticket)</td></tr><tr><td>jti, ID or set</td><td>a set of one ' +
  'shows the <code>jti</code> and opens that credential\'s lineage; a group ' +
  'shows the <em>set id</em> and opens the set. The set id is this ' +
  'service\'s own handle on a reply — it is in no token, no client ever sees ' +
  'it, and it is not a claim</td><td>the <code>ID</code> / ' +
  '<code>AssertionID</code></td><td>none exists — a ticket has no identifier ' +
  'to quote, and the KDC keeps no handle on one</td></tr><tr><td>the ' +
  'button</td><td>Revoke, or <strong>Revoke set</strong> on a group, which ' +
  'sends every revocable member through the same act one at a time. Nothing ' +
  'new is written: it is the same set of revoked <code>jti</code>s ' +
  '<code>/oauth2/revoke</code> writes to</td><td colspan="2">there is none, ' +
  'and there is nothing it could do — see above</td></tr></table>';

/**
 * Draws Tokens from the answer of `GET /admin-api/tokens`: every issuance this
 * service remembers, one row per set, filtered and paged, with the controls
 * that revoke.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class TokensPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const wantedFamily = json.filter.family || '';
    const wantedKind = json.filter.kind || '';
    const wantedState = json.filter.state || '';
    const wantedSession = json.filter.session || '';
    const paging = json.paging;
    const shown = json.sets;
    const heldByFamily = json.heldByFamily;
    // What every paging link has to carry with it. The page number is not in
    // here — kit.pageNavPair() supplies that per link — and neither is
    // `format`,
    // because JSON has no links in it and a caller asking for JSON passes its
    // own parameters anyway.
    const filterParams = { family: wantedFamily, kind: wantedKind,
                           state: wantedState,
                           session: wantedSession,
                           per: ctx.query.per ? paging.perPage : '' };
    const nav = kit.pageNavPair('/admin/tokens', filterParams, paging);
    // What the POST handler sends the browser back to. A row button returns
    // to THIS page of THIS filter; the bulk buttons below keep the filter but
    // not the page, because after "revoke everything" the list they were
    // looking at is a different list and page 7 of it means nothing.
    const backRow = kit.queryWith(filterParams, { page: paging.page });
    const backFilter = kit.queryWith(filterParams, {});

    // The list as the reader left it, for the drill-down link on every row:
    // the filter AND the page, so the way back from a credential is the row
    // it was clicked on rather than the top of everything.
    const listView = Object.assign({}, filterParams, { page: paging.page });
    const rows = shown.map(function (set) {
      return TokensPage.issuedSetRow(set, backRow, listView);
    }).join('');

    const familyOptions = ['<option value=""' +
        (wantedFamily ? '' : ' selected') + '>any ' +
        'family</option>']
      .concat(json.families.map(function (entry) {
        return '<option value="' + kit.esc(entry.family) + '"' +
               (entry.family === wantedFamily ? ' selected' : '') + '>' +
               kit.esc(entry.label) + '</option>';
      })).join('');

    // Grouped by family rather than flat, because "SAML 2.0" and "id_token"
    // in one list of nine reads as nine unrelated things. Both this and the
    // family select are built from the same structure in admin_stats.js, so
    // the two cannot come to disagree about which kind belongs to which
    // family — which they would, being two hand-written lists of the same
    // nine strings.
    const kindOptions = '<option value=""' + (wantedKind ? '' : ' selected') +
        '>any ' +
        'kind</option>' +
      json.families.map(function (entry) {
        return '<optgroup label="' + kit.esc(entry.label) + '">' +
               entry.kinds.map(function (k) {
          return '<option value="' + kit.esc(k) + '"' +
                 (k === wantedKind ? ' ' +
              'selected' : '') + '>' +
                 kit.esc(k) + '</option>';
        }).join('') + '</optgroup>';
      }).join('');
    const stateOptions = ['', 'valid', 'expired', 'revoked', 'not yet valid',
                          'no ' +
        'expiry stated']
      .map(function (s) {
        return '<option value="' + kit.esc(s) + '"' +
               (s === wantedState ? ' selected' : '') + '>' +
               kit.esc(s || 'any state') + '</option>';
      }).join('');
    const perOptions = kit.perPageOptions(paging.perPage);

    const inner = kit.note('Everything this service has issued and still ' +
      'remembers: ' +
      'every JWT, every SAML assertion — whether WS-Trust issued it or a ' +
      'WS-Federation sign-in did — and every Kerberos ticket the KDC ' +
      'minted, in one table, newest first. One table rather than three ' +
      'because a WS-Federation sign-in that produced an ID Token and a ' +
      'SAML 1.1 assertion is <em>one event</em>, and three tables would ' +
      'leave it to be reassembled by comparing timestamps.') +
      kit.note('<strong>One row is one issuance, not one ' +
      'credential.</strong> OAuth 2.0 and OIDC are the only protocols here ' +
      'that hand back several credentials at once — redeeming an ' +
      'authorization code returns an access token, a refresh token and an ' +
      'ID Token in a single reply, and <code>response_type=id_token ' +
      'token</code> returns two in one fragment — so those are drawn as ' +
      'one row saying what it contains, with a link to the set. Every ' +
      'other family issues one credential per act, so a SAML assertion, a ' +
      'Kerberos ticket and a SPIFFE SVID are each a <em>set of one</em> ' +
      'and look exactly as they always did. The grouping comes from an ' +
      'identifier the <em>issuer</em> stated at the moment it built the ' +
      'reply, never from guessing that two rows near each other in time ' +
      'belong together: two people redeeming two codes at the same client ' +
      'in the same millisecond produce six credentials that agree on every ' +
      'column below, and a table that merged them would report a reply ' +
      'nobody ever received.') +
      kit.note('<strong>Refreshing makes a new set beside the old one, ' +
      'not a bigger one.</strong> A set is one <em>response</em>: it has ' +
      'one issued instant and one grant, which a row that grew all ' +
      'afternoon could not have. What joins the generations of a grant is ' +
      'the refresh lineage, and that is drawn — as a picture, back to the ' +
      'issuance the whole line rests on — on each credential\'s own page.') +
      kit.note('Only the JWTs can be invalidated. Revoking one here is ' +
      'the SAME operation RFC 7009\'s <code>/oauth2/revoke</code> performs ' +
      '— there is one set of revoked <code>jti</code>s in this service, ' +
      'not one per page. So a token revoked here immediately introspects ' +
      'as inactive at <code>/oauth2/introspect</code>, is refused by ' +
      '<code>/oauth2/userinfo</code> with <code>invalid_token</code>, and ' +
      'fails the refresh grant with <code>invalid_grant</code>. Two sets ' +
      'would each look correct on their own and never see each other, ' +
      'which is a debugging session with no error message anywhere in it.') +
      kit.note('<strong>An assertion, a ticket and an SVID have a button ' +
      'since 2026-09-05, and pressing it changes nothing out ' +
      'there.</strong> That is not a contradiction and the distinction is ' +
      'the whole of what this row means: <em>what this service knows</em> ' +
      'and <em>what a relying party will honour</em> are two different ' +
      'claims. Nothing consults this service when one of these is ' +
      'presented — an assertion is valid because its signature verifies ' +
      'and its <code>Conditions</code> hold, a ticket because the service ' +
      'it names can decrypt it with a key it already has, an SVID because ' +
      'it chains to a bundle — so a revocation here reaches none of them ' +
      'and never will. What it does is record that <em>this identity ' +
      'provider has disowned the credential</em>, which is what a sign-out ' +
      'has to be able to say, what CAEP can carry to a receiver that ' +
      'subscribed, and what SAML Single Logout can carry for an assertion ' +
      'issued through a browser profile. A WS-Trust assertion has neither ' +
      'channel and the mark is the whole of what exists for it — which is ' +
      'exactly why it is worth having, because otherwise the answer to ' +
      '"did you sign them out" would depend on which endpoint issued the ' +
      'credential. The button says <em>(record only)</em> and its tooltip ' +
      'says this again, so it cannot be pressed by somebody who thinks it ' +
      'did more.') +

      '<h2>Invalidate</h2>' +
      '<form method="post" action="/admin/tokens">' +
        '<input type="hidden" name="action" value="revoke">' +
        '<input type="hidden" name="back" value="' + kit.esc(backFilter) +
        '"><div class="formrow"><label for="target">A jti, or paste the ' +
        'whole token</label><input type="text" id="target" name="target" ' +
        'size="60" placeholder="jti, or eyJhbGciOi..."><button ' +
        'class="danger">Revoke</button></div></form>' +
      kit.note('Pasting a token is read for its <code>jti</code> and the ' +
      'signature is not checked, which is safe: a forged token yields a ' +
      'jti this service never issued, and revoking one of those ' +
      'invalidates nothing. To undo a revocation, use the Restore button ' +
      'in the table — a NON-SPEC operation no real authorization server ' +
      'can offer, kept because otherwise getting back to a working token ' +
      'means restarting this service.') +
      '<div class="formrow">' +
        ['access_token', 'id_token', 'refresh_token'].map(function (kind) {
          return '<form method="post" action="/admin/tokens" ' +
            'class="inline"><input type="hidden" name="action" ' +
            'value="revoke-kind"><input type="hidden" name="kind" value="' +
            kit.esc(kind) + '">' +
            '<input type="hidden" name="back" value="' +
            kit.esc(backFilter) + '">' +
            '<button class="danger">Revoke every ' + kit.esc(kind) +
            '</button></form>';
        }).join(' ') +
        '<form method="post" action="/admin/tokens" class="inline">' +
        '<input type="hidden" name="action" value="revoke-all">' +
        '<input type="hidden" name="back" value="' + kit.esc(backFilter) +
        '"><button class="danger">Revoke everything</button></form>' +
      '</div>' +
      '<form method="post" action="/admin/tokens">' +
        '<input type="hidden" name="action" value="revoke-subject">' +
        '<input type="hidden" name="back" value="' + kit.esc(backFilter) +
        '"><div class="formrow"><label for="subject">Everything for one ' +
        'subject or username</label><input type="text" id="subject" ' +
        'name="subject" size="40" placeholder="alice, or ' +
        'urn:uuid:…"><button ' +
        'class="danger">Revoke</button></div></form><h2>What has been ' +
        'issued</h2>' +
      // No `page` input in this form, and that is the point: changing the
      // filter or the page size sends the reader back to page 1. Carrying the
      // old page number over would land somebody on page 6 of a two-page
      // result, and the clamp in pagingOf() would then quietly move them
      // again.
      '<form method="get" action="/admin/tokens"><div class="formrow">' +
        '<label for="family">Family</label><select id="family" ' +
        'name="family">' +
      familyOptions +
        '</select>' +
        '<label for="kind">Kind</label><select id="kind" name="kind">' +
      kindOptions + '</select><label ' +
        'for="state">State</label><select id="state" ' +
        'name="state">' + stateOptions + '</select><label ' +
        'for="per">Per page</label><select id="per" ' +
        'name="per">' + perOptions + '</select>' +
        // The session filter rides as a HIDDEN input rather than as a fourth
        // select: it is not a choice out of a short list, it is one session
        // somebody arrived from — so it survives a Filter and is taken off by
        // the sentence below, which names the session it is holding.
        (wantedSession
          ? '<input type="hidden" name="session" value="' +
            kit.esc(wantedSession) +
            '">'
          : '') +
        '<button class="secondary">Filter</button>' +
        (wantedFamily || wantedKind || wantedState || wantedSession
          ? ' <a href="/admin/tokens">clear</a>' : '') +
      '</div></form>' +
      (wantedSession
        ? kit.note('Narrowed to what was issued on the browser sign-on ' +
          'session <code>' + kit.esc(wantedSession) + '</code>, which is ' +
          'how <a href="' + kit.esc('/admin/sessions') +
          '">Sessions</a> links here. ' +
          'Only credentials issued UNDER a session carry one, so an ' +
          'assertion, a Kerberos ticket, a token from either direct grant ' +
          'and anything an RFC 8693 exchange produced are absent by ' +
          'construction rather than missing &mdash; that is a fact about ' +
          'the credential and not a gap in the recording. <a href="' +
          kit.esc('/admin/tokens' +
            kit.queryWith({ family: wantedFamily, kind: wantedKind,
                        state: wantedState }, {})) +
          '">Show every session\'s</a>.')
        : '') +
      // Family and Kind are ANDed, like any two filters, so a contradictory
      // pair (Kerberos tickets, id_token) matches nothing. Said here rather
      // than prevented, because the alternative is a page that silently
      // ignores one of the two selects the reader can see it obeying.
      kit.note('Family and Kind narrow together: choosing a family and a ' +
      'kind from a different one matches nothing, which is what an empty ' +
      'table below then means.') +
      // WHAT A FILTER MEANS NOW THAT A ROW IS A SET, said on the page because
      // it is the one behaviour a reader would otherwise call a bug: asking
      // for id_token and being shown an access token too looks like the
      // filter being ignored until somebody explains that the row IS the
      // reply.
      kit.note('<strong>A filter matches a set when any credential in it ' +
      'matches.</strong> Asking for <code>id_token</code> answers with the ' +
      'replies that <em>contain</em> an ID Token — the access token and ' +
      'the refresh token that came back with it are still on the row, ' +
      'because they are part of the same reply. The same goes for State: a ' +
      'set holding an expired access token and a valid refresh token is ' +
      'found by both, and its State column reads <em>mixed</em> rather ' +
      'than picking one.') +
      nav.head +
      '<table><tr><th>Contents</th><th>State</th><th>User</th><th>Subject' +
      '</th>' +
      '<th>Client, audience or service</th><th>Detail</th><th>Presented ' +
      'as</th><th>Issued</th><th>Expires</th><th>jti, ID or ' +
      'set</th><th></th></tr>' +
      (rows || '<tr><td colspan="11">Nothing matches.</td></tr>') +
      '</table>' +
      nav.foot +
      kit.note(json.matched + ' set(s) match, holding ' +
                json.matchedCredentials +
      ' credential(s)' +
      (paging.pages > 1 ?
       ', of which sets ' + paging.firstRow + '&ndash;' + paging.lastRow +
                          ' are on this page (' + paging.page + ' of ' +
                          paging.pages + ')' : '') +
      '; ' + json.heldSets + ' set(s) over ' + json.held + ' ' +
          'credential(s) held in total — ' +
      json.families.map(function (entry) {
        return (heldByFamily[entry.family] || 0) + ' ' +
               kit.esc(entry.label);
      }).join(', ') +
      '. <strong>The per-family figures are credentials, not ' +
      'sets</strong>, so that they agree with the count on <a ' +
      'href="/admin/metrics">the metrics page</a> — two pages of one ' +
      'console disagreeing about how much has been issued is worse than ' +
      'one line carrying both units and saying which is which. Paging is ' +
      'by SET, so a page is a whole number of replies rather than a ' +
      'boundary drawn through the middle of one. Newest first, so page 1 ' +
      'is what somebody is most likely to be debugging. Only the claims ' +
      'and the facts below are kept, never the signed token, the assertion ' +
      'XML or the ticket: a page rendering a thousand live credentials in ' +
      'a form a browser will display is a page that leaks them, and the ' +
      '<code>jti</code> is all any button here needs.') +

      '<h3>What each column means</h3>' +
      kit.note('Three families in one table, so most columns answer a ' +
      'slightly different question depending on the row. Rather than leave ' +
      'that to be inferred:') +
      COLUMN_LEGEND +
      kit.note('OID4VCI credentials are <strong>not</strong> in this ' +
      'table. They are recorded and counted on <a ' +
      'href="/admin/metrics">the metrics page</a> and listed nowhere. That ' +
      'is a gap rather than a principle — a credential is as much an ' +
      'issued artifact as an assertion is — and it is named here so that ' +
      '"everything this service has issued" above is read as the three ' +
      'families it says and not as four.') +

      kit.note('Paging is <code>?page=</code> and <code>?per=</code> (at ' +
        'most ' +
      kit.MAX_ROWS +
      ' sets a page), and both work with <code>?format=json</code> — where ' +
      'the reply carries <code>page</code>, <code>pages</code> and ' +
      '<code>matched</code>, so a test can walk the whole list without ' +
      'guessing when it has reached the end. <strong>Those three count ' +
      'SETS</strong>, which is what this list is; ' +
      '<code>matchedCredentials</code> and <code>held</code> are the same ' +
      'figures in credentials. The sets are in <code>sets</code>, each ' +
      'carrying its <code>members</code> — and <code>issued</code> is the ' +
      'same members flattened, so a caller written against the older ' +
      'per-credential shape reads exactly what it read and the two cannot ' +
      'disagree, because one is built out of the other. Every button on ' +
      'this page acts on a <code>jti</code> or a <code>setKey</code> and ' +
      'never on a row number, so a revocation between two clicks cannot ' +
      'make the wrong token the target — the most it can do is shift a row ' +
      'onto another page.');

    return inner;
  }

  /**
   * Draws one row of the tokens table for an issued set.
   *
   * Most cells are drawn from the set's first member.
   *
   * @param set - a set from stats.issuedSets()
   * @param backRow - the list state its form posts as `back`
   * @param listView - the list state carried into its identifier link
   * @returns a <tr> as HTML
   */
  static issuedSetRow(set, backRow, listView) {
    const first = set.members[0];
    return '<tr><td>' + TokensPage.contentsCell(set) + '</td>' +
      TokensPage.setStateCell(set) +
      '<td>' + TokensPage.userCell(first) + '</td>' +
      '<td>' + TokensPage.subjectCell(first) + '</td>' +
      '<td>' + TokensPage.partyCell(first) + '</td>' +
      '<td>' + TokensPage.detailCell(first) + '</td>' +
      '<td>' + TokensPage.presentedCell(first) + '</td>' +
      '<td>' + kit.esc(kit.whenText(set.issuedAt)) + '</td>' +
      '<td>' + TokensPage.setExpiryCell(set) + '</td>' +
      '<td>' + TokensPage.setIdentifierCell(set, listView) + '</td>' +
      '<td>' + TokensPage.setActionCell(set, backRow) + '</td></tr>';
  }

  // WHAT THE SET CONTAINS, which is the column that used to be Kind. A set of
  // one prints exactly what that column printed, so three families out of four
  // are untouched; a group prints its kinds in the order they were issued,
  // which for a code redemption is access token, refresh token, ID Token.
  /**
   * Draws what an issued set contains, in the order it was issued.
   *
   * @param set - a set from stats.issuedSets()
   * @returns the set's kinds, and its size when grouped, as HTML
   */
  static contentsCell(set) {
    if (!set.grouped) {
      return kit.esc(set.kinds[0] || '—');
    }
    return '<strong title="' +
      kit.esc(set.size + ' credentials came back in one reply' +
               (set.grant ? ', from the ' + set.grant + ' grant' : '') +
               '. Every one of them is on the set page, with its own ' +
               'identifier, its own expiry and its own button.') + '">' +
      kit.esc(set.kinds.join(' + ')) + '</strong>' +
      ' <span class="state-none">(' + set.size + ')</span>';
  }

  // The one extra fact each family has that no other column has room for. It is
  // headed Detail rather than Scope, because the three are not answers to the
  // same question — a scope says what an access token authorises, an enc-type
  // says which cipher sealed a ticket — and a header naming one of them would
  // make the other two rows look like answers to it.
  /**
   * Draws the one family-specific fact for a row.
   *
   * Signed or unsigned for an assertion, the enc-type for a ticket, and
   * the scope for a token.
   *
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static detailCell(record) {
    if (record.family === 'assertion') {
      if (record.signed === false) {
        return '<span class="state-revoked" title="' +
          kit.esc('Signing threw and the assertion went out unsigned rather ' +
                   'than not at all, so that a relying party can reject it ' +
                   'for the right reason. The log line says what failed.') +
          '">unsigned</span>';
      }
      return '<span title="' +
        kit.esc('An enveloped XML signature over the assertion, its ' +
                 'reference naming the ID (SAML 2.0) or the AssertionID ' +
                 '(SAML 1.1).') + '">signed</span>';
    }
    if (record.family === 'ticket') {
      return '<code title="' + kit.esc('The enc-type the ticket and its ' +
                                        'session key were sealed with.') +
        '">' + kit.esc(record.etype || '—') + '</code>';
    }
    return kit.esc(record.scope || '—');
  }

  // Who it was issued FOR: the party meant to accept it.
  /**
   * Draws the party a credential was issued for.
   *
   * The audience of an assertion (or "unrestricted"), the service of a
   * ticket, or the client_id of a token.
   *
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static partyCell(record) {
    if (record.family === 'assertion') {
      if (record.audience) {
        return kit.shortened(record.audience, 30);
      }
      return '<span class="state-none" title="' +
        kit.esc('This assertion carries no AudienceRestriction — WS-Trust ' +
                 'was asked to Issue with no AppliesTo. Any relying party ' +
                 'may accept it, which is the thing an audience restriction ' +
                 'exists to prevent, so it is named here rather than shown ' +
                 'as a dash.') +
        '">unrestricted</span>';
    }
    if (record.family === 'ticket') {
      // The realm recorded with a ticket is the realm that ANSWERED, which
      // under a cross-realm referral is not the service's own realm. So it is
      // stated as the issuer in the tooltip rather than appended to the service
      // name as though it were part of the principal — which is what it would
      // look like, since a Kerberos principal is written service/host@REALM.
      return '<code title="' + kit.esc(String(record.service || '') +
        (record.realm ? ' — issued by the ' + record.realm + ' KDC' : '')) +
        '">' +
        kit.esc(record.service || '—') + '</code>';
    }
    return kit.esc(record.client_id || '—');
  }

  // How the holder gets to use it, which is the question the DPoP column was
  // already asking and which the other two families have their own answers to.
  /**
   * Draws how the holder presents the credential.
   *
   * bearer for an assertion, TGS-REQ or AP-REQ for a ticket, and DPoP or
   * Bearer for a token.
   *
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static presentedCell(record) {
    if (record.family === 'assertion') {
      return '<span title="' +
        kit.esc('Both builders write a bearer SubjectConfirmation: whoever ' +
                 'holds the assertion may present it. There is no ' +
                 'holder-of-key confirmation here, so there is nothing for ' +
                 'this column to distinguish between.') + '">bearer</span>';
    }
    if (record.family === 'ticket') {
      if (record.kind === 'Kerberos TGT') {
        return '<span title="' +
          kit.esc('A TGT goes back to the KDC in a TGS-REQ to get a service ' +
                   'ticket. It is never presented to a service, which is why ' +
                   'it is the Kerberos session rather than one use of ' +
                   'one.') + '">TGS-REQ</span>';
      }
      return '<span title="' +
        kit.esc('A service ticket is presented to the service it names, in ' +
                 'an AP-REQ — over raw Kerberos, or wrapped in SPNEGO over ' +
                 'HTTP.') + '">AP-REQ</span>';
    }
    if (record.jkt) {
      return '<span title="' +
        kit.esc('Bound to a key: cnf.jkt is in the token and a DPoP proof ' +
                 'over that key has to accompany it.') + '">DPoP</span>';
    }
    return 'Bearer';
  }

  // THE BUTTON FOR A WHOLE SET. One act rather than three clicks, and it acts
  // on the members that CAN be acted on — which for a set of one outside OAuth
  // is none of them, so those rows keep the dash and the sentence actionCell()
  // already gives them.
  //
  // Restore rather than Revoke once every revocable member is revoked, which is
  // the same two-state rule the per-token button follows. A PARTLY revoked set
  // offers Revoke, because the useful act there is finishing the job — the way
  // back for the one member somebody wants un-revoked is its own button on the
  // set page.
  /**
   * Draws the Revoke set or Restore set form for a grouped set.
   *
   * A set of one draws its member's action cell; a set with nothing
   * revocable gets a dash.
   *
   * @param set - a set from stats.issuedSets()
   * @param backRow - the list state to return to, posted as `back`
   * @returns the form, or the dash, as HTML
   */
  static setActionCell(set, backRow) {
    if (!set.grouped) {
      return TokensPage.actionCell(set.members[0], backRow);
    }
    if (!set.revocableCount) {
      return '<span class="state-none" title="' +
        kit.esc('Nothing in this set can be revoked: only access tokens, ID ' +
                 'Tokens and refresh tokens can be, and the others are ' +
                 'replies rather than credentials or carry no jti to act on.') +
                 '">—</span>';
    }
    const allRevoked = set.revokedCount >= set.revocableCount;
    return '<form method="post" action="/admin/tokens" class="inline">' +
      '<input type="hidden" name="action" value="' +
      (allRevoked ? 'restore-set' : 'revoke-set') + '">' +
      '<input type="hidden" name="set" value="' + kit.esc(set.setKey) + '">' +
      '<input type="hidden" name="back" value="' + kit.esc(backRow) + '">' +
      '<button class="' + (allRevoked ? 'secondary' : 'danger') + '" title="' +
      kit.esc(allRevoked
        ? 'Un-revoke every revocable credential in this set. NON-SPEC — no ' +
               'real authorization server can undo a revocation.'
        : 'Revoke the ' + set.revocableCount + ' revocable credential(s) in ' +
               'this set in one act. Each one is revoked exactly as its own ' +
               'button would revoke it, into the same set of revoked jtis ' +
               'RFC 7009\'s /oauth2/revoke writes to.') + '">' +
      (allRevoked ? 'Restore set' : 'Revoke set') + '</button></form>';
  }

  // WHEN THE SET COMES APART, and when it is finished. Two instants because the
  // members have two, and the earlier one first because it is the one somebody
  // debugging a refused call has arrived to find: the access token died at
  // 12:19 and the refresh token that could mint another is good until tomorrow.
  /**
   * Draws when a set's first member expires, and its last if different.
   *
   * @param set - a set from stats.issuedSets()
   * @returns the expiry text or range as HTML, or a dash
   */
  static setExpiryCell(set) {
    if (!set.expiresAtMs) {
      return '—';
    }
    if (!set.lastExpiresAtMs || set.lastExpiresAtMs === set.expiresAtMs) {
      return kit.esc(kit.whenText(set.expiresAtMs));
    }
    return '<span title="' +
      kit.esc('The members of this set expire at different times. The first ' +
        'goes at ' +
               kit.whenText(set.expiresAtMs) + ' and the last at ' +
               kit.whenText(set.lastExpiresAtMs) +
               '; the set page says which is which.') +
      '">' + kit.esc(kit.whenText(set.expiresAtMs)) + ' &rarr; ' +
      kit.esc(kit.whenText(set.lastExpiresAtMs)) + '</span>';
  }

  // THE HANDLE, AND THE WAY IN. A group is named by the set id and opens the
  // set page; a set of one keeps the identifier cell it has always had and
  // opens the credential's lineage, because for one credential the set page
  // would add a click and nothing else. Both are links to somewhere, which is
  // why the two cases are here rather than in identifierCell(): that function
  // answers "what is this credential called", and this one answers "where does
  // this row go".
  /**
   * Draws a set's identifier: a link to the set page for a group.
   *
   * A set of one draws its member's identifier cell instead.
   *
   * @param set - a set from stats.issuedSets()
   * @param listView - the tokens page's list state, carried into the link
   * @returns the cell's content as HTML
   */
  static setIdentifierCell(set, listView) {
    if (!set.grouped) {
      return TokensPage.identifierCell(set.members[0], listView);
    }
    return '<a href="' +
      kit.esc('/admin/tokens/set' +
               kit.queryWith(listView || {}, { id: set.setKey })) +
      '" title="' +
      kit.esc('The ' + set.size + ' credentials this one reply carried, ' +
               'each with its own identifier, expiry and button — and a link ' +
               'on to where each of them came from. The set id is this ' +
               'service\'s own handle on the reply: it is in no token, no ' +
               'client ever sees it, and it is not a claim.') + '">set ' +
      // NOT kit.esc()'d: kit.shortened() returns MARKUP — a <code> carrying the
      // whole
      // value in its title, so a truncated identifier can still be read — which
      // is exactly what identifierCell() beside it does with the same call.
      // Escaping it prints the tag instead of the value.
      kit.shortened(set.setId, 10) + '</a>';
  }

  // THE STATE OF A SET, WHICH IS OFTEN NOT ONE STATE. An access token expires
  // in fifteen minutes and the refresh token beside it in a day, so within an
  // hour most sets on this page are neither valid nor expired — and reporting
  // either would be this column choosing which member matters. `mixed` says so
  // and the tooltip counts them, which is the same refusal-to-average the
  // sessions page's expiry column makes.
  /**
   * Draws the state cell of an issued set.
   *
   * A set whose members disagree reads `mixed`, with the counts per state
   * in its tooltip.
   *
   * @param set - a set from stats.issuedSets()
   * @returns a <td> as HTML
   */
  static setStateCell(set) {
    if (set.state !== 'mixed') {
      return '<td class="' + TokensPage.stateClass(set.state) + '">' +
             kit.esc(set.state) +
             '</td>';
    }
    const parts = Object.keys(set.states).map(function (state) {
      return set.states[state] + ' ' + state;
    });
    return '<td class="state-none" title="' +
      kit.esc('The members of this set are not all in the same state: ' +
               parts.join(', ') + '. That is the ordinary case rather than a ' +
               'fault — an access token and the refresh token issued with it ' +
               'have very different lifetimes — so this column reports the ' +
               'disagreement instead of picking one. The set page has each ' +
               'member and its own state. Filtering by a state finds a set ' +
               'when ANY member holds it.') +
      '">mixed</td>';
  }

  /**
   * Draws the tokens table's Subject cell: a JWT's sub, else its subject.
   *
   * @param record - an issued-credential row from admin_stats
   * @returns the shortened subject as HTML
   */
  static subjectCell(record) {
    if (record.family === 'token') {
      return kit.shortened(record.sub, 30);
    }
    return kit.shortened(record.subject, 30);
  }

  // A JWT has two names for one person — the `username` that was typed at the
  // login screen and the `sub` derived from it — and seeing both is how you
  // tell those two apart. A SAML NameID and a Kerberos client principal are ONE
  // name each, so they fill the Subject column and leave this one empty rather
  // than being printed twice to avoid an empty cell.
  /**
   * Draws the tokens table's User cell for one issued record.
   *
   * Only a JWT carries a username beside its sub; the other families get a
   * dash with a tooltip saying why.
   *
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static userCell(record) {
    if (record.family === 'token') {
      return kit.esc(record.username || '—');
    }
    return '<span class="state-none" title="' +
      kit.esc('A SAML assertion names a Subject and a Kerberos ticket names ' +
               'a client principal. Neither carries a second, human-readable ' +
               'name beside it the way a JWT carries username beside sub, so ' +
               'the one name it has is in the Subject column.') +
      '">—</span>';
  }

  // The button, or why there is not one. Two different reasons, and they are
  // not interchangeable: a signed UserInfo response has no jti to act on, and a
  // SAML assertion has an identifier and still cannot be revoked because
  // nothing out there would ask this service about it.
  //
  // **IT DRAWS A BUTTON FOR AN ASSERTION AND A TICKET SINCE 2026-09-05, AND THE
  // PARAGRAPH ABOVE USED TO SAY THAT WAS IMPOSSIBLE.** What it said was true
  // and is still true — nothing consults this service when one of those is
  // presented, so no mark here stops one working — and it was an answer to a
  // question this column was not asking. **What this service KNOWS and what a
  // relying party will HONOUR are two different claims**, and the old cell let
  // the second erase the first: an identity provider that has signed somebody
  // out has a position on every credential it issued them, and being unable to
  // enforce it is not a reason to be unable to state it.
  //
  // So `revocable` says whether there is a button and `revocationReach` says
  // what pressing it changes, and **the second is what the tooltip is built
  // from** — a `record-only` button that read like a `protocol` one would be
  // exactly the lie the old cell was avoiding.
  /**
   * Draws the Revoke or Restore form for one issued credential.
   *
   * A record-only credential (an assertion, a ticket, an SVID) is marked
   * in this service's own record and nothing else; a record with no jti
   * gets a dash instead of a form.
   *
   * @param record - an issued-credential row from admin_stats
   * @param backRow - the list state to return to, posted as `back`
   * @returns the form, or the dash, as HTML
   */
  static actionCell(record, backRow) {
    if (!record.revocable) {
      return '<span class="state-none" title="' +
        kit.esc('This one carries no jti to act on — a signed UserInfo ' +
                 'response has none, and the WS-Trust JWT is signed directly ' +
                 'rather than through signJwt(). There is nothing to name in ' +
                 'a revocation.') + '">—</span>';
    }
    const recordOnly = record.revocationReach === 'record-only';
    const target = recordOnly
      ? '<input type="hidden" name="artifact" value="' +
        kit.esc(record.key || '') +
        '">'
      : '<input type="hidden" name="target" value="' + kit.esc(record.jti) +
        '">';
    const verb = record.revoked ? 'restore' : 'revoke';
    const action = recordOnly ? verb + '-artifact' : verb;
    const title = recordOnly
      ? (record.revoked
          ? 'Take this service\'s disavowal back. NON-SPEC, like every ' +
            'restore here.'
          : 'Mark it revoked IN THIS SERVICE\'S OWN RECORD, which is the ' +
            'whole of what this can do and is worth doing. THE HOLDER WILL ' +
            'NOT BE TOLD BY THIS BUTTON: a relying party validates a SAML ' +
            'assertion\'s signature and its Conditions and asks nobody, a ' +
            'Kerberos service decrypts a ticket with a key it already has, ' +
            'and an X509-SVID chains to a bundle — so this credential goes ' +
            'on working out there until it expires. What the mark buys is ' +
            'that a global logout can say what it disowned, that CAEP can ' +
            'transmit it to a receiver that subscribed, and that SAML Single ' +
            'Logout can carry it for an assertion that came from a browser ' +
            'profile. A WS-Trust assertion has neither channel, and the mark ' +
            'is all there is.')
      : (record.revoked
          ? 'Un-revoke it. NON-SPEC — no real authorization server can undo ' +
            'a revocation.'
          : 'Revoke it. Introspection immediately reports it inactive, ' +
            'UserInfo refuses it with invalid_token, and the refresh grant ' +
            'fails with invalid_grant.');
    return '<form method="post" action="/admin/tokens" class="inline">' +
      '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
      target +
      '<input type="hidden" name="back" value="' + kit.esc(backRow) + '">' +
      '<button class="' + (record.revoked ? 'secondary' : 'danger') +
      '" title="' + kit.esc(title) + '">' +
      (record.revoked ? 'Restore' : 'Revoke') +
      (recordOnly ? ' (record only)' : '') + '</button></form>';
  }

  // The handle the row can be quoted by — and for one family there is none,
  // which is worth saying rather than leaving as a bare dash beside two columns
  // full of them. THE IDENTIFIER, AND THE WAY TO WHERE THE CREDENTIAL CAME
  // FROM.
  //
  // The cell is a link since 2026-08-26 and the id is the only thing it could
  // be keyed on — /admin/tokens/credential walks the delegation register by
  // exactly this string, which is what both registers hold about the same
  // object. A row with NO identifier therefore cannot have a link, and that is
  // the same sentence the cell already had to make: a Kerberos ticket has
  // nothing to quote, so it has nothing to look up, and the tooltip says why
  // rather than offering a link that could only ever answer "nothing is known".
  //
  // `listView` is the tokens page as the reader left it, carried into the query
  // so the drill-down's trail comes back to the same filter and the same page.
  /**
   * Draws a credential's identifier as a link to its lineage page.
   *
   * A Kerberos ticket, or a record with no identifier, gets a dash with a
   * tooltip instead of a link.
   *
   * @param record - an issued-credential row from admin_stats
   * @param listView - the tokens page's list state, carried into the link
   * @returns the cell's content as HTML
   */
  static identifierCell(record, listView) {
    if (record.family === 'ticket') {
      return '<span class="state-none" title="' +
        kit.esc('A Kerberos ticket carries no identifier anybody can quote: ' +
                 'no jti, no ID. It is named by its client, its service and ' +
                 'when it was issued — the columns to the left — and the KDC ' +
                 'keeps no handle on it either, because the KDC is stateless ' +
                 'and the ticket is the state. With no identifier there is ' +
                 'nothing to look a lineage up BY either, which is why this ' +
                 'row has no link where the others do.') + '">—</span>';
    }
    if (!record.identifier) {
      return '<span class="state-none" title="' +
        kit.esc('This one carries no identifier — the signed UserInfo ' +
                 'response has no jti, and the WS-Trust JWT is signed ' +
                 'directly rather than through signJwt(). Nothing can be ' +
                 'looked up by a name that does not exist.') + '">—</span>';
    }
    return '<a href="' +
      kit.esc('/admin/tokens/credential' +
               kit.queryWith(listView || {}, { id: record.identifier })) +
      '" title="' +
      kit.esc('Where this credential came from: who it was issued to, in ' +
               'whose name, to reach what — and, if it came out of a token ' +
               'exchange, the credential handed in to get it and every ' +
               'generation behind that, back to the issuance the whole line ' +
               'rests on.') + '">' +
      kit.shortened(record.identifier, 12) + '</a>';
  }

  /**
   * Returns the CSS class for a certificate's state.
   *
   * @param state - `valid`, `expired`, `not yet valid`, `revoked` or other
   * @returns the class name
   */
  static stateClass(state) {
    if (state === 'valid') return 'state-valid';
    if (state === 'expired' ||
        state === 'not yet valid') return 'state-expired';
    if (state === 'revoked') return 'state-revoked';
    return 'state-none';
  }
}

export = TokensPage;
