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
//
// A function of the page's translator since #539: the legend is words, one
// message per cell, so the table's markup stays here.
const columnLegend = function (t): string {
  const two = '<td colspan="2">';
  return '<table><tr><th>' + t.html('consoleTokens.legendThColumn') +
    '</th><th>' + t.html('consoleTokens.legendThJwt') + '</th><th>' +
    t.html('consoleTokens.legendThSaml') + '</th><th>' +
    t.html('consoleTokens.legendThTicket') + '</th></tr><tr><td>' +
    t.html('consoleTokens.legendContents') + '</td><td>' +
    t.html('consoleTokens.legendContentsJwt') + '</td>' + two +
    t.html('consoleTokens.legendContentsOther') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendState') + '</td><td>' +
    t.html('consoleTokens.legendStateJwt') + '</td>' + two +
    t.html('consoleTokens.legendStateOther') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendExpires') + '</td><td>' +
    t.html('consoleTokens.legendExpiresJwt') + '</td>' + two +
    t.html('consoleTokens.legendExpiresOther') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendUser') + '</td><td>' +
    t.html('consoleTokens.legendUserJwt') + '</td>' + two +
    t.html('consoleTokens.legendUserOther') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendSubject') + '</td><td><code>sub</code>' +
    '</td><td>' + t.html('consoleTokens.legendSubjectSaml') + '</td><td>' +
    t.html('consoleTokens.legendSubjectTicket') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendParty') + '</td><td>' +
    t.html('consoleTokens.legendPartyJwt') + '</td><td>' +
    t.html('consoleTokens.legendPartySaml') + '</td><td>' +
    t.html('consoleTokens.legendPartyTicket') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendDetail') + '</td><td>' +
    t.html('consoleTokens.legendDetailJwt') + '</td><td>' +
    t.html('consoleTokens.legendDetailSaml') + '</td><td>' +
    t.html('consoleTokens.legendDetailTicket') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendPresented') + '</td><td>' +
    t.html('consoleTokens.legendPresentedJwt') + '</td><td>' +
    t.html('consoleTokens.legendPresentedSaml') + '</td><td>' +
    t.html('consoleTokens.legendPresentedTicket') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendJti') + '</td><td>' +
    t.html('consoleTokens.legendJtiJwt') + '</td><td>' +
    t.html('consoleTokens.legendJtiSaml') + '</td><td>' +
    t.html('consoleTokens.legendJtiTicket') + '</td></tr><tr><td>' +
    t.html('consoleTokens.legendButton') + '</td><td>' +
    t.html('consoleTokens.legendButtonJwt') + '</td>' + two +
    t.html('consoleTokens.legendButtonOther') + '</td></tr></table>';
};

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
    // The page's words are its translator's (#539 phase 6); a kind, a
    // family's label and a credential's own state come from the view and
    // are drawn as they come. A link carries an href, which a message may
    // not, so a sentence around one is split with the anchor in the code.
    const t = ctx.t;
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
      return TokensPage.issuedSetRow(t, set, backRow, listView);
    }).join('');

    const familyOptions = ['<option value=""' +
        (wantedFamily ? '' : ' selected') + '>' +
        t.html('consoleTokens.anyFamily') + '</option>']
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
        '>' + t.html('consoleTokens.anyKind') + '</option>' +
      json.families.map(function (entry) {
        return '<optgroup label="' + kit.esc(entry.label) + '">' +
               entry.kinds.map(function (k) {
          return '<option value="' + kit.esc(k) + '"' +
                 (k === wantedKind ? ' ' +
              'selected' : '') + '>' +
                 kit.esc(k) + '</option>';
        }).join('') + '</optgroup>';
      }).join('');
    // The value is the filter's own word and stays; what the option SAYS is
    // the page's, one message per state.
    const stateLabels = {
      '': t.text('consoleTokens.anyState'),
      'valid': t.text('consoleTokens.stateValid'),
      'expired': t.text('consoleTokens.stateExpired'),
      'revoked': t.text('consoleTokens.stateRevoked'),
      'not yet valid': t.text('consoleTokens.stateNotYetValid'),
      'no expiry stated': t.text('consoleTokens.stateNoExpiry')
    };
    const stateOptions = ['', 'valid', 'expired', 'revoked', 'not yet valid',
                          'no ' +
        'expiry stated']
      .map(function (s) {
        return '<option value="' + kit.esc(s) + '"' +
               (s === wantedState ? ' selected' : '') + '>' +
               kit.esc(stateLabels[s]) + '</option>';
      }).join('');
    const perOptions = kit.perPageOptions(paging.perPage);

    const inner = kit.note(t.html('consoleTokens.leadEverything')) +
      kit.note(t.html('consoleTokens.leadOneRow')) +
      kit.note(t.html('consoleTokens.leadRefreshing')) +
      kit.note(t.html('consoleTokens.leadOnlyJwts')) +
      kit.note(t.html('consoleTokens.leadAssertionButton')) +

      '<h2>' + t.html('consoleTokens.hInvalidate') + '</h2>' +
      '<form method="post" action="/admin/tokens">' +
        '<input type="hidden" name="action" value="revoke">' +
        '<input type="hidden" name="back" value="' + kit.esc(backFilter) +
        '"><div class="formrow"><label for="target">' +
        t.html('consoleTokens.labelTarget') +
        '</label><input type="text" id="target" name="target" ' +
        'size="60" placeholder="' +
        kit.esc(t.text('consoleTokens.placeholderTarget')) + '"><button ' +
        'class="danger">' + t.html('consoleTokens.revoke') +
        '</button></div></form>' +
      kit.note(t.html('consoleTokens.pasting')) +
      '<div class="formrow">' +
        ['access_token', 'id_token', 'refresh_token'].map(function (kind) {
          return '<form method="post" action="/admin/tokens" ' +
            'class="inline"><input type="hidden" name="action" ' +
            'value="revoke-kind"><input type="hidden" name="kind" value="' +
            kit.esc(kind) + '">' +
            '<input type="hidden" name="back" value="' +
            kit.esc(backFilter) + '">' +
            '<button class="danger">' +
            t.html('consoleTokens.revokeEvery', { kind: kind }) +
            '</button></form>';
        }).join(' ') +
        '<form method="post" action="/admin/tokens" class="inline">' +
        '<input type="hidden" name="action" value="revoke-all">' +
        '<input type="hidden" name="back" value="' + kit.esc(backFilter) +
        '"><button class="danger">' +
        t.html('consoleTokens.revokeEverything') + '</button></form>' +
      '</div>' +
      '<form method="post" action="/admin/tokens">' +
        '<input type="hidden" name="action" value="revoke-subject">' +
        '<input type="hidden" name="back" value="' + kit.esc(backFilter) +
        '"><div class="formrow"><label for="subject">' +
        t.html('consoleTokens.labelSubject') +
        '</label><input type="text" id="subject" ' +
        'name="subject" size="40" placeholder="' +
        kit.esc(t.text('consoleTokens.placeholderSubject')) + '"><button ' +
        'class="danger">' + t.html('consoleTokens.revoke') +
        '</button></div></form><h2>' + t.html('consoleTokens.hIssued') +
        '</h2>' +
      // No `page` input in this form, and that is the point: changing the
      // filter or the page size sends the reader back to page 1. Carrying the
      // old page number over would land somebody on page 6 of a two-page
      // result, and the clamp in pagingOf() would then quietly move them
      // again.
      '<form method="get" action="/admin/tokens"><div class="formrow">' +
        '<label for="family">' + t.html('consoleTokens.labelFamily') +
        '</label><select id="family" ' +
        'name="family">' +
      familyOptions +
        '</select>' +
        '<label for="kind">' + t.html('consoleTokens.labelKind') +
        '</label><select id="kind" name="kind">' +
      kindOptions + '</select><label ' +
        'for="state">' + t.html('consoleTokens.labelState') +
        '</label><select id="state" ' +
        'name="state">' + stateOptions + '</select><label ' +
        'for="per">' + t.html('consoleTokens.labelPer') +
        '</label><select id="per" ' +
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
        '<button class="secondary">' + t.html('consoleTokens.filter') +
        '</button>' +
        (wantedFamily || wantedKind || wantedState || wantedSession
          ? ' <a href="/admin/tokens">' + t.html('consoleTokens.clear') +
            '</a>' : '') +
      '</div></form>' +
      (wantedSession
        ? kit.note(t.html('consoleTokens.sessionBefore',
                          { session: wantedSession }) +
          '<a href="' + kit.esc('/admin/sessions') +
          '">' + t.html('consoleTokens.sessionsLink') + '</a>' +
          t.html('consoleTokens.sessionAfter') + '<a href="' +
          kit.esc('/admin/tokens' +
            kit.queryWith({ family: wantedFamily, kind: wantedKind,
                        state: wantedState }, {})) +
          '">' + t.html('consoleTokens.everySession') + '</a>.')
        : '') +
      // Family and Kind are ANDed, like any two filters, so a contradictory
      // pair (Kerberos tickets, id_token) matches nothing. Said here rather
      // than prevented, because the alternative is a page that silently
      // ignores one of the two selects the reader can see it obeying.
      kit.note(t.html('consoleTokens.familyAndKind')) +
      // WHAT A FILTER MEANS NOW THAT A ROW IS A SET, said on the page because
      // it is the one behaviour a reader would otherwise call a bug: asking
      // for id_token and being shown an access token too looks like the
      // filter being ignored until somebody explains that the row IS the
      // reply.
      kit.note(t.html('consoleTokens.filterMatchesSet')) +
      nav.head +
      '<table><tr><th>' + t.html('consoleTokens.thContents') + '</th><th>' +
      t.html('consoleTokens.thState') + '</th><th>' +
      t.html('consoleTokens.thUser') + '</th><th>' +
      t.html('consoleTokens.thSubject') + '</th>' +
      '<th>' + t.html('consoleTokens.thParty') + '</th><th>' +
      t.html('consoleTokens.thDetail') + '</th><th>' +
      t.html('consoleTokens.thPresented') + '</th><th>' +
      t.html('consoleTokens.thIssued') + '</th><th>' +
      t.html('consoleTokens.thExpires') + '</th><th>' +
      t.html('consoleTokens.thJtiOrSet') + '</th><th></th></tr>' +
      (rows || '<tr><td colspan="11">' +
        t.html('consoleTokens.nothingMatches') + '</td></tr>') +
      '</table>' +
      nav.foot +
      kit.note(t.html('consoleTokens.matched', {
          sets: json.matched, credentials: json.matchedCredentials }) +
      (paging.pages > 1 ?
       t.html('consoleTokens.setsOnPage', {
         first: paging.firstRow, last: paging.lastRow, page: paging.page,
         pages: paging.pages }) : '') +
      t.html('consoleTokens.heldInTotal', {
        sets: json.heldSets, credentials: json.held }) +
      json.families.map(function (entry) {
        return (heldByFamily[entry.family] || 0) + ' ' +
               kit.esc(entry.label);
      }).join(', ') +
      t.html('consoleTokens.perFamilyBefore') + '<a ' +
      'href="/admin/metrics">' + t.html('consoleTokens.metricsLink') +
      '</a>' + t.html('consoleTokens.perFamilyAfter')) +

      '<h3>' + t.html('consoleTokens.hColumns') + '</h3>' +
      kit.note(t.html('consoleTokens.columnsLead')) +
      columnLegend(t) +
      kit.note(t.html('consoleTokens.oid4vciBefore') + '<a ' +
      'href="/admin/metrics">' + t.html('consoleTokens.metricsLink') +
      '</a>' + t.html('consoleTokens.oid4vciAfter')) +

      kit.note(t.html('consoleTokens.pagingJson', { max: kit.MAX_ROWS }));

    return inner;
  }

  /**
   * Draws one row of the tokens table for an issued set.
   *
   * Most cells are drawn from the set's first member.
   *
   * @param t - the page's translator (#539)
   * @param set - a set from stats.issuedSets()
   * @param backRow - the list state its form posts as `back`
   * @param listView - the list state carried into its identifier link
   * @returns a <tr> as HTML
   */
  static issuedSetRow(t, set, backRow, listView) {
    const first = set.members[0];
    return '<tr><td>' + TokensPage.contentsCell(t, set) + '</td>' +
      TokensPage.setStateCell(t, set) +
      '<td>' + TokensPage.userCell(t, first) + '</td>' +
      '<td>' + TokensPage.subjectCell(first) + '</td>' +
      '<td>' + TokensPage.partyCell(t, first) + '</td>' +
      '<td>' + TokensPage.detailCell(t, first) + '</td>' +
      '<td>' + TokensPage.presentedCell(t, first) + '</td>' +
      '<td>' + kit.esc(kit.whenText(set.issuedAt)) + '</td>' +
      '<td>' + TokensPage.setExpiryCell(t, set) + '</td>' +
      '<td>' + TokensPage.setIdentifierCell(t, set, listView) + '</td>' +
      '<td>' + TokensPage.setActionCell(t, set, backRow) + '</td></tr>';
  }

  // WHAT THE SET CONTAINS, which is the column that used to be Kind. A set of
  // one prints exactly what that column printed, so three families out of four
  // are untouched; a group prints its kinds in the order they were issued,
  // which for a code redemption is access token, refresh token, ID Token.
  /**
   * Draws what an issued set contains, in the order it was issued.
   *
   * @param t - the page's translator (#539)
   * @param set - a set from stats.issuedSets()
   * @returns the set's kinds, and its size when grouped, as HTML
   */
  static contentsCell(t, set) {
    if (!set.grouped) {
      return kit.esc(set.kinds[0] || '—');
    }
    return '<strong title="' +
      kit.esc(t.text('consoleTokens.contentsTitle', { n: set.size }) +
               (set.grant ? t.text('consoleTokens.contentsGrant',
                                   { grant: set.grant }) : '') +
               t.text('consoleTokens.contentsTitleEnd')) + '">' +
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
   * @param t - the page's translator (#539)
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static detailCell(t, record) {
    if (record.family === 'assertion') {
      if (record.signed === false) {
        return '<span class="state-revoked" title="' +
          kit.esc(t.text('consoleTokens.unsignedTitle')) +
          '">' + t.html('consoleTokens.unsigned') + '</span>';
      }
      return '<span title="' +
        kit.esc(t.text('consoleTokens.signedTitle')) + '">' +
        t.html('consoleTokens.signed') + '</span>';
    }
    if (record.family === 'ticket') {
      return '<code title="' +
        kit.esc(t.text('consoleTokens.etypeTitle')) +
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
   * @param t - the page's translator (#539)
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static partyCell(t, record) {
    if (record.family === 'assertion') {
      if (record.audience) {
        return kit.shortened(record.audience, 30);
      }
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleTokens.unrestrictedTitle')) +
        '">' + t.html('consoleTokens.unrestricted') + '</span>';
    }
    if (record.family === 'ticket') {
      // The realm recorded with a ticket is the realm that ANSWERED, which
      // under a cross-realm referral is not the service's own realm. So it is
      // stated as the issuer in the tooltip rather than appended to the service
      // name as though it were part of the principal — which is what it would
      // look like, since a Kerberos principal is written service/host@REALM.
      return '<code title="' + kit.esc(String(record.service || '') +
        (record.realm ? t.text('consoleTokens.issuedByKdc',
                               { realm: record.realm }) : '')) +
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
   * @param t - the page's translator (#539)
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static presentedCell(t, record) {
    if (record.family === 'assertion') {
      return '<span title="' +
        kit.esc(t.text('consoleTokens.bearerTitle')) + '">bearer</span>';
    }
    if (record.family === 'ticket') {
      if (record.kind === 'Kerberos TGT') {
        return '<span title="' +
          kit.esc(t.text('consoleTokens.tgsReqTitle')) +
          '">TGS-REQ</span>';
      }
      return '<span title="' +
        kit.esc(t.text('consoleTokens.apReqTitle')) + '">AP-REQ</span>';
    }
    if (record.jkt) {
      return '<span title="' +
        kit.esc(t.text('consoleTokens.dpopTitle')) + '">DPoP</span>';
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
   * @param t - the page's translator (#539)
   * @param set - a set from stats.issuedSets()
   * @param backRow - the list state to return to, posted as `back`
   * @returns the form, or the dash, as HTML
   */
  static setActionCell(t, set, backRow) {
    if (!set.grouped) {
      return TokensPage.actionCell(t, set.members[0], backRow);
    }
    if (!set.revocableCount) {
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleTokens.setNothingRevocable')) +
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
        ? t.text('consoleTokens.restoreSetTitle')
        : t.text('consoleTokens.revokeSetTitle',
                 { n: set.revocableCount })) + '">' +
      (allRevoked ? t.html('consoleTokens.restoreSet')
                  : t.html('consoleTokens.revokeSet')) + '</button></form>';
  }

  // WHEN THE SET COMES APART, and when it is finished. Two instants because the
  // members have two, and the earlier one first because it is the one somebody
  // debugging a refused call has arrived to find: the access token died at
  // 12:19 and the refresh token that could mint another is good until tomorrow.
  /**
   * Draws when a set's first member expires, and its last if different.
   *
   * @param t - the page's translator (#539)
   * @param set - a set from stats.issuedSets()
   * @returns the expiry text or range as HTML, or a dash
   */
  static setExpiryCell(t, set) {
    if (!set.expiresAtMs) {
      return '—';
    }
    if (!set.lastExpiresAtMs || set.lastExpiresAtMs === set.expiresAtMs) {
      return kit.esc(kit.whenText(set.expiresAtMs));
    }
    return '<span title="' +
      kit.esc(t.text('consoleTokens.expiryRangeTitle', {
        first: kit.whenText(set.expiresAtMs),
        last: kit.whenText(set.lastExpiresAtMs) })) +
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
   * @param t - the page's translator (#539)
   * @param set - a set from stats.issuedSets()
   * @param listView - the tokens page's list state, carried into the link
   * @returns the cell's content as HTML
   */
  static setIdentifierCell(t, set, listView) {
    if (!set.grouped) {
      return TokensPage.identifierCell(t, set.members[0], listView);
    }
    return '<a href="' +
      kit.esc('/admin/tokens/set' +
               kit.queryWith(listView || {}, { id: set.setKey })) +
      '" title="' +
      kit.esc(t.text('consoleTokens.setLinkTitle', { n: set.size })) +
      '">' + t.html('consoleTokens.setPrefix') +
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
   * @param t - the page's translator (#539)
   * @param set - a set from stats.issuedSets()
   * @returns a <td> as HTML
   */
  static setStateCell(t, set) {
    if (set.state !== 'mixed') {
      return '<td class="' + TokensPage.stateClass(set.state) + '">' +
             kit.esc(set.state) +
             '</td>';
    }
    const parts = Object.keys(set.states).map(function (state) {
      return set.states[state] + ' ' + state;
    });
    return '<td class="state-none" title="' +
      kit.esc(t.text('consoleTokens.mixedTitle',
                     { parts: parts.join(', ') })) +
      '">' + t.html('consoleTokens.mixed') + '</td>';
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
   * @param t - the page's translator (#539)
   * @param record - an issued-credential row from admin_stats
   * @returns the cell's content as HTML
   */
  static userCell(t, record) {
    if (record.family === 'token') {
      return kit.esc(record.username || '—');
    }
    return '<span class="state-none" title="' +
      kit.esc(t.text('consoleTokens.userNoneTitle')) +
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
   * @param t - the page's translator (#539)
   * @param record - an issued-credential row from admin_stats
   * @param backRow - the list state to return to, posted as `back`
   * @returns the form, or the dash, as HTML
   */
  static actionCell(t, record, backRow) {
    if (!record.revocable) {
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleTokens.noJtiTitle')) + '">—</span>';
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
          ? t.text('consoleTokens.restoreArtifactTitle')
          : t.text('consoleTokens.revokeArtifactTitle'))
      : (record.revoked
          ? t.text('consoleTokens.restoreTokenTitle')
          : t.text('consoleTokens.revokeTokenTitle'));
    return '<form method="post" action="/admin/tokens" class="inline">' +
      '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
      target +
      '<input type="hidden" name="back" value="' + kit.esc(backRow) + '">' +
      '<button class="' + (record.revoked ? 'secondary' : 'danger') +
      '" title="' + kit.esc(title) + '">' +
      (record.revoked ? t.html('consoleTokens.restore')
                      : t.html('consoleTokens.revoke')) +
      (recordOnly ? t.html('consoleTokens.recordOnly') : '') +
      '</button></form>';
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
   * @param t - the page's translator (#539)
   * @param record - an issued-credential row from admin_stats
   * @param listView - the tokens page's list state, carried into the link
   * @returns the cell's content as HTML
   */
  static identifierCell(t, record, listView) {
    if (record.family === 'ticket') {
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleTokens.ticketNoIdTitle')) + '">—</span>';
    }
    if (!record.identifier) {
      return '<span class="state-none" title="' +
        kit.esc(t.text('consoleTokens.noIdTitle')) + '">—</span>';
    }
    return '<a href="' +
      kit.esc('/admin/tokens/credential' +
               kit.queryWith(listView || {}, { id: record.identifier })) +
      '" title="' +
      kit.esc(t.text('consoleTokens.lineageTitle')) + '">' +
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

  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static setBody(ctx, json) {
    // The page's words are its translator's (#539 phase 6); the refusal the
    // view carries (`why`) and a credential's own values are drawn as they
    // come.
    const t = ctx.t;
    const set = json.set;
    const listView = kit.listViewOf('/admin/tokens', ctx.query);
    const upHref = '/admin/tokens' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">' + t.html('consoleTokens.backToTable') + '</a>');

    if (!set) {
      const inner = back +
        kit.note('<strong>' + kit.esc(json.why) + '</strong> ' +
        t.html('consoleTokens.noSetBefore') + '<a ' +
        'href="' + kit.esc(upHref) + '">' +
        t.html('consoleTokens.noSetLink') + '</a>' +
        t.html('consoleTokens.noSetAfter'));
      return inner;
    }

    // Where a member's own button sends the browser: back HERE, with the list
    // view the reader arrived through, so revoking one credential of three
    // does not land them on page 1 of everything. `from=set` is read as an
    // ENUM by backTo() and never as a path — the same rule the users page's
    // buttons follow, and what keeps a `back` field from becoming an open
    // redirect.
    const backRow = kit.queryWith(Object.assign({}, listView,
      { id: set.setKey }),
                              { from: 'set' });
    const memberRows = set.members.map(function (record) {
      return TokensPage.issuedRow(t, record, backRow, listView);
    }).join('');

    // The grant, spelled as the console spells it everywhere else. Empty for
    // anything minted where nothing states how — which cannot happen for a
    // GROUP, since only the two OAuth issuance sites group, but can for a set
    // of one.
    const grantText = set.grant || t.text('consoleTokens.notStated');

    const inner = back +
      kit.note('<strong>' + (set.grouped
        ? t.html('consoleTokens.setGrouped',
                 { n: set.size, grant: grantText })
        : t.html('consoleTokens.setOfOne')) +
      '</strong> ' + t.html('consoleTokens.setLeadBefore') +
      '<a href="' + kit.esc(upHref) + '">' +
      t.html('consoleTokens.setLeadLink') + '</a>' +
      t.html('consoleTokens.setLeadAfter')) +

      '<h2>' + t.html('consoleTokens.hIssuance') + '</h2>' +
      '<table>' +
      '<tr><th>' + t.html('consoleTokens.rowSet') + '</th><td><code>' +
      kit.esc(set.setId || set.setKey) +
      '</code>' +
        (set.setId
          ? ' <span class="state-none">' +
            t.html('consoleTokens.setIdNote') + '</span>'
          : ' <span class="state-none">' +
            t.html('consoleTokens.setKeyNote') + '</span>') +
      '</td></tr><tr><th>' + t.html('consoleTokens.thContents') +
      '</th><td>' +
      kit.esc(set.kinds.join(' ' +
                '+ ')) + '</td></tr><tr><th>' +
      t.html('consoleTokens.thState') + '</th><td>' +
                kit.esc(set.state) +
        (set.state === 'mixed'
          ? ' <span class="state-none">— ' +
            kit.esc(Object.keys(set.states).map(function (state) {
              return set.states[state] + ' ' + state;
            }).join(', ')) +
            t.html('consoleTokens.mixedNote') + '</span>'
          : '') + '</td></tr>' +
      '<tr><th>' + t.html('consoleTokens.rowGrant') + '</th><td>' +
      kit.esc(grantText) + '</td></tr>' +
      '<tr><th>' + t.html('consoleTokens.thUser') + '</th><td>' +
      TokensPage.userCell(t, set.members[0]) +
        '</td></tr>' +
      '<tr><th>' + t.html('consoleTokens.thSubject') + '</th><td>' +
      TokensPage.subjectCell(set.members[0]) +
      '</td></tr><tr><th>' + t.html('consoleTokens.rowClient') +
      '</th><td>' +
        TokensPage.partyCell(t, set.members[0]) +
      '</td></tr><tr><th>' + t.html('consoleTokens.rowSession') +
      '</th><td>' + (set.sessionId
        ? '<a href="' + kit.esc('/admin/tokens' +
            kit.queryWith({ session: set.sessionId }, {})) + '"><code>' +
          kit.esc(set.sessionId) + '</code></a>' +
          (set.sessionAuthenticated ? ''
            : ' <span class="state-revoked">' +
              t.html('consoleTokens.sessionUnauthenticated') + '</span>')
        : '<span class="state-none">' +
          t.html('consoleTokens.noSession') + '</span>') +
          '</td></tr><tr><th>' + t.html('consoleTokens.thIssued') +
          '</th><td>' +
      kit.esc(kit.whenText(set.issuedAt)) +
      '</td></tr><tr><th>' + t.html('consoleTokens.thExpires') +
      '</th><td>' +
      TokensPage.setExpiryCell(t, set) + '</td></tr></table>' +

      (set.grouped && set.revocableCount
        ? '<h2>' + t.html('consoleTokens.hInvalidateSet') + '</h2>' +
          kit.note(t.html('consoleTokens.invalidateSetLead') +
          (set.size > set.revocableCount
            ? t.html('consoleTokens.onlySomeRevocable',
                     { n: set.revocableCount, size: set.size })
            : t.html('consoleTokens.allRevocable', { size: set.size }))) +
          '<div class="formrow">' +
          '<form method="post" action="/admin/tokens" class="inline">' +
            '<input type="hidden" name="action" value="revoke-set">' +
            '<input type="hidden" name="set" value="' + kit.esc(set.setKey) +
            '"><input type="hidden" name="back" value="' + kit.esc(backRow) +
            '"><button class="danger">' +
            t.html('consoleTokens.revokeThisSet') + '</button></form> ' +
          '<form method="post" action="/admin/tokens" class="inline">' +
            '<input type="hidden" name="action" value="restore-set">' +
            '<input type="hidden" name="set" value="' + kit.esc(set.setKey) +
            '"><input type="hidden" name="back" value="' + kit.esc(backRow) +
            '"><button class="secondary">' +
            t.html('consoleTokens.restoreThisSet') + '</button></form>' +
          '</div>' +
          kit.note(t.html('consoleTokens.restoreNonSpec'))
        : '') +

      '<h2>' + (set.grouped
        ? t.html('consoleTokens.hCredentials', { n: set.size })
        : t.html('consoleTokens.hCredential')) +
      '</h2><table><tr><th>' + t.html('consoleTokens.labelKind') +
      '</th><th>' + t.html('consoleTokens.thState') + '</th><th>' +
      t.html('consoleTokens.thUser') + '</th><th>' +
      t.html('consoleTokens.thSubject') + '</th>' +
      '<th>' + t.html('consoleTokens.thParty') + '</th><th>' +
      t.html('consoleTokens.thDetail') + '</th><th>' +
      t.html('consoleTokens.thPresented') + '</th><th>' +
      t.html('consoleTokens.thIssued') + '</th><th>' +
      t.html('consoleTokens.thExpires') + '</th><th>' +
      t.html('consoleTokens.thJtiOrId') + '</th><th></th></tr>' +
      memberRows + '</table>' +
      kit.note(t.html('consoleTokens.membersNote')) +
      (set.grouped
        ? kit.note(t.html('consoleTokens.detailDisagrees'))
        : '');

    return inner;
  }

  /**
   * Draws one row of the tokens table for a single credential.
   *
   * @param t - the page's translator (#539)
   * @param record - an issued-credential row from admin_stats
   * @param backRow - the list state its form posts as `back`
   * @param listView - the list state carried into its identifier link
   * @returns a <tr> as HTML
   */
  static issuedRow(t, record, backRow, listView) {
    return '<tr><td>' + kit.esc(record.kind) + '</td>' +
      '<td class="' + TokensPage.stateClass(record.state) + '">' +
      kit.esc(record.state) +
      '</td><td>' + TokensPage.userCell(t, record) + '</td><td>' +
      TokensPage.subjectCell(record) +
      '</td><td>' + TokensPage.partyCell(t, record) + '</td><td>' +
      TokensPage.detailCell(t, record) +
      '</td><td>' + TokensPage.presentedCell(t, record) + '</td><td>' +
      kit.esc(kit.whenText(record.issuedAt)) + '</td><td>' +
      kit.esc(record.expiresAtMs ? kit.whenText(record.expiresAtMs) : '—') +
      '</td><td>' +
      TokensPage.identifierCell(t, record, listView) + '</td><td>' +
      TokensPage.actionCell(t, record, backRow) + '</td></tr>';
  }
}

export = TokensPage;
