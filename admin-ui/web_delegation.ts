// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_delegation.ts
//
// ---------------------------------------------------------------------------
// THE DELEGATION PAGES, DRAWN FROM THEIR ANSWERS ALONE (#446, 2026-10-05).
//
// The pieces every delegation page shares: a party, a row of the register, a
// box and a line of the picture, the two choosers, the policy and permission
// sections. They were the console's methods and read the application
// registry and the delegation vocabulary while they drew; here they read
// the answer instead.
//
// **`facts` IS WHAT `known` WAS, AND MORE.** Every page handed `known` (the
// user keys the console has seen) down to the cell that links a person.
// Here that argument is `facts`, which the answer carries as
// `AdminViews.delegationFacts()` builds it for the names on the page:
// `users` (the keys seen, as `known` was) and `apps` (each identifier the
// application registry holds, with its name), so a cell that asked
// `applications.get()` asks the answer.
//
// **THE DRAWINGS ARE LAID OUT ON THE SERVER**, as they always were: dagre
// runs there, the answer carries `svg`, and these draw the links under it.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import GroupsPage = require('./web_groups');
import TokensPage = require('./web_tokens');
import SettingsForms = require('./web_settings');

type Json = any;

// `user_graph.ts`'s FLOW_NOT_STATED sentence, copied: the browser cannot
// require that module, and a token that states no grant is drawn with it.
// Since #539 it is the message `consoleDelegation.flowNotStated`, which
// userFlowCell() draws through the page's translator.

/**
 * Draws the delegation pages and the pieces they share from their answers.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class DelegationPage {

  // The drawing and the two links under it. `path` and `params` are the
  // route's own, because the document-on-its-own link has to come back to the
  // page it was offered on carrying whatever selected these acts — a `chain=`
  // or an `application=`, not the map's filters. The drawing is the answer's
  // `svg`, laid out on the server with its links in it; the document on its
  // own is the page's `?format=svg`, which draws it again with none (see
  // `AdminConsole.sendDelegationSvg()`).
  /**
   * Draws a delegation picture from its answer, with a note under it
   * linking the standalone SVG and the graph as JSON.
   *
   * @param json - the answer: `svg` and `drawing` (`width`, `height`,
   *   `failed`)
   * @param path - the page's own path, for the two links
   * @param params - the page's query, carried into the two links
   * @returns the drawing and its note as HTML
   */
  static drawing(t, json: Json, path: string, params: Json): string {
    const drawn = json.drawing || {};
    return '<div class="diagram">' + json.svg + '</div>' +
      kit.note(drawn.width + '&times;' + drawn.height + ' — ' +
      '<a href="' + kit.esc(path + kit.queryWith(params, { format: 'svg' })) +
      '">' + t.html('consoleDelegation.drawingSvg') + '</a>' +
      t.html('consoleDelegation.drawingSvgNote') +
      '<a href="' + kit.esc(path + kit.queryWith(params, { format: 'json' })) +
      '">' + t.html('consoleDelegation.drawingJson') + '</a>.' +
      (drawn.failed ? ' <span class="state-revoked">The layout failed: ' +
        kit.esc(drawn.failed) + '</span>' : ''));
  }

  // One party of a chain — up to two links, because a party can be a person AND
  // an application and routinely is.
  //
  // `HTTP/frontend.example.com` has an entry under ou=users (it authenticates,
  // so the funnel files it with the people) and an entry under ou=applications
  // (a ticket was issued FOR it, so applications.js recorded it). A cell that
  // showed one of them would send half the readers to the wrong page.
  //
  // Both links follow the three-state rule /admin/groups uses for a member: a
  // name this console knows, a name it could file somebody under and never has,
  // and no name at all. An application NOT in the registry is the ordinary case
  // for an RFC 8693 `audience` and is worth seeing rather than hiding — the
  // registry holds what this service was ASKED ABOUT, and a delegation naming
  // something nobody has otherwise mentioned is exactly the row to notice.
  /**
   * Draws one party of a delegation chain, as up to two links.
   *
   * The party can be a person, an application, or both; a name neither
   * store holds is drawn marked rather than left out.
   *
   * @param party - a party of a delegation row
   * @param facts - the answer's `facts`: `users` (the keys seen here) and
   *   `apps` (the registered applications named on the page)
   * @returns the cell's content as HTML, or a dash
   */
  static delegationPartyCell(t, party, facts) {
    const parts = [];
    if (party.key) {
      parts.push(GroupsPage.usersPageCell(party.key, facts.users, t));
      if (party.presented && party.presented !== party.key) {
        parts.push('<code>' + kit.esc(party.presented) + '</code>');
      }
    } else if (party.presented) {
      parts.push('<code>' + kit.esc(party.presented) + '</code>');
    }
    if (party.application) {
      const registered = !!facts.apps[party.application];
      parts.push(registered
        ? '<a href="' + kit.esc('/admin/applications' +
            kit.queryWith({ application: party.application }, {})) + '" ' +
          'title="' + t.html('consoleDelegation.partyRegisteredTitle') +
          '">' +
          kit.esc(party.application) + '</a>'
        : '<span class="state-none" title="' +
          t.html('consoleDelegation.partyUnregisteredTitle') + '">' +
          kit.esc(party.application) + ' ' +
          t.html('consoleDelegation.partyUnregistered') + '</span>');
    }
    if (!parts.length) {
      return '<span class="state-none" title="' +
        t.html('consoleDelegation.partyNoneTitle') + '">&mdash;</span>';
    }
    return parts.join('<br>');
  }

  // Impersonation is drawn as the LOUDER of the two, which is a judgement worth
  // stating rather than leaving in a colour. It is not "worse" — both are
  // ordinary and both are configured on purpose — but it is the one whose
  // consequence is invisible everywhere else: nothing in the credential records
  // that a middle tier was involved, so this table is the only place it will
  // ever be seen. A delegation carries its own chain and can be read off the
  // token later.
  /**
   * Draws a delegation act's mode: impersonation or delegation.
   *
   * @param mode - `impersonation`, `delegation` or anything else
   * @returns a <span> as HTML, a dash for any other mode
   */
  static modeCell(t, mode) {
    if (mode === 'impersonation') {
      return '<span class="state-expired" title="' +
        t.html('consoleDelegation.modeImpersonationTitle') + '">' +
        t.html('consoleDelegation.modeImpersonation') + '</span>';
    }
    if (mode === 'delegation') {
      return '<span class="state-valid" title="' +
        t.html('consoleDelegation.modeDelegationTitle') + '">' +
        t.html('consoleDelegation.modeDelegation') + '</span>';
    }
    return '<span class="state-none">&mdash;</span>';
  }

  // THE KERBEROS ROWS' MODE IS THE MECHANISM'S (#491). [MS-SFU] 1.3 names
  // S4U2Self protocol transition and S4U2Proxy constrained delegation, and
  // the register records each by that, whatever chain it is part of — so a
  // Kerberos impersonation chain (S4U2Self, then S4U2Proxy hops) has ONE
  // impersonation row and the rest delegation, where an OAuth impersonation
  // chain is impersonation at every hop. The ticket out of S4U2Proxy does
  // carry the chain, in the PAC's S4U_DELEGATION_INFO, which is what makes
  // it a delegation. Said on the row, where the difference is met.
  /**
   * The note under a Kerberos S4U row's mode, or nothing for any other row.
   *
   * @param type - the act's mechanism
   * @returns HTML
   */
  static kerberosModeNote(t, type) {
    if (type === 'krb5-s4u2self') {
      return '<br><span class="state-none">' +
        t.html('consoleDelegation.s4u2selfNote') + '</span>';
    }
    if (type === 'krb5-s4u2proxy-classic' || type === 'krb5-s4u2proxy-rbcd') {
      return '<br><span class="state-none">' +
        t.html('consoleDelegation.s4u2proxyNote') + '</span>';
    }
    return '';
  }

  // What a delegation CONSUMED or PRODUCED, as one cell. `key=value` pairs
  // rather than JSON for the reason the audit log's detail cell gives — the
  // column is narrow and a reader is scanning for one fact — and `?format=json`
  // carries the objects for anything that is not a person.
  //
  //
  // Named for the delegation table since #70: the old file declared a second
  // `credentialCell()` — the person's way in, under the users list — and
  // JavaScript's hoisting gave that later one to both of this table's calls,
  // so the cell drew "unknown" for every delegation instead of what it
  // consumed and produced. The TypeScript conversion (#50) kept that
  // behaviour and surfaced it; the calls now reach this method.
  /**
   * Draws the credentials one direction of a delegation carried.
   *
   * @param list - the consumed or produced credentials
   * @param label - the direction's label, as HTML
   * @returns the list as HTML, or an empty string when there is none
   */
  static delegationCredentialCell(list, label) {
    if (!list || !list.length) {
      // NOTHING rather than a dash, because the two directions share one cell
      // now: a dash under the arrow for a direction that genuinely has no
      // credential reads as a value that failed to load, where an absent line
      // reads as what it is. The empty cell — no credential either way — is the
      // one case that still needs a mark, and it gets one from the caller
      // having drawn neither.
      return '';
    }
    // A DIV rather than a run of spans, because the cell holds BOTH directions
    // now and everything in them is inline: without a block the "out" label
    // continued the last note of the "in" list on the same line, which read as
    // one sentence made of two.
    return '<div><span class="state-none">' + label + '</span><br>' +
      list.map(function (one) {
        return '<code>' + kit.esc(one.kind) + '</code>' +
          // NOT kit.esc()'d and not wrapped: kit.shortened() returns the <code>
          // element with the whole value in its title. Escaping it printed the
          // markup.
          (one.identifier ? ' ' + kit.shortened(one.identifier, 10) : '') +
          (one.note ?
           '<br><span class="state-none">' + kit.esc(one.note) +
           '</span>' : '');
      }).join('<br>') + '</div>';
  }

  /**
   * Draws whether a delegation act was issued or refused.
   *
   * @param row - a delegation row
   * @returns a <span> as HTML
   */
  static delegationOutcomeCell(t, row) {
    if (row.outcome === 'issued') {
      return '<span class="state-valid">' +
        t.html('consoleDelegation.outcomeIssued') + '</span>';
    }
    return '<span class="state-revoked" title="' +
      t.html('consoleDelegation.outcomeRefusedTitle') + '">' +
      t.html('consoleDelegation.outcomeRefused') + '</span>';
  }

  // TEN COLUMNS RATHER THAN TWELVE, and the two that were merged were merged
  // because the table became unreadable rather than merely wide. `.who` breaks
  // a long identifier anywhere (or one DN would widen the whole page), so every
  // extra column costs the ones beside it:
  // `HTTP/frontend.example.com@EXAMPLE.COM` wrapped over five lines at twelve
  // and reads at ten.
  //
  // The protocol went into the mechanism cell because the mechanism id already
  // carries it — every one of them begins `krb5-`, `wstrust-` or `oauth-` — so
  // the column was saying a second time what the cell beside it said first. The
  // two credential columns became one because a row usually has one of each and
  // the arrows say which: what went IN, what came OUT. `options.listView` is
  // what the reader had the table filtered to, carried into the drill-down so
  // that its way back is the page they left rather than the top of an
  // unfiltered list — the rule kit.listViewOf() states. `options.chainLink` is
  // false on the chain page itself, where every row belongs to the chain being
  // drawn and the link would point at the page it is on.
  /**
   * Draws one row of the delegation acts table.
   *
   * @param row - a delegation row from common/delegation.js
   * @param facts - the answer's `facts`: `users` (the keys seen here) and
   *   `apps` (the registered applications named on the page)
   * @param options - `listView` for the chain link, and `chainLink`
   *   (default true), false on the chain page itself
   * @returns a <tr> as HTML
   */
  static delegationRow(t, row, facts, options) {
    const opts = options || {};
    const chainLink = opts.chainLink === undefined ? true : !!opts.chainLink;
    return '<tr>' +
      // THE WAY TO THE PICTURE OF THIS ONE RELATIONSHIP, in the narrowest
      // column on the page rather than in an eleventh of its own. The header
      // above says why this table is ten columns and not twelve: `.who` breaks
      // a long identifier anywhere, so every column costs the ones beside it.
      // `#` is the one cell whose content is four digits and can carry a second
      // line for nothing.
      //
      // It goes to the CHAIN and not to the act, which the link says out loud —
      // an act has no picture of its own, and a reader who clicked expecting
      // one would read the times off a diagram that has them taken out.
      '<td class="num">' + kit.esc(row.seq) +
        (chainLink
          ? '<br><a href="' + kit.esc('/admin/delegation/chain' +
              kit.queryWith(opts.listView || {}, { chain: row.chainKey })) +
            '" title="' + t.html('consoleDelegation.rowChainTitle') + '">' +
            t.html('consoleDelegation.rowChain') + '</a>'
          : '') + '</td>' +
      '<td>' + kit.esc(kit.whenText(row.at)) + '</td>' +
      '<td><code>' + kit.esc(row.type) + '</code><br>' +
        '<span class="state-none">' + kit.esc(row.typeLabel) + '</span><br>' +
        '<span class="state-none">' + kit.esc(row.protocol) +
        (row.spec ? ' &middot; ' + kit.esc(row.spec) : '') + '</span></td>' +
      '<td>' + DelegationPage.modeCell(t, row.mode) +
        DelegationPage.kerberosModeNote(t, row.type) + '</td>' +
      '<td>' + DelegationPage.delegationOutcomeCell(t, row) + '</td>' +
      '<td class="who">' +
        DelegationPage.delegationPartyCell(t, row.initial, facts) + '</td>' +
      '<td class="who">' +
        DelegationPage.delegationPartyCell(t, row.intermediary, facts) +
      '</td><td class="who">' +
        DelegationPage.delegationPartyCell(t, row.target, facts) + '</td>' +
      '<td>' + (row.outcome === 'refused'
                ? kit.esc(row.reason)
                : (row.authorizedBy ? kit.esc(row.authorizedBy)
                                    : '<span ' +
                                      'class="state-none">&mdash;</span>')) +
        (row.note ? '<br><span class="state-none">' + kit.esc(row.note) +
         '</span>' :
         '') +
      '</td><td class="who">' +
        DelegationPage.delegationCredentialCell(row.consumed,
          '&rarr; ' + t.html('consoleDelegation.credentialIn')) +
        DelegationPage.delegationCredentialCell(row.produced,
          '&larr; ' + t.html('consoleDelegation.credentialOut')) +
        '</td>' +
      '</tr>';
  }

  // One node, as a row of the party index under the picture. The party cell is
  // `delegationPartyCell()`'s, so a box that links to one page in the diagram
  // still offers BOTH links here — see the note in delegationNodeLook().
  /**
   * Draws one box of the delegation picture as a row of the party index:
   * label, shape, links, roles, acts and protocols.
   *
   * @param node - a graph node from delegation.graph()
   * @param facts - the answer's `facts`: `users` (the keys seen here) and
   *   `apps` (the registered applications named on the page)
   * @param look - the node's look (label, identifier, shape, dashed)
   * @returns the row as HTML, or '' for the service's own node
   */
  static delegationNodeRow(t, node, facts, look) {
    if (node.kind === 'sts') {
      return '';
    }
    const party = { key: node.key, presented: node.presented,
                    application: node.application, what: node.what };
    const roles = [];
    if (node.roles.initial) roles.push(t.html('consoleDelegation.nodeInitial',
                                              { n: node.roles.initial }));
    if (node.roles.intermediary) roles.push(
      t.html('consoleDelegation.nodeIntermediary',
             { n: node.roles.intermediary }));
    if (node.roles.target) roles.push(t.html('consoleDelegation.nodeTarget',
                                             { n: node.roles.target }));
    return '<tr>' +
      '<td>' + kit.esc(look.label) +
        (look.identifier
          ? '<br><span class="state-none" title="' +
            t.html('consoleDelegation.nodeIdentifierTitle') + '">' +
            kit.esc(look.identifier) + '</span>'
          : '') + '</td>' +
      '<td>' + (look.shape === 'both'
                  ? t.html('consoleDelegation.shapeBoth')
                  : look.shape === 'person'
                    ? t.html('consoleDelegation.shapePerson')
                  : look.shape === 'application'
                    ? t.html('consoleDelegation.shapeApplication')
                    : look.shape) +
        (look.dashed
          ? '<br><span class="state-none" title="' +
            t.html('consoleDelegation.shapeDashedTitle') + '">' +
            t.html('consoleDelegation.shapeDashed') + '</span>'
          : '') + '</td>' +
      '<td class="who">' + DelegationPage.delegationPartyCell(t, party,
                                                               facts) +
      '</td>' +
      '<td>' +
      (roles.join('<br>') || '<span class="state-none">&mdash;</span>') +
        (node.selfTarget
          ? '<br><span class="state-expired" title="' +
            t.html('consoleDelegation.selfTargetTitle') + '">' +
            t.html('consoleDelegation.selfTarget') + '</span>'
          : '') + '</td>' +
      '<td class="num">' + kit.esc(node.acts) + ' — ' +
        '<span class="state-valid">' +
        t.html('consoleDelegation.nIssued', { n: node.issued }) +
        '</span>, ' +
        (node.refused
          ? '<span class="state-revoked">' +
            t.html('consoleDelegation.nRefused', { n: node.refused }) +
            '</span>'
          : '<span class="state-none">' +
            t.html('consoleDelegation.nRefused', { n: 0 }) + '</span>') +
        '</td>' +
      '<td>' + (node.protocols.map(kit.esc.bind(kit)).join('<br>') ||
                '<span class="state-none">&mdash;</span>') + '</td>' +
      '</tr>';
  }

  // One edge, as a row of the relationship index. The columns are the picture
  // read as a sentence — who, to whom, meaning what, over what, how it came out
  // — so that everything the diagram says in colour is also said in words. A
  // picture nobody can read as text is one nobody can quote in a bug report.
  /**
   * Draws one line of the delegation picture as a row of the relationship
   * index, saying in words what the picture says in colour.
   *
   * An unpoliced act collapses to "nothing checks this" with the reason in
   * the tooltip; a refusal prints in full.
   *
   * @param edge - a graph edge from delegation.graph()
   * @param lookOf - function giving a node id's label
   * @returns the row as HTML
   */
  static delegationEdgeRow(t, edge, lookOf) {
    const relation = edge.relation === 'issued'
      ? '<span class="state-none" title="' +
        t.html('consoleDelegation.issuedToAskedTitle') + '">' +
        t.html('consoleDelegation.issuedTo') + '</span>'
      : edge.relation === 'acts-for'
        ? '<strong>' + t.html('consoleDelegation.actsFor') + '</strong>'
        : '<strong>' + t.html('consoleDelegation.reaches') + '</strong>' +
          (edge.subject ? '<br><span class="state-none">' +
           t.html('consoleDelegation.asSubject', { subject: edge.subject }) +
                          '</span>' : '');
    return '<tr>' +
      '<td class="who">' + kit.esc(lookOf(edge.from)) + '</td>' +
      '<td class="who">' + kit.esc(lookOf(edge.to)) + '</td>' +
      '<td>' + relation +
        ((edge.skipped || []).length
          ? '<br><span class="state-expired" title="' +
            t.html('consoleDelegation.jumpsTitleForwarded') + '">' +
            t.html('consoleDelegation.jumps',
                   { skipped: edge.skipped.join(' and ') }) + '</span>'
          : '') + '</td>' +
      '<td>' + (edge.typeLabel
                  ? '<code>' + kit.esc(edge.type) + '</code><br>' +
                    '<span class="state-none">' + kit.esc(edge.typeLabel) +
                    '</span><br><span ' +
                    'class="state-none">' + kit.esc(edge.protocol) +
                    (edge.spec ? ' &middot; ' + kit.esc(edge.spec) : '') +
                    '</span>'
                  : '<span class="state-none">' +
                    kit.esc((edge.protocols || []).join(', ') || '&mdash;') +
                    '</span>') +
      '</td>' +
      '<td>' + DelegationPage.modeCell(t, edge.mode) + '</td>' +
      '<td class="num">' + kit.esc(edge.acts) + ' — ' +
        '<span class="state-valid">' +
        t.html('consoleDelegation.nIssued', { n: edge.issued }) +
        '</span>, ' +
        (edge.refused
          ? '<span class="state-revoked">' +
            t.html('consoleDelegation.nRefused', { n: edge.refused }) +
            '</span>'
          : '<span class="state-none">' +
            t.html('consoleDelegation.nRefused', { n: 0 }) + '</span>') +
        '</td>' +
      '<td class="who">' + (edge.produced.length
        ? edge.produced.map(function (one) {
            return '<code>' + kit.esc(one.kind) + '</code> × ' +
                   kit.esc(one.count) +
              (one.identifiers.length
                ? '<br>' + one.identifiers.map(function (id) {
                    // kit.shortened() brings its own <code title=…> — see the
                    // note in credentialCell().
                    return kit.shortened(id, 10);
                  }).join(' ') +
                  (one.moreIdentifiers ? ' <span class="state-none">' +
                    t.html('consoleDelegation.nMore',
                           { n: one.moreIdentifiers }) + '</span>' : '')
                : '');
          }).join('<br>')
        : '<span class="state-none">&mdash;</span>') + '</td>' +
      // WHY, AND THE UNPOLICED FAMILIES ARE COLLAPSED. This is the delegation
      // page's own rule about its *Also requires* column read again: a sentence
      // that is a property of the MECHANISM and identical on every row of its
      // kind is not a column, it is a paragraph. `authorizedBy` on a WS-Trust
      // or an RFC 8693 row is exactly that — *nothing checks this, and here is
      // the paragraph* — repeated down the table it squeezed the four columns
      // that DO differ per row into shreds, which is the failure that took that
      // page from twelve columns to ten.
      //
      // So a REFUSAL prints in full, because it is specific to the act and is
      // most of what this page is for; a POLICED grant prints its attribute,
      // because that is short and names an account; and an unpoliced grant
      // becomes three words with the paragraph in the tooltip. Nothing is lost
      // — the line's own tooltip in the picture carries the same text.
      '<td>' + (edge.reason
                ? kit.esc(edge.reason)
                : edge.relation === 'issued'
                  ? '<span class="state-none">&mdash;</span>'
                  : edge.policed
                    ? (edge.authorizedBy ? kit.esc(edge.authorizedBy)
                                         : '<span ' +
                                           'class="state-none">&mdash;</span>')
                    : '<span class="state-expired" title="' +
                      kit.esc(edge.authorizedBy ||
                        t.text('consoleDelegation.nothingDecides')) +
                      '">' + t.html('consoleDelegation.nothingChecks') +
                      '</span>') +
      '</td>' +
      '</tr>';
  }

  // One credential that came out of an act in the picture. `extra` is an
  // optional leading cell — the application page uses it for the ROLE that
  // application played in the act that produced this, which is the whole
  // question that page answers and is a fact about the act rather than about
  // the credential.
  /**
   * Draws one credential that came out of a delegation act as a table row.
   *
   * @param token - the credential row from the delegation graph
   * @param labelOf - function giving a node id's label
   * @param extra - optional; HTML for a leading cell, such as the role the
   *   application played
   * @returns the row as HTML
   */
  static delegationTokenRow(t, token, labelOf, extra?) {
    return '<tr>' +
      '<td class="num">' + kit.esc(token.seq) + '</td>' +
      '<td>' + kit.esc(kit.whenText(token.at)) + '</td>' +
      (extra === undefined ? '' : '<td>' + extra + '</td>') +
      '<td class="who"><code>' + kit.esc(token.kind) + '</code>' +
        (token.identifier
          ? '<br>' + kit.shortened(token.identifier, 14)
          : '<br><span class="state-none" title="' +
            t.html('consoleDelegation.noIdentifierTitle') + '">' +
            t.html('consoleDelegation.noIdentifier') + '</span>') +
        (token.note ? '<br><span class="state-none">' + kit.esc(token.note) +
                      '</span>' : '') + '</td>' +
      '<td class="who">' + kit.esc(labelOf(token.subject) ||
        '<span class="state-none">&mdash;</span>') + '</td>' +
      '<td class="who">' + (token.actor ? kit.esc(labelOf(token.actor))
        : '<span class="state-none" title="' +
          t.html('consoleDelegation.noActorTitle') + '">&mdash;</span>') +
      '</td><td ' +
      'class="who">' + (token.target ? kit.esc(labelOf(token.target))
        : '<span class="state-none">&mdash;</span>') + '</td>' +
      '<td><code>' + kit.esc(token.type) + '</code><br>' +
        '<span class="state-none">' + kit.esc(token.protocol) +
        '</span></td>' +
      '</tr>';
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION CHOOSER, DRAWN IN THREE PLACES AND THEREFORE A FUNCTION.
  //
  // It is on /admin/delegation (where somebody looking at the table wants to
  // pivot), on /admin/delegation/application with nothing selected (where it IS
  // the page), and again under a selected application (so that comparing two is
  // one click rather than two). Three copies of a `<select>` built from the
  // same list would be three chances for one of them to offer an option the
  // route cannot resolve.
  //
  // **THE OPTION'S VALUE IS A SPELLING AND NOT THE NORMALISED KEY**,
  // deliberately. The route normalises whatever it is given (see its header),
  // so both work — and the identifier is what a reader recognises in the
  // address bar and in a link they paste into a ticket. A URL carrying
  // `HTTP%2Fbackend%40EXAMPLE.COM` is one somebody can check; one carrying a
  // key they have never seen is not.
  //
  // **IT WAS A `<select>` UNTIL 2026-08-26 AND IS A SEARCH NOW** —
  // kit.chooserPane() above carries the whole argument, including why it cannot
  // be a type-ahead. What survives of the old one is the sentence that made it
  // a select rather than a wall of links: a control here must be the same size
  // whatever the register holds, because the table it sits above is what the
  // reader came for. The pane scrolls instead. The full list IS still drawn as
  // links, below, where it is the content rather than a control.
  // ---------------------------------------------------------------------------
  // `carry` is the delegation table's own filter, spelt into every RESULT's
  // href for the reason kit.perPageForm() gives about hidden inputs: without it
  // a click here quietly empties the breadcrumb's way back to the list the
  // reader came from. `here` is the page this control is DRAWN on, which is
  // where its own form submits — a different page from the one a result opens,
  // and conflating the two is what a search added to a chooser gets wrong.
  /**
   * Draws the search over every application a delegation act named, each
   * result linking to /admin/delegation/application by its identifier.
   *
   * @param chooser - the answer's slice of it (`AdminViews.
   *   delegationChooser()`): `total`, the `entries` on the pane, `slice`
   * @param selectedKey - the application already chosen, marked in the pane
   * @param here - the page this is drawn on, as path and query
   * @returns the chooser as HTML, or a note when there is none to choose
   */
  static delegationApplicationChooser(t, chooser, selectedKey, here) {
    if (!chooser.total) {
      return kit.note(t.html('consoleDelegation.appChooserEmpty'));
    }
    return kit.chooserPane({
      here: here, param: 'appq', fromParam: 'appfrom',
      label: t.text('consoleDelegation.appChooserLabel'),
      placeholder: t.text('consoleDelegation.appChooserPlaceholder'),
      entries: chooser.entries, selectedKey: selectedKey,
      slice: chooser.slice,
      nothing: t.text('consoleDelegation.appChooserNothing')
    });
  }


  // ---------------------------------------------------------------------------
  // THE PERSON CHOOSER, AND IT IS THE APPLICATION CHOOSER'S ARGUMENT MADE AGAIN
  // RATHER THAN COPIED.
  //
  // Drawn in three places for the same reason that one is: on /admin/delegation
  // (where somebody looking at the table wants to pivot), on
  // /admin/delegation/map (where the ask came from — *filter the picture by a
  // person the way it filters by an application*), and on the person's own page
  // (so comparing two is one click rather than two).
  //
  // **THE OPTION'S VALUE IS THE NORMALISED KEY AND NOT A SPELLING**, which is
  // the one place this differs from the application chooser next door, and the
  // difference is the whole reason the two lists are keyed differently
  // (`delegation.js`'s `identityList()` header argues it). An application is
  // chosen by the identifier a protocol NAMED, because that is what a reader
  // recognises in a URL. A person has no such identifier: they arrive as
  // `alice`, as `alice@STS.MOCK` and as `urn:uuid:<entryUUID>`, and the console
  // has filed all three under one name — which is the name on /admin/users, on
  // /admin/audit and in the directory. Putting a spelling in the URL would make
  // a link from this console disagree with every other link in it. The route
  // normalises whatever it is given anyway, so a hand-written
  // `?user=alice@REALM` still lands on the right page.
  //
  // **IT OFFERS IDENTITIES NOTHING WAS EVER ISSUED TO, AND THAT IS THE POINT.**
  // `userGraph.userList()` unions the identity register with the delegation
  // register, so somebody who has never signed in here is in this list if an
  // S4U2Self or an OnBehalfOf named them — which is the case worth finding, and
  // exactly the case a chooser built from /admin/users alone would hide.
  // ---------------------------------------------------------------------------
  /**
   * Draws the search over every identity the identity and delegation
   * registers know, each result linking to /admin/delegation/user by its
   * normalised key.
   *
   * @param chooser - the answer's slice of it (`AdminViews.
   *   delegationChooser()`): `total`, the `entries` on the pane, `slice`
   * @param selectedKey - the identity already chosen, marked in the pane
   * @param here - the page this is drawn on, as path and query
   * @returns the chooser as HTML, or a note when there is nobody to choose
   */
  static delegationUserChooser(t, chooser, selectedKey, here) {
    if (!chooser.total) {
      return kit.note(t.html('consoleDelegation.userChooserEmpty'));
    }
    return kit.chooserPane({
      here: here, param: 'userq', fromParam: 'userfrom',
      label: t.text('consoleDelegation.userChooserLabel'),
      placeholder: t.text('consoleDelegation.userChooserPlaceholder'),
      entries: chooser.entries, selectedKey: selectedKey,
      slice: chooser.slice,
      nothing: t.text('consoleDelegation.userChooserNothing')
    });
  }


  // THE SECTION SEARCHES, AS HIDDEN INPUTS FOR SOMEBODY ELSE'S FORM.
  //
  // The acts table's own filter is a GET form, and a GET form posts its own
  // fields and NOTHING else — so narrowing the table by mechanism would clear
  // every other search on the page, which is a control undoing a control the
  // reader is still using. Each search re-emits the OTHERS through its own
  // hidden inputs; this is for the forms on the page that are none of them.
  //
  // It was two names until 2026-09-01 and is four now: `permq` and `grantq`,
  // the searches over the two tables of the configured register, joined the two
  // chooser searches the day those tables were paged. The function is still
  // called chooserCarry() because sixteen call sites and one name is cheaper
  // than a rename that says nothing new — what it carries is "every search on
  // this page that is not the form asking".
  /**
   * Re-emits the page's section searches (`appq`, `appfrom`, `userq`,
   * `userfrom`, `permq`, `grantq`) as hidden inputs, so a form that is none
   * of them does not clear them.
   *
   * @param query - the request's query
   * @returns hidden inputs as HTML, one per non-empty search
   */
  static chooserCarry(query) {
    return ['appq', 'appfrom', 'userq', 'userfrom', 'permq', 'grantq'].map(
        function (name) {
      const value = kit.queryOne(query, name);
      return value === ''
        ? ''
        : '<input type="hidden" name="' + kit.esc(name) + '" value="' +
          kit.esc(value) +
          '">';
    }).join('');
  }

  // One line of the person's picture, in words. `delegationEdgeRow()`'s
  // argument applied to five relations instead of three: everything the diagram
  // says in colour is said here in text, because a picture nobody can quote is
  // a picture nobody can put in a bug report.
  /**
   * Draws one line of a person's picture as a row, in words, over its five
   * relations (issued to, signed in, issued for, acts for, reaches).
   *
   * @param edge - an edge from the person's graph
   * @param lookOf - function giving a node id's label
   * @returns the row as HTML
   */
  static userEdgeRow(t, edge, lookOf) {
    const relation =
      edge.relation === 'issued'
        ? '<span class="state-none" title="' +
          t.html('consoleDelegation.issuedToTitle') + '">' +
          t.html('consoleDelegation.issuedTo') + '</span>'
      : edge.relation === 'signed-in'
        ? '<strong>' + t.html('consoleDelegation.signedIn') +
          '</strong><br><span class="state-none">' +
          t.html('consoleDelegation.toThisService') + '</span>'
      : edge.relation === 'issued-for'
        ? '<strong>' + t.html('consoleDelegation.issuedFor') +
          '</strong><br><span class="state-none">' +
          t.html('consoleDelegation.byOrdinaryGrant') + '</span>'
      : edge.relation === 'acts-for'
        ? '<strong>' + t.html('consoleDelegation.actsFor') +
          '</strong><br><span class="state-none">' +
          t.html('consoleDelegation.aDelegation') + '</span>'
        : '<strong>' + t.html('consoleDelegation.reaches') + '</strong>' +
          (edge.subject ? '<br><span class="state-none">' +
           t.html('consoleDelegation.asSubject', { subject: edge.subject }) +
                          '</span>' : '') +
          // WHAT THE TOKEN MAY DO AT THE FAR END, said here as well as on the
          // picture because the two are drawn from ONE graph and a reader
          // comparing them must not find the line and the row disagreeing. The
          // picture cuts the list at 26 characters and this does not, which is
          // the ordinary division of labour between them.
          //
          // `permissions` is present only on a line built from a CREDENTIAL —
          // see common/user_graph.ts — so a `reaches` line out of the
          // delegation register renders exactly as it did. An EMPTY array is
          // drawn rather than skipped, for the renderer's reason: it means the
          // token named this resource and asked for none of its permissions,
          // which is a state and not a gap.
          (edge.permissions
            ? '<br>' + (edge.permissions.length
                ? edge.permissions.map(function (one) {
                    return '<code>' + kit.esc(one) + '</code>';
                  }).join(' ')
                : '<span class="state-none" title="' +
                  t.html('consoleDelegation.defaultPermissionsTitle') +
                  '">' + t.html('consoleDelegation.defaultPermissions') +
                  '</span>')
            : '');
    const mechanism = edge.typeLabel
      ? (edge.type ? '<code>' + kit.esc(edge.type) + '</code><br>' : '') +
        '<span class="state-none">' + kit.esc(edge.typeLabel) + '</span>' +
        (edge.protocol || edge.spec
          ? '<br><span class="state-none">' + kit.esc(edge.protocol) +
            (edge.spec ? ' &middot; ' + kit.esc(edge.spec) : '') + '</span>'
          : '')
      : '<span class="state-none">' +
        kit.esc((edge.protocols || []).join(', ') || '—') + '</span>';
    return '<tr>' +
      '<td class="who">' + kit.esc(lookOf(edge.from)) + '</td>' +
      '<td class="who">' + kit.esc(lookOf(edge.to)) + '</td>' +
      '<td>' + relation +
        ((edge.skipped || []).length
          ? '<br><span class="state-expired" title="' +
            t.html('consoleDelegation.jumpsTitle') + '">' +
            t.html('consoleDelegation.jumps',
                   { skipped: edge.skipped.join(' and ') }) + '</span>'
          : '') + '</td>' +
      '<td>' + mechanism + '</td>' +
      '<td>' + (edge.mode ? DelegationPage.modeCell(t, edge.mode)
        : '<span class="state-none" title="' +
          t.html('consoleDelegation.noModeTitle') + '">&mdash;</span>') +
      '</td>' +
      '<td class="num">' + (edge.acts
        ? kit.esc(edge.acts) + (edge.relation === 'signed-in' ? ''
            : ' — <span class="state-valid">' +
              t.html('consoleDelegation.nIssued', { n: edge.issued }) +
              '</span>' +
              (edge.refused
                ? ', <span class="state-revoked">' +
                  t.html('consoleDelegation.nRefused', { n: edge.refused }) +
                  '</span>' : ''))
        : '<span class="state-none">&mdash;</span>') + '</td>' +
      '<td class="num">' + (edge.credentials
        ? '<strong>' + kit.esc(edge.credentials) + '</strong>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td class="who">' + ((edge.produced || []).length
        ? edge.produced.map(function (one) {
            return '<code>' + kit.esc(one.kind) + '</code> × ' +
                   kit.esc(one.count) +
              (one.identifiers.length
                ? '<br>' + one.identifiers.map(function (id) {
                    return kit.shortened(id, 10);
                  }).join(' ') +
                  (one.moreIdentifiers ? ' <span class="state-none">' +
                    t.html('consoleDelegation.nMore',
                           { n: one.moreIdentifiers }) + '</span>' : '')
                : '');
          }).join('<br>')
        : '<span class="state-none">&mdash;</span>') + '</td>' +
      '</tr>';
  }

  // One box on the person's picture. `delegationNodeRow()`'s columns plus the
  // two this page adds, rather than that function with a flag: half its columns
  // are about ACTS, and a box that received four tokens and took part in no
  // delegation would otherwise be a row of zeroes with the interesting number
  // nowhere on it.
  /**
   * Draws one box of a person's picture as a row, adding the credentials
   * and flows columns to what delegationNodeRow() draws.
   *
   * @param node - a node from the person's graph
   * @param facts - the answer's `facts`: `users` (the keys seen here) and
   *   `apps` (the registered applications named on the page)
   * @param look - the node's look (label, identifier, shape, dashed)
   * @returns the row as HTML, or '' for the service's own node
   */
  static userNodeRow(t, node, facts, look) {
    if (node.kind === 'sts') {
      return '';
    }
    const party = { key: node.key, presented: node.presented,
                    application: node.application, what: node.what };
    const roles = [];
    if (node.roles.initial) roles.push(t.html('consoleDelegation.nodeInitial',
                                              { n: node.roles.initial }));
    if (node.roles.intermediary) roles.push(
      t.html('consoleDelegation.nodeIntermediary',
             { n: node.roles.intermediary }));
    if (node.roles.target) roles.push(t.html('consoleDelegation.nodeTarget',
                                             { n: node.roles.target }));
    return '<tr>' +
      '<td>' + kit.esc(look.label) +
        (node.isSubject
          ? '<br><span class="state-valid" title="' +
            t.html('consoleDelegation.thisPageTitle') + '">' +
            t.html('consoleDelegation.thisPage') + '</span>'
          : '') +
        (look.identifier
          ? '<br><span class="state-none" title="' +
            t.html('consoleDelegation.nodeIdentifierTitle') + '">' +
            kit.esc(look.identifier) + '</span>'
          : '') + '</td>' +
      '<td>' + (look.shape === 'both'
                  ? t.html('consoleDelegation.shapeBoth')
                  : look.shape === 'person'
                    ? t.html('consoleDelegation.shapePerson')
                  : look.shape === 'application'
                    ? t.html('consoleDelegation.shapeApplication')
                    : look.shape) +
        (look.dashed
          ? '<br><span class="state-none" title="' +
            t.html('consoleDelegation.shapeDashedTitle') + '">' +
            t.html('consoleDelegation.shapeDashed') + '</span>'
          : '') + '</td>' +
      '<td class="who">' + DelegationPage.delegationPartyCell(t, party,
                                                               facts) +
      '</td>' +
      '<td class="num">' + (node.credentials
        ? '<strong>' + kit.esc(node.credentials) + '</strong>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td>' + (node.flows.map(kit.esc.bind(kit)).join('<br>') ||
                '<span class="state-none">&mdash;</span>') + '</td>' +
      '<td>' + (roles.join('<br>') || '<span class="state-none" title="' +
        t.html('consoleDelegation.notInDelegationTitle') + '">' +
        t.html('consoleDelegation.notInDelegation') + '</span>') + '</td>' +
      '<td class="num">' + (node.acts
        ? kit.esc(node.acts) + ' — <span class="state-valid">' +
          t.html('consoleDelegation.nIssued', { n: node.issued }) +
          '</span>' + (node.refused
            ? ', <span class="state-revoked">' +
              t.html('consoleDelegation.nRefused', { n: node.refused }) +
              '</span>'
            : '')
        : '<span class="state-none">0</span>') + '</td>' +
      '<td>' + (node.protocols.map(kit.esc.bind(kit)).join('<br>') ||
                '<span class="state-none">&mdash;</span>') + '</td>' +
      '</tr>';
  }

  // One credential from the ISSUED register, as a row. `back` carries the list
  // the reader came from, so the revoke button on a token returns them to it —
  // the same `carryBack` rule every form on a drill-down follows.
  /**
   * Draws one credential from the issued register as a row: when, what,
   * the flow that issued it, its holder, its state and its session.
   *
   * @param credential - a row of the issued-credential register
   * @param facts - the answer's `facts`: `users` (the keys seen here) and
   *   `apps` (the registered applications named on the page)
   * @returns the row as HTML
   */
  static userCredentialRow(t, credential, facts) {
    const holder = credential.holder
      ? DelegationPage.delegationPartyCell(t, { key: '', presented: '',
                                   application: credential.holder, what: '' },
                                   facts)
      : '<span class="state-none" title="' +
        t.html('consoleDelegation.noHolderTitle') + '">&mdash;</span>';
    return '<tr>' +
      '<td>' + kit.esc(kit.whenText(credential.at)) + '</td>' +
      '<td class="who"><code>' + kit.esc(credential.kind) + '</code>' +
        (credential.identifier
          ? '<br>' + kit.shortened(credential.identifier, 14)
          : '<br><span class="state-none" title="' +
            t.html('consoleDelegation.noIdentifierTitle') + '">' +
            t.html('consoleDelegation.noIdentifier') + '</span>') +
        (credential.detail
          ? '<br><span class="state-none">' + kit.esc(credential.detail) +
            '</span>'
          : '') + '</td>' +
      '<td>' + DelegationPage.userFlowCell(t, credential) + '</td>' +
      '<td class="who">' + holder + '</td>' +
      '<td class="' + TokensPage.stateClass(credential.state) + '">' +
      kit.esc(credential.state) +
        '</td>' +
      '<td>' + (credential.sessionId
        ? kit.shortened(credential.sessionId, 10)
        : '<span class="state-none" title="' +
          t.html('consoleDelegation.noSessionTitle') + '">' +
          t.html('consoleDelegation.none') + '</span>') + '</td>' +
      '</tr>';
  }

  // WHAT ISSUED ONE CREDENTIAL, as a cell, and this is the column the whole
  // page was asked for: *label exactly what OAuth2 grant or OIDC authentication
  // flow was used, if not a delegation call.*
  //
  // Three states rather than two, and the third is the one worth keeping apart.
  // A JWT that states a grant gets the grant, with the OIDC name for the same
  // exchange beside it where OpenID Connect gives it one — an *Authorization
  // Code grant* and an *Authorization Code Flow* are one thing under two
  // vocabularies, and somebody debugging an OIDC client is looking for the
  // second while the token endpoint is answering the first. An ARTIFACT gets
  // the mechanism its own specification names, because a SAML assertion was
  // never issued by an OAuth grant and borrowing the word would be a small lie.
  // And a JWT that states NOTHING says so in as many words: `signJwt()` is
  // reached from outside the token endpoint by WS-Trust's JWT token type and by
  // the credential issuer, and an empty cell there would read as a recording
  // failure.
  /**
   * Draws what issued one credential: the grant it states (with the OIDC
   * name where there is one), an artifact's own mechanism, or "no grant
   * stated".
   *
   * @param credential - a row of the issued-credential register
   * @returns the cell's HTML
   */
  static userFlowCell(t, credential) {
    if (credential.flowStated) {
      return '<code>' + kit.esc(credential.flow) + '</code><br>' +
        '<strong>' + kit.esc(credential.flowLabel) + '</strong>' +
        (credential.flowOidc && credential.flowOidc !== credential.flowLabel
          ? '<br><span class="state-none" title="' +
            t.html('consoleDelegation.oidcNameTitle') + '">OIDC: ' +
            kit.esc(credential.flowOidc) + '</span>'
          : '') +
        (credential.flowSpec
          ? '<br><span class="state-none">' + kit.esc(credential.flowSpec) +
            '</span>'
          : '');
    }
    if (credential.family !== 'token') {
      return '<strong>' + kit.esc(credential.flowLabel) + '</strong>' +
        (credential.flowProtocol
          ? '<br><span class="state-none">' +
            kit.esc(credential.flowProtocol) +
            (credential.flowSpec ? ' &middot; ' +
             kit.esc(credential.flowSpec) : '') +
            '</span>'
          : '') +
        '<br><span class="state-none" title="' +
        t.html('consoleDelegation.notOauthGrantTitle') + '">' +
        t.html('consoleDelegation.notOauthGrant') + '</span>';
    }
    return '<span class="state-none" title="' +
      kit.esc(t.text('consoleDelegation.flowNotStated')) + '">' +
      t.html('consoleDelegation.noGrantStated') + '</span>';
  }

  // The roles an application played in one act, as cells. Two is possible and
  // is S4U2Self — the requester asks for a ticket to ITSELF, so it is the
  // intermediary and the target of the same act.
  /**
   * Draws the roles an application played in one act, one per line, each
   * with its description as a tooltip.
   *
   * @param roles - the role keys
   * @param vocabulary - the answer's `roles`, the register's role list
   * @returns the cell's HTML, or a dash when there are none
   */
  static delegationRoleCell(roles, vocabulary) {
    if (!roles || !roles.length) {
      return '<span class="state-none">&mdash;</span>';
    }
    return roles.map(function (role) {
      const entry = (vocabulary || []).filter(function (one) {
        return one.role === role;
      })[0];
      return '<span title="' + kit.esc(entry ? entry.what : '') + '">' +
             kit.esc(entry ? entry.label : role) + '</span>';
    }).join('<br>');
  }

  // The same list as CONTENT: every application some act named, with what it
  // did and the way in. It is not the same as `/admin/applications` and the
  // page says so — that page is the REGISTRY, which holds what this service has
  // been asked about; this is what has actually delegated, which can name
  // something the registry has never seen.
  /**
   * Draws every application some delegation act named, with its roles,
   * acts, credentials, relationships and when it was last seen.
   *
   * @param catalogue - the delegation register's application list
   * @param facts - the answer's `facts`: `users` (the keys seen here) and
   *   `apps` (the registered applications named on the page)
   * @param carry - the delegation table's filter, kept in each link
   * @returns the table as HTML
   */
  static delegationApplicationTable(t, catalogue, facts, carry) {
    const rows = catalogue.map(function (entry) {
      const roles = [];
      if (entry.roles.intermediary) {
        roles.push(t.html('consoleDelegation.nodeIntermediary',
                          { n: entry.roles.intermediary }));
      }
      if (entry.roles.target) {
        roles.push(t.html('consoleDelegation.nodeTarget',
                          { n: entry.roles.target }));
      }
      if (entry.roles.initial) {
        roles.push(t.html('consoleDelegation.nodeInitial',
                          { n: entry.roles.initial }));
      }
      const registered = entry.spellings.filter(function (spelling) {
        return !!facts.apps[spelling];
      }).length > 0;
      return '<tr>' +
        '<td class="who"><a href="' + kit.esc('/admin/delegation/application' +
          kit.queryWith(carry || {}, { application: entry.identifier })) +
        '"><code>' +
          kit.esc(entry.identifier) + '</code></a>' +
          (entry.spellings.length > 1
            ? '<br><span class="state-none" title="' +
              kit.esc(entry.spellings.join(', ')) + '">' +
              t.html('consoleDelegation.spellingsCollapsed',
                     { n: entry.spellings.length }) + '</span>'
            : '') +
          (registered ? ''
            : '<br><span class="state-none" title="' +
              t.html('consoleDelegation.appNotRegisteredTitle') + '">' +
              t.html('consoleDelegation.notInRegistry') + '</span>') +
          (entry.identityKey
            ? '<br>' + GroupsPage.usersPageCell(entry.identityKey,
                                                facts.users, t)
            : '') + '</td>' +
        '<td>' +
        (roles.join('<br>') || '<span class="state-none">&mdash;</span>') +
          '</td>' +
        '<td class="num">' + kit.esc(entry.acts) + ' — ' +
          '<span class="state-valid">' +
          t.html('consoleDelegation.nIssued', { n: entry.issued }) +
          '</span>, ' +
          (entry.refused
            ? '<span class="state-revoked">' +
              t.html('consoleDelegation.nRefused', { n: entry.refused }) +
              '</span>'
            : '<span class="state-none">' +
              t.html('consoleDelegation.nRefused', { n: 0 }) + '</span>') +
          '</td>' +
        '<td class="num">' + kit.esc(entry.credentials) + '</td>' +
        '<td class="num">' + kit.esc(entry.chains) + '</td>' +
        '<td>' + kit.esc(kit.whenText(entry.lastAt)) + '</td>' +
        '</tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleDelegation.thApplication') +
      '</th><th>' + t.html('consoleDelegation.thRolesPlayed') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thCredentials') + '</th><th>' +
      t.html('consoleDelegation.thRelationships') + '</th><th>' +
      t.html('consoleDelegation.thLastSeen') + '</th></tr>' +
      (rows || '<tr><td colspan="6">' +
       t.html('consoleDelegation.noAppNamed') + '</td></tr>') + '</table>';
  }

  // The same list as CONTENT. It is not /admin/users and the page says so: that
  // page is the identity register, and this one holds everybody that register
  // knows PLUS everybody a delegation named who has never been near this
  // service. The `Where from` column is the only reason to draw it rather than
  // link to the users page, and it is the column worth reading.
  /**
   * Draws every identity the identity and delegation registers know, with
   * where it came from, sign-ins, tokens, artifacts, acts and protocols.
   *
   * @param catalogue - the union of the two registers' identities
   * @param facts - the answer's `facts`: `users` (the keys seen here) and
   *   `apps` (the registered applications named on the page)
   * @param carry - the delegation table's filter, kept in each link
   * @returns the table as HTML
   */
  static delegationUserTable(t, catalogue, facts, carry) {
    const rows = catalogue.map(function (entry) {
      const where = [];
      if (entry.authenticated) {
        where.push('<span class="state-valid" title="' +
          t.html('consoleDelegation.authenticatedHereTitle') + '">' +
          t.html('consoleDelegation.authenticatedHere') + '</span>');
      }
      if (entry.delegated) {
        where.push('<span class="state-expired" title="' +
          t.html('consoleDelegation.namedInDelegationTitle') + '">' +
          t.html('consoleDelegation.namedInDelegation') + '</span>');
      }
      if (!entry.authenticated) {
        where.push('<span class="state-none" title="' +
          t.html('consoleDelegation.neverAuthenticatedTitle') + '">' +
          t.html('consoleDelegation.neverAuthenticated') + '</span>');
      }
      return '<tr>' +
        '<td class="who"><a href="' + kit.esc('/admin/delegation/user' +
          kit.queryWith(carry || {}, { user: entry.key })) + '"><code>' +
          kit.esc(entry.key) + '</code></a>' +
          (entry.isClient
            ? '<br><span class="state-none" title="' +
              t.html('consoleDelegation.clientNotPersonTitle') + '">' +
              t.html('consoleDelegation.clientNotPerson') + '</span>'
            : '') +
          '<br>' + GroupsPage.usersPageCell(entry.key, facts.users, t) +
          '</td>' +
        '<td>' + where.join('<br>') + '</td>' +
        '<td class="num">' + kit.esc(entry.authentications) + '</td>' +
        '<td class="num">' + kit.esc(entry.tokens.issued) + ' — ' +
          '<span class="state-valid">' +
          t.html('consoleDelegation.nValid', { n: entry.tokens.valid }) +
          '</span>' +
          (entry.tokens.revoked
            ? ', <span class="state-revoked">' +
              t.html('consoleDelegation.nRevoked',
                     { n: entry.tokens.revoked }) +
              '</span>' : '') + '</td>' +
        '<td class="num">' + kit.esc(entry.artifacts) + '</td>' +
        '<td class="num">' + (entry.acts
          ? kit.esc(entry.acts) + ' — <span class="state-valid">' +
            t.html('consoleDelegation.nIssued', { n: entry.issued }) +
            '</span>' + (entry.refused
              ? ', <span class="state-revoked">' +
                t.html('consoleDelegation.nRefused', { n: entry.refused }) +
                '</span>' : '')
          : '<span class="state-none">0</span>') + '</td>' +
        '<td>' + (entry.protocols.map(kit.esc.bind(kit)).join('<br>') ||
                  '<span class="state-none">&mdash;</span>') + '</td>' +
        '<td>' + kit.esc(kit.whenText(entry.lastAt)) + '</td>' +
        '</tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleDelegation.thIdentity') +
      '</th><th>' + t.html('consoleDelegation.thWhereFrom') + '</th><th>' +
      t.html('consoleDelegation.thSignIns') + '</th>' +
      '<th>' + t.html('consoleDelegation.thTokens') + '</th><th>' +
      t.html('consoleDelegation.thArtifacts') + '</th><th>' +
      t.html('consoleDelegation.thDelegationActs') + '</th>' +
      '<th>' + t.html('consoleDelegation.thProtocols') + '</th><th>' +
      t.html('consoleDelegation.thLastSeen') + '</th></tr>' +
      (rows || '<tr><td colspan="8">' +
       t.html('consoleDelegation.nobodyAuthenticated') + '</td></tr>') +
      '</table>';
  }

  // ---------------------------------------------------------------------------
  // THE APPLICATION SEARCH OVER THE CONFIGURED REGISTER, AND WHY IT NEEDED
  // PARAMETER NAMES OF ITS OWN.
  //
  // It is `kit.chooserPane()` again — the same control, the same
  // twenty-at-a-time pane, the same "an empty box matches everything" — drawn
  // on /admin/delegation/allowed and again on /admin/delegation/cluster under
  // the group it opened, for the reason `delegationApplicationChooser()` gives
  // about its own second copy: comparing two groups should be one click rather
  // than two.
  //
  // **THE CATALOGUE IS A DIFFERENT LIST FROM THE ACTS CHOOSER'S AND THAT IS THE
  // WHOLE REASON THIS IS A SECOND FUNCTION.** `delegationApplicationChooser()`
  // offers what some act NAMED — what has actually delegated, spellings and
  // all, including an RFC 8693 audience nobody registered. This one offers what
  // the CONFIGURED register touches: every application carrying a base URI or a
  // permission, and every application holding a grant. The two lists overlap
  // and neither contains the other, and a reader searching here for something
  // they saw on the acts picture must be told it is not in this register rather
  // than shown a group it is not in.
  //
  // **IT USES `permappq` / `permappfrom` AND MUST NOT REUSE `appq` /
  // `appfrom`.** Those two belong to the acts chooser, they are in LIST_PARAMS
  // for /admin/delegation, and a drill-down of that page carries them through
  // untouched so that the way back lands on the search the reader left. A
  // second control writing the same two names would overwrite that on every
  // search — the reader would come back to /admin/delegation holding a term
  // they typed into a different list. That is precisely the failure the acts
  // page's own two pairs are split to prevent, made once more between two pages
  // instead of twice on one.
  // ---------------------------------------------------------------------------
  /**
   * Draws the search over the applications the permissions register touches.
   *
   * Each result opens that application's group at /admin/delegation/cluster.
   *
   * @param view - the view holding the register and its clusters
   * @param selectedKey - the application currently selected, if any
   * @param carry - the parameters carried into each result's link
   * @param here - the page the search submits to
   * @returns the chooser, or a note when there is nothing, as HTML
   */
  static allowedApplicationChooser(t, view, selectedKey, carry, here) {
    const groups = view.clusters;
    if (!groups.counts.applications) {
      return kit.note(t.html('consoleDelegation.allowedEmptyBefore') +
        '<a href="/admin/delegation#allowed">' +
        t.html('consoleDelegation.theRegister') + '</a>' +
        t.html('consoleDelegation.allowedEmptyAfter'));
    }

    // Everything one row of the pane has to say, worked out from the register
    // ONCE rather than per entry: `register()` is already in hand, and a filter
    // per application over `grants` and `permissions` would be quadratic in a
    // registry whose whole point is that it can be large.
    const holds = {};
    const reached = {};
    const exposes = {};
    view.register.grants.forEach(function (one) {
      holds[one.client] = (holds[one.client] || 0) + 1;
      if (one.resource) {
        reached[one.resource] = (reached[one.resource] || 0) + 1;
      }
    });
    view.register.permissions.forEach(function (one) {
      exposes[one.resource] = (exposes[one.resource] || 0) + 1;
    });

    const entries = [];
    groups.clusters.forEach(function (group) {
      group.members.forEach(function (identifier) {
        const registered = view.apps[identifier];
        const name = registered
          ? (registered.name || registered.dnLabel || identifier) : '';
        const parts = [];
        if (holds[identifier]) {
          parts.push(t.text('consoleDelegation.grantsHeld',
                            { n: holds[identifier] }));
        }
        if (exposes[identifier]) {
          parts.push(t.text('consoleDelegation.permissionsExposed',
                            { n: exposes[identifier] }));
        }
        if (reached[identifier]) {
          parts.push(t.text('consoleDelegation.grantsOnIt',
                            { n: reached[identifier] }));
        }
        if (!parts.length) {
          parts.push(t.text('consoleDelegation.baseUriOnly'));
        }
        entries.push({
          key: identifier,
          // The identifier AND the name somebody gave the entry, because the
          // chooser shows one of them and a reader is about as likely to be
          // holding the other — `kit.chooserMatches()`'s whole subject.
          names: name && name !== identifier ? [identifier, name] :
                 [identifier],
          label: identifier,
          detail: parts.join(', ') + ' — ' +
                  (group.counts.applications === 1
                    ? t.text('consoleDelegation.groupOwn')
                    : t.text('consoleDelegation.groupOneOf',
                             { n: group.counts.applications })),
          // THE GROUP AND NOT THE APPLICATION IS WHAT OPENS, which is the one
          // way this control differs from every other chooser in the console: a
          // result here is not a page about the thing clicked, it is the page
          // about everything that thing is joined to. The application is still
          // the parameter, because it is what the reader chose and it is what
          // makes the URL one somebody can check — a group's own key is the
          // alphabetically first member, which is a name nobody typed.
          href: '/admin/delegation/cluster' +
                kit.queryWith(carry || {}, { application: identifier })
        });
      });
    });
    // ALPHABETICAL AND NOT IN GROUP ORDER. The groups are sorted biggest-first
    // for the table below, and that is the right order for a list of GROUPS; it
    // is the wrong one for a list of applications, where the reader is looking
    // for a name and the group is what they are about to find out.
    entries.sort(function (a, b) { return a.key.localeCompare(b.key); });

    return kit.chooserPane({
      here: here, param: 'permappq', fromParam: 'permappfrom',
      label: t.text('consoleDelegation.appChooserLabel'),
      placeholder: t.text('consoleDelegation.allowedPlaceholder'),
      entries: entries, selectedKey: selectedKey,
      // The pane escapes this, link and all, as it always has: the anchor is
      // kept in the code (a message may not carry one) so the text drawn is
      // the same.
      nothing: t.text('consoleDelegation.allowedNothingBefore') +
        '<a href="/admin/applications">' +
        t.text('consoleDelegation.theRegistry') + '</a>' +
        t.text('consoleDelegation.allowedNothingAfter')
    });
  }

  // The chooser's own two parameters, carried by hand from the page the search
  // was typed on to the page a result opens.
  //
  // They are deliberately NOT in LIST_PARAMS for /admin/delegation. That table
  // is the state of the acts LIST, spent by the breadcrumb's way back to it,
  // and these two names belong to neither the list nor the page it hangs under
  // — a crumb pointing at /admin/delegation carrying a search that page cannot
  // use would be state nobody can get back to, which is exactly what that
  // table's header says a row is for. So the way BACK to the allowed picture
  // carries them and the way UP to the acts table does not, and each link says
  // which it is.
  /**
   * Picks the application chooser's two parameters out of a query.
   *
   * @param query - the request's query
   * @returns `permappq` and `permappfrom`, where set
   */
  static allowedChooserState(query) {
    const out = {};
    ['permappq', 'permappfrom'].forEach(function (name) {
      const value = kit.queryOne(query, name);
      if (value !== '') {
        out[name] = value;
      }
    });
    return out;
  }

  // The groups themselves, as a table: the answer to *what is joined to what*
  // without opening a picture of any of it.
  //
  // One row per group, biggest first, with the applications in it spelled out —
  // because the size of a group is not what makes it interesting, its MEMBERS
  // are, and a table of counts with no names in it would send a reader into
  // every picture in turn to find the one they meant.
  /**
   * Draws the table of groups of applications joined by permissions.
   *
   * @param groups - the clusters view, for its counts
   * @param shown - the groups on this page
   * @param carry - the parameters carried into each link
   * @param apps - the answer's registered applications, by identifier
   * @returns the table as HTML
   */
  static allowedClusterTable(t, groups, shown, carry, apps) {
    const rows = shown.map(function (group) {
      const members = group.members.map(function (identifier) {
        const registered = apps[identifier];
        const name = registered
          ? (registered.name || registered.dnLabel || identifier) : identifier;
        return '<a href="' + kit.esc('/admin/delegation/cluster' +
          kit.queryWith(carry || {}, { application: identifier })) +
          '"><code>' +
          kit.esc(identifier) + '</code></a>' +
          (name !== identifier
            ? ' <span class="state-none">' + kit.esc(name) + '</span>' : '') +
          (registered ? ''
            : ' <span class="state-none" title="' +
              t.html('consoleDelegation.ldapmodifyOnlyTitle') + '">' +
              t.html('consoleDelegation.notInRegistry') + '</span>');
      }).join('<br>');
      return '<tr>' +
        '<td class="who"><a href="' + kit.esc('/admin/delegation/cluster' +
          kit.queryWith(carry || {}, { application: group.key })) + '">' +
          (group.counts.applications === 1
            ? t.html('consoleDelegation.thisOneAlone')
            : t.html('consoleDelegation.nApplications',
                     { n: group.counts.applications })) + '</a>' +
          '<br><span class="state-none" title="' +
          t.html('consoleDelegation.namedForTitle') + '">' +
          t.html('consoleDelegation.namedFor', { key: group.key }) +
          '</span></td>' +
        '<td>' + members + '</td>' +
        '<td class="num">' + (group.counts.lines
          ? kit.esc(group.counts.lines)
          : '<span class="state-none" title="' +
            t.html('consoleDelegation.noLinesTitle') + '">0</span>') +
        '</td><td ' +
        'class="num">' + (group.counts.asked
          ? '<span class="state-valid">' + kit.esc(group.counts.asked) +
            '</span>'
          : '<span class="state-none">0</span>') + ' ' +
          t.html('consoleDelegation.askedFor') + '<br>' +
          (group.counts.unused
            ? '<span class="state-expired" title="' +
              t.html('consoleDelegation.unusedTitle') + '">' +
              kit.esc(group.counts.unused) + '</span>'
            : '<span class="state-none">0</span>') + ' ' +
          t.html('consoleDelegation.neverUsed') + '</td>' +
        '<td class="num">' + kit.esc(group.counts.permissions) + '</td>' +
        '<td class="num">' + (group.counts.dangling
          ? '<span class="state-revoked" title="' +
            t.html('consoleDelegation.danglingCountTitle') + '">' +
            t.html('consoleDelegation.nDangling',
                   { n: group.counts.dangling }) + '</span>'
          : '<span class="state-none">&mdash;</span>') +
          (group.counts.selfGrants
            ? '<br><span class="state-expired" title="' +
              t.html('consoleDelegation.selfGrantsTitle') + '">' +
              t.html('consoleDelegation.nToItself',
                     { n: group.counts.selfGrants }) + '</span>'
            : '') + '</td>' +
        '</tr>';
    }).join('');
    return '<table><tr><th>' + t.html('consoleDelegation.thGroup') +
      '</th><th>' + t.html('consoleDelegation.thGroupApps') + '</th>' +
      '<th>' + t.html('consoleDelegation.thLinesDrawn') + '</th><th>' +
      t.html('consoleDelegation.thGrants') + '</th><th>' +
      t.html('consoleDelegation.thPermissionsExposed') + '</th>' +
      '<th>' + t.html('consoleDelegation.thNotDrawn') + '</th></tr>' +
      (rows || '<tr><td colspan="6">' +
        (groups.counts.clusters
          ? t.html('consoleDelegation.noGroupOnPage')
          : t.html('consoleDelegation.noGroups')) + '</td></tr>') +
      '</table>';
  }

  // One row of the permissions table: what a resource EXPOSES.
  // `options.readOnly` swaps the Remove form for a link to the page that has
  // it, for the reason permissionGrantRow() carries the same parameter: the
  // picture pages list what they draw and change nothing, and one row function
  // is what stops two tables coming to disagree about what a permission
  // identifier is.
  /**
   * Draws one permission a resource application exposes.
   *
   * @param one - a permission from the configured register
   * @param listView - the list state carried into links and the form
   * @param options - optional; `readOnly` swaps the Remove form for a link
   * @returns a <tr> as HTML
   */
  static permissionDefinitionRow(t, one, listView, options?) {
    const href = '/admin/applications' +
                 kit.queryWith(listView || {}, { application: one.resource });
    return '<tr>' +
      '<td class="who"><a href="' + kit.esc(href) + '">' +
      kit.esc(one.resourceName) +
      '</a>' +
        (one.resourceName === one.resource ? ''
          : '<br><code>' + kit.esc(one.resource) + '</code>') + '</td>' +
      '<td><code>' + kit.esc(one.name) + '</code>' +
        (one.description ?
         '<br><span class="state-none">' + kit.esc(one.description) + '</span>'
                         : '') + '</td>' +
      // THE IDENTIFIER IS THE COLUMN SOMEBODY COPIES, so it is `<code>` and it
      // is whole rather than shortened. A permission whose entry has no base
      // URI has none at all, and that is said rather than left as an empty cell
      // — it is the one state on this table that means the row cannot work.
      '<td>' + (one.id
        ? '<code>' + kit.esc(one.id) + '</code>'
        : '<span class="state-revoked" title="' +
          t.html('consoleDelegation.noPermissionIdTitle') + '">' +
          t.html('consoleDelegation.noPermissionId') + '</span>') + '</td>' +
      '<td class="num">' + (one.grantedTo.length
        ? '<span class="state-valid">' + one.grantedTo.length + '</span>'
        : '<span class="state-none" title="' +
          t.html('consoleDelegation.nobodyHoldsTitle') + '">0</span>') +
      '</td>' +
      '<td class="who">' + (one.grantedTo.length
        ? one.grantedTo.map(function (who) {
            return kit.esc(who.name) + (who.asked ? '' :
              ' <span class="state-none" title="' +
              t.html('consoleDelegation.grantedNeverAskedTitle') + '">' +
              t.html('consoleDelegation.unused') + '</span>');
          }).join('<br>')
        : '<span class="state-none">&mdash;</span>') + '</td>' +
      // THE TWO BRANCHES DREW THE SAME FORM, and they did before this row
      // carried a `back` as well — the `one.id` test above decides the
      // IDENTIFIER cell, not this one, and a permission with no identifier is
      // removed by exactly the same call. One form, once.
      '<td>' + (options && options.readOnly
        ? '<a href="/admin/delegation-settings#allowed" title="' +
          t.html('consoleDelegation.changeRemoveTitle') + '">' +
          t.html('consoleDelegation.changeIt') + '</a>'
        : '<form method="post" action="/admin/delegation-settings">' +
          DelegationPage.permissionsBack(listView) + '<div class="formrow">' +
          '<input type="hidden" name="action" value="remove-permission">' +
          '<input type="hidden" name="resource" value="' +
          kit.esc(one.resource) +
          '"><input ' +
          'type="hidden" name="name" value="' + kit.esc(one.name) + '">' +
          '<button type="submit" class="danger">' +
          t.html('consoleDelegation.remove') + '</button>' +
          '</div></form>') + '</td>' +
      '</tr>';
  }

  // One row of the grants table: the RELATIONSHIP itself. `options.readOnly`
  // swaps the last cell for a link to the page that DOES have the form on it,
  // and is what lets the group picture at /admin/delegation/cluster list the
  // grants it is drawing without becoming a fourth door onto the register
  // (2026-09-02). It is a parameter rather than a second row function for the
  // reason kit.chooserPane() is one function drawn eight times: the six cells
  // before it are the whole of what a grant IS, and two copies of them is two
  // tables that come to disagree about what the access token will say.
  //
  // The picture pages are read-only ON PURPOSE — /admin/delegation/allowed says
  // so in as many words — so a Revoke drawn there would be the one control on a
  // page whose text says it has none, and it would answer by throwing the
  // reader back to a table three screens up on a different page, because
  // permissionsReturnTo() has nowhere else to send it.
  /**
   * Draws one grant of a permission to a client application.
   *
   * A grant whose permission no application defines is marked dangling.
   *
   * @param one - a grant from the configured register
   * @param listView - the list state carried into links and the form
   * @param options - optional; `readOnly` swaps the Revoke form for a link
   * @returns a <tr> as HTML
   */
  static permissionGrantRow(t, one, listView, options?) {
    const clientHref = '/admin/applications' +
      kit.queryWith(listView || {}, { application: one.client });
    const resourceHref = one.resource
      ? '/admin/applications' +
        kit.queryWith(listView || {}, { application: one.resource }) : '';
    return '<tr>' +
      '<td class="who"><a href="' + kit.esc(clientHref) + '">' +
      kit.esc(one.clientName) +
      '</a>' +
        (one.clientName === one.client ? ''
          : '<br><code>' + kit.esc(one.client) + '</code>') + '</td>' +
      '<td class="who">' + (one.resource
        ? '<a href="' + kit.esc(resourceHref) + '">' +
          kit.esc(one.resourceName) + '</a>'
        // A DANGLING GRANT NAMES NO RESOURCE, and the cell says why rather than
        // being empty. Both ways it can happen are named, because they are
        // different problems: one is a deleted application and the other is a
        // permission removed from under a grant that was made correctly.
        : '<span class="state-revoked" title="' +
          t.html('consoleDelegation.danglingTitle') + '">' +
          t.html('consoleDelegation.dangling') + '</span>') + '</td>' +
      '<td>' + (one.permissionName
        ? '<code>' + kit.esc(one.permissionName) + '</code>' +
          (one.description ?
           '<br><span class="state-none">' + kit.esc(one.description) +
                             '</span>' : '')
        : '<span class="state-none">&mdash;</span>') + '</td>' +
      '<td><code>' + kit.esc(one.permissionId) + '</code></td>' +
      // WHAT THE TOKEN WILL SAY, spelled out per row. It is the whole point of
      // the feature and it is two facts a reader would otherwise have to
      // compose from two other columns — which is exactly the arithmetic a
      // table should do for somebody.
      '<td>' + (one.baseUri
        ? '<code>aud: ' + kit.esc(one.baseUri) + '</code><br>' +
          '<code>scope: ' + kit.esc(one.permissionName) + '</code>'
        : '<span class="state-none">' +
          t.html('consoleDelegation.doesNotResolve') + '</span>') +
      '</td><td>' + (one.asked
        ? '<span class="state-valid" title="' +
          t.html('consoleDelegation.askedTitle') + '">' +
          t.html('consoleDelegation.askedFor') + '</span>'
        : '<span class="state-none" title="' +
          t.html('consoleDelegation.neverAskedTitle') + '">' +
          t.html('consoleDelegation.neverAskedFor') + '</span>') + '</td>' +
      '<td>' + (options && options.readOnly
        ? '<a href="/admin/delegation-settings#allowed" title="' +
          t.html('consoleDelegation.changeRevokeTitle') + '">' +
          t.html('consoleDelegation.changeIt') + '</a>'
        : '<form method="post" action="/admin/delegation-settings">' +
          DelegationPage.permissionsBack(listView) + '<div class="formrow">' +
          '<input type="hidden" name="action" value="revoke-permission">' +
          '<input type="hidden" name="client" value="' + kit.esc(one.client) +
          '"><input type="hidden" name="permission" value="' +
          kit.esc(one.permissionId) + '"><button ' +
          'type="submit" class="danger">' +
          t.html('consoleDelegation.revoke') + '</button></div></form>') +
          '</td>' +
      '</tr>';
  }

  // THE LIST STATE, AS ONE FIELD, FOR THE ROW BUTTONS OF THE CONFIGURED
  // REGISTER.
  //
  // It cost nothing while /admin/delegation drew every row it had: a Revoke
  // answered with a redirect to the top of the register and the row that had
  // gone was on the screen anyway. With seven paged tables and two searches on
  // that page it is the difference between a Revoke that answers where you were
  // standing and one that throws you back to page 1 of an unfiltered list,
  // three screens up, with the search you were reading by cleared.
  //
  // One opaque field rather than the parameters loose in the body, for the
  // reason /admin/applications' `carryBack` gives: an action reads its own body
  // BY NAME, and a `q` or a `permissionsPage` loose in there is a field some
  // action added later could pick up by accident. permissionsReturnTo()
  // rebuilds a query from it through kit.listViewOf()'s whitelist rather than
  // echoing it, which is what keeps a hand-written `back` from becoming a
  // redirect somewhere this file did not write.
  /**
   * Draws the hidden `back` input the permission forms carry.
   *
   * @param listView - the list state to return to
   * @returns an <input> as HTML
   */
  static permissionsBack(listView) {
    return '<input type="hidden" name="back" value="' +
           kit.esc(kit.queryWith(listView || {}, {})) + '">';
  }

  // ---------------------------------------------------------------------------
  // WHO MAY ACT FOR WHOM AT WS-TRUST AND THE TOKEN EXCHANGE (#108,
  // 2026-09-23) — the section of /admin/delegation drawn from
  // `adminViews.delegationPolicyView()`, the function GET
  // /admin-api/delegation/policy answers with. READ ONLY here: each value is
  // an attribute on an application or a person, so it is edited where every
  // attribute of one is — the application's page (and POST
  // /admin-api/applications/set, /add and /remove) and the person's page
  // (and POST /admin-api/users/set-not-delegated, /set-may-act). A second
  // form here
  // would be a second door onto the same attribute, which this console
  // refuses everywhere else.
  // ---------------------------------------------------------------------------
  /**
   * Draws who may act for whom at WS-Trust and RFC 8693, read only.
   *
   * Three paged tables: the pairs, the intermediaries and the people who
   * carry either flag.
   *
   * @param ctx - the render context, for the page parameters
   * @param view - the view from adminViews.delegationPolicyView()
   * @returns the section as HTML
   */
  static delegationPolicySection(ctx, view) {
    // The section's words are the page's translator's (#539 phase 6); a
    // pair's own warning comes from the view and is drawn as it comes.
    const t = ctx.t;
    const navParams = kit.pageParamsOf(ctx.query);
    const pairsNav = kit.pageNavPair('/admin/delegation', navParams,
                                      view.pairs.paging);
    const intermediariesNav = kit.pageNavPair('/admin/delegation', navParams,
                                               view.intermediaries.paging);
    const peopleNav = kit.pageNavPair('/admin/delegation', navParams,
                                       view.people.paging);
    const appLink = function (identifier) {
      // The application's page is `?application=`, not a path segment:
      // `/admin/applications/<id>` is no route and 404s, which the console
      // crawl in `sts_admin_console.js` reports (2026-09-23).
      return '<a href="' + kit.esc('/admin/applications?application=' +
        encodeURIComponent(String(identifier))) + '"><code>' +
        kit.esc(identifier) + '</code></a>';
    };
    const pairRows = view.pairs.shown.map(function (pair) {
      return '<tr><td><code>' + kit.esc(pair.mechanism) + '</code></td>' +
        '<td class="who">' + appLink(pair.intermediary) +
        (pair.impersonates ? '<br><span class="state-expired">' +
          t.html('consoleDelegation.mayImpersonate') + '</span>' : '') +
        '</td>' +
        '<td class="who"><code>' + kit.esc(pair.target) + '</code>' +
        (pair.targetApplication && pair.targetApplication !== pair.target
          ? '<br><span class="state-none">' +
            t.html('consoleDelegation.theApplication',
                   { name: pair.targetApplication }) + '</span>' : '') +
        '</td>' +
        '<td class="who"><code>' + kit.esc(pair.attribute) + '</code><br>' +
        '<span class="state-none">' +
        t.html('consoleDelegation.onThe', { role: pair.setOnRole }) +
        ', ' + appLink(pair.setOn) + '</span></td>' +
        '<td>' + (pair.subjectGroups.length
          ? pair.subjectGroups.map(function (dn) {
            return '<code>' + kit.esc(dn) + '</code>';
          }).join('<br>')
          : t.html('consoleDelegation.anybodyNotProtected')) + '</td>' +
        '<td>' + (pair.warning
          ? '<span class="state-expired">' + kit.esc(pair.warning) +
            '</span>'
          : '<span class="state-valid">' +
            t.html('consoleDelegation.nothingMissing') + '</span>') +
        '</td></tr>';
    }).join('');
    const intermediaryRows = view.intermediaries.shown.map(function (row) {
      return '<tr><td class="who">' + appLink(row.application) + '</td>' +
        '<td>' + (row.semantics && row.semantics.length
          ? row.semantics.map(function (one: string) {
            return kit.esc(one);
          }).join(', ') : t.html('consoleDelegation.delegationOnly')) +
        (row.defaultSemantics ? '<br><span class="state-none">' +
          t.html('consoleDelegation.defaultSemantics',
                 { value: row.defaultSemantics }) + '</span>' : '') +
        (row.notDelegated ? '<br>' +
          t.html('consoleDelegation.appNeverActedFor') : '') +
        '</td><td>' + (row.subjectGroups.length
          ? row.subjectGroups.map(function (dn) {
            return '<code>' + kit.esc(dn) + '</code>';
          }).join('<br>') : t.html('consoleDelegation.anybodyNotProtected')) +
        '</td></tr>';
    }).join('');
    const peopleRows = view.people.shown.map(function (row) {
      return '<tr><td class="who"><a href="' + kit.esc('/admin/users?user=' +
        encodeURIComponent(String(row.username))) + '">' +
        kit.esc(row.username) + '</a></td><td>' +
        (row.notDelegated ? t.html('consoleDelegation.personNeverActedFor')
                          : '&mdash;') + '</td><td>' +
        (row.mayAct ? '<code>' + kit.esc(row.mayAct) + '</code>'
                    : '&mdash;') + '</td><td>' +
        ((row.semantics && row.semantics.length) || row.defaultSemantics
          ? kit.esc((row.semantics || []).join(', ') ||
                    t.text('consoleDelegation.both')) +
            (row.defaultSemantics ? '; ' +
              t.html('consoleDelegation.defaultSemantics',
                     { value: row.defaultSemantics }) : '')
          : '&mdash;') + '</td></tr>';
    }).join('');
    const register = view.register;
    return '<h2 id="delegation-policy">' +
      t.html('consoleDelegation.hPolicy') + '</h2>' +
      kit.note(t.html('consoleDelegation.policyLead') +
      (register.protectedGroups.length
        ? register.protectedGroups.map(function (one) {
          return '<code>' + kit.esc(one) + '</code>';
        }).join(' ' + t.html('consoleDelegation.orWord') + ' ')
        : t.html('consoleDelegation.aConsoleRoster')) +
      t.html('consoleDelegation.policyNeverDelegated') +
      (register.enforced
        ? t.html('consoleDelegation.policyEnforced')
        : t.html('consoleDelegation.policyNotEnforced')) +
      t.html('consoleDelegation.policyEdit')) +
      pairsNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thMechanism') +
      '</th><th>' + t.html('consoleDelegation.thIntermediary') + '</th>' +
      '<th>' + t.html('consoleDelegation.thTargetReached') + '</th><th>' +
      t.html('consoleDelegation.thAttributeWhere') + '</th><th>' +
      t.html('consoleDelegation.thMayActFor') + '</th><th>' +
      t.html('consoleDelegation.thMissing') + '</th></tr>' +
      (pairRows || '<tr><td colspan="6">' +
        (register.enforced ? t.html('consoleDelegation.noPairsEnforced')
                           : t.html('consoleDelegation.noPairsDevelopment')) +
        '</td></tr>') + '</table>' + pairsNav.foot +
      '<h3>' + t.html('consoleDelegation.hIntermediaries') + '</h3>' +
      intermediariesNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thApplication') +
      '</th><th>' + t.html('consoleDelegation.thSemantics') + '</th>' +
      '<th>' + t.html('consoleDelegation.thMayActFor') + '</th></tr>' +
      (intermediaryRows || '<tr><td colspan="3">' +
        t.html('consoleDelegation.noIntermediaries') + '</td></tr>') +
      '</table>' + intermediariesNav.foot +
      '<h3>' + t.html('consoleDelegation.hPeople') + '</h3>' +
      kit.note(t.html('consoleDelegation.mayActNote')) +
      peopleNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thPerson') +
      '</th><th>' + t.html('consoleDelegation.thCannotBeDelegated') +
      '</th><th>' + t.html('consoleDelegation.thMayActForThem') +
      '</th><th>' + t.html('consoleDelegation.thSemantics') + '</th></tr>' +
      (peopleRows || '<tr><td colspan="4">' +
        t.html('consoleDelegation.nobodyCarries') + '</td></tr>') +
      '</table>' + peopleNav.foot;
  }

  // The whole configured section. Extracted into a function of its own because
  // the delegation page's `inner` is already the longest expression in this
  // console and a fourth screen of string concatenation inside it would be
  // unreadable.
  //
  // **IT IS DRAWN ON TWO PAGES SINCE 2026-10-01, AND ONLY ONE OF THEM CHANGES
  // ANYTHING** (rcbj). Monitoring → Delegation (/admin/delegation) is what
  // HAPPENED, and a register of what is ALLOWED drawn there is the reading the
  // acts are compared against — so it keeps the tables, read-only, with every
  // row button swapped for a link (the `readOnly` the picture pages already
  // pass). Protocols → Delegation (/admin/delegation-settings) is where the
  // register is CONFIGURED: the same tables with their Remove and Revoke
  // buttons, Expose an API and Define a permission for any application, and
  // the page's one setting. One function, so the two pages cannot come to
  // disagree about what a row says; `editable` decides only the controls and
  // which page the searches and pagings stay on.
  /**
   * Draws the delegated permissions register: the paged permissions and
   * grants tables, and — when editable — the Expose an API and Define a
   * permission forms and each row's button.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param view - the delegation view holding the register, with
   *   `listState` (`permissionsListState()`'s answer) and `allApplications`
   *   (every application in the registry, for the two selects)
   * @param listView - the list state carried into links and forms
   * @param editable - true on Protocols → Delegation, which configures the
   *   register; false on Monitoring → Delegation, which only reads it
   * @returns the section as HTML
   */
  static permissionsSection(ctx, view, listView, editable) {
    // The section's words are the page's translator's (#539 phase 6). A
    // link carries an href, which a message may not, so a sentence around
    // one is split into messages with the anchor in the code.
    const t = ctx.t;
    // The page this section is on: its searches and pagings stay there.
    const here = editable ? '/admin/delegation-settings' : '/admin/delegation';
    const rowOptions = editable ? undefined : { readOnly: true };
    const register = view.register;
    const counts = register.counts;
    // Every application in the registry, for the two selects. A select rather
    // than a text box because BOTH sides of a grant must already be entries —
    // there is nothing to type that is not on this list, and a typed identifier
    // that did not match would be refused with a sentence the reader could have
    // been spared.
    const all = view.allApplications;
    const applicationOptions = all.map(function (row) {
      return '<option value="' + kit.esc(row.identifier) + '">' +
             kit.esc(row.name && row.name !== row.identifier
               ? row.name + ' — ' + row.identifier : row.identifier) +
             '</option>';
    }).join('');
    // Only the permissions that HAVE an identifier can be granted, so only
    // those are offered. One with no base URI is on the table above with the
    // reason.
    const grantable = register.permissions.filter(function (
        one) { return !!one.id; });

    // -------------------------------------------------------------------------
    // THE TWO SEARCHES AND THE TWO PAGINGS (2026-09-01).
    //
    // Both tables here are unbounded — one row per permission defined and one
    // row per (client, permission) — and a service driven for an afternoon puts
    // tens of each on a page that already carries five other tables. Ten rows a
    // page is what makes the page navigable at all; DELEGATION_PER_PAGE argues
    // the number.
    //
    // THE SEARCH IS OVER THE APPLICATION AND NOT OVER THE WHOLE ROW, and the
    // two tables answer it differently because a permission has ONE application
    // in it and a grant has TWO. `permq` searches the application that EXPOSES
    // the permission; `grantq` searches BOTH ends of the relationship, for the
    // reason the acts table's own box gives — the fact a reader arrives with
    // names one of the two and they do not know which column it will be in.
    // Both match on the display name AND on the identifier, because half the
    // names in this registry are the identifier and the other half are not, and
    // a reader pastes whichever one the page showed them last.
    //
    // Filter first, then page — pagingOf()'s rule, and for its reason: paging a
    // list and then filtering it gives a page 2 whose length depends on what
    // page 1 happened to hold.
    // -------------------------------------------------------------------------
    const state = view.listState;
    const permWanted = state.permWanted;
    const grantWanted = state.grantWanted;
    const permPage = state.permPage;
    const grantPage = state.grantPage;
    // EVERY parameter the reader is already carrying, so that paging one table
    // moves nothing else on the page — the six other lists, both chooser
    // searches and the other table's own search all ride along.
    // kit.pageNavPair() overrides only the one name off the paging object it is
    // handed.
    const navParams = kit.pageParamsOf(ctx.query);
    const permNav = kit.pageNavPair(here, navParams, permPage.paging);
    const grantNav = kit.pageNavPair(here, navParams, grantPage.paging);

    return '<h2 id="allowed">' + t.html('consoleDelegation.hAllowed') +
      '</h2>' +

      kit.note(t.html('consoleDelegation.allowedEvidence')) +

      kit.note(t.html('consoleDelegation.allowedResourceBefore') +
      '<a href="/admin/applications">' +
      t.html('consoleDelegation.applicationsLink') + '</a>' +
      t.html('consoleDelegation.allowedResourceAfter')) +

      kit.note(t.html('consoleDelegation.allowedScope')) +

      kit.note('<strong>' + t.html('consoleDelegation.allowedProductBefore') +
      '<a href="/admin/oauth2">' +
      t.html('consoleDelegation.oauthSettingsLink') + '</a>.</strong>' +
      t.html('consoleDelegation.allowedProductAfter')) +

      '<div class="tiles">' +
        kit.tile(counts.resources,
                 t.text('consoleDelegation.tileResources')) +
        kit.tile(counts.permissions,
                 t.text('consoleDelegation.tilePermissions')) +
        kit.tile(counts.grants, t.text('consoleDelegation.tileGrants')) +
        kit.tile(counts.clients, t.text('consoleDelegation.tileClients')) +
        kit.tile(counts.unused, t.text('consoleDelegation.tileUnused')) +
        kit.tile(counts.dangling, t.text('consoleDelegation.dangling')) +
      '</div>' +

      kit.note('<a class="btn" href="/admin/delegation/allowed">' +
      t.html('consoleDelegation.seeAllowedPicture') + ' &rarr;</a> ' +
      t.html('consoleDelegation.secondDiagramBefore') + '<a ' +
      'href="/admin/delegation/map">' +
      t.html('consoleDelegation.actsPictureLink') + '</a>' +
      t.html('consoleDelegation.secondDiagramAfter')) +

      '<h3 id="permissions">' + t.html('consoleDelegation.hPermissions') +
      '</h3>' +
      kit.note(t.html('consoleDelegation.permissionsLead')) +
      kit.sectionSearchForm({
        path: here, query: ctx.query,
        param: 'permq', pageParam: 'permissionsPage',
        label: t.text('consoleDelegation.narrowLabel'),
        placeholder: t.text('consoleDelegation.narrowPlaceholder'),
        what: t.html('consoleDelegation.permSearchWhat')
      }, t) +
      permNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thExposedBy') +
      '</th><th>' + t.html('consoleDelegation.thPermission') + '</th><th>' +
      t.html('consoleDelegation.thIdentifierSent') + '</th><th>' +
      t.html('consoleDelegation.thHeldBy') + '</th><th>' +
      t.html('consoleDelegation.thWhichApplications') +
      '</th><th></th></tr>' +
      (permPage.shown.map(function (one) {
        return DelegationPage.permissionDefinitionRow(t, one, listView,
                                                      rowOptions);
      }).join('') || '<tr><td colspan="6">' +
        (permWanted
          ? t.html('consoleDelegation.noPermMatch', { wanted: permWanted }) +
            ' ' +
            (register.permissions.length
              ? t.html('consoleDelegation.permsElsewhere',
                       { n: register.permissions.length })
              : t.html('consoleDelegation.noPermsAtAll'))
          : t.html('consoleDelegation.noApiYet')) +
        '</td></tr>') +
      '</table>' +
      permNav.foot +

      (editable ? '' :
        kit.note(t.html('consoleDelegation.readOnlyBefore') + '<a ' +
        'href="/admin/delegation-settings#allowed">' +
        t.html('consoleDelegation.protocolsDelegationLink') + '</a>' +
        t.html('consoleDelegation.readOnlyMiddle') + '<a ' +
        'href="/admin/applications">' +
        t.html('consoleDelegation.directoryApplicationsLink') + '</a>' +
        t.html('consoleDelegation.readOnlyAfter'))) +

      (!editable ? '' :
        '<h4>' + t.html('consoleDelegation.hExposeApi') + '</h4>' +
        kit.note(t.html('consoleDelegation.exposeApiNote')) +
        '<form method="post" action="/admin/delegation-settings">' +
        DelegationPage.permissionsBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="set-permission-base">' +
        '<label for="base-resource">' +
        t.html('consoleDelegation.labelApplication') + '</label>' +
        '<select id="base-resource" name="resource">' + applicationOptions +
        '</select><label for="baseUri">' +
        t.html('consoleDelegation.labelBaseUri') +
        '</label><input type="text" ' +
        'id="baseUri" name="baseUri" size="34" ' +
        'placeholder="https://example.com/"><button type="submit">' +
        t.html('consoleDelegation.setBaseUri') + '</button></div></form>' +
        '<h4>' + t.html('consoleDelegation.hDefinePermission') + '</h4>' +
        kit.note(t.html('consoleDelegation.definePermissionNote')) +
        '<form method="post" action="/admin/delegation-settings">' +
        DelegationPage.permissionsBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="define-permission">' +
        '<label for="perm-resource">' +
        t.html('consoleDelegation.thExposedBy') + '</label>' +
        '<select id="perm-resource" name="resource">' + applicationOptions +
        '</select><label for="perm-name">' +
        t.html('consoleDelegation.labelName') +
        '</label><input type="text" ' +
        'id="perm-name" name="name" size="18" placeholder="write"><label ' +
        'for="perm-description">' +
        t.html('consoleDelegation.labelDescription') +
        '</label><input type="text" ' +
        'id="perm-description" name="description" size="34" ' +
        'placeholder="' +
        t.html('consoleDelegation.descriptionPlaceholder') + '"><button ' +
        'type="submit">' + t.html('consoleDelegation.defineIt') +
        '</button></div></form>') +
      '<h3 id="grants">' + t.html('consoleDelegation.hGrants') + '</h3>' +
      kit.note(t.html('consoleDelegation.grantsLead')) +
      kit.sectionSearchForm({
        path: here, query: ctx.query,
        param: 'grantq', pageParam: 'grantsPage',
        label: t.text('consoleDelegation.narrowLabel'),
        placeholder: t.text('consoleDelegation.narrowPlaceholder'),
        what: t.html('consoleDelegation.grantSearchWhat')
      }, t) +
      grantNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thClientWho') +
      '</th><th>' + t.html('consoleDelegation.thResourceWhat') + '</th><th>' +
      t.html('consoleDelegation.thPermission') + '</th><th>' +
      t.html('consoleDelegation.thIdentifier') + '</th><th>' +
      t.html('consoleDelegation.thTokenWillSay') + '</th><th>' +
      t.html('consoleDelegation.thEverAsked') + '</th><th></th></tr>' +
      (grantPage.shown.map(function (one) {
        return DelegationPage.permissionGrantRow(t, one, listView,
                                                 rowOptions);
      }).join('') || '<tr><td colspan="7">' +
        (grantWanted
          ? t.html('consoleDelegation.noGrantMatch', { wanted: grantWanted }) +
            ' ' +
            (register.grants.length
              ? t.html('consoleDelegation.grantsElsewhere',
                       { n: register.grants.length })
              : t.html('consoleDelegation.noGrantsAtAll'))
          : t.html('consoleDelegation.nothingGrantedYet')) +
        '</td></tr>') +
      '</table>' +
      grantNav.foot +

      '<h4>' + t.html('consoleDelegation.hGrantPermission') + '</h4>' +
      (grantable.length
        ? kit.note(t.html('consoleDelegation.grantOnPagesBefore') +
          '<a href="/admin/applications">' +
          t.html('consoleDelegation.directoryApplicationsLink') + '</a>' +
          t.html('consoleDelegation.grantOnPagesAfter'))
        : kit.note(t.html('consoleDelegation.nothingToGrantBefore') + '<a ' +
          'href="/admin/applications">' +
          t.html('consoleDelegation.directoryApplicationsLink') + '</a>' +
          t.html('consoleDelegation.nothingToGrantAfter'))) +

      kit.note(t.html('consoleDelegation.ordinaryAttributes'));
  }


  // ---------------------------------------------------------------------------
  // /admin/delegation/map, FROM `GET /admin-api/delegation/map` (#446).
  //
  // The picture of every act that matched the filter: the drawing (laid out
  // on the server), the filter, the two choosers, the key, and the parties,
  // lines and credentials in words. The way back and the filter are read off
  // the query the page was asked with.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation/map` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation/map`
   * @returns the body as HTML
   */
  static map(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6); a mechanism's
    // label, a mode's label and the key drawn on the server come from the
    // view and are drawn as they come.
    const t = ctx.t;
    const filter = json.filter || {};
    const wanted = { type: filter.type || '', mode: filter.mode || '',
                     outcome: filter.outcome || '',
                     protocol: filter.protocol || '', q: filter.q || '' };
    const upHref = '/admin/delegation' +
      kit.queryWith(kit.listViewOf('/admin/delegation', ctx.query), {});
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    const parties = json.nodes.filter(function (node) {
      return node.kind !== 'sts';
    });
    const filtering = wanted.type || wanted.mode ||
                      wanted.outcome ||
                      wanted.protocol || wanted.q;

    // The filter, exactly the table's, so that narrowing the picture and
    // narrowing the table are one control rather than two that could take
    // different values. It is a GET form and carries no `page`: this page has
    // none, and a page number carried into a view with no paging is a
    // parameter that does nothing and comes back with the reader on the next
    // hop.
    const protocolsInOrder = [];
    json.types.forEach(function (entry) {
      if (protocolsInOrder.indexOf(entry.protocol) < 0) {
        protocolsInOrder.push(entry.protocol);
      }
    });
    const typeOptions = '<option value=""' +
      (wanted.type ? '' : ' selected') +
      '>' + t.html('consoleDelegation.anyMechanism') + '</option>' +
      protocolsInOrder.map(function (protocol) {
        return '<optgroup label="' + kit.esc(protocol) + '">' +
          json.types.filter(function (entry) {
            return entry.protocol === protocol;
          }).map(function (entry) {
            return '<option value="' + kit.esc(entry.type) + '"' +
                   (entry.type === wanted.type ? ' selected' : '') + '>' +
                   kit.esc(entry.label) + ' (' +
                   (json.summary.byType[entry.type] || 0) +
                   ')</option>';
          }).join('') + '</optgroup>';
      }).join('');
    const modeOptions = ['<option value=""' +
                         (wanted.mode ? '' : ' selected') +
                         '>' + t.html('consoleDelegation.eitherKind') +
                         '</option>']
      .concat(json.modes.map(function (entry) {
        return '<option value="' + kit.esc(entry.mode) + '"' +
               (entry.mode === wanted.mode ? ' selected' : '') + '>' +
               kit.esc(entry.label) + ' (' +
               (json.summary.byMode[entry.mode] || 0) +
               ')</option>';
      })).join('');
    const outcomeOptions = ['<option value=""' +
                            (wanted.outcome ? '' : ' ' +
        'selected') +
                            '>' + t.html('consoleDelegation.anyOutcome') +
                            '</option>']
      .concat(json.outcomes.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
               (name === wanted.outcome ? ' selected' : '') + '>' +
               kit.esc(name) +
               ' (' + (json.summary.byOutcome[name] || 0) + ')</option>';
      })).join('');

    // THE WAY BACK, AT THE TOP, ABOVE EVERYTHING. The trail under the nav
    // already offers it and this is deliberately a second one: the trail is
    // a strip of small grey text a reader learns to look at, and somebody
    // who followed a link into a diagram is looking at the diagram. It
    // carries the filter, so "back" means the table they came from and not
    // the top of an unfiltered one.
    return kit.note('<a class="btn" href="' + kit.esc(upHref) +
                '">&larr; ' + t.html('consoleDelegation.backToTable') +
                '</a>') +

      '<div class="tiles">' +
        kit.tile(parties.length, t.text('consoleDelegation.tileParties')) +
        kit.tile(json.edges.filter(function (e) {
          return e.relation !== 'issued';
        }).length,
                  t.text('consoleDelegation.tileRelationships')) +
        kit.tile(json.chains, t.text('consoleDelegation.tileChains')) +
        kit.tile(json.acts, t.text('consoleDelegation.tileActsDrawn')) +
        kit.tile(json.summary.byMode.impersonation || 0,
                 t.text('consoleDelegation.tileImpersonations')) +
        kit.tile(json.tokens.length,
                 t.text('consoleDelegation.tileCredentialsIssued')) +
      '</div>' +

      // The headline holds a link, so its <strong> is in the code and the
      // words either side of the anchor are messages of their own.
      kit.note('<strong>' + t.html('consoleDelegation.mapSameActsBefore') +
      '<a href="' + kit.esc(upHref) +
      '">' + t.html('consoleDelegation.theTable') + '</a>' +
      t.html('consoleDelegation.mapSameActsAfter') + '</strong>' +
      t.html('consoleDelegation.mapSameActsRest')) +

      kit.note(t.html('consoleDelegation.mapMatched', { n: json.matched }) +
      (json.all !== json.matched
        ? t.html('consoleDelegation.mapOfHeld', { all: json.all }) : '') +
      t.html('consoleDelegation.mapAllInPicture')) +

      '<form method="get" action="/admin/delegation/map"><div ' +
      'class="formrow">' +
        DelegationPage.chooserCarry(ctx.query) +
        '<label for="type">' + t.html('consoleDelegation.thMechanism') +
        '</label><select id="type" name="type">' +
          typeOptions + '</select>' +
        '<label for="mode">' + t.html('consoleDelegation.labelKind') +
        '</label><select id="mode" name="mode">' +
          modeOptions + '</select>' +
        '<label for="outcome">' + t.html('consoleDelegation.labelOutcome') +
        '</label><select id="outcome" ' +
        'name="outcome">' +
          outcomeOptions + '</select>' +
      '</div><div class="formrow">' +
        '<label for="q">' + t.html('consoleDelegation.labelText') +
        '</label>' +
        '<input type="text" id="q" name="q" size="40" value="' +
      kit.esc(wanted.q) +
          '" placeholder="' +
          kit.esc(t.text('consoleDelegation.textPlaceholder')) + '">' +
        '<button class="secondary">' + t.html('consoleDelegation.redraw') +
        '</button>' +
        (filtering ? ' <a href="/admin/delegation/map">' +
          t.html('consoleDelegation.clear') + '</a>' : '') +
      '</div></form>' +
      kit.note(t.html('consoleDelegation.mapSameFilter')) +

      // THE TWO PIVOTS, HERE AS WELL AS ON THE TABLE, and this is where the
      // person one was actually asked for: somebody looking at a picture
      // wants to narrow the PICTURE, and the text box above narrows it to
      // acts that mention a name where these two redraw it around one party.
      // They are the same two controls the delegation table carries, so a
      // reader who learnt them there finds them here.
      //
      // The difference between them is worth the sentence: the application
      // chooser stays inside this register, and the person chooser leaves it
      // — that page also draws the ordinary issuance, which is most of what
      // happens in somebody's name and none of what is on this diagram.
      kit.note(t.html('consoleDelegation.mapOnePartyInstead')) +
      DelegationPage.delegationApplicationChooser(t, json.applicationChooser,
        '', { path: '/admin/delegation/map', query: ctx.query }) +
      DelegationPage.delegationUserChooser(t, json.userChooser, '',
        { path: '/admin/delegation/map', query: ctx.query }) +

      (json.acts
        ? DelegationPage.drawing(t, json, '/admin/delegation/map', wanted)
        : kit.note((filtering
            ? t.html('consoleDelegation.mapNothingFiltered')
            : t.html('consoleDelegation.mapNothing')) +
          t.html('consoleDelegation.mapNothingThree'))) +

      '<h2>' + t.html('consoleDelegation.hKey') + '</h2>' +
      kit.note(t.html('consoleDelegation.keyNote')) +
      json.mapKey +

      '<h2>' + t.html('consoleDelegation.hParties') + '</h2>' +
      kit.note(t.html('consoleDelegation.partiesNote') +
      (json.directoryLoaded ? '' :
        t.html('consoleDelegation.noDirectory'))) +
      '<table><tr><th>' + t.html('consoleDelegation.thLabel') +
      '</th><th>' + t.html('consoleDelegation.thDrawnAs') + '</th><th>' +
      t.html('consoleDelegation.thIdentity') + '</th>' +
      '<th>' + t.html('consoleDelegation.thRolesItPlayed') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thProtocols') + '</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(t, node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">' +
        t.html('consoleDelegation.noPartiesYet') + '</td></tr>') +
      '</table><h2>' + t.html('consoleDelegation.hRelationships') +
      '</h2>' +
      kit.note(t.html('consoleDelegation.relationshipsNote')) +
      kit.note(t.html('consoleDelegation.lastColumnNote')) +
      '<table><tr><th>' + t.html('consoleDelegation.thFrom') + '</th><th>' +
      t.html('consoleDelegation.thTo') + '</th><th>' +
      t.html('consoleDelegation.thRelationship') + '</th>' +
      '<th>' + t.html('consoleDelegation.thMechanism') + '</th><th>' +
      t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thWhatCameOut') + '</th>' +
      '<th>' + t.html('consoleDelegation.thAuthorizedBy') + '</th></tr>' +
      (json.edges.map(function (edge) {
        return DelegationPage.delegationEdgeRow(t, edge, labelOf);
      }).join('') || '<tr><td colspan="8">' +
        t.html('consoleDelegation.noRelationshipsYet') + '</td></tr>') +
      '</table>' +

      '<h2>' + t.html('consoleDelegation.hWhatIssued') + '</h2>' +
      kit.note(t.html('consoleDelegation.whatIssuedNote')) +
      kit.note(t.html('consoleDelegation.refusedProducedNothing',
                      { tokens: json.tokens.length, acts: json.acts })) +
      '<table><tr><th class="num">#</th><th>' +
      t.html('consoleDelegation.thWhen') + '</th><th>' +
      t.html('consoleDelegation.thCredential') + '</th>' +
      '<th>' + t.html('consoleDelegation.thSubject') + '</th><th>' +
      t.html('consoleDelegation.thActor') + '</th><th>' +
      t.html('consoleDelegation.thTarget') + '</th><th>' +
      t.html('consoleDelegation.thMechanism') + '</th>' +
      '</tr>' +
      (json.tokens.map(function (token) {
        return DelegationPage.delegationTokenRow(t, token, labelOf);
      }).join('') ||
        '<tr><td colspan="7">' +
        t.html('consoleDelegation.nothingIssuedThrough') +
        '</td></tr>') + '</table>' +
      (json.tokensLeftOff
        ? kit.note(t.html('consoleDelegation.tokensLeftOff', {
            n: json.tokensLeftOff, max: json.maxTokenRows }))
        : '') +

      '<h2>' + t.html('consoleDelegation.hCannotSay') + '</h2>' +
      kit.note(t.html('consoleDelegation.impersonationInvisible')) +
      kit.note(t.html('consoleDelegation.lineIsRelationship') + '<a href="' +
      kit.esc(upHref) + '">' + t.html('consoleDelegation.theTableCap') +
      '</a>' + t.html('consoleDelegation.lineIsRelationshipAfter')) +
      kit.note(t.html('consoleDelegation.whoMayBefore') + '<a ' +
      'href="' + kit.esc(upHref) + '">' +
      t.html('consoleDelegation.theDelegationPage') + '</a>' +
      t.html('consoleDelegation.whoMayAfter')) +
      kit.note(t.html('consoleDelegation.noScript')) +
      kit.note(t.html('consoleDelegation.mapFormats'));

  }

  // ---------------------------------------------------------------------------
  // /admin/delegation/chain, FROM `GET /admin-api/delegation/chain` (#446).
  //
  // One relationship drawn alone: the sentence that says which, the drawing,
  // the key, its parties, lines, credentials and every act on it — or, for
  // a key no act is held under, which of the two reasons that is.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation/chain` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation/chain`
   * @returns the body as HTML
   */
  static chain(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6).
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const upHref = '/admin/delegation' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; ' + t.html('consoleDelegation.backToTable') + '</a>');
    const chain = json.chain;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!chain) {
      return back +
        (json.chainKey
          ? kit.note(t.html('consoleDelegation.chainGone',
                            { key: json.chainKey, max: json.maxRecords }) +
            '<a href="/admin/delegation-settings">' +
            t.html('consoleDelegation.protocolsDelegationLink') + '</a>' +
            t.html('consoleDelegation.chainGoneAfter'))
          : kit.note(t.html('consoleDelegation.chainNameOne') +
            '<a href="' + kit.esc(upHref) +
            '">' + t.html('consoleDelegation.theDelegationTable') + '</a>' +
            t.html('consoleDelegation.chainNameOneAfter'))) +
        kit.note('<a href="/admin/delegation/map">' +
        t.html('consoleDelegation.wholePicture') + '</a>' +
        t.html('consoleDelegation.wholePictureHeld'));
    }
    const parties = json.graph.nodes.filter(function (node) {
      return node.kind !== 'sts';
    });

    // The chain as ONE SENTENCE, above everything. It is the row the reader
    // clicked, said in words: the table gave them four columns and this page
    // has to open by confirming it is describing the same four, or a reader
    // who followed the wrong link finds out three tables later.
    const sentence =
      kit.note('<strong>' +
      kit.esc(chain.initial.presented || chain.initial.application ||
               t.text('consoleDelegation.somebodyNobodyNamed')) +
      '</strong> — ' +
      (chain.intermediary.presented || chain.intermediary.application
        ? t.html('consoleDelegation.actedForBy', {
            name: chain.intermediary.presented ||
                  chain.intermediary.application })
        : '<span class="state-none">' +
          t.html('consoleDelegation.noIntermediaryNamed') + '</span>') +
      t.html('consoleDelegation.reaching', {
        target: chain.target.application || chain.target.presented ||
                t.text('consoleDelegation.nothingInParticular'),
        type: chain.type, label: chain.typeLabel,
        protocol: chain.protocol }) +
      DelegationPage.modeCell(t, chain.mode) +
      t.html('consoleDelegation.happened', {
        acts: chain.acts, first: kit.whenText(chain.firstAt),
        last: kit.whenText(chain.lastAt) }));

    return back +
      '<div class="tiles">' +
        kit.tile(chain.acts, t.text('consoleDelegation.tileActsOnIt')) +
        kit.tile(chain.issued, t.text('consoleDelegation.outcomeIssued')) +
        kit.tile(chain.refused, t.text('consoleDelegation.outcomeRefused')) +
        kit.tile(json.graph.tokens.length,
                 t.text('consoleDelegation.tileCredentialsIssued')) +
        kit.tile(parties.length, t.text('consoleDelegation.tileParties')) +
        kit.tile(json.graph.edges.filter(function (e) {
          return e.relation !== 'issued';
        }).length,
                  t.text('consoleDelegation.tileLines')) +
      '</div>' +

      sentence +

      kit.note('<strong>' + t.html('consoleDelegation.oneRowOf') +
      '<a href="' + kit.esc(upHref) +
      '">' + t.html('consoleDelegation.theChainsTable') + '</a>' +
      t.html('consoleDelegation.drawnOnItsOwn') + '</strong>' +
      t.html('consoleDelegation.chainIs') +
      '<a href="/admin/delegation/map">' +
      t.html('consoleDelegation.theWholePicture') + '</a>' +
      t.html('consoleDelegation.chainIsAfter')) +

      (json.graph.acts
        ? DelegationPage.drawing(t, json, '/admin/delegation/chain',
          Object.assign({}, listView, { chain: json.chainKey }))
        : kit.note(t.html('consoleDelegation.nothingToDraw'))) +

      '<h2>' + t.html('consoleDelegation.hKey') + '</h2>' +
      kit.note(t.html('consoleDelegation.keyNote')) +
      json.mapKey +

      '<h2>' + t.html('consoleDelegation.hParties') + '</h2>' +
      kit.note(t.html('consoleDelegation.chainParties')) +
      '<table><tr><th>' + t.html('consoleDelegation.thLabel') +
      '</th><th>' + t.html('consoleDelegation.thDrawnAs') + '</th><th>' +
      t.html('consoleDelegation.thIdentity') + '</th>' +
      '<th>' + t.html('consoleDelegation.thRolesItPlayed') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thProtocols') + '</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(t, node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">' +
        t.html('consoleDelegation.noParties') + '</td></tr>') +
        '</table>' +

      '<h2>' + t.html('consoleDelegation.hRelationships') + '</h2>' +
      kit.note(t.html('consoleDelegation.chainRelationships')) +
      '<table><tr><th>' + t.html('consoleDelegation.thFrom') + '</th><th>' +
      t.html('consoleDelegation.thTo') + '</th><th>' +
      t.html('consoleDelegation.thRelationship') + '</th><th>' +
      t.html('consoleDelegation.thMechanism') + '</th><th>' +
      t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thWhatCameOut') + '</th><th>' +
      t.html('consoleDelegation.thAuthorizedBy') + '</th></tr>' +
      (json.graph.edges.map(function (edge) {
        return DelegationPage.delegationEdgeRow(t, edge, labelOf);
      }).join('') || '<tr><td colspan="8">' +
        t.html('consoleDelegation.noRelationships') + '</td></tr>') +
      '</table>' +

      '<h2>' + t.html('consoleDelegation.hIssuedOnIt') + '</h2>' +
      kit.note(t.html('consoleDelegation.chainIssued', {
        tokens: json.graph.tokens.length, acts: chain.acts })) +
      '<table><tr><th class="num">#</th><th>' +
      t.html('consoleDelegation.thWhen') + '</th><th>' +
      t.html('consoleDelegation.thCredential') + '</th>' +
      '<th>' + t.html('consoleDelegation.thSubject') + '</th><th>' +
      t.html('consoleDelegation.thActor') + '</th><th>' +
      t.html('consoleDelegation.thTarget') + '</th><th>' +
      t.html('consoleDelegation.thMechanism') + '</th></tr>' +
      (json.graph.tokens.map(function (token) {
        return DelegationPage.delegationTokenRow(t, token, labelOf);
      }).join('') || '<tr><td colspan="7">' +
        t.html('consoleDelegation.nothingIssuedOnChain') + '</td></tr>') +
      '</table>' +

      '<h2>' + t.html('consoleDelegation.hEveryAct') + '</h2>' +
      kit.note(t.html('consoleDelegation.sameRowsBefore') + '<a href="' +
      kit.esc(upHref) + '">' +
      t.html('consoleDelegation.theDelegationTable') + '</a>' +
      t.html('consoleDelegation.sameRowsAfter', {
        n: json.acts.length, max: json.maxRecords })) +
      '<table><tr><th class="num">#</th><th>' +
      t.html('consoleDelegation.thWhen') + '</th><th>' +
      t.html('consoleDelegation.thMechanism') + '</th>' +
      '<th>' + t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.labelOutcome') + '</th><th>' +
      t.html('consoleDelegation.thInitial') + '</th>' +
      '<th>' + t.html('consoleDelegation.thIntermediaryShort') +
      '</th><th>' + t.html('consoleDelegation.thTarget') + '</th><th>' +
      t.html('consoleDelegation.thAuthorizedBy') + '</th>' +
      '<th>' + t.html('consoleDelegation.thCredentials') + '</th></tr>' +
      json.acts.map(function (row) {
        // No `chain` link on this table: every row on it belongs to the chain
        // being drawn, so the link would point at the page it is on.
        return DelegationPage.delegationRow(t, row, json.facts,
                                         { chainLink: false });
      }).join('') + '</table>' +

      kit.note(t.html('consoleDelegation.chainFormats'));

  }

  // ---------------------------------------------------------------------------
  // /admin/delegation/application, FROM
  // `GET /admin-api/delegation/application` (#446).
  //
  // Everything delegated through an application or to it: who it is, both
  // its roles, the drawing, the parties, every credential and act — or, for
  // a name no act holds, the chooser and the catalogue to pick from.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation/application` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation/application`
   * @returns the body as HTML
   */
  static application(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6); a role's label
    // and description come from the view and are drawn as they come.
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const upHref = '/admin/delegation' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; ' + t.html('consoleDelegation.backToTable') + '</a>');
    // The chooser itself, drawn on the bare page AND under a selected
    // application — the second is what makes comparing two of them one
    // click rather than two.
    const chooser = DelegationPage.delegationApplicationChooser(t,
      json.chooser, json.key,
      { path: '/admin/delegation/application', query: ctx.query });
    const entry = json.application;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!entry) {
    return back +
      (json.asked
        ? kit.note(t.html('consoleDelegation.appNoAct',
                          { name: json.asked, max: json.maxRecords }))
        : '') +
      kit.note(t.html('consoleDelegation.appChoose')) +
      chooser +
      DelegationPage.delegationApplicationTable(t, json.applications,
                                                 json.facts, listView) +
      kit.note(t.html('consoleDelegation.appListFromActsBefore') + '<a ' +
      'href="/admin/applications">' +
      t.html('consoleDelegation.theRegistry') + '</a>' +
      t.html('consoleDelegation.appListFromActsAfter'));
    }
    const parties = json.graph.nodes.filter(function (node) {
      return node.kind !== 'sts';
    });

    return back +
      '<div class="tiles">' +
        kit.tile(entry.acts, t.text('consoleDelegation.tileActs')) +
        kit.tile(entry.issued, t.text('consoleDelegation.outcomeIssued')) +
        kit.tile(entry.refused, t.text('consoleDelegation.outcomeRefused')) +
        kit.tile(json.graph.tokens.length,
                 t.text('consoleDelegation.tileCredentialsIssued')) +
        kit.tile(entry.chains, t.text('consoleDelegation.tileRelationships')) +
        kit.tile(entry.roles.intermediary,
                 t.text('consoleDelegation.tileAsIntermediary')) +
      '</div>' +

      kit.note('<strong><code>' + kit.esc(entry.identifier) +
                '</code></strong> — ' +
      (json.registered
        ? '<a href="' + kit.esc('/admin/applications' +
            kit.queryWith({ application: entry.identifier }, {})) +
            '">' + t.html('consoleDelegation.inTheRegistry') + '</a>' +
          t.html('consoleDelegation.registeredAs',
                 { name: json.registeredName || entry.identifier })
        : '<span class="state-none" title="' +
          t.html('consoleDelegation.appUnregisteredTitle') + '">' +
          t.html('consoleDelegation.notInRegistry') + '</span>') +
      (entry.identityKey
        ? t.html('consoleDelegation.alsoPersonBefore') +
          GroupsPage.usersPageCell(entry.identityKey, json.facts.users) +
          t.html('consoleDelegation.alsoPersonAfter')
        : '.') +
      (entry.spellings.length > 1
        ? t.html('consoleDelegation.spelledWays',
                 { n: entry.spellings.length }) +
          kit.codeList(entry.spellings) +
          t.html('consoleDelegation.spelledWaysAfter')
        : '') +
      t.html('consoleDelegation.protocolsLabel') +
      (entry.protocols.length ? kit.codeList(entry.protocols)
                              : t.html('consoleDelegation.none')) +
      t.html('consoleDelegation.firstLastSeen', {
        first: kit.whenText(entry.firstAt),
        last: kit.whenText(entry.lastAt) })) +

      '<h2>' + t.html('consoleDelegation.hWhatItDoes') + '</h2>' +
      kit.note(t.html('consoleDelegation.bothSides')) +
      '<table><tr><th>' + t.html('consoleDelegation.thRole') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thWhatRoleIs') + '</th></tr>' +
      json.roles.map(function (role) {
        const n = entry.roles[role.role] || 0;
        return '<tr>' +
          '<td>' + kit.esc(role.label) + '</td>' +
          '<td class="num">' + (n
            ? '<strong>' + kit.esc(n) + '</strong>'
            : '<span class="state-none">0</span>') + '</td>' +
          '<td>' + kit.esc(role.what) + '</td>' +
          '</tr>';
      }).join('') + '</table>' +

      (json.graph.acts
        ? '<h2>' + t.html('consoleDelegation.hPartOf') + '</h2>' +
          kit.note(t.html('consoleDelegation.partOfNote')) +
          DelegationPage.drawing(t, json, '/admin/delegation/application',
            Object.assign({}, listView,
                          { application: entry.identifier }))
        : '') +

      '<h2>' + t.html('consoleDelegation.hKey') + '</h2>' +
      kit.note(t.html('consoleDelegation.keyNote')) +
      json.mapKey +

      '<h2>' + t.html('consoleDelegation.hPartiesDeals') + '</h2>' +
      kit.note(t.html('consoleDelegation.partiesDealsNote')) +
      '<table><tr><th>' + t.html('consoleDelegation.thLabel') +
      '</th><th>' + t.html('consoleDelegation.thDrawnAs') + '</th><th>' +
      t.html('consoleDelegation.thIdentity') + '</th>' +
      '<th>' + t.html('consoleDelegation.thRolesItPlayed') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thProtocols') + '</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(t, node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">' +
        t.html('consoleDelegation.noParties') + '</td></tr>') +
        '</table>' +

      '<h2>' + t.html('consoleDelegation.hEveryDelegated') + '</h2>' +
      kit.note(t.html('consoleDelegation.everyDelegatedNote', {
        tokens: json.graph.tokens.length, acts: entry.acts })) +
      '<table><tr><th class="num">#</th><th>' +
      t.html('consoleDelegation.thWhen') + '</th><th>' +
      t.html('consoleDelegation.thItsRole') + '</th>' +
      '<th>' + t.html('consoleDelegation.thCredential') + '</th><th>' +
      t.html('consoleDelegation.thSubject') + '</th><th>' +
      t.html('consoleDelegation.thActor') + '</th><th>' +
      t.html('consoleDelegation.thTarget') + '</th>' +
      '<th>' + t.html('consoleDelegation.thMechanism') + '</th></tr>' +
      (json.graph.tokens.map(function (token) {
        return DelegationPage.delegationTokenRow(t,
          token, labelOf,
          DelegationPage.delegationRoleCell(json.rolesBySeq[token.seq],
                                            json.roles));
      }).join('') ||
        '<tr><td colspan="8">' +
        t.html('consoleDelegation.nothingThroughApp') + '</td></tr>') +
        '</table>' +
      (json.graph.tokensLeftOff
        ? kit.note(t.html('consoleDelegation.appTokensLeftOff', {
            n: json.graph.tokensLeftOff, max: json.graph.maxTokenRows }))
        : '') +

      '<h2>' + t.html('consoleDelegation.hEveryActPart') + '</h2>' +
      kit.note(t.html('consoleDelegation.theRows') + '<a href="' +
      kit.esc(upHref) + '">' +
      t.html('consoleDelegation.theDelegationTable') + '</a>' +
      t.html('consoleDelegation.theRowsAppAfter')) +
      '<table><tr><th class="num">#</th><th>' +
      t.html('consoleDelegation.thWhen') + '</th><th>' +
      t.html('consoleDelegation.thMechanism') + '</th>' +
      '<th>' + t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.labelOutcome') + '</th><th>' +
      t.html('consoleDelegation.thInitial') + '</th>' +
      '<th>' + t.html('consoleDelegation.thIntermediaryShort') +
      '</th><th>' + t.html('consoleDelegation.thTarget') + '</th><th>' +
      t.html('consoleDelegation.thAuthorizedBy') + '</th>' +
      '<th>' + t.html('consoleDelegation.thCredentials') + '</th></tr>' +
      json.acts.map(function (row) {
        return DelegationPage.delegationRow(t, row, json.facts,
                                         { listView: listView });
      }).join('') + '</table>' +

      '<h2>' + t.html('consoleDelegation.hAnotherApplication') + '</h2>' +
      chooser +
      DelegationPage.delegationApplicationTable(t, json.applications,
                                                 json.facts, listView) +

      kit.note(t.html('consoleDelegation.appFormats'));

  }

  // ---------------------------------------------------------------------------
  // /admin/delegation/user, FROM `GET /admin-api/delegation/user` (#446).
  //
  // Everything this service has done in one person's name: the picture of
  // the ordinary issuance and the delegations together, the grants used,
  // every credential, the parties, the lines and the acts — or, for a name
  // neither register holds, the chooser and the catalogue.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation/user` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation/user`
   * @returns the body as HTML
   */
  static user(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6); a grant's
    // label, specification and description come from the view and are
    // drawn as they come.
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const upHref = '/admin/delegation' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; ' + t.html('consoleDelegation.backToTable') + '</a>');
    const chooser = DelegationPage.delegationUserChooser(t, json.chooser,
      json.key, { path: '/admin/delegation/user', query: ctx.query });
    const entry = json.user;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!entry) {
    return back +
      (json.asked
        ? kit.note(t.html('consoleDelegation.userNoRegister',
                          { name: json.asked }))
        : '') +
      kit.note(t.html('consoleDelegation.userChoose')) +
      chooser +
      DelegationPage.delegationUserTable(t, json.users, json.facts,
                                        listView) +
      kit.note(t.html('consoleDelegation.userListUnioned'));
    }
    const parties = json.graph.nodes.filter(function (node) {
      return node.kind !== 'sts';
    });

    return back +
      '<div class="tiles">' +
        kit.tile(json.counts.credentials,
                 t.text('consoleDelegation.tileCredentialsIssued')) +
        kit.tile(json.counts.authentications,
                 t.text('consoleDelegation.tileSignIns')) +
        kit.tile(json.flows.length,
                 t.text('consoleDelegation.tileGrantsUsed')) +
        kit.tile(json.counts.applications,
                 t.text('consoleDelegation.tileOtherParties')) +
        kit.tile(json.counts.acts,
                 t.text('consoleDelegation.tileDelegationActs')) +
        kit.tile(json.counts.chains,
                 t.text('consoleDelegation.tileDelegationRelationships')) +
      '</div>' +

      kit.note('<strong><code>' + kit.esc(json.key) +
                '</code></strong> — ' +
      (entry.authenticated
        ? t.html('consoleDelegation.theyHave') + '<a href="' +
            kit.esc('/admin/users' +
            kit.queryWith({ user: json.key }, {})) + '">' +
            t.html('consoleDelegation.authenticatedHere') + '</a> ' +
          t.html('consoleDelegation.nTimes', { n: entry.authentications })
        : '<span class="state-expired" title="' +
          t.html('consoleDelegation.neverAuthenticatedUserTitle') + '">' +
          t.html('consoleDelegation.neverAuthenticatedUser') + '</span>') +
      (entry.isClient ? t.html('consoleDelegation.isClient') : '') +
      (entry.forms.length > 1
        ? t.html('consoleDelegation.userSpelled',
                 { n: entry.forms.length }) +
          kit.codeList(entry.forms) +
          t.html('consoleDelegation.userSpelledAfter')
        : '') +
      '.' + t.html('consoleDelegation.protocolsLabel') +
      (entry.protocols.length ? kit.codeList(entry.protocols)
                              : t.html('consoleDelegation.none')) +
      t.html('consoleDelegation.lastSeen',
             { last: kit.whenText(entry.lastAt) })) +

      '<h2>' + t.html('consoleDelegation.hOnePicture') + '</h2>' +
      kit.note(t.html('consoleDelegation.onePictureNote')) +
      DelegationPage.drawing(t, json, '/admin/delegation/user',
        Object.assign({}, listView, { user: json.key })) +

      '<h2>' + t.html('consoleDelegation.hKey') + '</h2>' +
      kit.note(t.html('consoleDelegation.keyNote') + ' ' +
      t.html('consoleDelegation.userKeyNote')) +
      json.mapKey +

      '<h2>' + t.html('consoleDelegation.hWhatUsed') + '</h2>' +
      kit.note(t.html('consoleDelegation.whatUsedNote')) +
      (json.flows.length
        ? '<table><tr><th>' + t.html('consoleDelegation.thGrant') +
          '</th><th>' + t.html('consoleDelegation.thOidcCalls') +
          '</th><th>' + t.html('consoleDelegation.thSpecification') +
          '</th><th>' + t.html('consoleDelegation.thThroughBrowser') +
          '</th><th>' + t.html('consoleDelegation.thWhatItIs') +
          '</th></tr>' +
          json.flows.map(function (flow) {
            return '<tr>' +
              '<td><code>' + kit.esc(flow.flow) + '</code><br>' +
                '<strong>' + kit.esc(flow.label) + '</strong></td>' +
              '<td>' + (flow.oidc ? kit.esc(flow.oidc)
                : '<span class="state-none" title="' +
                  t.html('consoleDelegation.noOidcFlowTitle') +
                  '">&mdash;</span>') + '</td>' +
              '<td>' + kit.esc(flow.spec) + '</td>' +
              '<td>' + (flow.browser
                ? '<span class="state-valid" title="' +
                  t.html('consoleDelegation.browserYesTitle') + '">' +
                  t.html('consoleDelegation.yes') + '</span>'
                : '<span class="state-none" title="' +
                  t.html('consoleDelegation.browserNoTitle') + '">' +
                  t.html('consoleDelegation.no') + '</span>') +
                  '</td>' +
              '<td>' + kit.esc(flow.what) +
                (flow.delegating
                  ? t.html('consoleDelegation.alsoDelegationAct')
                  : '') + '</td>' +
              '</tr>';
          }).join('') + '</table>'
        : kit.note(t.html('consoleDelegation.noGrantStatedNote'))) +

      '<h2>' + t.html('consoleDelegation.hEveryCredential') + '</h2>' +
      kit.note(t.html('consoleDelegation.everyCredentialNote') +
      (json.onDelegationLines
        ? t.html('consoleDelegation.onDelegationLines',
                 { n: json.onDelegationLines })
        : '')) +
      '<table><tr><th>' + t.html('consoleDelegation.thWhen') + '</th><th>' +
      t.html('consoleDelegation.thCredential') + '</th><th>' +
      t.html('consoleDelegation.thWhatIssued') + '</th>' +
      '<th>' + t.html('consoleDelegation.thWentTo') + '</th><th>' +
      t.html('consoleDelegation.thState') + '</th><th>' +
      t.html('consoleDelegation.thSession') + '</th></tr>' +
      (json.credentials.map(function (credential) {
        return DelegationPage.userCredentialRow(t, credential, json.facts);
      }).join('') ||
        '<tr><td colspan="6">' +
        t.html('consoleDelegation.nothingNamingThem') + '</td></tr>') +
      '</table>' +
      kit.note(t.html('consoleDelegation.sameRowsRevoke') + '<a href="' +
      kit.esc('/admin/users' + kit.queryWith({ user: json.key }, {})) +
      '">' + t.html('consoleDelegation.theirPage') + '</a>' +
      t.html('consoleDelegation.sameRowsRevokeAfter')) +

      '<h2>' + t.html('consoleDelegation.hParties') + '</h2>' +
      kit.note(t.html('consoleDelegation.userPartiesNote')) +
      '<table><tr><th>' + t.html('consoleDelegation.thLabel') +
      '</th><th>' + t.html('consoleDelegation.thDrawnAs') + '</th><th>' +
      t.html('consoleDelegation.thIdentity') + '</th>' +
      '<th>' + t.html('consoleDelegation.thCredentials') + '</th><th>' +
      t.html('consoleDelegation.thBy') + '</th><th>' +
      t.html('consoleDelegation.thDelegationRoles') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thProtocols') + '</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.userNodeRow(t, node, json.facts,
                                          json.looks[node.id]);
      }).join('') || '<tr><td colspan="8">' +
        t.html('consoleDelegation.noParties') + '</td></tr>') +
        '</table>' +

      '<h2>' + t.html('consoleDelegation.hEveryLine') + '</h2>' +
      kit.note(t.html('consoleDelegation.everyLineNote')) +
      '<table><tr><th>' + t.html('consoleDelegation.thFrom') + '</th><th>' +
      t.html('consoleDelegation.thTo') + '</th><th>' +
      t.html('consoleDelegation.thRelationship') + '</th><th>' +
      t.html('consoleDelegation.thMechanismOrGrant') + '</th><th>' +
      t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thCredentials') + '</th><th>' +
      t.html('consoleDelegation.thWhatCameOut') + '</th></tr>' +
      (json.graph.edges.map(function (edge) {
        return DelegationPage.userEdgeRow(t, edge, labelOf);
      }).join('') || '<tr><td colspan="8">' +
        t.html('consoleDelegation.noLines') + '</td></tr>') + '</table>' +

      (json.acts.length
        ? '<h2>' + t.html('consoleDelegation.hEveryActNaming') + '</h2>' +
          kit.note(t.html('consoleDelegation.theRows') + '<a href="' +
          kit.esc(upHref) + '">' +
          t.html('consoleDelegation.theDelegationTable') + '</a>' +
          t.html('consoleDelegation.theRowsUserAfter')) +
          '<table><tr><th class="num">#</th><th>' +
          t.html('consoleDelegation.thWhen') + '</th><th>' +
          t.html('consoleDelegation.thMechanism') + '</th>' +
          '<th>' + t.html('consoleDelegation.labelKind') + '</th><th>' +
          t.html('consoleDelegation.labelOutcome') + '</th><th>' +
          t.html('consoleDelegation.thInitial') + '</th>' +
          '<th>' + t.html('consoleDelegation.thIntermediaryShort') +
          '</th><th>' + t.html('consoleDelegation.thTarget') + '</th><th>' +
          t.html('consoleDelegation.thAuthorizedBy') + '</th><th>' +
          t.html('consoleDelegation.thCredentials') + '</th></tr>' +
          json.acts.map(function (row) {
            return DelegationPage.delegationRow(t, row, json.facts,
                                             { listView: listView });
          }).join('') + '</table>'
        : '<h2>' + t.html('consoleDelegation.hDelegation') + '</h2>' +
          kit.note(t.html('consoleDelegation.noActNamesThem'))) +

      '<h2>' + t.html('consoleDelegation.hSomebodyElse') + '</h2>' +
      chooser +
      DelegationPage.delegationUserTable(t, json.users, json.facts,
                                          listView) +

      kit.note(t.html('consoleDelegation.userFormats'));

  }

  // ---------------------------------------------------------------------------
  // /admin/tokens/credential, FROM `GET /admin-api/tokens/credential` (#446).
  //
  // One credential and every generation behind it: the sentence, the
  // generations newest first, the walls a line stops at, the picture, its
  // parties and lines, and the acts — or, with nothing named, how to get
  // here.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/tokens/credential` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/tokens/credential`
   * @returns the body as HTML
   */
  static credential(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6); a credential's
    // kind, its state and an origin's label come from the view and are
    // drawn as they come.
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/tokens', ctx.query);
    const upHref = '/admin/tokens' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; ' + t.html('consoleDelegation.backToTokens') + '</a>');
    const credential = json.credential;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!json.counts) {
    return back +
      kit.note(t.html('consoleDelegation.nameCredential') + '<a href="' +
      kit.esc(upHref) +
      '">' + t.html('consoleDelegation.theTokensTable') + '</a>' +
      t.html('consoleDelegation.nameCredentialAfter'));
    }
    const parties = json.graph.nodes.filter(function (node) {
      return node.kind !== 'sts';
    });

    // THE ONE SENTENCE THIS PAGE OPENS WITH. A reader arriving from a row of
    // a ten-column table has to be told immediately that they are looking at
    // the same credential — and then the one fact the row could not tell
    // them, which is whether anything is behind it.
    const sentence = kit.note('<strong><code>' + kit.esc(json.identifier) +
      '</code></strong> — ' +
      (credential
        ? t.html('consoleDelegation.kindIssued', {
            kind: credential.kind,
            when: kit.whenText(credential.issuedAt) }) +
          ', <span class="' + TokensPage.stateClass(credential.state) + '">' +
          kit.esc(credential.state) + '</span>'
        : '<span class="state-expired" title="' +
          kit.esc(t.text('consoleDelegation.noLongerHeldTitle')) +
          '">' + t.html('consoleDelegation.noLongerHeld') + '</span>') +
      '. ' +
      (json.counts.exchanges
        ? t.html('consoleDelegation.exchangesBehind', {
            n: json.counts.exchanges,
            generation: json.generations.length - 1 })
        : t.html('consoleDelegation.nothingExchanged')));

    return back +
      '<div class="tiles">' +
        kit.tile(json.counts.generations,
                 t.text('consoleDelegation.tileGenerations')) +
        kit.tile(json.counts.exchanges,
                 t.text('consoleDelegation.tileExchangesBehind')) +
        kit.tile(json.counts.parties,
                 t.text('consoleDelegation.tilePartiesInvolved')) +
        kit.tile(json.counts.acts,
                 t.text('consoleDelegation.tileDelegationActs')) +
      '</div>' +

      sentence +

      (json.truncated
        ? '<p class="note state-expired">' +
          t.html('consoleDelegation.truncated',
                 { max: json.maxGenerations }) + '</p>'
        : '') +

      '<h2>' + t.html('consoleDelegation.hHowItCame') + '</h2>' +
      kit.note(t.html('consoleDelegation.howItCameNote')) +
      '<table><tr><th class="num">' + t.html('consoleDelegation.thGen') +
      '</th><th>' + t.html('consoleDelegation.thIdentifier') + '</th><th>' +
      t.html('consoleDelegation.labelKind') + '</th>' +
      '<th>' + t.html('consoleDelegation.thHeldBy') + '</th><th>' +
      t.html('consoleDelegation.thInWhoseName') + '</th><th>' +
      t.html('consoleDelegation.thIssued') + '</th>' +
      '<th>' + t.html('consoleDelegation.thHowGot') + '</th></tr>' +
      json.generations.map(function (row) {
        const held = row.credential;
        return '<tr>' +
          '<td class="num">' + kit.esc(row.generation) + '</td>' +
          '<td class="who">' + kit.shortened(row.identifier, 14) +
            (row.identifier === json.identifier
              ? '<br><span class="state-none">' +
                t.html('consoleDelegation.thisPage') + '</span>' : '') +
                '</td>' +
          '<td>' + (held ? kit.esc(held.kind)
            : '<span class="state-none" title="' +
              kit.esc(t.text('consoleDelegation.notHeldTitle')) +
              '">' + t.html('consoleDelegation.notHeld') + '</span>') +
          '</td>' +
          '<td class="who">' + (held
            ? kit.esc(row.holder || '—') : '<span ' +
              'class="state-none">&mdash;</span>') + '</td>' +
          '<td class="who">' + (held
            ? kit.esc((held.family === 'token' ? (held.username || held.sub)
                                                : held.subject) || '—')
            : '<span class="state-none">&mdash;</span>') + '</td>' +
          '<td>' + (held ? kit.esc(kit.whenText(held.issuedAt))
            : '<span class="state-none">&mdash;</span>') + '</td>' +
          '<td>' + (row.act
            ? '<code>' + kit.esc(row.act.type) + '</code><br>' +
              '<span class="state-none">' + kit.esc(row.act.typeLabel) +
              '</span><br><a href="' + kit.esc('/admin/delegation/chain' +
                kit.queryWith({}, { chain: row.act.chainKey })) +
              '">' + t.html('consoleDelegation.theRelationship') + '</a>'
            : '<strong>' + t.html('consoleDelegation.theOrigin') +
              '</strong><br><span class="state-none">' +
              kit.esc(row.originLabel) + '</span>') +
                          '</td>' +
          '</tr>';
      }).join('') + '</table>' +

      (json.walls.length
        ? kit.note(t.html('consoleDelegation.wallsBefore') + ' ' +
          json.walls.map(function (wall) {
            return kit.esc(wall.credential.kind) + ' — ' +
              kit.esc(wall.credential.note ||
                      t.text('consoleDelegation.noIdentifier'));
          }).join('; ') +
          t.html('consoleDelegation.wallsAfter'))
        : '') +

      '<h2>' + t.html('consoleDelegation.hWholeLine') + '</h2>' +
      kit.note(t.html('consoleDelegation.wholeLineBefore') +
      '<a href="/admin/delegation/map">' +
      t.html('consoleDelegation.theMap') + '</a>' +
      t.html('consoleDelegation.wholeLineAfter')) +
      DelegationPage.drawing(t, json, '/admin/tokens/credential',
        Object.assign({}, listView, { id: json.identifier })) +

      '<h2>' + t.html('consoleDelegation.hParties') + '</h2>' +
      kit.note(t.html('consoleDelegation.credentialPartiesNote')) +
      '<table><tr><th>' + t.html('consoleDelegation.thLabel') +
      '</th><th>' + t.html('consoleDelegation.thDrawnAs') + '</th><th>' +
      t.html('consoleDelegation.thIdentity') + '</th>' +
      '<th>' + t.html('consoleDelegation.thRolesItPlayed') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thProtocols') + '</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(t, node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">' +
        t.html('consoleDelegation.noParties') + '</td></tr>') +
        '</table>' +

      '<h2>' + t.html('consoleDelegation.hEveryLine') + '</h2>' +
      kit.note(t.html('consoleDelegation.pictureAsTable')) +
      '<table><tr><th>' + t.html('consoleDelegation.thFrom') + '</th><th>' +
      t.html('consoleDelegation.thTo') + '</th><th>' +
      t.html('consoleDelegation.thRelationship') + '</th><th>' +
      t.html('consoleDelegation.thMechanismOrGrant') + '</th><th>' +
      t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thCredentials') + '</th><th>' +
      t.html('consoleDelegation.thWhatCameOut') + '</th></tr>' +
      (json.graph.edges.map(function (edge) {
        return DelegationPage.userEdgeRow(t, edge, labelOf);
      }).join('') || '<tr><td colspan="8">' +
        t.html('consoleDelegation.noLines') + '</td></tr>') + '</table>' +

      (json.acts.length
        ? '<h2>' + t.html('consoleDelegation.hEveryActLine') + '</h2>' +
          kit.note(t.html('consoleDelegation.theRows') +
          '<a href="/admin/delegation">' +
          t.html('consoleDelegation.theDelegationTable') + '</a>' +
          t.html('consoleDelegation.theRowsLineageAfter')) +
          '<table><tr><th class="num">#</th><th>' +
          t.html('consoleDelegation.thWhen') + '</th><th>' +
          t.html('consoleDelegation.thMechanism') + '</th>' +
          '<th>' + t.html('consoleDelegation.labelKind') + '</th><th>' +
          t.html('consoleDelegation.labelOutcome') + '</th><th>' +
          t.html('consoleDelegation.thInitial') + '</th>' +
          '<th>' + t.html('consoleDelegation.thIntermediaryShort') +
          '</th><th>' + t.html('consoleDelegation.thTarget') + '</th><th>' +
          t.html('consoleDelegation.thAuthorizedBy') + '</th><th>' +
          t.html('consoleDelegation.thCredentials') + '</th></tr>' +
          json.acts.map(function (row) {
            return DelegationPage.delegationRow(t, row, json.facts,
                                             { listView: {} });
          }).join('') + '</table>'
        : '') +

      (credential && credential.family === 'token' &&
       (credential.username || credential.sub)
        ? kit.note('<a href="' + kit.esc('/admin/delegation/user' +
            kit.queryWith({}, { user: json.subjectKey })) +
          '">' + t.html('consoleDelegation.everythingInName') + '</a>' +
          t.html('consoleDelegation.everythingInNameAfter'))
        : '') +

      kit.note(t.html('consoleDelegation.credentialFormats'));

  }

  // ---------------------------------------------------------------------------
  // /admin/delegation-settings, FROM `GET /admin-api/delegation-settings`
  // (#446): the configured permissions register, editable, and the page's
  // settings.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation-settings` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation-settings`
   * @returns the body as HTML
   */
  static settings(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6); the settings
    // forms take it too.
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/delegation-settings', ctx.query);
    return kit.note(t.html('consoleDelegation.settingsLeadBefore') +
      '<a href="/admin/delegation">' +
      t.html('consoleDelegation.monitoringDelegationLink') + '</a>' +
      t.html('consoleDelegation.settingsLeadMiddle') +
      '<a href="/admin/applications">' +
      t.html('consoleDelegation.directoryApplicationsLink') + '</a>' +
      t.html('consoleDelegation.settingsLeadAfter')) +
      DelegationPage.permissionsSection(ctx, json, listView, true) +
      SettingsForms.forms(json.settings, '/admin/delegation-settings',
                          undefined, t);
  }

  // ---------------------------------------------------------------------------
  // /admin/delegation/allowed, FROM `GET /admin-api/delegation/allowed`
  // (#446): what is ALLOWED, drawn, and the groups the grants join.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation/allowed` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation/allowed`
   * @returns the body as HTML
   */
  static allowed(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6).
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const groupNav = kit.pageNavPair('/admin/delegation/allowed',
                                     kit.pageParamsOf(ctx.query),
                                     json.groupsPaging);
    // What a link OUT of this page carries: the acts list's state, and this
    // page's own search (`allowedChooserState()` says why).
    const onward = Object.assign({}, listView,
                                 DelegationPage.allowedChooserState(ctx.query));
    return (
      kit.note(t.html('consoleDelegation.allowedNotHappened') + '<a ' +
      'href="/admin/delegation/map">' +
      t.html('consoleDelegation.theOtherPicture') + '</a>' +
      t.html('consoleDelegation.allowedNotHappenedAfter')) +

      kit.note(t.html('consoleDelegation.allowedNoPerson')) +

      kit.note(t.html('consoleDelegation.allowedEnds')) +

      kit.note(t.html('consoleDelegation.allowedDashed')) +

      (json.counts.dangling
        ? kit.note(t.html('consoleDelegation.allowedDangling',
                          { n: json.counts.dangling }) + '<a ' +
          'href="/admin/delegation#allowed">' +
          t.html('consoleDelegation.theRegister') + '</a>' +
          t.html('consoleDelegation.allowedDanglingAfter'))
        : '') +

      DelegationPage.drawing(t, json, '/admin/delegation/allowed', {}) +

      '<div class="tiles">' +
        kit.tile(json.counts.grants, t.text('consoleDelegation.tileGrants')) +
        kit.tile(json.counts.permissions,
                 t.text('consoleDelegation.tilePermissions')) +
        kit.tile(json.counts.unused,
                 t.text('consoleDelegation.neverAskedFor')) +
        kit.tile(json.counts.dangling,
                 t.text('consoleDelegation.tileDanglingNotDrawn')) +
      '</div>' +

      '<h2 id="groups">' + t.html('consoleDelegation.hGroupings') + '</h2>' +

      kit.note(t.html('consoleDelegation.groupDefinition')) +

      kit.note(t.html('consoleDelegation.groupWholeRegister')) +

      DelegationPage.allowedApplicationChooser(t, json, '', onward,
        { path: '/admin/delegation/allowed', query: ctx.query }) +

      // This page has no filter form to hang `per` on, which is the case
      // perPageForm() exists for. The leaf it carries is the CHOOSER'S SEARCH
      // rather than a selected thing, because that is the only state on this
      // page a reader would lose by changing the size.
      kit.perPageForm('/admin/delegation/allowed', 'permappq',
                       kit.queryOne(ctx.query, 'permappq'),
                       json.groupsPaging.perPage,
                       t.html('consoleDelegation.oneTableBelow'),
                       kit.filterOnly(listView)) +

      groupNav.head +
      DelegationPage.allowedClusterTable(t, json.clusters, json.shownGroups,
                                       onward, json.apps) +
      groupNav.foot +

      '<div class="tiles">' +
        kit.tile(json.clusters.counts.clusters,
                 t.text('consoleDelegation.tileGroups')) +
        kit.tile(json.clusters.counts.joined,
                 t.text('consoleDelegation.tileJoined')) +
        kit.tile(json.clusters.counts.alone,
                 t.text('consoleDelegation.tileAlone')) +
        kit.tile(json.clusters.counts.largest,
                 t.text('consoleDelegation.tileLargest')) +
      '</div>' +

      kit.note(t.html('consoleDelegation.groupOfOne')) +

      kit.note(t.html('consoleDelegation.registerItselfBefore') +
      '<a href="/admin/delegation#allowed">' +
      t.html('consoleDelegation.theDelegationPage') + '</a>' +
      t.html('consoleDelegation.registerItselfAfter')));
  }

  // ---------------------------------------------------------------------------
  // /admin/delegation/cluster, FROM `GET /admin-api/delegation/cluster`
  // (#446): one group of applications joined by permissions, drawn, with
  // its members, permissions and grants — or the chooser and the groups.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation/cluster` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation/cluster`
   * @returns the body as HTML
   */
  static cluster(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6).
    const t = ctx.t;
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    // The way back to the picture this page was opened from, carrying the
    // search that opened it — see allowedChooserState().
    const onward = Object.assign({}, listView,
                                 DelegationPage.allowedChooserState(ctx.query));
    const back = kit.note('<a class="btn" href="' +
      kit.esc('/admin/delegation/allowed' + kit.queryWith(onward, {})) +
      '">&larr; ' + t.html('consoleDelegation.backToAllowed') + '</a>');
    const group = json.cluster;
    const chooser = DelegationPage.allowedApplicationChooser(t, json,
      group ? json.asked : '', onward,
      { path: '/admin/delegation/cluster', query: ctx.query });
    if (!group) {
      const groupNav = kit.pageNavPair('/admin/delegation/cluster',
                                       kit.pageParamsOf(ctx.query),
                                       json.groupPage.paging);
    return back +
      (json.asked
        ? kit.note(t.html('consoleDelegation.clusterNothingAbout',
                          { name: json.asked }) +
          '<a href="/admin/applications' +
          kit.esc(kit.queryWith({ application: json.asked }, {})) + '">' +
          t.html('consoleDelegation.theRegistryCap') + '</a>' +
          t.html('consoleDelegation.settlesBoth'))
        : '') +
      kit.note(t.html('consoleDelegation.clusterChoose') + '<a ' +
      'href="/admin/delegation/allowed">' +
      t.html('consoleDelegation.theWholeRegister') + '</a>' +
      t.html('consoleDelegation.clusterChooseAfter')) +
      chooser +
      kit.perPageForm('/admin/delegation/cluster', 'permappq',
                       kit.queryOne(ctx.query, 'permappq'),
                       json.groupPage.paging.perPage,
                       '', kit.filterOnly(listView)) +
      groupNav.head +
      DelegationPage.allowedClusterTable(t, json.clusters,
        json.groupPage.shown, onward, json.apps) +
      groupNav.foot +
      kit.note(t.html('consoleDelegation.configuredListBefore') +
      '<a href="/admin/applications">' +
      t.html('consoleDelegation.theRegistry') + '</a>' +
      t.html('consoleDelegation.configuredListMiddle') + '<a ' +
      'href="/admin/delegation/application">' +
      t.html('consoleDelegation.actsDrillDown') + '</a>' +
      t.html('consoleDelegation.configuredListAfter'));
    }
    // WHAT EACH MEMBER IS IN THIS GROUP, counted once over the group's own
    // rows rather than filtered per member — the same reason the chooser does
    // it: a filter per application over the grant list is quadratic, and a
    // group is the one place in this console where the list being walked is
    // deliberately allowed to be large.
    const holds = {};
    const reached = {};
    const dangles = {};
    group.grants.forEach(function (one) {
      holds[one.client] = (holds[one.client] || 0) + 1;
      if (one.dangling) {
        dangles[one.client] = (dangles[one.client] || 0) + 1;
      } else if (one.resource) {
        reached[one.resource] = (reached[one.resource] || 0) + 1;
      }
    });
    const exposes = {};
    group.permissions.forEach(function (one) {
      exposes[one.resource] = (exposes[one.resource] || 0) + 1;
    });


    const memberRows = group.members.map(function (identifier) {
      const registered = json.apps[identifier];
      const name = registered
        ? (registered.name || registered.dnLabel || identifier) : '';
      const href = '/admin/applications' +
        kit.queryWith(listView, { application: identifier });
      // The chosen application is marked with a WORD and not with a class:
      // `.on` in this console's stylesheet is scoped to the chooser's own
      // list, so a class here would be markup that styles nothing — and a
      // colour alone would say it to sighted readers only.
      return '<tr>' +
        '<td class="who">' + (registered
          ? '<a href="' + kit.esc(href) + '">' + kit.esc(name) +
            '</a><br><code>' +
            kit.esc(identifier) + '</code>'
          : '<code>' + kit.esc(identifier) + '</code><br><span ' +
            'class="state-none" title="' +
            t.html('consoleDelegation.memberUnregisteredTitle') + '">' +
            t.html('consoleDelegation.notInRegistry') + '</span>') +
          (identifier === json.asked
            ? '<br><span class="state-valid">' +
              t.html('consoleDelegation.theOneYouChose') + '</span>' : '') +
          '</td>' +
        '<td class="num">' + (exposes[identifier]
          ? '<strong>' + kit.esc(exposes[identifier]) + '</strong>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + (reached[identifier]
          ? '<strong>' + kit.esc(reached[identifier]) + '</strong>'
          : '<span class="state-none">0</span>') + '</td>' +
        '<td class="num">' + (holds[identifier]
          ? '<strong>' + kit.esc(holds[identifier]) + '</strong>'
          : '<span class="state-none">0</span>') +
          (dangles[identifier]
            ? '<br><span class="state-revoked" title="' +
              t.html('consoleDelegation.memberDanglingTitle') + '">' +
              t.html('consoleDelegation.nDangling',
                     { n: dangles[identifier] }) + '</span>'
            : '') + '</td>' +
        '<td class="who"><a href="' +
        kit.esc('/admin/delegation/application' +
          kit.queryWith(listView, { application: identifier })) + '">' +
          t.html('consoleDelegation.whatActuallyDelegated') + '</a></td>' +
        '</tr>';
    }).join('');

    const grantNav = kit.pageNavPair('/admin/delegation/cluster',
                                     kit.pageParamsOf(ctx.query),
                                     json.grantPage.paging);
    const permissionNav = kit.pageNavPair('/admin/delegation/cluster',
                                          kit.pageParamsOf(ctx.query),
                                          json.permissionPage.paging);

    return back +

      '<div class="tiles">' +
        kit.tile(group.counts.applications,
                 t.text('consoleDelegation.tileAppsInGroup')) +
        kit.tile(group.counts.lines,
                 t.text('consoleDelegation.tileLinesDrawn')) +
        kit.tile(group.counts.asked,
                 t.text('consoleDelegation.tileAskedOnce')) +
        kit.tile(group.counts.unused,
                 t.text('consoleDelegation.neverAskedFor')) +
        kit.tile(group.counts.permissions,
                 t.text('consoleDelegation.tilePermissionsExposed')) +
        kit.tile(group.counts.dangling,
                 t.text('consoleDelegation.tileDanglingNotDrawn')) +
      '</div>' +

      kit.note(t.html('consoleDelegation.clusterOneOf', {
        name: json.asked, n: group.counts.applications }) + ' ' +
      (group.counts.applications === 1
        ? t.html('consoleDelegation.clusterJoinedToNothing')
        : t.html('consoleDelegation.clusterNamedAfter',
                 { key: group.key })) +
      t.html('consoleDelegation.clusterDirection')) +

      // Three paged tables on this page and no filter form to hang the size
      // on, which is exactly the drill-down case perPageForm()'s header
      // describes. The leaf is the application, and the chooser's search
      // rides along so that changing the size does not clear a search the
      // reader is still reading by.
      kit.perPageForm('/admin/delegation/cluster', 'application',
                       json.asked, json.grantPage.paging.perPage,
                       t.html('consoleDelegation.diagramNeverPaged'),
                       Object.assign({}, kit.filterOnly(listView),
                         DelegationPage.allowedChooserState(ctx.query))) +

      (group.counts.lines
        ? '<h2>' + t.html('consoleDelegation.hGroupDrawn') + '</h2>' +
          kit.note(t.html('consoleDelegation.groupDrawnBefore') + '<a href="' +
          kit.esc('/admin/delegation/allowed' + kit.queryWith(onward, {})) +
          '">' + t.html('consoleDelegation.wholeRegister') + '</a>' +
          t.html('consoleDelegation.groupDrawnAfter')) +
          DelegationPage.drawing(t, json, '/admin/delegation/cluster',
            Object.assign({}, onward, { application: json.asked }))
        // WHY THERE IS NOTHING TO DRAW, and the three reasons are three
        // different states rather than one empty page. Saying "every grant
        // here is dangling" about an application that holds no grants at all
        // would be the page inventing rows to explain their absence.
        : kit.note('<strong>' + t.html('consoleDelegation.nothingToDraw') +
          '</strong> ' +
          (!group.counts.grants
            ? t.html('consoleDelegation.noGrantNamesAnything')
            : t.html('consoleDelegation.everyGrantLeftOut')) +
          t.html('consoleDelegation.svgEmpty'))) +

      '<h2>' + t.html('consoleDelegation.hAppsInIt') + '</h2>' +
      kit.note(t.html('consoleDelegation.appsInItNote')) +
      '<table><tr><th>' + t.html('consoleDelegation.thApplication') +
      '</th><th>' + t.html('consoleDelegation.thPermsItExposes') +
      '</th>' +
      '<th>' + t.html('consoleDelegation.thGrantsOnIt') + '</th><th>' +
      t.html('consoleDelegation.thGrantsItHolds') + '</th>' +
      '<th>' + t.html('consoleDelegation.thActsSide') + '</th></tr>' +
      (memberRows || '<tr><td colspan="5">' +
        t.html('consoleDelegation.noApplications') + '</td></tr>') +
      '</table>' +

      '<h2>' + t.html('consoleDelegation.hMayBeAsked') + '</h2>' +
      kit.note(t.html('consoleDelegation.mayBeAskedNote')) +
      permissionNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thResource') +
      '</th><th>' + t.html('consoleDelegation.thPermission') + '</th><th>' +
      t.html('consoleDelegation.thIdentifier') + '</th>' +
      '<th class="num">' + t.html('consoleDelegation.thHeldBy') +
      '</th><th>' + t.html('consoleDelegation.thWhoHolds') +
      '</th><th></th></tr>' +
      (json.permissionPage.shown.map(function (one) {
        return DelegationPage.permissionDefinitionRow(t, one, listView,
                                            { readOnly: true });
      }).join('') ||
        '<tr><td colspan="6">' +
        t.html('consoleDelegation.noPermsInGroup') + '</td></tr>') +
      '</table>' +
      permissionNav.foot +

      '<h2>' + t.html('consoleDelegation.hEveryGrantGroup') + '</h2>' +
      kit.note(t.html('consoleDelegation.theRows') +
      '<a href="/admin/delegation#allowed">' +
      t.html('consoleDelegation.theRegister') + '</a>' +
      t.html('consoleDelegation.grantsGroupAfter')) +
      grantNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thClientWho') +
      '</th><th>' + t.html('consoleDelegation.thResourceWhat') + '</th><th>' +
      t.html('consoleDelegation.thPermission') + '</th><th>' +
      t.html('consoleDelegation.thIdentifier') + '</th><th>' +
      t.html('consoleDelegation.thTokenWillSay') + '</th><th>' +
      t.html('consoleDelegation.thEverAsked') + '</th><th></th></tr>' +
      (json.grantPage.shown.map(function (one) {
        return DelegationPage.permissionGrantRow(t, one, listView,
                                                 { readOnly: true });
      }).join('') ||
        '<tr><td colspan="7">' +
        t.html('consoleDelegation.noGrantInGroup') + '</td></tr>') +
      '</table>' +
      grantNav.foot +

      '<h2>' + t.html('consoleDelegation.hAnotherApplication') + '</h2>' +
      kit.note(t.html('consoleDelegation.sameSearchBefore') + '<a href="' +
      kit.esc('/admin/delegation/allowed' + kit.queryWith(onward, {})) +
      '">' + t.html('consoleDelegation.theAllowedPicture') + '</a>' +
      t.html('consoleDelegation.sameSearchAfter')) +
      chooser +

      kit.note(t.html('consoleDelegation.clusterFormats',
                      { name: json.asked }));

  }

  // One configured pair. `setOn` is the column to read first and is why the two
  // mechanisms are in ONE table rather than two: the messages are identical,
  // the KDC options are identical, and the whole difference is which of the two
  // accounts carries the permission. Two tables would have let a reader learn
  // one of them without ever meeting that fact. FIVE COLUMNS, and `requires` is
  // not one of them although the JSON carries it per pair. It is a property of
  // the MECHANISM rather than of the pair — every classic row has the same
  // sentence and every resource-based row has the other — so as a column it was
  // the same two paragraphs repeated down the table, squeezing the three
  // columns that DO differ per row into unreadable shreds. It is said once
  // above the table instead. The API keeps it on every pair, because a caller
  // reading one pair should not have to know that.
  /**
   * Draws one configured Kerberos delegation pair.
   *
   * @param pair - a pair from the Kerberos delegation policy
   * @returns a <tr> as HTML
   */
  static policyPairRow(t, pair) {
    return '<tr>' +
      '<td><code>' + kit.esc(pair.mechanism) +
      '</code><br><span class="state-none">' +
        kit.esc(pair.type) + '</span></td>' +
      '<td class="who"><code>' + kit.esc(pair.frontEnd) + '</code></td>' +
      '<td class="who"><code>' + kit.esc(pair.target) + '</code>' +
        (pair.targetKnown ? ''
          : '<br><span class="state-revoked">' +
            t.html('consoleDelegation.noSuchPrincipal') + '</span>') +
      '</td>' +
      '<td class="who"><code>' + kit.esc(pair.attribute) + '</code><br>' +
        '<span class="state-none">' +
        t.html('consoleDelegation.onThe', { role: pair.setOnRole }) + ', ' +
          '<code>' +
        kit.esc(pair.setOn) + '</code></span></td>' +
      '<td>' + (pair.warning
                ? '<span class="state-expired">' + kit.esc(pair.warning) +
                  '</span>'
                : '<span class="state-valid">' +
            t.html('consoleDelegation.nothingMissing') + '</span>') +
      '</td>' +
      '</tr>';
  }

  /**
   * Draws one Kerberos account's delegation flags and their effects.
   *
   * @param account - an account row from the Kerberos delegation policy
   * @returns a <tr> as HTML
   */
  static policyAccountRow(account) {
    const flags = [];
    // The entry's attribute, then Active Directory's name for it (#186).
    if (account.notDelegated) {
      flags.push('appNotDelegated (NOT_DELEGATED)');
    }
    if (account.trustedToAuthenticateForDelegation) {
      flags.push('appDelegationSemantics: impersonation ' +
                 '(TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)');
    }
    if (account.okAsDelegate) {
      flags.push('krb5TrustedForDelegation (ok-as-delegate)');
    }
    return '<tr>' +
      '<td class="who"><code>' + kit.esc(account.principal) + '</code></td>' +
      '<td>' + flags.map(function (f) {
        return '<code>' + kit.esc(f) + '</code>';
      }).join('<br>') + '</td>' +
      '<td>' + account.effects.map(function (e) {
        return kit.esc(e);
      }).join('<br><br>') + '</td>' +
      '</tr>';
  }

  // ---------------------------------------------------------------------------
  // /admin/delegation, FROM `GET /admin-api/delegation` (#446).
  //
  // The acts filtered and paged, the chains, the configured permissions
  // register (read-only here), the Kerberos policy, the WS-Trust and
  // token-exchange policy, and the mechanisms — every list on a page
  // parameter of its own, every control carrying the others.
  // ---------------------------------------------------------------------------
  /**
   * Draws `/admin/delegation` from its answer.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/delegation`
   * @returns the body as HTML
   */
  static acts(ctx: Json, json: Json): string {
    // The page's words are its translator's (#539 phase 6); a role's,
    // a mechanism's and a mode's label and description come from the view
    // and are drawn as they come.
    const t = ctx.t;
    const filter = json.filter || {};
    const wanted = { type: filter.type || '', mode: filter.mode || '',
                     outcome: filter.outcome || '',
                     protocol: filter.protocol || '', q: filter.q || '' };
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    // What every paging link on this page carries: the whole query, each
    // control overriding its OWN list's page and nothing else.
    const navParams = kit.pageParamsOf(ctx.query);
    const nav = kit.pageNavPair('/admin/delegation', navParams, json.paging);
    const chainsNav = kit.pageNavPair('/admin/delegation', navParams,
                                      json.chainPage.paging);
    const pairsNav = kit.pageNavPair('/admin/delegation', navParams,
                                     json.pairPage.paging);
    const flagsNav = kit.pageNavPair('/admin/delegation', navParams,
                                     json.flagPage.paging);
    const mechanismsNav = kit.pageNavPair('/admin/delegation', navParams,
                                          json.mechanismPage.paging);
    const rows = json.acts.map(function (row) {
      return DelegationPage.delegationRow(t, row, json.facts,
                                          { listView: listView });
    }).join('');

    // Grouped by protocol and built from the SAME table the filter offers, so
    // the two cannot come to disagree about which mechanism belongs to which
    // family.
    const protocolsInOrder = [];
    json.types.forEach(function (entry) {
      if (protocolsInOrder.indexOf(entry.protocol) < 0) {
        protocolsInOrder.push(entry.protocol);
      }
    });
    const typeOptions = '<option value=""' +
      (wanted.type ? '' : ' selected') +
      '>' + t.html('consoleDelegation.anyMechanism') + '</option>' +
      protocolsInOrder.map(function (protocol) {
        return '<optgroup label="' + kit.esc(protocol) + '">' +
          json.types.filter(function (entry) {
            return entry.protocol === protocol;
          }).map(function (entry) {
            return '<option value="' + kit.esc(entry.type) + '"' +
                   (entry.type === wanted.type ? ' selected' : '') + '>' +
                   kit.esc(entry.label) + ' (' +
                   (json.byType[entry.type] || 0) +
                   ')</option>';
          }).join('') + '</optgroup>';
      }).join('');

    const modeOptions = ['<option value=""' +
                         (wanted.mode ? '' : ' selected') +
                         '>' + t.html('consoleDelegation.eitherKind') +
                         '</option>']
      .concat(json.modes.map(function (entry) {
        return '<option value="' + kit.esc(entry.mode) + '"' +
               (entry.mode === wanted.mode ? ' selected' : '') + '>' +
               kit.esc(entry.label) + ' (' +
               (json.byMode[entry.mode] || 0) +
               ')</option>';
      })).join('');

    const outcomeOptions = ['<option value=""' +
                            (wanted.outcome ? '' : ' ' +
        'selected') +
                            '>' + t.html('consoleDelegation.anyOutcome') +
                            '</option>']
      .concat(json.outcomes.map(function (name) {
        return '<option value="' + kit.esc(name) + '"' +
               (name === wanted.outcome ? ' selected' : '') + '>' +
               kit.esc(name) +
               ' (' + (json.byOutcome[name] || 0) + ')</option>';
      })).join('');

    const perOptions = kit.perPageOptions(json.paging.perPage);

    const filtering = wanted.type || wanted.mode ||
                      wanted.outcome ||
                      wanted.protocol || wanted.q;

    return (
      '<div class="tiles">' +
        kit.tile(json.held, t.text('consoleDelegation.tileActsHeld')) +
        kit.tile(json.chains.length, t.text('consoleDelegation.tileChains')) +
        kit.tile(json.byMode.impersonation || 0,
                 t.text('consoleDelegation.tileImpersonations')) +
        kit.tile(json.byMode.delegation || 0,
                 t.text('consoleDelegation.tileDelegations')) +
        kit.tile(json.byOutcome.refused || 0,
                 t.text('consoleDelegation.outcomeRefused')) +
        kit.tile(json.policy.pairs.length,
                 t.text('consoleDelegation.tileConfiguredPairs')) +
      '</div>' +

      kit.note(t.html('consoleDelegation.actsLead')) +

      kit.note(t.html('consoleDelegation.actsLayers')) +
      '<ul>' + json.roles.map(function (entry) {
        return '<li><strong>' + kit.esc(entry.label) + '</strong> — ' +
               kit.esc(entry.what) +
               '</li>';
      }).join('') + '</ul>' +
      kit.note(t.html('consoleDelegation.actsPersonOrApp')) +

      kit.note(t.html('consoleDelegation.actsAxis')) +

      kit.note(t.html('consoleDelegation.actsRefusals')) +

      // THE WAY TO THE PICTURE, ABOVE THE TABLE RATHER THAN UNDER IT. The
      // chains table lower down is what the diagram is drawn from and the
      // obvious place to put this link is beside it — which is most of a page
      // below the fold on a busy day. A reader who wants the shape of things
      // wants it before they have read four hundred rows, so the offer is
      // here and is repeated where the chains are.
      //
      // It carries the CURRENT FILTER AND NOT THE PAGE: the picture has no
      // paging (see that route's header) and a `page` in its query would be a
      // parameter that does nothing.
      kit.note('<a class="btn" href="' +
        kit.esc('/admin/delegation/map' + kit.queryWith({ type: wanted.type,
          mode: wanted.mode, outcome: wanted.outcome,
          protocol: wanted.protocol, q: wanted.q }, {})) +
        '">' + t.html('consoleDelegation.seeAsPicture') + ' &rarr;</a> ' +
      t.html('consoleDelegation.sameActsDrawn') + (filtering
        ? t.html('consoleDelegation.opensWithFilter')
        : t.html('consoleDelegation.filterFirst'))) +

      // THE SECOND WAY IN, BESIDE THE PICTURE AND ABOVE THE TABLE. The
      // picture link answers "what does all of this look like"; this answers
      // "what has this one application got itself into", which is the other
      // question a person arrives with and the one the tables below cannot be
      // sorted into. Both are here rather than at the foot, because a reader
      // who wants either wants it before reading four hundred rows.
      kit.note(t.html('consoleDelegation.pivotApplication')) +
      DelegationPage.delegationApplicationChooser(t, json.applicationChooser,
        '', { path: '/admin/delegation', query: ctx.query }) +

      // AND THE THIRD WAY IN, which is the other half of the same question.
      // The application chooser answers *what has this thing got itself
      // into*; this one answers *what has this service done in somebody's
      // NAME* — and it is the only one of the three that leaves this
      // register: a person's picture draws their ordinary OAuth 2.0, OIDC,
      // SAML, Kerberos and SPIFFE issuance too, because most of what happens
      // in somebody's name is not a delegation and a page drawn from these
      // acts alone would be empty for anybody who merely signed in. See that
      // route's header.
      kit.note(t.html('consoleDelegation.pivotPerson')) +
      DelegationPage.delegationUserChooser(t, json.userChooser, '',
        { path: '/admin/delegation', query: ctx.query }) +

      '<h2>' + t.html('consoleDelegation.hWhatHappened') + '</h2>' +
      // No `page` input in this form, deliberately: changing a filter or the
      // page size returns to page 1. Carrying the old page number over would
      // land somebody on page 6 of a two-page result and the clamp in
      // pagingOf() would then move them again, which reads as the form
      // ignoring them. THE ANCHOR, for the reason chooserPane() gives at
      // length: this is a GET that reloads the page, and without it a reader
      // who had scrolled down to the filter was thrown back to the top of the
      // document by the click that answered them — on the longest page in
      // this console. It lands on the form rather than on the first row of
      // the table because the reader has usually just CHANGED a control and
      // wants to see what they set beside what came back; `scroll-margin-top`
      // then keeps the `What happened` heading above it on screen, so the
      // answer arrives with its question.
      '<form method="get" id="filter-acts" class="finder" ' +
        'action="/admin/delegation#filter-acts"><div class="formrow">' +
        DelegationPage.chooserCarry(ctx.query) +
        '<label for="type">' + t.html('consoleDelegation.thMechanism') +
        '</label><select id="type" name="type">' +
          typeOptions + '</select>' +
        '<label for="mode">' + t.html('consoleDelegation.labelKind') +
        '</label><select id="mode" name="mode">' +
          modeOptions + '</select>' +
        '<label for="outcome">' + t.html('consoleDelegation.labelOutcome') +
        '</label><select id="outcome" ' +
        'name="outcome">' +
          outcomeOptions + '</select>' +
        '<label for="per">' + t.html('consoleDelegation.labelPerPage') +
        '</label><select id="per" name="per">' +
      perOptions +
          '</select>' +
      '</div><div class="formrow">' +
        '<label for="q">' + t.html('consoleDelegation.labelText') +
        '</label>' +
        '<input type="text" id="q" name="q" size="40" value="' +
      kit.esc(wanted.q) +
          '" placeholder="' +
          kit.esc(t.text('consoleDelegation.textPlaceholder')) + '">' +
        '<button class="secondary">' + t.html('consoleDelegation.filter') +
        '</button>' +
        (filtering
          ? ' <a href="/admin/delegation#filter-acts">' +
            t.html('consoleDelegation.clear') + '</a>'
          : '') +
      '</div></form>' +
      kit.note(t.html('consoleDelegation.textSearchesEvery')) +
      kit.note(t.html('consoleDelegation.chainLinkNote')) +
      nav.head +
      '<table><tr><th class="num">#</th><th>' +
      t.html('consoleDelegation.thWhen') + '</th><th>' +
      t.html('consoleDelegation.thMechanism') + '</th>' +
      '<th>' + t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.labelOutcome') + '</th><th>' +
      t.html('consoleDelegation.thInitial') + '</th>' +
      '<th>' + t.html('consoleDelegation.thIntermediaryShort') + '</th><th>' +
      t.html('consoleDelegation.thTarget') + '</th><th>' +
      t.html('consoleDelegation.thAuthorizedBy') + '</th>' +
      '<th>' + t.html('consoleDelegation.thCredentials') + '</th></tr>' +
      (rows || '<tr><td colspan="10">' +
        (json.all
          ? t.html('consoleDelegation.nothingMatchesFilter')
          : t.html('consoleDelegation.nothingDelegatedYet')) +
        '</td></tr>') + '</table>' +
      nav.foot +

      kit.note(t.html('consoleDelegation.actsMatch', { n: json.matched }) +
      (json.paging.pages > 1 ?
       t.html('consoleDelegation.rowsOnPage', {
         first: json.paging.firstRow, last: json.paging.lastRow,
         page: json.paging.page, pages: json.paging.pages }) : '') +
      t.html('consoleDelegation.nHeld', { n: json.held }) +
      // ---------------------------------------------------------------------
      // ONE PROCESS OR SEVERAL, AND THE TWO NUMBERS ARE NOT COMPARABLE WHEN
      // IT IS SEVERAL (2026-09-11). `held` is every process's acts, fanned in
      // by `delegation.merged()`; `recorded` is a plain counter in THIS
      // process and there is no store to fan in. So "N held of M recorded"
      // reads as nonsense the moment N exceeds M, which in `dispatch` mode it
      // routinely does. The sentence says which is which instead of quietly
      // putting them in one comparison.
      // ---------------------------------------------------------------------
      (json.processes > 1
        ? t.html('consoleDelegation.acrossProcesses', {
            processes: json.processes, here: json.heldHere,
            recorded: json.recorded })
        : t.html('consoleDelegation.ofRecorded',
                 { recorded: json.recorded })) +
      (json.dropped
        ? t.html('consoleDelegation.droppedBefore', {
            dropped: json.dropped, max: json.maxRecords }) + '<a ' +
          'href="/admin/delegation-settings">' +
          t.html('consoleDelegation.protocolsDelegationLink') + '</a>' +
          t.html('consoleDelegation.droppedAfter')
        : t.html('consoleDelegation.capNothingDropped',
                 { max: json.maxRecords })) +
      t.html('consoleDelegation.seqNote')) +

      '<h2>' + t.html('consoleDelegation.hChains') + '</h2>' +
      kit.note(t.html('consoleDelegation.chainsBefore') +
      '<a href="/admin/delegation/map">' +
      t.html('consoleDelegation.chainsLink') + '</a>' +
      t.html('consoleDelegation.chainsAfter')) +
      chainsNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thMechanism') +
      '</th><th>' + t.html('consoleDelegation.labelKind') + '</th><th>' +
      t.html('consoleDelegation.thInitial') + '</th>' +
      '<th>' + t.html('consoleDelegation.thIntermediaryShort') + '</th><th>' +
      t.html('consoleDelegation.thTarget') + '</th><th>' +
      t.html('consoleDelegation.thActs') + '</th><th>' +
      t.html('consoleDelegation.thLastSeen') + '</th>' +
      '<th>' + t.html('consoleDelegation.thJustThisOne') + '</th></tr>' +
      (json.chainPage.shown.map(function (chain) {
        return '<tr>' +
          '<td><code>' + kit.esc(chain.type) + '</code></td>' +
          '<td>' + DelegationPage.modeCell(t, chain.mode) + '</td>' +
          '<td class="who">' +
          DelegationPage.delegationPartyCell(t, chain.initial, json.facts) +
          '</td><td class="who">' +
          DelegationPage.delegationPartyCell(t, chain.intermediary,
                                             json.facts) +
          '</td><td ' +
          'class="who">' +
          DelegationPage.delegationPartyCell(t, chain.target, json.facts) +
          '</td><td ' +
          'class="num">' + kit.esc(chain.acts) + ' — ' +
            '<span class="state-valid">' +
            t.html('consoleDelegation.nIssued', { n: chain.issued }) +
            '</span>, ' +
            (chain.refused
              ? '<span class="state-revoked">' +
                t.html('consoleDelegation.nRefused', { n: chain.refused }) +
                '</span>'
              : '<span class="state-none">' +
                t.html('consoleDelegation.nRefused', { n: 0 }) +
                '</span>') + '</td>' +
          '<td>' + kit.esc(kit.whenText(chain.lastAt)) + '</td>' +
          // An eighth column here where the acts table above puts the same
          // link inside its `#` cell, and the difference is width: this
          // table's five party columns are already narrow, but it has seven
          // of them against that one's ten and none of the long explanation
          // cells. A column can be afforded here and cannot be there.
          '<td><a href="' + kit.esc('/admin/delegation/chain' +
            kit.queryWith(listView, { chain: chain.chainKey })) +
            '">' + t.html('consoleDelegation.picture') + ' &rarr;</a></td>' +
          '</tr>';
      }).join('') || '<tr><td colspan="8">' +
        t.html('consoleDelegation.noChainsYet') + '</td></tr>') +
      '</table>' +
      chainsNav.foot +

      DelegationPage.permissionsSection(ctx, json.permissionsView,
                                        listView, false) +

      '<h2>' + t.html('consoleDelegation.hKerberosPolicy') + '</h2>' +
      kit.note(t.html('consoleDelegation.kdcView')) +
      kit.note(t.html('consoleDelegation.twoAttributes')) +
      kit.note(t.html('consoleDelegation.beyondAttribute')) +
      pairsNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thMechanism') +
      '</th><th>' + t.html('consoleDelegation.thFrontEnd') + '</th>' +
      '<th>' + t.html('consoleDelegation.thTargetReached') + '</th><th>' +
      t.html('consoleDelegation.thAttributeWhere') + '</th><th>' +
      t.html('consoleDelegation.thMissing') + '</th></tr>' +
      (json.pairPage.shown.map(function (pair) {
        return DelegationPage.policyPairRow(t, pair);
      }).join('') ||
        '<tr><td colspan="5">' +
        t.html('consoleDelegation.noConstrainedPrincipal') +
        '</td></tr>') + '</table>' +
      pairsNav.foot +

      '<h3>' + t.html('consoleDelegation.hAccountFlags') + '</h3>' +
      kit.note(t.html('consoleDelegation.accountFlagsNote')) +
      flagsNav.head +
      '<table><tr><th>' + t.html('consoleDelegation.thPrincipal') +
      '</th><th>' + t.html('consoleDelegation.thFlags') + '</th><th>' +
      t.html('consoleDelegation.thWhatEachDoes') + '</th></tr>' +
      (json.flagPage.shown.map(DelegationPage.policyAccountRow).join('') ||
        '<tr><td colspan="3">' + t.html('consoleDelegation.noFlags') +
        '</td></tr>') +
      '</table>' +
      flagsNav.foot +

      DelegationPage.delegationPolicySection(ctx,
                                             json.exchangePolicyView) +

      '<h3>' + t.html('consoleDelegation.hMechanisms') + '</h3>' +
      kit.note(t.html('consoleDelegation.mechanismsNote')) +
      mechanismsNav.head +
      '<ul>' + json.mechanismPage.shown.map(function (entry) {
        // The mechanism, its id, its specification and how many have been
        // recorded stay on the row; the paragraph saying what it IS folds
        // under them. Folding the whole item would have put the count — the
        // one figure that changes while somebody watches this page — behind a
        // click.
        return '<li><strong>' + kit.esc(entry.label) + '</strong> (<code>' +
          kit.esc(entry.type) + '</code>, ' + kit.esc(entry.protocol) +
          ', ' +
          kit.esc(entry.spec) + ' — ' +
          t.html('consoleDelegation.nRecorded',
                 { n: json.byType[entry.type] || 0 }) + ') ' +
          kit.note(kit.esc(entry.what) +
            (entry.policed
              ? ' ' + t.html('consoleDelegation.serviceDecides')
              : ' ' + t.html('consoleDelegation.nothingChecksWho'))) +
          '</li>';
      }).join('') + '</ul>' +
      mechanismsNav.foot +

      kit.note(t.html('consoleDelegation.inMemory')) +

      kit.note('<strong>' + t.html('consoleDelegation.succeededBefore') +
      '<a href="/admin/audit">' + t.html('consoleDelegation.theAuditLog') +
      '</a></strong>' + t.html('consoleDelegation.succeededMiddle') +
      '<a href="/admin/users">' + t.html('consoleDelegation.theUsersPage') +
      '</a>' + t.html('consoleDelegation.succeededAfter')) +

      // THE ONE SETTING THIS PAGE HAD, `delegation.maxRecords`, is on
      // Protocols → Delegation since 2026-10-01 with every other control
      // that was here (rcbj): this page reads, and that one configures.
      kit.note(t.html('consoleDelegation.nothingChangesBefore') + '<a ' +
      'href="/admin/delegation-settings">' +
      t.html('consoleDelegation.protocolsDelegationLink') + '</a>' +
      t.html('consoleDelegation.nothingChangesAfter')) +

      kit.note(t.html('consoleDelegation.everyTablePaged', {
        per: json.delegationPerPage, max: kit.MAX_ROWS })) +

      kit.note(t.html('consoleDelegation.jsonWhole')));
  }
}

export = DelegationPage;
