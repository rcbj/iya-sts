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
const FLOW_NOT_STATED_WHAT =
  'Whatever minted this said nothing about how. That is true of every ' +
  'JWT signed outside the token endpoint — WS-Trust\'s JWT token type ' +
  'and the credential issuer both sign directly — and of the signed ' +
  'UserInfo response, which is a reply rather than a credential a ' +
  'grant produced.';

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
  static drawing(json: Json, path: string, params: Json): string {
    const drawn = json.drawing || {};
    return '<div class="diagram">' + json.svg + '</div>' +
      kit.note(drawn.width + '&times;' + drawn.height + ' — ' +
      '<a href="' + kit.esc(path + kit.queryWith(params, { format: 'svg' })) +
      '">the document on its own</a> (SVG, no links in it), or ' +
      '<a href="' + kit.esc(path + kit.queryWith(params, { format: 'json' })) +
      '">the graph as JSON</a>.' +
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
  static delegationPartyCell(party, facts) {
    const parts = [];
    if (party.key) {
      parts.push(GroupsPage.usersPageCell(party.key, facts.users));
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
          'title="This application is in the registry (ou=applications).">' +
          kit.esc(party.application) + '</a>'
        : '<span class="state-none" title="No entry under ou=applications ' +
          'names this. The registry holds what this service has been ASKED ' +
          'ABOUT — a client_id presented, an AppliesTo a token was issued ' +
          'for, an SPN a ticket was cut for — and this delegation named ' +
          'something nobody has otherwise mentioned. That is ordinary for an ' +
          'RFC 8693 audience and is worth seeing rather than ' +
          'hiding.">' + kit.esc(party.application) +
          ' <em>(not in the registry)</em></span>');
    }
    if (!parts.length) {
      return '<span class="state-none" title="Nothing here names this party, ' +
        'and on some mechanisms nothing can: a forwarded ticket-granting ' +
        'ticket is handed to whichever service the client chooses, and this ' +
        'KDC is never told which.">&mdash;</span>';
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
  static modeCell(mode) {
    if (mode === 'impersonation') {
      return '<span class="state-expired" title="What came out names the ' +
        'initial identity and nothing else. The far end cannot tell an ' +
        'intermediary was involved, and neither can anybody reading the ' +
        'credential afterwards — which is why the issuer is the only place ' +
        'this is ever visible.">impersonation</span>';
    }
    if (mode === 'delegation') {
      return '<span class="state-valid" title="What came out CARRIES the ' +
        'chain: an `act` claim, a composite ActAs, or S4U_DELEGATION_INFO in ' +
        'the PAC. The far end can see who is really asking.">delegation</span>';
    }
    return '<span class="state-none">&mdash;</span>';
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
  static delegationOutcomeCell(row) {
    if (row.outcome === 'issued') {
      return '<span class="state-valid">issued</span>';
    }
    return '<span class="state-revoked" title="This service refused the ' +
      'delegation. The reason is the KDC\'s own words — the same text the ' +
      'client was sent — rather than a second wording written for this ' +
      'page.">refused</span>';
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
  static delegationRow(row, facts, options) {
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
            '" title="Draw THIS relationship on its own — the whole chain ' +
            'this act belongs to, with everything else in the service left ' +
            'out.">chain</a>'
          : '') + '</td>' +
      '<td>' + kit.esc(kit.whenText(row.at)) + '</td>' +
      '<td><code>' + kit.esc(row.type) + '</code><br>' +
        '<span class="state-none">' + kit.esc(row.typeLabel) + '</span><br>' +
        '<span class="state-none">' + kit.esc(row.protocol) +
        (row.spec ? ' &middot; ' + kit.esc(row.spec) : '') + '</span></td>' +
      '<td>' + DelegationPage.modeCell(row.mode) + '</td>' +
      '<td>' + DelegationPage.delegationOutcomeCell(row) + '</td>' +
      '<td class="who">' +
        DelegationPage.delegationPartyCell(row.initial, facts) + '</td>' +
      '<td class="who">' +
        DelegationPage.delegationPartyCell(row.intermediary, facts) +
      '</td><td class="who">' +
        DelegationPage.delegationPartyCell(row.target, facts) + '</td>' +
      '<td>' + (row.outcome === 'refused'
                ? kit.esc(row.reason)
                : (row.authorizedBy ? kit.esc(row.authorizedBy)
                                    : '<span ' +
                                      'class="state-none">&mdash;</span>')) +
        (row.note ? '<br><span class="state-none">' + kit.esc(row.note) +
         '</span>' :
         '') +
      '</td><td class="who">' +
        DelegationPage.delegationCredentialCell(row.consumed, '&rarr; in') +
        DelegationPage.delegationCredentialCell(row.produced, '&larr; out') +
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
  static delegationNodeRow(node, facts, look) {
    if (node.kind === 'sts') {
      return '';
    }
    const party = { key: node.key, presented: node.presented,
                    application: node.application, what: node.what };
    const roles = [];
    if (node.roles.initial) roles.push(node.roles.initial +
                                       ' × initial identity');
    if (node.roles.intermediary) roles.push(node.roles.intermediary + ' × ' +
        'intermediary');
    if (node.roles.target) roles.push(node.roles.target + ' × target');
    return '<tr>' +
      '<td>' + kit.esc(look.label) +
        (look.identifier
          ? '<br><span class="state-none" title="What a protocol would have ' +
            'to present to reach this party, and that protocol\'s own word ' +
            'for it. It is the second line inside the box in the picture ' +
            'above; where the label IS the identifier, only the word is ' +
            'drawn.">' +
            kit.esc(look.identifier) + '</span>'
          : '') + '</td>' +
      '<td>' + (look.shape === 'both'
                  ? 'person <strong>and</strong> application'
                  : look.shape === 'person' ? 'person'
                  : look.shape === 'application' ? 'application' : look.shape) +
        (look.dashed
          ? '<br><span class="state-none" title="Neither ou=users nor ' +
            'ou=applications holds an entry for this. The shape is the one ' +
            'its role implies.">drawn from its role &mdash; neither store ' +
            'knows it</span>'
          : '') + '</td>' +
      '<td class="who">' + DelegationPage.delegationPartyCell(party, facts) +
      '</td>' +
      '<td>' +
      (roles.join('<br>') || '<span class="state-none">&mdash;</span>') +
        (node.selfTarget
          ? '<br><span class="state-expired" title="S4U2Self is a request ' +
            'for a ticket to yourself, so the intermediary and the target ' +
            'are one party. There is no line for it in the picture because ' +
            'an arrow leaving a box and coming back is a drawing of ' +
            'nothing.">also its own target</span>'
          : '') + '</td>' +
      '<td class="num">' + kit.esc(node.acts) + ' — ' +
        '<span class="state-valid">' + kit.esc(node.issued) + ' ' +
          'issued</span>, ' +
        (node.refused
          ? '<span class="state-revoked">' + kit.esc(node.refused) +
            ' refused</span>'
          : '<span class="state-none">0 refused</span>') + '</td>' +
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
  static delegationEdgeRow(edge, lookOf) {
    const relation = edge.relation === 'issued'
      ? '<span class="state-none" title="This service handed that party a ' +
        'credential. It goes to whoever ASKED.">issued to</span>'
      : edge.relation === 'acts-for'
        ? '<strong>acts for</strong>'
        : '<strong>reaches</strong>' +
          (edge.subject ? '<br><span class="state-none">as ' +
           kit.esc(edge.subject) +
                          '</span>' : '');
    return '<tr>' +
      '<td class="who">' + kit.esc(lookOf(edge.from)) + '</td>' +
      '<td class="who">' + kit.esc(lookOf(edge.to)) + '</td>' +
      '<td>' + relation +
        ((edge.skipped || []).length
          ? '<br><span class="state-expired" title="Nobody named this party ' +
            'on these acts, so the line jumps it. A forwarded ' +
            'ticket-granting ticket has no intermediary and cannot have ' +
            'one.">jumps the ' +
            kit.esc(edge.skipped.join(' and ')) + '</span>'
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
      '<td>' + DelegationPage.modeCell(edge.mode) + '</td>' +
      '<td class="num">' + kit.esc(edge.acts) + ' — ' +
        '<span class="state-valid">' + kit.esc(edge.issued) + ' ' +
          'issued</span>, ' +
        (edge.refused
          ? '<span class="state-revoked">' + kit.esc(edge.refused) +
            ' refused</span>'
          : '<span class="state-none">0 refused</span>') + '</td>' +
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
                  (one.moreIdentifiers ? ' <span class="state-none">+' +
                    kit.esc(one.moreIdentifiers) + ' more</span>' : '')
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
                      kit.esc(edge.authorizedBy || 'Nothing in this service ' +
                               'decides who may perform this act.') +
                      '">nothing checks this</span>') +
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
  static delegationTokenRow(token, labelOf, extra?) {
    return '<tr>' +
      '<td class="num">' + kit.esc(token.seq) + '</td>' +
      '<td>' + kit.esc(kit.whenText(token.at)) + '</td>' +
      (extra === undefined ? '' : '<td>' + extra + '</td>') +
      '<td class="who"><code>' + kit.esc(token.kind) + '</code>' +
        (token.identifier
          ? '<br>' + kit.shortened(token.identifier, 14)
          : '<br><span class="state-none" title="A Kerberos ticket has no ' +
            'identifier this service could quote — there is no jti and no ' +
            'AssertionID in one.">no identifier</span>') +
        (token.note ? '<br><span class="state-none">' + kit.esc(token.note) +
                      '</span>' : '') + '</td>' +
      '<td class="who">' + kit.esc(labelOf(token.subject) ||
        '<span class="state-none">&mdash;</span>') + '</td>' +
      '<td class="who">' + (token.actor ? kit.esc(labelOf(token.actor))
        : '<span class="state-none" title="A forwarded ticket-granting ' +
          'ticket has no intermediary this KDC was told ' +
          'about.">&mdash;</span>') +
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
  static delegationApplicationChooser(chooser, selectedKey, here) {
    if (!chooser.total) {
      return kit.note('<strong>No delegation held here names an application ' +
        'yet</strong>, so there is nothing to choose between. An application ' +
        'arrives in this list the moment something delegates through it or ' +
        'to it: an RFC 8693 <code>audience</code> or the ' +
        '<code>client_id</code> that performed the exchange, a WS-Trust ' +
        '<code>AppliesTo</code>, or the service principal a Kerberos S4U ' +
        'request asked for a ticket to.');
    }
    return kit.chooserPane({
      here: here, param: 'appq', fromParam: 'appfrom',
      label: 'Find an application',
      placeholder: 'part of a client_id, an SPN or an audience',
      entries: chooser.entries, selectedKey: selectedKey,
      slice: chooser.slice,
      nothing: 'No application any act named matches that. This list holds ' +
        'what some delegation actually presented, spellings and all, so a ' +
        'name that is in the acts table above and not in here is one this ' +
        'register filed as a person rather than as an application.'
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
  static delegationUserChooser(chooser, selectedKey, here) {
    if (!chooser.total) {
      return kit.note('<strong>Nothing has authenticated here and no ' +
        'delegation names anybody</strong>, so there is nobody to choose. An ' +
        'identity arrives in this list the moment a credential is accepted ' +
        'in any of the sixteen families, the moment a token or an assertion ' +
        'is issued naming somebody, or the moment a delegation names them — ' +
        'including one they were never present for.');
    }
    return kit.chooserPane({
      here: here, param: 'userq', fromParam: 'userfrom',
      label: 'Find a person',
      placeholder: 'part of a username, a principal or a subject',
      entries: chooser.entries, selectedKey: selectedKey,
      slice: chooser.slice,
      nothing: 'Nobody here matches that. This list is the identity register ' +
        'UNIONED with everybody a delegation named, so a name that is on the ' +
        'page above and not in here reached this service as an application ' +
        'rather than as a person.'
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
  static userEdgeRow(edge, lookOf) {
    const relation =
      edge.relation === 'issued'
        ? '<span class="state-none" title="This service handed that party a ' +
          'credential.">issued to</span>'
      : edge.relation === 'signed-in'
        ? '<strong>signed in</strong><br><span class="state-none">to this ' +
          'service</span>'
      : edge.relation === 'issued-for'
        ? '<strong>issued for</strong><br><span class="state-none">by an ' +
          'ordinary grant</span>'
      : edge.relation === 'acts-for'
        ? '<strong>acts for</strong><br><span class="state-none">a ' +
          'delegation</span>'
        : '<strong>reaches</strong>' +
          (edge.subject ? '<br><span class="state-none">as ' +
           kit.esc(edge.subject) +
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
                : '<span class="state-none" title="The token names this ' +
                  'resource and none of its delegated permissions \u2014 ' +
                  'which is what a scope naming the resource\'s client_id ' +
                  'produces, because that value becomes the audience and ' +
                  'comes off the scope claim. It is also what a resource ' +
                  'that defines no permissions can ever produce.">default ' +
                  'permissions</span>')
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
          ? '<br><span class="state-expired" title="Nobody named this party ' +
            'on these acts, so the line jumps it.">jumps the ' +
            kit.esc(edge.skipped.join(' and ')) + '</span>'
          : '') + '</td>' +
      '<td>' + mechanism + '</td>' +
      '<td>' + (edge.mode ? DelegationPage.modeCell(edge.mode)
        : '<span class="state-none" title="Impersonation and delegation are ' +
          'properties of a DELEGATION mechanism. An ordinary grant makes ' +
          'neither claim, and calling it one would be this console inventing ' +
          'a judgement.">&mdash;</span>') + '</td>' +
      '<td class="num">' + (edge.acts
        ? kit.esc(edge.acts) + (edge.relation === 'signed-in' ? ''
            : ' — <span class="state-valid">' + kit.esc(edge.issued) + ' ' +
                'issued</span>' +
              (edge.refused
                ? ', <span class="state-revoked">' + kit.esc(edge.refused) +
                  ' refused</span>' : ''))
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
                  (one.moreIdentifiers ? ' <span class="state-none">+' +
                    kit.esc(one.moreIdentifiers) + ' more</span>' : '')
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
  static userNodeRow(node, facts, look) {
    if (node.kind === 'sts') {
      return '';
    }
    const party = { key: node.key, presented: node.presented,
                    application: node.application, what: node.what };
    const roles = [];
    if (node.roles.initial) roles.push(node.roles.initial +
                                       ' × initial identity');
    if (node.roles.intermediary) roles.push(node.roles.intermediary + ' × ' +
        'intermediary');
    if (node.roles.target) roles.push(node.roles.target + ' × target');
    return '<tr>' +
      '<td>' + kit.esc(look.label) +
        (node.isSubject
          ? '<br><span class="state-valid" title="This is the person this ' +
            'page is about. Every line on the picture starts or ends ' +
            'here.">this page</span>'
          : '') +
        (look.identifier
          ? '<br><span class="state-none" title="What a protocol would have ' +
            'to present to reach this party, and that protocol\'s own word ' +
            'for it. It is the second line inside the box in the picture ' +
            'above; where the label IS the identifier, only the word is ' +
            'drawn.">' +
            kit.esc(look.identifier) + '</span>'
          : '') + '</td>' +
      '<td>' + (look.shape === 'both'
                  ? 'person <strong>and</strong> application'
                  : look.shape === 'person' ? 'person'
                  : look.shape === 'application' ? 'application' : look.shape) +
        (look.dashed
          ? '<br><span class="state-none" title="Neither ou=users nor ' +
            'ou=applications holds an entry for this. The shape is the one ' +
            'its role implies.">drawn from its role &mdash; neither store ' +
            'knows it</span>'
          : '') + '</td>' +
      '<td class="who">' + DelegationPage.delegationPartyCell(party, facts) +
      '</td>' +
      '<td class="num">' + (node.credentials
        ? '<strong>' + kit.esc(node.credentials) + '</strong>'
        : '<span class="state-none">0</span>') + '</td>' +
      '<td>' + (node.flows.map(kit.esc.bind(kit)).join('<br>') ||
                '<span class="state-none">&mdash;</span>') + '</td>' +
      '<td>' + (roles.join('<br>') || '<span class="state-none" title="This ' +
        'box is in no delegation at all — it holds credentials from an ' +
        'ordinary grant. The delegation roles are a fact about the OTHER ' +
        'register.">not in a delegation</span>') + '</td>' +
      '<td class="num">' + (node.acts
        ? kit.esc(node.acts) + ' — <span class="state-valid">' +
          kit.esc(node.issued) +
          ' issued</span>' + (node.refused
            ? ', <span class="state-revoked">' + kit.esc(node.refused) + ' ' +
                'refused</span>'
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
  static userCredentialRow(credential, facts) {
    const holder = credential.holder
      ? DelegationPage.delegationPartyCell({ key: '', presented: '',
                                   application: credential.holder, what: '' },
                                   facts)
      : '<span class="state-none" title="Nothing holds this one. An ' +
        'X509-SVID has no audience, and a token can be minted with no ' +
        'client_id — this service issued it and there is no second party to ' +
        'draw.">&mdash;</span>';
    return '<tr>' +
      '<td>' + kit.esc(kit.whenText(credential.at)) + '</td>' +
      '<td class="who"><code>' + kit.esc(credential.kind) + '</code>' +
        (credential.identifier
          ? '<br>' + kit.shortened(credential.identifier, 14)
          : '<br><span class="state-none" title="A Kerberos ticket has no ' +
            'identifier this service could quote — there is no jti and no ' +
            'AssertionID in one.">no identifier</span>') +
        (credential.detail
          ? '<br><span class="state-none">' + kit.esc(credential.detail) +
            '</span>'
          : '') + '</td>' +
      '<td>' + DelegationPage.userFlowCell(credential) + '</td>' +
      '<td class="who">' + holder + '</td>' +
      '<td class="' + TokensPage.stateClass(credential.state) + '">' +
      kit.esc(credential.state) +
        '</td>' +
      '<td>' + (credential.sessionId
        ? kit.shortened(credential.sessionId, 10)
        : '<span class="state-none" title="No browser sign-on session was ' +
          'stated. That is true of every direct grant — client_credentials, ' +
          'password, the pre-authorized code, a token exchange — and of ' +
          'everything issued outside the token ' +
          'endpoint.">none</span>') + '</td>' +
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
  static userFlowCell(credential) {
    if (credential.flowStated) {
      return '<code>' + kit.esc(credential.flow) + '</code><br>' +
        '<strong>' + kit.esc(credential.flowLabel) + '</strong>' +
        (credential.flowOidc && credential.flowOidc !== credential.flowLabel
          ? '<br><span class="state-none" title="OpenID Connect\'s name for ' +
            'the same exchange. One thing, two vocabularies.">OIDC: ' +
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
        '<br><span class="state-none" title="A SAML assertion, a Kerberos ' +
        'ticket and an SVID are issued by protocols that have never heard of ' +
        'an OAuth grant. The mechanism named here is their own ' +
        'specification\'s.">not an OAuth grant</span>';
    }
    return '<span class="state-none" title="' +
      kit.esc(FLOW_NOT_STATED_WHAT) + '">no grant stated</span>';
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
  static delegationApplicationTable(catalogue, facts, carry) {
    const rows = catalogue.map(function (entry) {
      const roles = [];
      if (entry.roles.intermediary) {
        roles.push(kit.esc(entry.roles.intermediary) + ' × intermediary');
      }
      if (entry.roles.target) {
        roles.push(kit.esc(entry.roles.target) + ' × target');
      }
      if (entry.roles.initial) {
        roles.push(kit.esc(entry.roles.initial) + ' × initial identity');
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
              kit.esc(entry.spellings.length) +
              ' spellings, collapsed</span>'
            : '') +
          (registered ? ''
            : '<br><span class="state-none" title="No entry under ' +
              'ou=applications names this. The registry holds what this ' +
              'service has been ASKED ABOUT; a delegation can name something ' +
              'nobody has otherwise mentioned.">not in the registry</span>') +
          (entry.identityKey
            ? '<br>' + GroupsPage.usersPageCell(entry.identityKey, facts.users)
            : '') + '</td>' +
        '<td>' +
        (roles.join('<br>') || '<span class="state-none">&mdash;</span>') +
          '</td>' +
        '<td class="num">' + kit.esc(entry.acts) + ' — ' +
          '<span class="state-valid">' + kit.esc(entry.issued) + ' ' +
            'issued</span>, ' +
          (entry.refused
            ? '<span class="state-revoked">' + kit.esc(entry.refused) + ' ' +
                'refused</span>'
            : '<span class="state-none">0 refused</span>') + '</td>' +
        '<td class="num">' + kit.esc(entry.credentials) + '</td>' +
        '<td class="num">' + kit.esc(entry.chains) + '</td>' +
        '<td>' + kit.esc(kit.whenText(entry.lastAt)) + '</td>' +
        '</tr>';
    }).join('');
    return '<table><tr><th>Application</th><th>Roles it has played</th><th>' +
      'Acts</th><th>Credentials</th><th>Relationships</th><th>Last ' +
      'seen</th></tr>' +
      (rows || '<tr><td colspan="6">No delegation held here names an ' +
       'application.</td></tr>') + '</table>';
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
  static delegationUserTable(catalogue, facts, carry) {
    const rows = catalogue.map(function (entry) {
      const where = [];
      if (entry.authenticated) {
        where.push('<span class="state-valid" title="A credential was ' +
          'accepted for this name here, so the identity register has a row ' +
          'for them.">authenticated here</span>');
      }
      if (entry.delegated) {
        where.push('<span class="state-expired" title="Some delegation act ' +
          'names them, in one of the three roles. That does NOT mean they ' +
          'were present — S4U2Self and OnBehalfOf name somebody who proved ' +
          'nothing.">named in a delegation</span>');
      }
      if (!entry.authenticated) {
        where.push('<span class="state-none" title="Nothing has ever ' +
          'presented a credential under this name in this process. Something ' +
          'was issued in it, or somebody delegated using it, which is ' +
          'exactly the state worth noticing.">never authenticated here</span>');
      }
      return '<tr>' +
        '<td class="who"><a href="' + kit.esc('/admin/delegation/user' +
          kit.queryWith(carry || {}, { user: entry.key })) + '"><code>' +
          kit.esc(entry.key) + '</code></a>' +
          (entry.isClient
            ? '<br><span class="state-none" title="Something authenticated ' +
              'as this name and said it was a client rather than a person — ' +
              'the client_credentials grant is the usual way.">a client, not ' +
              'a person</span>'
            : '') +
          '<br>' + GroupsPage.usersPageCell(entry.key, facts.users) + '</td>' +
        '<td>' + where.join('<br>') + '</td>' +
        '<td class="num">' + kit.esc(entry.authentications) + '</td>' +
        '<td class="num">' + kit.esc(entry.tokens.issued) + ' — ' +
          '<span class="state-valid">' + kit.esc(entry.tokens.valid) +
        ' valid</span>' +
          (entry.tokens.revoked
            ? ', <span class="state-revoked">' +
              kit.esc(entry.tokens.revoked) +
              ' revoked</span>' : '') + '</td>' +
        '<td class="num">' + kit.esc(entry.artifacts) + '</td>' +
        '<td class="num">' + (entry.acts
          ? kit.esc(entry.acts) + ' — <span class="state-valid">' +
            kit.esc(entry.issued) +
            ' issued</span>' + (entry.refused
              ? ', <span class="state-revoked">' + kit.esc(entry.refused) +
                ' refused</span>' : '')
          : '<span class="state-none">0</span>') + '</td>' +
        '<td>' + (entry.protocols.map(kit.esc.bind(kit)).join('<br>') ||
                  '<span class="state-none">&mdash;</span>') + '</td>' +
        '<td>' + kit.esc(kit.whenText(entry.lastAt)) + '</td>' +
        '</tr>';
    }).join('');
    return '<table><tr><th>Identity</th><th>Where from</th><th>Sign-ins</th>' +
      '<th>Tokens</th><th>Artifacts</th><th>Delegation acts</th>' +
      '<th>Protocols</th><th>Last seen</th></tr>' +
      (rows || '<tr><td colspan="8">Nobody has authenticated here and no ' +
       'delegation names anybody.</td></tr>') + '</table>';
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
  static allowedApplicationChooser(view, selectedKey, carry, here) {
    const groups = view.clusters;
    if (!groups.counts.applications) {
      return kit.note('<strong>No application in this registry exposes an ' +
        'API or holds a permission yet</strong>, so there is nothing to ' +
        'search. An application arrives in this list the moment it is given ' +
        'a base URI or a permission of its own — which makes it a RESOURCE — ' +
        'or is granted one somebody else exposes, which makes it a CLIENT. ' +
        'Both are done on <a href="/admin/delegation#allowed">the ' +
        'register</a> or through <code>POST /admin-api/permissions/…</code>.');
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
          parts.push(holds[identifier] + ' grant(s) held');
        }
        if (exposes[identifier]) {
          parts.push(exposes[identifier] + ' permission(s) exposed');
        }
        if (reached[identifier]) {
          parts.push(reached[identifier] + ' grant(s) on it');
        }
        if (!parts.length) {
          parts.push('a base URI and nothing on it yet');
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
                    ? 'in no group but its own'
                    : 'one of ' + group.counts.applications +
                      ' applications joined to each other'),
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
      label: 'Find an application',
      placeholder: 'part of a client_id, a base URI or an application name',
      entries: entries, selectedKey: selectedKey,
      nothing: 'No application in the configured register matches that. This ' +
        'list holds what the PERMISSION register touches — an entry with a ' +
        'base URI or a permission of its own, or one holding a grant — so a ' +
        'name that is on <a href="/admin/applications">the registry</a> and ' +
        'not in here is an application nothing has been configured about yet.'
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
  static allowedClusterTable(groups, shown, carry, apps) {
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
            : ' <span class="state-none" title="No entry under ' +
              'ou=applications answers to this identifier. It can only have ' +
              'got here through an ldapmodify, since both console doors read ' +
              'the registry.">not in the registry</span>');
      }).join('<br>');
      return '<tr>' +
        '<td class="who"><a href="' + kit.esc('/admin/delegation/cluster' +
          kit.queryWith(carry || {}, { application: group.key })) + '">' +
          (group.counts.applications === 1
            ? 'this one alone'
            : kit.esc(group.counts.applications) + ' applications') + '</a>' +
          '<br><span class="state-none" title="A group is named after the ' +
          'application whose identifier sorts first, so that adding a grant ' +
          'inside it does not rename it.">named for <code>' +
          kit.esc(group.key) +
          '</code></span></td>' +
        '<td>' + members + '</td>' +
        '<td class="num">' + (group.counts.lines
          ? kit.esc(group.counts.lines)
          : '<span class="state-none" title="Nothing in this group may reach ' +
            'anything else in it. A group of one with a base URI is an API ' +
            'somebody described and nothing was granted on.">0</span>') +
        '</td><td ' +
        'class="num">' + (group.counts.asked
          ? '<span class="state-valid">' + kit.esc(group.counts.asked) +
            '</span>'
          : '<span class="state-none">0</span>') + ' asked for<br>' +
          (group.counts.unused
            ? '<span class="state-expired" title="Granted and never ' +
              'requested. Read off the client\'s own oauthScope — evidence ' +
              'rather than proof.">' + kit.esc(group.counts.unused) + '</span>'
            : '<span class="state-none">0</span>') + ' never used</td>' +
        '<td class="num">' + kit.esc(group.counts.permissions) + '</td>' +
        '<td class="num">' + (group.counts.dangling
          ? '<span class="state-revoked" title="Naming a permission no ' +
            'application in this registry defines. Not drawn on any picture, ' +
            'because a line to nowhere would be a drawing of a resource that ' +
            'is there.">' + kit.esc(group.counts.dangling) + ' dangling</span>'
          : '<span class="state-none">&mdash;</span>') +
          (group.counts.selfGrants
            ? '<br><span class="state-expired" title="An application granted ' +
              'its own permission. Neither console door will create one; an ' +
              'ldapmodify can. No arrow is drawn, because an arrow from a ' +
              'box back to itself is a drawing of nothing.">' +
              kit.esc(group.counts.selfGrants) + ' to itself</span>'
            : '') + '</td>' +
        '</tr>';
    }).join('');
    return '<table><tr><th>The group</th><th>The applications in it</th>' +
      '<th>Lines drawn</th><th>Grants</th><th>Permissions exposed</th>' +
      '<th>Not drawn</th></tr>' +
      (rows || '<tr><td colspan="6">' +
        (groups.counts.clusters
          ? 'No group on this page.'
          : 'Nothing in this registry exposes an API or holds a permission, ' +
            'so there are no groups to draw.') + '</td></tr>') + '</table>';
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
  static permissionDefinitionRow(one, listView, options?) {
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
        : '<span class="state-revoked" title="This permission has no ' +
          'identifier because its application has no oauthPermissionBaseUri. ' +
          'A permission is named by its base URI followed by its name, so no ' +
          'client can ever ask for this one. Set the base on the application ' +
          'and it resolves.">no identifier &mdash; the application has no ' +
          'base URI</span>') + '</td>' +
      '<td class="num">' + (one.grantedTo.length
        ? '<span class="state-valid">' + one.grantedTo.length + '</span>'
        : '<span class="state-none" title="Nothing holds this permission. ' +
          'That is the ordinary state of a permission that has just been ' +
          'defined — defining one grants it to nobody.">0</span>') + '</td>' +
      '<td class="who">' + (one.grantedTo.length
        ? one.grantedTo.map(function (who) {
            return kit.esc(who.name) + (who.asked ? '' :
              ' <span class="state-none" title="Granted and never asked ' +
              'for.">(unused)</span>');
          }).join('<br>')
        : '<span class="state-none">&mdash;</span>') + '</td>' +
      // THE TWO BRANCHES DREW THE SAME FORM, and they did before this row
      // carried a `back` as well — the `one.id` test above decides the
      // IDENTIFIER cell, not this one, and a permission with no identifier is
      // removed by exactly the same call. One form, once.
      '<td>' + (options && options.readOnly
        ? '<a href="/admin/delegation-settings#allowed" title="This page ' +
          'draws the register and does not change it. The Remove button for ' +
          'this permission is on Protocols › Delegation.">change it</a>'
        : '<form method="post" action="/admin/delegation-settings">' +
          DelegationPage.permissionsBack(listView) + '<div class="formrow">' +
          '<input type="hidden" name="action" value="remove-permission">' +
          '<input type="hidden" name="resource" value="' +
          kit.esc(one.resource) +
          '"><input ' +
          'type="hidden" name="name" value="' + kit.esc(one.name) + '">' +
          '<button type="submit" class="danger">Remove</button>' +
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
  static permissionGrantRow(one, listView, options?) {
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
        : '<span class="state-revoked" title="No application in this ' +
          'registry defines this permission. Either the resource\'s entry ' +
          'was deleted, or the permission was removed from it while this ' +
          'grant still named it, or an ldapmodify wrote a grant that never ' +
          'resolved — both console doors refuse to create ' +
          'one.">dangling</span>') + '</td>' +
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
        : '<span class="state-none">nothing &mdash; the permission does not ' +
          'resolve, so this scope is treated as an ordinary one</span>') +
      '</td><td>' + (one.asked
        ? '<span class="state-valid" title="This client\'s entry records ' +
          'having asked for this scope. It is evidence rather than proof: ' +
          'oauthScope records what was requested, not what was ' +
          'issued.">asked for</span>'
        : '<span class="state-none" title="This client has never asked for ' +
          'it. A configured grant nobody has needed is exactly what this ' +
          'register is here to show.">never asked for</span>') + '</td>' +
      '<td>' + (options && options.readOnly
        ? '<a href="/admin/delegation-settings#allowed" title="This page ' +
          'draws the register and does not change it. The Revoke button for ' +
          'this grant is on Protocols › Delegation.">change it</a>'
        : '<form method="post" action="/admin/delegation-settings">' +
          DelegationPage.permissionsBack(listView) + '<div class="formrow">' +
          '<input type="hidden" name="action" value="revoke-permission">' +
          '<input type="hidden" name="client" value="' + kit.esc(one.client) +
          '"><input type="hidden" name="permission" value="' +
          kit.esc(one.permissionId) + '"><button ' +
          'type="submit" class="danger">Revoke</button></div></form>') +
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
  // /admin-api/applications/update) and the person's page (and POST
  // /admin-api/users/set-not-delegated, /set-may-act). A second form here
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
        (pair.impersonates ? '<br><span class="state-expired">may ' +
          'impersonate</span>' : '') + '</td>' +
        '<td class="who"><code>' + kit.esc(pair.target) + '</code>' +
        (pair.targetApplication && pair.targetApplication !== pair.target
          ? '<br><span class="state-none">the application ' +
            kit.esc(pair.targetApplication) + '</span>' : '') + '</td>' +
        '<td class="who"><code>' + kit.esc(pair.attribute) + '</code><br>' +
        '<span class="state-none">on the ' + kit.esc(pair.setOnRole) +
        ', ' + appLink(pair.setOn) + '</span></td>' +
        '<td>' + (pair.subjectGroups.length
          ? pair.subjectGroups.map(function (dn) {
            return '<code>' + kit.esc(dn) + '</code>';
          }).join('<br>')
          : 'anybody not protected') + '</td>' +
        '<td>' + (pair.warning
          ? '<span class="state-expired">' + kit.esc(pair.warning) +
            '</span>'
          : '<span class="state-valid">nothing else is missing</span>') +
        '</td></tr>';
    }).join('');
    const intermediaryRows = view.intermediaries.shown.map(function (row) {
      return '<tr><td class="who">' + appLink(row.application) + '</td>' +
        '<td>' + (row.semantics && row.semantics.length
          ? row.semantics.map(function (one: string) {
            return kit.esc(one);
          }).join(', ') : 'delegation only (empty)') +
        (row.defaultSemantics ? '<br><span class="state-none">default ' +
          kit.esc(row.defaultSemantics) + '</span>' : '') +
        (row.notDelegated ? '<br><code>appNotDelegated</code> — never ' +
          'acted for' : '') +
        '</td><td>' + (row.subjectGroups.length
          ? row.subjectGroups.map(function (dn) {
            return '<code>' + kit.esc(dn) + '</code>';
          }).join('<br>') : 'anybody not protected') + '</td></tr>';
    }).join('');
    const peopleRows = view.people.shown.map(function (row) {
      return '<tr><td class="who"><a href="' + kit.esc('/admin/users?user=' +
        encodeURIComponent(String(row.username))) + '">' +
        kit.esc(row.username) + '</a></td><td>' +
        (row.notDelegated ? '<code>stsNotDelegated</code> — nobody may act ' +
          'for them' : '&mdash;') + '</td><td>' +
        (row.mayAct ? '<code>' + kit.esc(row.mayAct) + '</code>'
                    : '&mdash;') + '</td><td>' +
        ((row.semantics && row.semantics.length) || row.defaultSemantics
          ? kit.esc((row.semantics || []).join(', ') || 'both') +
            (row.defaultSemantics ? '; default ' +
              kit.esc(row.defaultSemantics) : '')
          : '&mdash;') + '</td></tr>';
    }).join('');
    const register = view.register;
    return '<h2 id="delegation-policy">Who may act for whom &mdash; ' +
      'WS-Trust, token exchange and Kerberos</h2>' +
      kit.note('<strong>Decided by the issuance policy</strong> (#186), ' +
      'from facts on the entries — one set of settings for the three ' +
      'protocols. <code>appAllowedToDelegateTo</code> on an application ' +
      'names the applications it delegates to (the analogue of ' +
      '<code>msDS-AllowedToDelegateTo</code>); ' +
      '<code>appAllowedToActOnBehalfOf</code> on the TARGET names the actors ' +
      'it accepts (the resource-based one); ' +
      '<code>appDelegationSubjectGroup</code> narrows who an actor may act ' +
      'for; and <code>appDelegationSemantics</code> says whether it may ' +
      'IMPERSONATE as well as delegate (empty is delegation only), with ' +
      '<code>appDefaultDelegationSemantics</code> the default. A person ' +
      'acting needs the role <code>delegation.actorRole</code> names. A ' +
      'person carrying <code>stsNotDelegated</code>, an application carrying ' +
      '<code>appNotDelegated</code>, or a member of ' +
      (register.protectedGroups.length
        ? register.protectedGroups.map(function (one) {
          return '<code>' + kit.esc(one) + '</code>';
        }).join(' or ')
        : 'a console roster') +
      ', is never delegated. The rules are the issuance policy\'s ' +
      '(action-ids <code>choose-exchange-semantics</code> and ' +
      '<code>exchange-token</code>); a realm changes them in its own ' +
      'policy. ' + (register.enforced
        ? '<strong>This realm is in product mode, so this is ' +
          'ENFORCED</strong>: a refusal is <code>wst:RequestFailed</code>, ' +
          '<code>invalid_request</code> or <code>invalid_target</code>.'
        : '<strong>This realm is in development mode, so nothing is ' +
          'refused</strong>: the policy is asked and each act above says ' +
          'what WOULD have been refused in product.') +
      ' Edit an application\'s on its own page, and a person\'s on ' +
      'theirs. <code>GET /admin-api/delegation/policy</code> is this ' +
      'section as JSON.') +
      pairsNav.head +
      '<table><tr><th>Mechanism</th><th>Intermediary (who acts)</th>' +
      '<th>Target (what is reached)</th><th>Attribute, and where it ' +
      'lives</th><th>May act for</th><th>Anything missing?</th></tr>' +
      (pairRows || '<tr><td colspan="6">No application here names a ' +
        'delegation target or an intermediary it accepts, so every ' +
        'WS-Trust and token-exchange delegation is ' +
        (register.enforced ? 'refused' : 'one product would refuse') +
        '.</td></tr>') + '</table>' + pairsNav.foot +
      '<h3>Intermediaries</h3>' +
      intermediariesNav.head +
      '<table><tr><th>Application</th><th>Semantics allowed</th>' +
      '<th>May act for</th></tr>' +
      (intermediaryRows || '<tr><td colspan="3">No application carries ' +
        'delegation semantics, appNotDelegated or a subject group.' +
        '</td></tr>') +
      '</table>' + intermediariesNav.foot +
      '<h3>People</h3>' +
      kit.note('<code>stsMayAct</code> is a person\'s own choice of the ' +
      'one party who may act for them; the access tokens issued about them ' +
      'carry it as RFC 8693\'s <code>may_act</code>, and a token exchange ' +
      'of one by anybody else is refused in every mode.') +
      peopleNav.head +
      '<table><tr><th>Person</th><th>Cannot be delegated</th><th>May act for ' +
      'them (stsMayAct)</th><th>Semantics allowed</th></tr>' +
      (peopleRows || '<tr><td colspan="4">Nobody carries any of them.' +
        '</td></tr>') + '</table>' + peopleNav.foot;
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

    return '<h2 id="allowed">What is ALLOWED, decided in advance</h2>' +

      kit.note('<strong>Everything above this heading is EVIDENCE and ' +
      'everything below it is INTENT, and the difference is the most useful ' +
      'thing on this page.</strong> The acts, the chains and the picture ' +
      'they are drawn from are things that happened — a credential was ' +
      'issued or refused, at a moment, to somebody. What follows is ' +
      'CONFIGURATION: which client applications may reach which resource ' +
      'applications, typed in before anybody asked for anything. Read one ' +
      'against the other and two questions answer themselves: <em>which ' +
      'grants has nobody ever used</em>, and <em>what has been delegated ' +
      'that nobody granted</em>.') +

      kit.note('<strong>A RESOURCE application exposes an API and a CLIENT ' +
      'application is granted permissions on it.</strong> The resource is ' +
      'given a base URI &mdash; anything absolute works here &mdash; and a ' +
      'list of permissions. A permission is identified by the two joined ' +
      'together &mdash; base <code>https://example.com/</code> and name ' +
      '<code>write</code> make <code>https://example.com/write</code> ' +
      '&mdash; and a client application is granted some of them. <strong>A ' +
      'permission must be DEFINED before it can be GRANTED</strong>, which ' +
      'is the one ordering rule this feature has; it is checked in ' +
      '<code>applications.js</code> so that this form, the management API ' +
      'and the attribute editor on <a ' +
      'href="/admin/applications">Applications</a> cannot disagree about it.') +

      kit.note('<strong>Then a client asks for it as an OAuth scope, and ' +
      'the access token says both halves.</strong> <code>scope=openid ' +
      'https://example.com/write</code> produces a token audienced to ' +
      '<code>https://example.com/</code> carrying <code>scope: openid ' +
      'write</code> &mdash; the base becomes the <code>aud</code> and the ' +
      'name becomes the scope, which is what a resource server wants: check ' +
      'the audience once, then read bare permission names. That is the same ' +
      'rule a scope naming another application\'s <code>client_id</code> ' +
      'already follows, one step more precise.') +

      kit.note('<strong>In product mode an ungranted permission is refused ' +
      '<code>invalid_scope</code>, always. In development a grant refuses ' +
      'nothing by default, and that is a setting on <a ' +
      'href="/admin/oauth2">OAuth 2.0 / OIDC settings</a>.</strong> With ' +
      '<code>oauth2.delegatedPermissionsEnforced</code> off &mdash; which it ' +
      'is unless somebody turned it on &mdash; an ungranted permission is ' +
      'honoured exactly as a granted one is, logged as ungranted, and marked ' +
      'here. With it on the same request is refused ' +
      '<code>invalid_scope</code> at the authorization endpoint, where the ' +
      'client can still be told. Both answers exercise a client and neither ' +
      'is the right one for every test, which is why the register is fully ' +
      'readable before anybody enforces anything.') +

      '<div class="tiles">' +
        kit.tile(counts.resources, 'applications exposing an API') +
        kit.tile(counts.permissions, 'permissions defined') +
        kit.tile(counts.grants, 'grants') +
        kit.tile(counts.clients, 'applications holding one') +
        kit.tile(counts.unused, 'granted and never asked for') +
        kit.tile(counts.dangling, 'dangling') +
      '</div>' +

      kit.note('<a class="btn" href="/admin/delegation/allowed">See the ' +
      'allowed mappings as a picture &rarr;</a> <strong>A SECOND diagram, ' +
      'and it is not the one above.</strong> <a ' +
      'href="/admin/delegation/map">The picture of the acts</a> draws what ' +
      'happened: three layers, a stick figure for the person it happened to, ' +
      'and a hexagon for this service, which issued it. This one draws what ' +
      'is allowed: every box is an application, there is no person on it at ' +
      'all &mdash; a permission says <em>webapp1 may reach the API as ' +
      'whoever is signed in</em>, and there is no whoever yet &mdash; and ' +
      'this service is not on it either, because not one line of it has been ' +
      'issued. A line is DASHED until the client has actually asked for that ' +
      'permission, which is the reading a configured register exists for and ' +
      'the one an acts diagram can never give.') +

      '<h3 id="permissions">Permissions applications expose</h3>' +
      kit.note('One row per permission. <strong>Defining one grants it to ' +
      'nobody</strong>, so a row with nothing in the last two columns is the ' +
      'ordinary first step rather than a mistake. Removing a permission does ' +
      'NOT revoke the grants naming it &mdash; they stay on the clients\' ' +
      'entries and become dangling, because tidying them would be this page ' +
      'writing to entries nobody named.') +
      kit.sectionSearchForm({
        path: here, query: ctx.query,
        param: 'permq', pageParam: 'permissionsPage',
        label: 'Narrow to an application',
        placeholder: 'part of an application name or identifier',
        what: 'It matches the application that EXPOSES the permission ' +
          '&mdash; the first column &mdash; on its name and on its ' +
          'identifier both, and nothing else on the row. A permission ' +
          'belongs to exactly one application, so there is no second column ' +
          'this box could have meant. To find every permission some ' +
          'application HOLDS, search the grants table below instead: that is ' +
          'the relationship, and this table is the definition.'
      }) +
      permNav.head +
      '<table><tr><th>Exposed by</th><th>Permission</th><th>Identifier ' +
      '&mdash; what a client sends</th><th>Held by</th><th>Which ' +
      'applications</th><th></th></tr>' +
      (permPage.shown.map(function (one) {
        return DelegationPage.permissionDefinitionRow(one, listView,
                                                      rowOptions);
      }).join('') || '<tr><td colspan="6">' +
        (permWanted
          ? 'No application whose name or identifier contains <code>' +
            kit.esc(permWanted) + '</code> exposes a permission. ' +
            (register.permissions.length
              ? register.permissions.length + ' permission(s) are defined ' +
                'here under other applications.'
              : 'None is defined here at all yet.')
          : 'No application here exposes an API yet. Give one a base URI ' +
            'below and then define a permission on it.') +
        '</td></tr>') +
      '</table>' +
      permNav.foot +

      (editable ? '' :
        kit.note('<strong>This page READS the register and changes ' +
        'none of it (2026-10-01).</strong> Exposing an API, defining and ' +
        'removing a permission and revoking a grant are on <a ' +
        'href="/admin/delegation-settings#allowed">Protocols &rsaquo; ' +
        'Delegation</a>, for every application at once, and on each ' +
        'application\'s own <em>Permissions</em> tab under <a ' +
        'href="/admin/applications">Directory &rsaquo; Applications</a>, ' +
        'for that one. Each row\'s last column links there instead of ' +
        'carrying a button.')) +

      (!editable ? '' :
        '<h4>Expose an API</h4>' +
        kit.note('The base URI is one answer per application and ' +
        'everything it exposes hangs off it. A trailing separator is added ' +
        'where there is none, because the identifier is a plain ' +
        'concatenation and <code>https://example.com</code> + ' +
        '<code>write</code> would otherwise read as one word. Clearing it ' +
        'leaves the permissions on the entry with no identifier at all, ' +
        'which the table above reports rather than hides.') +
        '<form method="post" action="/admin/delegation-settings">' +
        DelegationPage.permissionsBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="set-permission-base">' +
        '<label for="base-resource">Application</label>' +
        '<select id="base-resource" name="resource">' + applicationOptions +
        '</select><label for="baseUri">Base URI</label><input type="text" ' +
        'id="baseUri" name="baseUri" size="34" ' +
        'placeholder="https://example.com/"><button type="submit">Set the ' +
        'base URI</button></div></form>' +
        '<h4>Define a permission</h4>' +
        kit.note('The name is what ends up on the token\'s ' +
        '<code>scope</code> claim, so it must be a legal OAuth scope token: ' +
        'any printable ASCII except space, double quote and backslash (RFC ' +
        '6749 section 3.3), and not <code>|</code>, which separates the name ' +
        'from the description in the attribute. The description is optional ' +
        'and is shown wherever the permission is; changing it means removing ' +
        'the permission and defining it again, because a permission has one ' +
        'description and two rows with one name would leave the second ' +
        'unreachable.') +
        '<form method="post" action="/admin/delegation-settings">' +
        DelegationPage.permissionsBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="define-permission">' +
        '<label for="perm-resource">Exposed by</label>' +
        '<select id="perm-resource" name="resource">' + applicationOptions +
        '</select><label for="perm-name">Name</label><input type="text" ' +
        'id="perm-name" name="name" size="18" placeholder="write"><label ' +
        'for="perm-description">Description</label><input type="text" ' +
        'id="perm-description" name="description" size="34" ' +
        'placeholder="Change widgets on somebody\'s behalf"><button ' +
        'type="submit">Define it</button></div></form>') +
      '<h3 id="grants">Grants &mdash; the delegation relationships</h3>' +
      kit.note('<strong>One row per (client, permission), and that IS the ' +
      'relationship.</strong> A client granted three permissions on one ' +
      'resource is three rows rather than one labelled <em>3</em>, because ' +
      'the permission is what was granted and the pair of applications is ' +
      'what it happens to join. That is also how one-to-many and many-to-one ' +
      'both work here with no store of their own: three clients granted one ' +
      'permission is one value on each of three entries.') +
      kit.sectionSearchForm({
        path: here, query: ctx.query,
        param: 'grantq', pageParam: 'grantsPage',
        label: 'Narrow to an application',
        placeholder: 'part of an application name or identifier',
        what: 'It matches EITHER END of the relationship &mdash; the client ' +
          'that may ask and the resource that is reached &mdash; on the name ' +
          'and on the identifier both. Both ends deliberately, and it is the ' +
          'same argument the acts table\'s own text box makes: a reader ' +
          'arrives holding one application name and the question <em>what is ' +
          'this thing mixed up in</em>, and they do not know, and should not ' +
          'have to guess, which of the two columns it will turn up in. ' +
          'Searching one end would answer half that question while looking ' +
          'as though it had answered all of it. A DANGLING grant has no ' +
          'resource at all, so it matches only on its client &mdash; which ' +
          'is right: there is no other application in that row to find it by.'
      }) +
      grantNav.head +
      '<table><tr><th>Client &mdash; who may ask</th><th>Resource &mdash; ' +
      'what is reached</th><th>Permission</th><th>Identifier</th><th>What ' +
      'the access token will say</th><th>Ever asked for?</th><th></th></tr>' +
      (grantPage.shown.map(function (one) {
        return DelegationPage.permissionGrantRow(one, listView, rowOptions);
      }).join('') || '<tr><td colspan="7">' +
        (grantWanted
          ? 'No grant names an application whose name or identifier contains ' +
            '<code>' + kit.esc(grantWanted) + '</code>, at either end. ' +
            (register.grants.length
              ? register.grants.length + ' grant(s) are held here between ' +
                'other applications.'
              : 'Nothing is granted here at all yet.')
          : 'Nothing is granted yet. Define a permission above, then grant ' +
            'it on the client\'s own page &mdash; until then every scope ' +
            'this service is sent is an ordinary scope.') +
        '</td></tr>') +
      '</table>' +
      grantNav.foot +

      // -----------------------------------------------------------------------
      // THE GRANT FORM IS NOT HERE ANY MORE, AND THIS PARAGRAPH IS WHAT IS LEFT
      // OF IT (2026-09-01).
      //
      // It was a `<select>` of every application beside a `<select>` of every
      // permission, and it asked the reader to get BOTH right on a page that is
      // about neither of them in particular. That is the one control in this
      // register where picking the wrong option still SUCCEEDS: a grant written
      // to the resource instead of to the client resolves in both directions
      // and reads correctly on this very table, and the only place it shows as
      // wrong is at the token endpoint, later, to somebody else.
      //
      // On an application's own page there is no first select at all: the
      // client is the entry the reader is standing on. So the control that
      // could be half wrong became a control that cannot be.
      //
      // **AND SINCE 2026-10-01 THE RESOURCE'S PAGE GRANTS TOO** (rcbj): its
      // Permissions tab offers ITS OWN permissions to another application.
      // That is still one select of applications, but the other half — the
      // permission, and so the resource — is settled by the page, which is
      // the property the move above was for. The register stays without a
      // grant form; `revoke-permission` is a ROW BUTTON here and on both
      // applications' pages, because the row is the pair and neither half
      // can be got wrong.
      //
      // THE HANDLER MOVED WITH THE CONTROLS (2026-10-01): every form that
      // changes the register posts to `POST /admin/delegation-settings`, the
      // Protocols page's handler, and Monitoring → Delegation has no POST.
      // PERMISSION_ACTIONS still lists all five, and `POST
      // /admin-api/permissions/:action` mirrors the new path.
      // -----------------------------------------------------------------------
      '<h4>Grant a permission</h4>' +
      (grantable.length
        ? kit.note('<strong>This one is on the two applications\' own ' +
          'pages.</strong> A grant lands on the CLIENT\'s entry, as a value ' +
          'of <code>oauthDelegatedPermission</code>, because the client is ' +
          'the party that will name the permission in a <code>scope</code> — ' +
          'so the entry that answers <em>may this request be honoured</em> ' +
          'is the entry the request identifies. Open an application under ' +
          '<a href="/admin/applications">Directory &rsaquo; Applications</a> ' +
          'and its <em>Permissions</em> tab grants it somebody else\'s ' +
          'permission, or grants one of ITS OWN to another application — ' +
          'either way one half of the pair is settled by the page you are ' +
          'on rather than chosen out of a list of every application here. ' +
          'An application still cannot be granted its own permission: the ' +
          'token would be addressed to itself, which is what an ID Token ' +
          'already is, and neither page offers it.')
        : kit.note('<strong>There is nothing to grant yet.</strong> A ' +
          'permission must be defined before it can be granted, so the ' +
          'control appears — on each application\'s own page under <a ' +
          'href="/admin/applications">Directory &rsaquo; Applications</a> — ' +
          'once an application exposes one with an identifier. That ordering ' +
          'is the whole shape of the feature rather than a limitation of ' +
          'either page.')) +

      kit.note('<strong>Every one of these is an ordinary attribute on an ' +
      'ordinary directory entry</strong>, and an <code>ldapmodify</code> ' +
      'reaches them exactly as it reaches a redirect URI: ' +
      '<code>oauthPermissionBaseUri</code> and <code>oauthPermission</code> ' +
      'on the resource, <code>oauthDelegatedPermission</code> on the client. ' +
      'What LDAP does not get is the ordering check &mdash; this directory ' +
      'enforces nothing anywhere &mdash; which is why a grant naming a ' +
      'permission nobody defines can exist at all, and why it is shown as ' +
      'dangling rather than treated as an error. <code>GET ' +
      '/admin/ldap/applications</code> publishes all three, and they persist ' +
      'wherever the directory does.');
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
      '>any mechanism</option>' +
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
                         '>either kind</option>']
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
                            '>any outcome</option>']
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
                '">&larr; Back to ' +
      'the delegation table</a>') +

      '<div class="tiles">' +
        kit.tile(parties.length, 'parties') +
        kit.tile(json.edges.filter(function (e) {
          return e.relation !== 'issued';
        }).length,
                  'relationships') +
        kit.tile(json.chains, 'distinct chains') +
        kit.tile(json.acts, 'acts drawn') +
        kit.tile(json.summary.byMode.impersonation || 0, 'impersonations') +
        kit.tile(json.tokens.length, 'credentials issued') +
      '</div>' +

      kit.note('<strong>The same acts as ' +
      '<a href="' + kit.esc(upHref) +
      '">the table</a>, with the time taken out ' +
      'and the parties shared.</strong> A party that is the intermediary ' +
      'of six chains is ONE box here with six lines leaving it, which is ' +
      'the thing a table of rows cannot show and the reason to draw this ' +
      'at all. Every box and every line carries the whole story in its ' +
      'tooltip; the two tables under the picture say the same things in ' +
      'words, because a diagram nobody can quote is a diagram nobody can ' +
      'put in a bug report.') +

      kit.note('<strong>It is drawn from everything that MATCHED the ' +
      'filter and not from one page of it.</strong> ' + json.matched +
      ' act(s) match' + (json.all !== json.matched
        ? ' of ' + json.all + ' held' : '') +
      ', and all of them are in the picture — paging a diagram would draw ' +
      'the boxes that happen to be on page 2 and the lines that happen to ' +
      'join them, which is a picture of the pagination.') +

      '<form method="get" action="/admin/delegation/map"><div ' +
      'class="formrow">' +
        DelegationPage.chooserCarry(ctx.query) +
        '<label for="type">Mechanism</label><select id="type" name="type">' +
          typeOptions + '</select>' +
        '<label for="mode">Kind</label><select id="mode" name="mode">' +
          modeOptions + '</select>' +
        '<label for="outcome">Outcome</label><select id="outcome" ' +
        'name="outcome">' +
          outcomeOptions + '</select>' +
      '</div><div class="formrow">' +
        '<label for="q">Text</label>' +
        '<input type="text" id="q" name="q" size="40" value="' +
      kit.esc(wanted.q) +
          '" placeholder="a person, an SPN, a client_id, an attribute">' +
        '<button class="secondary">Redraw</button>' +
        (filtering ? ' <a href="/admin/delegation/map">clear</a>' : '') +
      '</div></form>' +
      kit.note('The same filter the table has, so narrowing one narrows ' +
      'the other. <strong>Filtering to one person is how a busy picture is ' +
      'read</strong> — the text box searches every party of the chain and ' +
      'both explanations at once.') +

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
      kit.note('<strong>Or draw one party\'s picture instead.</strong> ' +
      'These redraw around a single party rather than narrowing these ' +
      'acts: an application, with everything delegated through it or to it ' +
      'in either role — or a <strong>person</strong>, which is the wider ' +
      'picture of the two, because it adds every ordinary grant, ' +
      'assertion, ticket and SVID issued in their name and the sign-ins ' +
      'the lot rests on. None of that is a delegation, so none of it can ' +
      'be on this diagram.') +
      DelegationPage.delegationApplicationChooser(json.applicationChooser,
        '', { path: '/admin/delegation/map', query: ctx.query }) +
      DelegationPage.delegationUserChooser(json.userChooser, '',
        { path: '/admin/delegation/map', query: ctx.query }) +

      (json.acts
        ? DelegationPage.drawing(json, '/admin/delegation/map', wanted)
        : kit.note('<strong>Nothing has delegated anything yet' +
          (filtering ? ' that matches this filter' : '') + ', so there is ' +
          'nothing to draw.</strong> Three things put a box on this page: ' +
          'a Kerberos S4U2Self, S4U2Proxy or forwarded-TGT request at the ' +
          'KDC; a WS-Trust <code>RequestSecurityToken</code> carrying ' +
          '<code>&lt;wst:OnBehalfOf&gt;</code> or ' +
          '<code>&lt;wst14:ActAs&gt;</code>; and an RFC 8693 token ' +
          'exchange at <code>/oauth2/token</code>. A REFUSED attempt ' +
          'counts and is drawn in red.')) +

      '<h2>The key</h2>' +
      kit.note('The shapes are drawn by the same functions the picture ' +
      'uses, so a legend cannot come to describe a diagram this service no ' +
      'longer draws.') +
      json.mapKey +

      '<h2>The parties</h2>' +
      kit.note('Every box, with both of its links where it has two. The ' +
      'picture can only put a shape inside ONE anchor, so a party that is ' +
      'a person AND an application links to the users page there and to ' +
      'both here.' +
      (json.directoryLoaded ? '' :
        ' <strong>No LDAP directory is loaded in this process</strong>, so ' +
        'nothing here can be resolved to a person and every box is drawn ' +
        'from its role. That is a build without ' +
        '<code>ldap_server.js</code> and not a failure.')) +
      '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
      '<th>Roles it played</th><th>Acts</th><th>Protocols</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">No parties yet.</td></tr>') +
      '</table><h2>The relationships</h2>' +
      kit.note('Every line, as a sentence. <strong>The two kinds are ' +
      'different claims and the picture colours them differently</strong>: ' +
      '<em>acts for</em> is the DELEGATION relationship — who is acting on ' +
      'whose behalf — and <em>reaches</em> is the TRUST relationship, what ' +
      'the credential is FOR, which is the question <em>what is this ' +
      'token\'s audience</em> asked as a picture. The grey lines from the ' +
      'hexagon are neither: they are this service handing a credential to ' +
      'whoever asked for one.') +
      kit.note('<strong>The last column collapses one sentence and it is ' +
      'the same collapse the delegation table makes.</strong> Kerberos is ' +
      'the only family here that polices delegation at all, so a Kerberos ' +
      'row names an ATTRIBUTE and an account — short, and different on ' +
      'every row — while every WS-Trust and RFC 8693 row carries the ' +
      'identical paragraph saying that nothing checked it. Repeated down a ' +
      'table that paragraph is the column, so it is <em>nothing checks ' +
      'this</em> with the wording in the tooltip. <strong>A REFUSAL is ' +
      'never collapsed</strong> and prints in full: it is the KDC\'s own ' +
      'words, the same sentence the client was sent, and it is specific to ' +
      'the act rather than to the mechanism.') +
      '<table><tr><th>From</th><th>To</th><th>Relationship</th>' +
      '<th>Mechanism</th><th>Kind</th><th>Acts</th><th>What came out</th>' +
      '<th>Authorized by / why not</th></tr>' +
      (json.edges.map(function (edge) {
        return DelegationPage.delegationEdgeRow(edge, labelOf);
      }).join('') || '<tr><td colspan="8">No relationships yet.</td></tr>') +
      '</table>' +

      '<h2>What was issued</h2>' +
      kit.note('<strong>Every credential that came out of an act in this ' +
      'picture</strong>, newest first — a Kerberos service ticket, a SAML ' +
      'assertion, an access token — with the chain it came out of. ' +
      '<strong>NO CREDENTIAL IS EVER HERE, only its kind and its ' +
      'identifier</strong>, which is the rule the audit log follows and ' +
      'which applies here for one more reason: a delegation act is ' +
      'precisely the request that carries two credentials at once. A ' +
      'Kerberos ticket genuinely has no identifier to quote, which this ' +
      'says rather than leaving a blank column to be read as a bug.') +
      kit.note('A REFUSED act produced nothing by definition, so it is ' +
      'not in this list — which is why ' + json.tokens.length + ' ' +
      'credential(s) sit under ' + json.acts +
      ' act(s) and the two numbers do not have to agree.') +
      '<table><tr><th class="num">#</th><th>When</th><th>Credential</th>' +
      '<th>Subject</th><th>Actor</th><th>Target</th><th>Mechanism</th>' +
      '</tr>' +
      (json.tokens.map(function (token) {
        return DelegationPage.delegationTokenRow(token, labelOf);
      }).join('') ||
        '<tr><td colspan="7">Nothing has been issued through a ' +
        'delegation yet. A REFUSED act produces nothing, so a page of red ' +
        'lines and an empty table here is a consistent state rather than a ' +
        'broken one.</td></tr>') + '</table>' +
      (json.tokensLeftOff
        ? kit.note('<strong>' + json.tokensLeftOff + ' more ' +
          'credential(s) are not listed.</strong> This list holds at most ' +
          json.maxTokenRows +
          ' and keeps the newest; every one of them is still COUNTED on ' +
          'its line in the picture and in the relationship table, so what ' +
          'is lost is the individual identifiers of the oldest. Filter to ' +
          'narrow it.')
        : '') +

      '<h2>What this picture cannot say</h2>' +
      kit.note('<strong>An IMPERSONATION is invisible everywhere else, ' +
      'and that is why the amber lines matter.</strong> Under a delegation ' +
      'the credential carries the chain, so a resource server can read the ' +
      'actor off the token afterwards. Under an impersonation nothing ' +
      'does: no reading of the token, at the far end or in a log, can ' +
      'recover the fact that a middle tier was involved. This diagram and ' +
      'the table behind it are the only places that fact will ever exist.') +
      kit.note('<strong>A line is a RELATIONSHIP and not a ' +
      'request.</strong> Four acts a second apart between the same three ' +
      'parties are one line with <em>4 issued</em> on it; the outcome is ' +
      'deliberately not part of a chain\'s identity, so a chain refused ' +
      'nine times and then fixed is one line that changes colour rather ' +
      'than two that never meet. <a href="' + kit.esc(upHref) +
      '">The table</a> is where the individual ' +
      'acts are, in order, with their times.') +
      kit.note('<strong>Who MAY delegate to whom is not on this ' +
      'page</strong>, because it is CONFIGURATION rather than history and ' +
      'it is Kerberos-only — Kerberos is the one family here that polices ' +
      'delegation at all. It is the second half of <a ' +
      'href="' + kit.esc(upHref) + '">the delegation page</a>, ' +
      'and the asymmetry between the two is worth reading there: the same ' +
      'picture, policed at one end and not at the other.') +
      kit.note('<strong>This page runs no script and neither does ' +
      'anything else in this console.</strong> The diagram is generated on ' +
      'the server and arrives as markup, which is why it does not pan, ' +
      'zoom or drag — and why nothing here relaxes <code>script-src ' +
      '\'none\'</code>. Use the filter to narrow a busy picture, or take ' +
      'the document and open it in something that does zoom.') +
      kit.note('<code>?format=json</code> carries the whole graph — the ' +
      'nodes, the edges, the credentials folded onto each edge, and the ' +
      'token list — and it is also in the <code>graph</code> member of ' +
      '<code>GET /admin-api/delegation</code>, so a test can assert what ' +
      'this page draws without parsing an SVG. <code>?format=svg</code> is ' +
      'the document alone.');

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
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const upHref = '/admin/delegation' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; Back to the delegation table</a>');
    const chain = json.chain;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!chain) {
      return back +
        (json.chainKey
          ? kit.note('<strong>No act held here belongs to that ' +
            'relationship.</strong> <code>' + kit.esc(json.chainKey) +
            '</code> ' +
            'names a chain this page can describe only while at least one ' +
            'of its acts is still held, and this store is CAPPED — it ' +
            'keeps at most ' +
            kit.esc(json.maxRecords) + ' acts and drops ' +
            'the oldest first. So an old link coming back empty is the ' +
            'ordinary outcome rather than a mistake, and so is a link from ' +
            'a service that has restarted since: nothing here is ' +
            'persisted. Raise <code>delegation.maxRecords</code> on <a ' +
            'href="/admin/delegation-settings">Protocols &rsaquo; ' +
            'Delegation</a> if this keeps happening to something you need.')
          : kit.note('<strong>Name a relationship.</strong> This page ' +
            'draws ONE of them, and the way to it is a link on ' +
            '<a href="' + kit.esc(upHref) +
            '">the delegation table</a> — every row of both tables there ' +
            'has one, because the key that identifies a chain is ' +
            '<em>(mechanism, initial identity, intermediary, target)</em> ' +
            'and is not something worth typing.')) +
        kit.note('<a href="/admin/delegation/map">The whole picture</a> ' +
        'is everything that is still held, drawn together.');
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
               'somebody nobody named') +
      '</strong> — ' +
      (chain.intermediary.presented || chain.intermediary.application
        ? 'acted for by <strong>' +
          kit.esc(chain.intermediary.presented ||
                   chain.intermediary.application) +
          '</strong>'
        : '<span class="state-none">with no intermediary this service was ' +
          'ever told the name of</span>') +
      ' — reaching <strong>' +
      kit.esc(chain.target.application || chain.target.presented ||
               'nothing in particular') +
      '</strong>, by <code>' + kit.esc(chain.type) + '</code> (' +
      kit.esc(chain.typeLabel) + ', ' + kit.esc(chain.protocol) + '). ' +
      'It is an ' + DelegationPage.modeCell(chain.mode) +
      ' and it has happened ' +
      kit.esc(chain.acts) + ' time(s) — first ' +
      kit.esc(kit.whenText(chain.firstAt)) +
      ', last ' + kit.esc(kit.whenText(chain.lastAt)) + '.');

    return back +
      '<div class="tiles">' +
        kit.tile(chain.acts, 'acts on it') +
        kit.tile(chain.issued, 'issued') +
        kit.tile(chain.refused, 'refused') +
        kit.tile(json.graph.tokens.length, 'credentials issued') +
        kit.tile(parties.length, 'parties') +
        kit.tile(json.graph.edges.filter(function (e) {
          return e.relation !== 'issued';
        }).length,
                  'lines') +
      '</div>' +

      sentence +

      kit.note('<strong>This is one row of ' +
      '<a href="' + kit.esc(upHref) +
      '">the chains table</a> drawn on its ' +
      'own</strong> , with everything else in the service left out. A ' +
      'chain is <em>(mechanism, initial identity, intermediary, ' +
      'target)</em> and the OUTCOME is deliberately not part of it, so a ' +
      'relationship refused nine times and then fixed is this one page ' +
      'rather than two that never meet — which is why the acts below can ' +
      'be red and green at once. <a href="/admin/delegation/map">The whole ' +
      'picture</a> is every relationship at once, where this one\'s ' +
      'parties are shared with the others they take part in.') +

      (json.graph.acts
        ? DelegationPage.drawing(json, '/admin/delegation/chain',
          Object.assign({}, listView, { chain: json.chainKey }))
        : kit.note('There is nothing to draw.')) +

      '<h2>The key</h2>' +
      kit.note('The shapes are drawn by the same functions the picture ' +
      'uses, so a legend cannot come to describe a diagram this service no ' +
      'longer draws.') +
      json.mapKey +

      '<h2>The parties</h2>' +
      kit.note('Up to three boxes — the layers of the architecture — with ' +
      'both of a party\'s links where it has two. <strong>A box here can ' +
      'carry more acts than this relationship has</strong> only if it ' +
      'played two roles in one of them, which is what S4U2Self is: the ' +
      'requester asks for a ticket to itself, so it is the intermediary ' +
      'AND the target.') +
      '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
      '<th>Roles it played</th><th>Acts</th><th>Protocols</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">No parties.</td></tr>') +
        '</table>' +

      '<h2>The relationships</h2>' +
      kit.note('A chain has three parties and therefore up to TWO lines, ' +
      'and they are different claims: <em>acts for</em> is the DELEGATION ' +
      'relationship — who is acting on whose behalf — and <em>reaches</em> ' +
      'is the TRUST relationship, what the credential is FOR. The grey ' +
      'line from the hexagon is neither: it is this service handing a ' +
      'credential to whoever asked for one.') +
      '<table><tr><th>From</th><th>To</th><th>Relationship</th><th>' +
      'Mechanism</th><th>Kind</th><th>Acts</th><th>What came ' +
      'out</th><th>Authorized by / why not</th></tr>' +
      (json.graph.edges.map(function (edge) {
        return DelegationPage.delegationEdgeRow(edge, labelOf);
      }).join('') || '<tr><td colspan="8">No relationships.</td></tr>') +
      '</table>' +

      '<h2>What was issued on it</h2>' +
      kit.note('<strong>Every credential that came out of this ' +
      'relationship</strong>, newest first. <strong>NO CREDENTIAL IS EVER ' +
      'HERE, only its kind and its identifier</strong> — the rule the ' +
      'audit log follows, and one that applies here for one more reason: a ' +
      'delegation act is precisely the request that carries two ' +
      'credentials at once. A REFUSED act produced nothing by definition, ' +
      'which is why ' + json.graph.tokens.length +
      ' credential(s) sit under ' + chain.acts + ' act(s).') +
      '<table><tr><th class="num">#</th><th>When</th><th>Credential</th>' +
      '<th>Subject</th><th>Actor</th><th>Target</th><th>Mechanism</th></tr>' +
      (json.graph.tokens.map(function (token) {
        return DelegationPage.delegationTokenRow(token, labelOf);
      }).join('') || '<tr><td colspan="7">Nothing was issued on this ' +
        'relationship. A page of red acts and an empty table here is a ' +
        'consistent state rather than a broken one.</td></tr>') + '</table>' +

      '<h2>Every act on it</h2>' +
      kit.note('The same rows <a href="' + kit.esc(upHref) +
                '">the delegation ' +
      'table</a> holds, narrowed to this ' +
      'relationship and not paged — there are ' +
      kit.esc(json.acts.length) +
      ' of them and the cap on the whole store is ' +
      kit.esc(json.maxRecords) + '. This is where the ' +
      'TIMES are: the picture has them taken out, because four acts a ' +
      'second apart between the same three parties are one line.') +
      '<table><tr><th class="num">#</th><th>When</th><th>Mechanism</th>' +
      '<th>Kind</th><th>Outcome</th><th>Initial identity</th>' +
      '<th>Intermediary</th><th>Target</th><th>Authorized by / why not</th>' +
      '<th>Credentials</th></tr>' +
      json.acts.map(function (row) {
        // No `chain` link on this table: every row on it belongs to the chain
        // being drawn, so the link would point at the page it is on.
        return DelegationPage.delegationRow(row, json.facts,
                                         { chainLink: false });
      }).join('') + '</table>' +

      kit.note('<code>?format=json</code> carries this chain, its acts ' +
      'and the graph behind the picture; <code>?format=svg</code> is the ' +
      'document alone, with no links in it. There is no form on this page ' +
      'and therefore no operation on <code>/admin-api</code> — everything ' +
      'here is an observation, and the acts are in <code>GET ' +
      '/admin-api/delegation</code> where a caller can filter them.');

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
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const upHref = '/admin/delegation' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; Back to the delegation table</a>');
    // The chooser itself, drawn on the bare page AND under a selected
    // application — the second is what makes comparing two of them one
    // click rather than two.
    const chooser = DelegationPage.delegationApplicationChooser(
      json.chooser, json.key,
      { path: '/admin/delegation/application', query: ctx.query });
    const entry = json.application;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!entry) {
    return back +
      (json.asked
        ? kit.note('<strong>No act held here names ' +
          '<code>' + kit.esc(json.asked) + '</code> as an ' +
          'application.</strong> Three things could be true and they are ' +
          'different: nothing has ever delegated through or to it; ' +
          'something did and the acts have been DROPPED, because this ' +
          'store keeps at most ' +
          kit.esc(json.maxRecords) + ' and discards the ' +
          'oldest; or the name is spelled differently from the way a ' +
          'protocol presented it. The list below is every application ' +
          'some act actually named, which settles the third.')
        : '') +
      kit.note('<strong>Choose an application to see everything that ' +
      'has been delegated through it or to it.</strong> A delegation has ' +
      'three parties and an application can be two of them — the ' +
      'INTERMEDIARY that acts on somebody\'s behalf, and the TARGET the ' +
      'credential is for — so this page shows both sides of one ' +
      'application rather than making you pick a side. That is the ' +
      'question worth asking before turning a middle tier off: not ' +
      '<em>what reaches it</em>, but <em>what exists because of it</em>.') +
      chooser +
      DelegationPage.delegationApplicationTable(json.applications,
                                                 json.facts, listView) +
      kit.note('The list is built from the ACTS rather than from <a ' +
      'href="/admin/applications">the registry</a>, which is why an ' +
      'entry here can be marked <em>not in the registry</em>: the ' +
      'registry holds what this service has been asked about, and an RFC ' +
      '8693 <code>audience</code> nobody has otherwise mentioned is a ' +
      'real delegation target that nothing else in this console knows ' +
      'the name of.');
    }
    const parties = json.graph.nodes.filter(function (node) {
      return node.kind !== 'sts';
    });

    return back +
      '<div class="tiles">' +
        kit.tile(entry.acts, 'acts') +
        kit.tile(entry.issued, 'issued') +
        kit.tile(entry.refused, 'refused') +
        kit.tile(json.graph.tokens.length, 'credentials issued') +
        kit.tile(entry.chains, 'relationships') +
        kit.tile(entry.roles.intermediary, 'as the intermediary') +
      '</div>' +

      kit.note('<strong><code>' + kit.esc(entry.identifier) +
                '</code></strong> — ' +
      (json.registered
        ? '<a href="' + kit.esc('/admin/applications' +
            kit.queryWith({ application: entry.identifier }, {})) +
            '">in the ' +
          'registry</a> as <strong>' +
          kit.esc(json.registeredName || entry.identifier) +
          '</strong>'
        : '<span class="state-none" title="No entry under ou=applications ' +
          'names this. The registry holds what this service has been ASKED ' +
          'ABOUT, and a delegation naming something nobody has otherwise ' +
          'mentioned is ordinary — an RFC 8693 audience is exactly ' +
          'that.">not in the registry</span>') +
      (entry.identityKey
        ? '. It has also PRESENTED a credential of its own, so it is a ' +
          'person here as well as an application: ' +
          GroupsPage.usersPageCell(entry.identityKey, json.facts.users) +
          ' on the users ' +
          'page. That is the middle tier being both, which is ordinary — a ' +
          'service account authenticates, so the identity funnel files it ' +
          'under <code>ou=users</code>, and tickets are issued FOR it, so ' +
          'the registry files it under <code>ou=applications</code>.'
        : '.') +
      (entry.spellings.length > 1
        ? ' <strong>It has been spelled ' + entry.spellings.length + ' ' +
          'ways</strong> and they are one application ' +
          'here: ' + kit.codeList(entry.spellings) +
          '. Two spellings of one identity is two people, so they are ' +
          'collapsed on the same normalisation the picture uses — the ' +
          'spellings are kept so that the collapse is something you can ' +
          'see rather than take on trust.'
        : '') +
      ' Protocols: ' +
      (entry.protocols.length ? kit.codeList(entry.protocols) : 'none') +
      '. First seen ' + kit.esc(kit.whenText(entry.firstAt)) + ', last ' +
      kit.esc(kit.whenText(entry.lastAt)) + '.') +

      '<h2>What it does in a delegation</h2>' +
      kit.note('<strong>Both sides of one application.</strong> The ' +
      'counts below are of ACTS, and one act can count twice here — an ' +
      'S4U2Self names the requester as the intermediary and as the target, ' +
      'because the ticket is to itself.') +
      '<table><tr><th>Role</th><th>Acts</th><th>What the role is</th></tr>' +
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
        ? '<h2>The relationships it is part of</h2>' +
          kit.note('Every chain this application appears in, drawn ' +
          'together — so a middle tier shows the people it acts for on one ' +
          'side and what it reaches on the other, which is the shape a ' +
          'list of rows cannot show. The <strong>chain</strong> link ' +
          'beside each act at the foot of this page draws ONE of them ' +
          'alone.') +
          DelegationPage.drawing(json, '/admin/delegation/application',
            Object.assign({}, listView,
                          { application: entry.identifier }))
        : '') +

      '<h2>The key</h2>' +
      kit.note('The shapes are drawn by the same functions the picture ' +
      'uses, so a legend cannot come to describe a diagram this service no ' +
      'longer draws.') +
      json.mapKey +

      '<h2>The parties it deals with</h2>' +
      kit.note('Every box in the picture above, including this ' +
      'application itself.') +
      '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
      '<th>Roles it played</th><th>Acts</th><th>Protocols</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">No parties.</td></tr>') +
        '</table>' +

      '<h2>Every delegated credential related to it</h2>' +
      kit.note('<strong>This is the list this page exists for.</strong> ' +
      'Every credential that came out of an act this application took part ' +
      'in, newest first, WHATEVER ROLE IT PLAYED — so a token issued ' +
      'THROUGH it (it was the intermediary) and one issued FOR it (it was ' +
      'the target) are both here, with the role in its own column. ' +
      '<strong>NO CREDENTIAL IS EVER HERE, only its kind and its ' +
      'identifier</strong>, which is the rule the audit log follows; a ' +
      'Kerberos ticket genuinely has no identifier to quote. A REFUSED act ' +
      'produced nothing by definition, which is why ' +
      json.graph.tokens.length +
      ' credential(s) sit under ' + entry.acts + ' act(s).') +
      '<table><tr><th class="num">#</th><th>When</th><th>Its role</th>' +
      '<th>Credential</th><th>Subject</th><th>Actor</th><th>Target</th>' +
      '<th>Mechanism</th></tr>' +
      (json.graph.tokens.map(function (token) {
        return DelegationPage.delegationTokenRow(
          token, labelOf,
          DelegationPage.delegationRoleCell(json.rolesBySeq[token.seq],
                                            json.roles));
      }).join('') ||
        '<tr><td colspan="8">Nothing has been issued through this ' +
        'application or to it. A page of red acts and an empty table here ' +
        'is a consistent state rather than a broken one.</td></tr>') +
        '</table>' +
      (json.graph.tokensLeftOff
        ? kit.note('<strong>' + json.graph.tokensLeftOff + ' more ' +
          'credential(s) are not listed.</strong> This list holds at most ' +
          json.graph.maxTokenRows +
          ' and keeps the newest; every one of them is still COUNTED on ' +
          'its line in the picture, so what is lost is the individual ' +
          'identifiers of the oldest.')
        : '') +

      '<h2>Every act it took part in</h2>' +
      kit.note('The rows <a href="' + kit.esc(upHref) +
                '">the delegation table</a> ' +
      'holds, narrowed to this application and not paged. This is where ' +
      'the TIMES and the REFUSALS are — a refusal produced no credential, ' +
      'so it is in this table and not in the one above.') +
      '<table><tr><th class="num">#</th><th>When</th><th>Mechanism</th>' +
      '<th>Kind</th><th>Outcome</th><th>Initial identity</th>' +
      '<th>Intermediary</th><th>Target</th><th>Authorized by / why not</th>' +
      '<th>Credentials</th></tr>' +
      json.acts.map(function (row) {
        return DelegationPage.delegationRow(row, json.facts,
                                         { listView: listView });
      }).join('') + '</table>' +

      '<h2>Another application</h2>' + chooser +
      DelegationPage.delegationApplicationTable(json.applications,
                                                 json.facts, listView) +

      kit.note('<code>?format=json</code> carries this application, its ' +
      'acts and the graph behind the picture; <code>?format=svg</code> is ' +
      'the document alone. There is no form that changes anything on this ' +
      'page and therefore no operation on <code>/admin-api</code> — the ' +
      'acts are in <code>GET /admin-api/delegation</code>, where a caller ' +
      'can filter them by the same free text.');

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
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const upHref = '/admin/delegation' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; Back to the delegation table</a>');
    const chooser = DelegationPage.delegationUserChooser(json.chooser,
      json.key, { path: '/admin/delegation/user', query: ctx.query });
    const entry = json.user;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!entry) {
    return back +
      (json.asked
        ? kit.note('<strong>Neither register names ' +
          '<code>' + kit.esc(json.asked) + '</code>.</strong> Three things ' +
          'could be true and they are different: nothing has ever ' +
          'authenticated, been issued anything or been delegated under ' +
          'that name; something did and the records have been DROPPED, ' +
          'because each of these stores keeps a bounded number and ' +
          'discards the oldest; or the name is spelled differently from ' +
          'the way a protocol presented it. The list below is every ' +
          'identity either register actually holds, which settles the ' +
          'third.')
        : '') +
      kit.note('<strong>Choose a person to see everything this service ' +
      'has done in their name.</strong> Not just the delegations — this ' +
      'is the one picture here that also draws the ordinary issuance: ' +
      'every OAuth 2.0 grant and OIDC flow, every SAML assertion, every ' +
      'Kerberos ticket and every SVID, each labelled with exactly what ' +
      'produced it, beside the applications that hold them and the ' +
      'sign-ins the whole lot rests on.') +
      chooser +
      DelegationPage.delegationUserTable(json.users, json.facts,
                                        listView) +
      kit.note('The list is the identity register and the delegation ' +
      'register UNIONED, which is why a row can say <em>never ' +
      'authenticated here</em>: a delegation names somebody who was not ' +
      'present and proved nothing — that is what S4U2Self and ' +
      '<code>OnBehalfOf</code> ARE — so their name exists here and in no ' +
      'other list this console keeps.');
    }
    const parties = json.graph.nodes.filter(function (node) {
      return node.kind !== 'sts';
    });

    return back +
      '<div class="tiles">' +
        kit.tile(json.counts.credentials, 'credentials issued') +
        kit.tile(json.counts.authentications, 'sign-ins') +
        kit.tile(json.flows.length, 'grants used') +
        kit.tile(json.counts.applications, 'other parties') +
        kit.tile(json.counts.acts, 'delegation acts') +
        kit.tile(json.counts.chains, 'delegation relationships') +
      '</div>' +

      kit.note('<strong><code>' + kit.esc(json.key) +
                '</code></strong> — ' +
      (entry.authenticated
        ? 'they have <a href="' + kit.esc('/admin/users' +
            kit.queryWith({ user: json.key }, {})) + '">authenticated ' +
              'here</a> ' +
          kit.esc(entry.authentications) + ' time(s)'
        : '<span class="state-expired" title="Nothing has ever presented a ' +
          'credential under this name in this process. Something was ' +
          'issued in it, or somebody delegated using it — which is exactly ' +
          'the state this page exists to make visible.">they have NEVER ' +
          'authenticated here</span>') +
      (entry.isClient
        ? '. It is a <strong>client rather than a person</strong>: ' +
          'something authenticated under this name and said so, which the ' +
          '<code>client_credentials</code> grant is the usual way of doing'
        : '') +
      (entry.forms.length > 1
        ? '. They have been spelled ' + entry.forms.length + ' ways and ' +
          'they are one person here: ' + kit.codeList(entry.forms) +
          '. Two spellings of one identity is two people, so the console ' +
          'collapses them on the same normalisation the picture uses'
        : '') +
      '. Protocols: ' +
      (entry.protocols.length ? kit.codeList(entry.protocols) : 'none') +
      '. Last seen ' + kit.esc(kit.whenText(entry.lastAt)) + '.') +

      '<h2>Everything, as one picture</h2>' +
      kit.note('<strong>This is the page.</strong> The dotted line into ' +
      'the hexagon is them SIGNING IN, and it is why anything else here ' +
      'was allowed. Every solid indigo line is a credential issued NAMING ' +
      'them, labelled with the exact grant or flow that produced it: out ' +
      'of THEM it went to that application, out of an APPLICATION it is ' +
      'the resource that application may reach with it, and out of the ' +
      'HEXAGON nobody else holds it — a <code>client_credentials</code> ' +
      'token is about the client itself and an X509-SVID has no audience. ' +
      'The amber and green lines, where there are any, are delegations — ' +
      'somebody acting on their behalf — and they are the only lines here ' +
      'that carry a mode, because impersonation and delegation are ' +
      'properties of a delegation mechanism and an ordinary grant makes ' +
      'neither claim.') +
      DelegationPage.drawing(json, '/admin/delegation/user',
        Object.assign({}, listView, { user: json.key })) +

      '<h2>The key</h2>' +
      kit.note('The shapes are drawn by the same functions the picture ' +
      'uses, so a legend cannot come to describe a diagram this service no ' +
      'longer draws. The last three rows are this page\'s own — no other ' +
      'picture in this console has a line for an ordinary grant, because ' +
      'no other picture is drawn from anything but the delegation ' +
      'register.') +
      json.mapKey +

      '<h2>What was used to get a credential</h2>' +
      kit.note('<strong>Exactly which OAuth 2.0 grant or OpenID Connect ' +
      'flow, with the section that defines it.</strong> Only the ones this ' +
      'person\'s credentials actually used are here; the rest of the table ' +
      'is on no page, because a list of eight grants under a person who ' +
      'used one is a list nobody reads. A SAML assertion, a Kerberos ' +
      'ticket and an SVID have no grant at all and are not in this table — ' +
      'the credentials below say what their own specifications call the ' +
      'mechanism instead.') +
      (json.flows.length
        ? '<table><tr><th>Grant</th><th>OpenID Connect calls ' +
          'it</th><th>Specification</th><th>Through a browser</th><th>What ' +
          'it is</th></tr>' +
          json.flows.map(function (flow) {
            return '<tr>' +
              '<td><code>' + kit.esc(flow.flow) + '</code><br>' +
                '<strong>' + kit.esc(flow.label) + '</strong></td>' +
              '<td>' + (flow.oidc ? kit.esc(flow.oidc)
                : '<span class="state-none" title="OpenID Connect defines ' +
                  'no flow of its own for this grant — it is OAuth 2.0\'s, ' +
                  'used as it is.">&mdash;</span>') + '</td>' +
              '<td>' + kit.esc(flow.spec) + '</td>' +
              '<td>' + (flow.browser
                ? '<span class="state-valid" title="The person was at an ' +
                  'authorization endpoint in a browser, so this issuance ' +
                  'can be put under a sign-on session.">yes</span>'
                : '<span class="state-none" title="A direct grant: there ' +
                  'is no browser anywhere in it, which is why its ' +
                  'credentials are listed with no session.">no</span>') +
                  '</td>' +
              '<td>' + kit.esc(flow.what) +
                (flow.delegating
                  ? ' <strong>It is also a delegation act</strong>, so its ' +
                    'credentials are drawn on the delegation line rather ' +
                    'than twice.'
                  : '') + '</td>' +
              '</tr>';
          }).join('') + '</table>'
        : kit.note('No credential of theirs states a grant. That is the ' +
          'ordinary state for somebody who has only ever been issued ' +
          'assertions, tickets or SVIDs — none of those protocols has a ' +
          'grant — and for a JWT minted outside the token endpoint.')) +

      '<h2>Every credential issued in their name</h2>' +
      kit.note('<strong>The issued register: every JWT, assertion, ' +
      'ticket, SVID and verifiable credential this service has minted ' +
      'naming them, newest first.</strong> <strong>NO CREDENTIAL IS EVER ' +
      'HERE, only its kind and its identifier</strong> — the rule the ' +
      'audit log follows — and a Kerberos ticket genuinely has none to ' +
      'quote. <em>Went to</em> is the application that holds it: a ' +
      'token\'s <code>client_id</code>, an assertion\'s audience, the ' +
      'service principal a ticket was cut for. Nothing holds an X509-SVID, ' +
      'which is why some rows have none.' +
      (json.onDelegationLines
        ? ' <strong>' + kit.esc(json.onDelegationLines) + ' more are ' +
          'not in this table</strong> and are not missing: a token ' +
          'exchange writes a row in BOTH registers for one credential, so ' +
          'those are listed under the delegation acts below, where the row ' +
          'says more — it names the actor and whether the far end can see ' +
          'them.'
        : '')) +
      '<table><tr><th>When</th><th>Credential</th><th>What issued it</th>' +
      '<th>Went to</th><th>State</th><th>Session</th></tr>' +
      (json.credentials.map(function (credential) {
        return DelegationPage.userCredentialRow(credential, json.facts);
      }).join('') ||
        '<tr><td colspan="6">Nothing has been issued naming them. ' +
        'For somebody only a delegation names — an S4U2Self subject, an ' +
        '<code>OnBehalfOf</code> — that is the expected state and not a ' +
        'broken one.</td></tr>') + '</table>' +
      kit.note('The same rows with their revoke buttons, grouped by the ' +
      'sign-on session each was issued on, are on <a href="' +
      kit.esc('/admin/users' + kit.queryWith({ user: json.key }, {})) +
      '">their page in the identity register</a>. This page draws the ' +
      'RELATIONSHIPS; that one is where a token is acted on.') +

      '<h2>The parties</h2>' +
      kit.note('Every box in the picture above, including them. A box ' +
      'with credentials and no delegation roles is an ordinary client — it ' +
      'has never been part of a delegation, which is a fact about the ' +
      'other register rather than a gap here.') +
      '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
      '<th>Credentials</th><th>By</th><th>Delegation ' +
      'roles</th><th>Acts</th><th>Protocols</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.userNodeRow(node, json.facts,
                                          json.looks[node.id]);
      }).join('') || '<tr><td colspan="8">No parties.</td></tr>') +
        '</table>' +

      '<h2>Every line, in words</h2>' +
      kit.note('The picture read as a table, because a diagram nobody can ' +
      'quote is a diagram nobody can put in a bug report. <strong>Acts and ' +
      'credentials are different units</strong> and have their own ' +
      'columns: an act is one delegation exchange, a credential is one ' +
      'thing that came out of the issued register, and a line can carry ' +
      'either, both or — a refused delegation — acts and nothing else.') +
      '<table><tr><th>From</th><th>To</th><th>Relationship</th><th>' +
      'Mechanism ' +
      'or grant</th><th>Kind</th><th>Acts</th><th>Credentials</th><th>What ' +
      'came out</th></tr>' +
      (json.graph.edges.map(function (edge) {
        return DelegationPage.userEdgeRow(edge, labelOf);
      }).join('') || '<tr><td colspan="8">No lines.</td></tr>') + '</table>' +

      (json.acts.length
        ? '<h2>Every delegation act naming them</h2>' +
          kit.note('The rows <a href="' + kit.esc(upHref) +
                    '">the delegation ' +
          'table</a> holds, narrowed to this person and not paged — in ANY ' +
          'of the three roles, because the whole reason to look somebody ' +
          'up in a delegation register is that their name appears in ' +
          'exchanges they were never present for. This is where the ' +
          'REFUSALS are: a refusal produced no credential, so it is in ' +
          'this table and in none of the ones above.') +
          '<table><tr><th class="num">#</th><th>When</th><th>Mechanism</th>' +
          '<th>Kind</th><th>Outcome</th><th>Initial identity</th>' +
          '<th>Intermediary</th><th>Target</th><th>Authorized by / why ' +
          'not</th><th>Credentials</th></tr>' +
          json.acts.map(function (row) {
            return DelegationPage.delegationRow(row, json.facts,
                                             { listView: listView });
          }).join('') + '</table>'
        : '<h2>Delegation</h2>' +
          kit.note('No delegation act names them, in any role. Everything ' +
          'above was issued to them directly — which is the ordinary ' +
          'state, since three of the sixteen families here can delegate at ' +
          'all.')) +

      '<h2>Somebody else</h2>' + chooser +
      DelegationPage.delegationUserTable(json.users, json.facts,
                                          listView) +

      kit.note('<code>?format=json</code> carries this person, their ' +
      'credentials with the grant on each, their acts and the graph behind ' +
      'the picture; <code>?format=svg</code> is the document alone. There ' +
      'is no form that changes anything on this page and therefore no ' +
      'operation on <code>/admin-api</code> — the acts are in <code>GET ' +
      '/admin-api/delegation</code> and the tokens in <code>GET ' +
      '/admin-api/users</code>.');

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
    const listView = kit.listViewOf('/admin/tokens', ctx.query);
    const upHref = '/admin/tokens' + kit.queryWith(listView, {});
    const back = kit.note('<a class="btn" href="' + kit.esc(upHref) +
      '">&larr; Back to the tokens table</a>');
    const credential = json.credential;
    const labelOf = function (id) {
      return json.looks[id] ? json.looks[id].label : id;
    };
    if (!json.counts) {
    return back +
      kit.note('<strong>Name a credential.</strong> This page draws ONE ' +
      'of them and the way to it is a link on <a href="' +
      kit.esc(upHref) +
      '">the tokens table</a> — every identifier there is one. It is ' +
      'keyed on the identifier the protocol gave the credential (a ' +
      '<code>jti</code>, an <code>AssertionID</code>), which is the only ' +
      'thing the issued register and the delegation register both hold ' +
      'about the same object, and is the reason a Kerberos ticket has no ' +
      'link: that protocol has no identifier to quote.');
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
        ? kit.esc(credential.kind) + ', issued ' +
          kit.esc(kit.whenText(credential.issuedAt)) +
          ', <span class="' + TokensPage.stateClass(credential.state) + '">' +
          kit.esc(credential.state) + '</span>'
        : '<span class="state-expired" title="' +
          kit.esc('The issued register is capped and drops the oldest, so ' +
                   'a credential a delegation act still names can be one ' +
                   'this service can no longer describe. That is a bounded ' +
                   'store working as intended rather than a gap in the ' +
                   'recording.') +
          '">no longer held in the issued register</span>') +
      '. ' +
      (json.counts.exchanges
        ? '<strong>' + kit.esc(json.counts.exchanges) + ' ' +
          'exchange(s)</strong> are behind it, so it is generation ' +
          kit.esc(json.generations.length - 1) + ' of a line that ' +
          'starts at an ordinary issuance.'
        : '<strong>Nothing was exchanged to get it.</strong> It was issued ' +
          'directly, which is the ordinary case: three of the sixteen ' +
          'protocol families here can delegate at all.'));

    return back +
      '<div class="tiles">' +
        kit.tile(json.counts.generations, 'generations') +
        kit.tile(json.counts.exchanges, 'exchanges behind it') +
        kit.tile(json.counts.parties, 'parties involved') +
        kit.tile(json.counts.acts, 'delegation acts') +
      '</div>' +

      sentence +

      (json.truncated
        ? '<p class="note state-expired"><strong>The line is longer than ' +
          kit.esc(json.maxGenerations) + ' generations and ' +
          'the rest was not walked.</strong> What is drawn below is the ' +
          'newest ' +
          kit.esc(json.maxGenerations) + ' of it, so the ' +
          'oldest box on this picture is NOT the origin. Said rather than ' +
          'left to be assumed, because a lineage that stops quietly reads ' +
          'as an issuance that never happened.</p>'
        : '') +

      '<h2>How it came to exist</h2>' +
      kit.note('One row per generation, newest first: the credential ' +
      'itself, then whatever was handed in to get it, and so on. ' +
      '<strong>The last row is the origin</strong> — the row with no ' +
      'exchange behind it, which is the issuance the whole line rests on.') +
      '<table><tr><th class="num">Gen</th><th>Identifier</th><th>Kind</th>' +
      '<th>Held by</th><th>In whose name</th><th>Issued</th>' +
      '<th>How it was got</th></tr>' +
      json.generations.map(function (row) {
        const held = row.credential;
        return '<tr>' +
          '<td class="num">' + kit.esc(row.generation) + '</td>' +
          '<td class="who">' + kit.shortened(row.identifier, 14) +
            (row.identifier === json.identifier
              ? '<br><span class="state-none">this page</span>' : '') +
                '</td>' +
          '<td>' + (held ? kit.esc(held.kind)
            : '<span class="state-none" title="' +
              kit.esc('Named by a delegation act, and no longer in the ' +
                       'issued register — the two stores are capped ' +
                       'separately.') +
              '">not held</span>') + '</td>' +
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
              '">the relationship</a>'
            : '<strong>the origin</strong><br><span class="state-none">' +
              kit.esc(row.originLabel) + '</span>') +
                          '</td>' +
          '</tr>';
      }).join('') + '</table>' +

      (json.walls.length
        ? kit.note('<strong>One line stops at a credential this service ' +
          'cannot name.</strong> ' +
          json.walls.map(function (wall) {
            return kit.esc(wall.credential.kind) + ' — ' +
              kit.esc(wall.credential.note || 'no identifier');
          }).join('; ') +
          '. That is a different answer from "this is the origin": ' +
          'something was presented and exchanged, and the protocol gave it ' +
          'nothing this register could write down. A Kerberos ticket has ' +
          'no identifier at all, and WS-Trust consumes the requester\'s ' +
          'WS-Security credential, which this service never issued.')
        : '') +

      '<h2>The whole line, as one picture</h2>' +
      kit.note('Every actor and every relationship behind this one ' +
      'credential. <strong>The hexagon is this service</strong>; a dashed ' +
      'grey line from it is a credential being handed to whoever asked. An ' +
      '<em>issued for</em> line is an ordinary grant — this client holds a ' +
      'credential naming that person — and it is the console\'s neutral ' +
      'indigo, because an authorization code grant claims neither ' +
      'impersonation nor delegation. <em>acts for</em> and ' +
      '<em>reaches</em> are the delegation picture\'s own two claims and ' +
      'are coloured by mode where a delegation is what produced them, ' +
      'exactly as they are on <a href="/admin/delegation/map">the map</a>. ' +
      'A <em>reaches</em> line out of an ordinary grant takes no mode and ' +
      'stays indigo, for the reason the <em>issued for</em> line beside it ' +
      'does: what a token is ADDRESSED to is a relationship this service ' +
      'granted, and nothing was impersonated to get it. The audience the ' +
      'token carries is in that line\'s tooltip, because the box is named ' +
      'after whichever application registered it.') +
      DelegationPage.drawing(json, '/admin/tokens/credential',
        Object.assign({}, listView, { id: json.identifier })) +

      '<h2>The parties</h2>' +
      kit.note('Every box on the picture. A party can appear because it ' +
      'held one of these credentials, because it exchanged one, or both — ' +
      'the middle tier of a chain is the TARGET of one generation and the ' +
      'INTERMEDIARY of the next, which is what makes the two hops one line ' +
      'rather than two pictures.') +
      '<table><tr><th>Label</th><th>Drawn as</th><th>Identity</th>' +
      '<th>Roles it played</th><th>Acts</th><th>Protocols</th></tr>' +
      (parties.map(function (node) {
        return DelegationPage.delegationNodeRow(node, json.facts,
                                               json.looks[node.id]);
      }).join('') || '<tr><td colspan="6">No parties.</td></tr>') +
        '</table>' +

      '<h2>Every line, in words</h2>' +
      kit.note('The picture read as a table, because a diagram nobody can ' +
      'quote is a diagram nobody can put in a bug report.') +
      '<table><tr><th>From</th><th>To</th><th>Relationship</th><th>' +
      'Mechanism ' +
      'or grant</th><th>Kind</th><th>Acts</th><th>Credentials</th><th>What ' +
      'came out</th></tr>' +
      (json.graph.edges.map(function (edge) {
        return DelegationPage.userEdgeRow(edge, labelOf);
      }).join('') || '<tr><td colspan="8">No lines.</td></tr>') + '</table>' +

      (json.acts.length
        ? '<h2>Every delegation act in the line</h2>' +
          kit.note('The rows <a href="/admin/delegation">the delegation ' +
          'table</a> holds for this lineage, in order, not paged.') +
          '<table><tr><th class="num">#</th><th>When</th><th>Mechanism</th>' +
          '<th>Kind</th><th>Outcome</th><th>Initial identity</th>' +
          '<th>Intermediary</th><th>Target</th><th>Authorized by / why ' +
          'not</th><th>Credentials</th></tr>' +
          json.acts.map(function (row) {
            return DelegationPage.delegationRow(row, json.facts,
                                             { listView: {} });
          }).join('') + '</table>'
        : '') +

      (credential && credential.family === 'token' &&
       (credential.username || credential.sub)
        ? kit.note('<a href="' + kit.esc('/admin/delegation/user' +
            kit.queryWith({}, { user: json.subjectKey })) +
          '">Everything this service has done in that person\'s name</a> ' +
          'is the other picture: this one is one credential and its ' +
          'ancestors, that one is one person and everything ever issued ' +
          'naming them.')
        : '') +

      kit.note('<code>?format=json</code> carries the lineage — every ' +
      'generation with the act that produced it, the acts, the origins and ' +
      'the graph behind the picture; <code>?format=svg</code> is the ' +
      'document alone. There is no form on this page and therefore no ' +
      'operation on <code>/admin-api</code>: the acts are in <code>GET ' +
      '/admin-api/delegation</code> and the credentials are in <code>GET ' +
      '/admin-api/tokens</code>.');

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
    const listView = kit.listViewOf('/admin/delegation-settings', ctx.query);
    return kit.note('<strong>Which applications may reach which, decided ' +
      'in advance, and how much of what HAPPENED is kept.</strong> This ' +
      'page configures; <a href="/admin/delegation">Monitoring &rsaquo; ' +
      'Delegation</a> shows the acts &mdash; Kerberos S4U, WS-Trust ' +
      '<code>OnBehalfOf</code> / <code>ActAs</code> and RFC 8693 token ' +
      'exchange &mdash; with this register beside them, read-only. One ' +
      'application\'s part of it is also on that application\'s ' +
      '<em>Permissions</em> tab under <a href="/admin/applications">' +
      'Directory &rsaquo; Applications</a>, which is where a grant is ' +
      'made. Who may act for whom at Kerberos, WS-Trust and token ' +
      'exchange is attributes of applications and people, edited on ' +
      'their pages.') +
      DelegationPage.permissionsSection(ctx, json, listView, true) +
      SettingsForms.forms(json.settings, '/admin/delegation-settings');
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
    const listView = kit.listViewOf('/admin/delegation', ctx.query);
    const groupNav = kit.pageNavPair('/admin/delegation/allowed',
                                     kit.pageParamsOf(ctx.query),
                                     json.groupsPaging);
    // What a link OUT of this page carries: the acts list's state, and this
    // page's own search (`allowedChooserState()` says why).
    const onward = Object.assign({}, listView,
                                 DelegationPage.allowedChooserState(ctx.query));
    return (
      kit.note('<strong>What is ALLOWED, not what happened.</strong> ' +
      'Every line here is a delegated permission somebody configured: a ' +
      'client application has been granted a permission that a resource ' +
      'application exposes, and a request naming it in a ' +
      '<code>scope</code> would be issued an access token audienced to ' +
      'that resource. Not one of these lines has been issued anything. <a ' +
      'href="/admin/delegation/map">The other picture</a> is the one that ' +
      'draws what actually happened.') +

      kit.note('<strong>Every box is an application and there is no ' +
      'person on this diagram</strong>, which is the visual difference ' +
      'between the two and the reason they are not one drawing. A ' +
      'delegation ACT has three layers and the first of them is somebody — ' +
      'a stick figure, the person on whose behalf it happened. A ' +
      'permission has nobody in it: it says <em>this client may reach that ' +
      'API as whoever is signed in</em>, and there is no whoever yet. ' +
      '<strong>This service is not on it either</strong>, for the same ' +
      'reason the hexagon is on the other one: every line there exists ' +
      'because this service issued or refused something, and none of these ' +
      'has been asked for.') +

      kit.note('<strong>A line leaves the box with the ROUND end and ' +
      'arrives at the box with the ARROWHEAD.</strong> That is worth ' +
      'saying on this page in particular, because it is the one where ' +
      'nearly every box is at both ends of something: an application here ' +
      'is usually a client of one and a resource of another, and the ' +
      'question is always <em>which of the lines touching this box are its ' +
      'own?</em> Both marks are on every line, and each one has a berth of ' +
      'its own on the box\'s edge, so a grant this application holds and a ' +
      'grant somebody holds on it never start from the same point. No line ' +
      'here is two-way: where two applications may reach each other, that ' +
      'is two grants and it is drawn as two lines.') +

      kit.note('<strong>A DASHED line is a grant nobody has ever ' +
      'used</strong> and a solid one has been asked for at least once — ' +
      'read off the client\'s own <code>oauthScope</code>, which records ' +
      'the scopes it has requested. That one bit is what a configured ' +
      'picture can say and an acts diagram cannot: a grant nobody needed ' +
      'draws no act at all, so it is invisible on the other one. It is ' +
      'evidence rather than proof — that attribute records what was ASKED ' +
      'FOR, not what was issued.') +

      (json.counts.dangling
        ? kit.note('<strong>' + json.counts.dangling +
          ' grant(s) are DANGLING ' +
          'and are not drawn.</strong> They name a permission no ' +
          'application in this registry defines, so there is no box at the ' +
          'far end to reach — and a line to nowhere would be a drawing of ' +
          'a resource that is there. They are in the table on <a ' +
          'href="/admin/delegation#allowed">the register</a>, which is ' +
          'where that state belongs.')
        : '') +

      DelegationPage.drawing(json, '/admin/delegation/allowed', {}) +

      '<div class="tiles">' +
        kit.tile(json.counts.grants, 'grants') +
        kit.tile(json.counts.permissions, 'permissions defined') +
        kit.tile(json.counts.unused, 'never asked for') +
        kit.tile(json.counts.dangling, 'dangling, not drawn') +
      '</div>' +

      '<h2 id="groups">The groupings: which applications are joined to ' +
      'each other</h2>' +

      kit.note('<strong>A GROUP IS A SET OF APPLICATIONS THAT CAN BE ' +
      'REACHED FROM ONE ANOTHER BY FOLLOWING GRANTS, IGNORING WHICH WAY ' +
      'EACH ONE POINTS.</strong> That is the whole definition, and the ' +
      'direction is dropped ON PURPOSE. A grant is directed — a client is ' +
      'granted a permission a resource exposes, which is why every line ' +
      'above has a round end and a pointed one — but following the arrows ' +
      'would answer <em>what can this client eventually reach</em>, and a ' +
      'permission register has no chains in it: holding a permission on an ' +
      'API does not grant that API\'s permissions to anybody. Following a ' +
      'grant EITHER WAY answers the question somebody actually arrives ' +
      'with — <em>which applications are in the same conversation as this ' +
      'one</em> — and it is the only reading under which an API and the ' +
      'three front ends holding permissions on it come out as ONE group ' +
      'rather than as four. Every picture still draws every line with its ' +
      'direction on it, so what is dropped is direction as a test of ' +
      'MEMBERSHIP, never direction as a fact.') +

      kit.note('<strong>This is what the whole-register picture above ' +
      'stops being able to say.</strong> One canvas is the right drawing ' +
      'of five applications and the wrong drawing of eighty, where the ' +
      'interesting reading is almost never the whole of it. Search for an ' +
      'application below and the picture you get is its group and nothing ' +
      'else — the applications it is joined to, however many hops away, ' +
      'and none of the ones it is not.') +

      DelegationPage.allowedApplicationChooser(json, '', onward,
        { path: '/admin/delegation/allowed', query: ctx.query }) +

      // This page has no filter form to hang `per` on, which is the case
      // perPageForm() exists for. The leaf it carries is the CHOOSER'S SEARCH
      // rather than a selected thing, because that is the only state on this
      // page a reader would lose by changing the size.
      kit.perPageForm('/admin/delegation/allowed', 'permappq',
                       kit.queryOne(ctx.query, 'permappq'),
                       json.groupsPaging.perPage,
                       'There is one table below. The drawing above is ' +
                       'never paged: paging a picture draws the pagination ' +
                       'rather than the service.',
                       kit.filterOnly(listView)) +

      groupNav.head +
      DelegationPage.allowedClusterTable(json.clusters, json.shownGroups,
                                       onward, json.apps) +
      groupNav.foot +

      '<div class="tiles">' +
        kit.tile(json.clusters.counts.clusters, 'groups') +
        kit.tile(json.clusters.counts.joined, 'with more than one in them') +
        kit.tile(json.clusters.counts.alone, 'of one application') +
        kit.tile(json.clusters.counts.largest, 'in the largest') +
      '</div>' +

      kit.note('<strong>A group of ONE is a real answer and not an empty ' +
      'row.</strong> Three different things produce one and they are worth ' +
      'telling apart: an application carrying a base URI and permissions ' +
      'that nobody has been granted — somebody described an API and ' +
      'nothing may reach it; a client holding only DANGLING grants, which ' +
      'name permissions no application defines, so there is no far end to ' +
      'be in a group with; and an application granted its OWN permission, ' +
      'which is one application however it is drawn. The last two columns ' +
      'say which.') +

      kit.note('The register itself, with the forms that change it, is on ' +
      '<a href="/admin/delegation#allowed">the delegation page</a>. ' +
      '<strong>Nothing on this page changes anything</strong> — the search ' +
      'above is the only control, and it narrows nothing here: it opens a ' +
      'picture of its own. There is still no FILTER over the drawing at ' +
      'the top, because this register has no dimension to narrow on the ' +
      'way the acts have a mechanism, a mode and an outcome — the one ' +
      'division it does have is which applications can reach each other at ' +
      'all, and that is the list above rather than a filter. ' +
      '<code>?format=json</code> is the graph and the groups, ' +
      '<code>?format=svg</code> is the document alone, and the graph is ' +
      'also in the <code>allowed.graph</code> member of <code>GET ' +
      '/admin-api/delegation</code> with the groups at <code>GET ' +
      '/admin-api/permissions/groups</code>.'));
  }
}

export = DelegationPage;
