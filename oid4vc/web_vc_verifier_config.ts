// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_verifier_config.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → OPENID4VP VERIFIER REQUEST, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws the Verifier request from the answer of `GET
// /admin-api/vc-verifier-config`: which claims the mock Verifier asks for, in
// which format, and the DCQL query it builds.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/vc-verifier-config` in
// `admin-ui/admin.ts`, which still draws the page until the console's cutover
// by calling this with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws the Verifier request from the answer of `GET
 * /admin-api/vc-verifier-config`: which claims the mock Verifier asks for, in
 * which format, and the DCQL query it builds.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class VcVerifierConfigPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const format = json.format;
    const requested = json.requested;
    const query = json.dcqlQuery;

    const inner = kit.note('What the mock Verifier at <a ' +
      'href="/oid4vp/verifier">/oid4vp/verifier</a> — the pages call it ' +
      '<em>The Bar Door</em> — asks a wallet for, and in which credential ' +
      'format. It reaches the wire as the <code>dcql_query</code> of the ' +
      'next OID4VP Authorization Request, and it is what the Verifier then ' +
      'checks the presentation against: a claim asked for and not ' +
      'presented fails the <em>Requested claims</em> check by name.') +

      kit.note('The claims are the same catalogue <a ' +
      'href="/admin/vc">/admin/vc</a> fills a credential from, grouped ' +
      'into <strong>claims</strong> rather than listed as attribute types. ' +
      'A credential carries one Disclosure per top-level claim, so ' +
      '<code>address</code> is one unit of disclosure however many LDAP ' +
      'attributes feed it — asking for it gets the street, the locality, ' +
      'the region, the postal code and the country together, and a page ' +
      'offering six address checkboxes would be offering a choice that ' +
      'does not exist on the wire.') +

      kit.warn('<strong>This asks; it does not admit anybody.</strong> A ' +
      'presentation made to this door starts no session, issues no token ' +
      'and grants no access — the door says yes and that is the whole of ' +
      'it. Signing in with a wallet is a different door, <code>' +
      '/authn/wallet</code>, which asks for a credential this realm ' +
      'issued with a request of its own and is not configured here ' +
      '(<a href="/admin/oid4vp">OpenID4VP</a> has its switch). The two ' +
      'settings are also deliberately separate: this page decides what is ' +
      'ASKED FOR and <a href="/admin/vc">/admin/vc</a> decides what is ' +
      'ISSUED, so that asking for a claim the issuer does not mint stays ' +
      'reachable. That is the negative worth testing, and one page setting ' +
      'both would make it impossible to reach.') +

      '<h2>The claims</h2>' +
      (requested.length
        ? kit.note('Asking for ' + requested.length + ': ' +
                    kit.codeList(requested) +
                    '.')
        : kit.warn('<strong>No claim is selected, and that is a real ' +
          'request rather than an empty form.</strong> DCQL reads an ' +
          'absent <code>claims</code> member as the WHOLE credential, so ' +
          'the query below carries none and the wallet is being asked for ' +
          'everything — the opposite of what selective disclosure is for, ' +
          'which is exactly why it is worth being able to ask for it.')) +
      VcVerifierConfigPage.vpClaimsSection(json) +

      '<h2>The credential types that can be submitted</h2>' +
      VcVerifierConfigPage.vpFormatsSection(json) +

      '<h2>The query this builds</h2>' +
      kit.note('Built by the function that builds the real one, not by a ' +
      'second walk of the table above — a preview that agreed with this ' +
      'page and disagreed with the request would be worse than no preview. ' +
      'It is the <code>dcql_query</code> parameter of the next ' +
      'Authorization Request, by value or inside the signed Request ' +
      'Object.') +
      '<textarea readonly spellcheck="false">' +
      kit.esc(JSON.stringify(query, null, 2)) + '</textarea><h2>What ' +
      'this page does not change</h2>' +
      kit.note('Not what the issuer mints — that is <a ' +
      'href="/admin/vc">/admin/vc</a>, and the <em>Issued now</em> column ' +
      'above is this page reporting on that one. Not a request already in ' +
      'flight, which keeps the claims it was built with. Not the ' +
      '<code>vct</code> or the type array a credential is identified by. ' +
      'And not what a verified presentation is worth: nothing here turns ' +
      'one into a credential of any kind, and nothing here decides whether ' +
      'one signs anybody in — that is <code>/authn/wallet</code>\'s ' +
      'question, asked only of a credential this realm issued.');

    return inner;
  }

  /**
   * Draws the Verifier's claim selection form, the extra claims, the note on
   * claims dropped from an ldp_vc query, and the add and defaults forms.
   *
   * A saved selection applies to the next Authorization Request, not to one
   * already in flight.
   *
   * @param json - the page's view (`vpConfigJson()`)
   * @returns the forms and notes as HTML
   */
  static vpClaimsSection(json) {
    const format = json.format;
    const rows = json.catalogue.map(function (
        row) { return VcVerifierConfigPage.vpClaimRow(row, format); }).join('');
    const omitted = format === 'ldp_vc' ? json.ldpOmitted : [];
    return '<form method="post" action="/admin/vc-verifier-config"><input ' +
      'type="hidden" name="action" value="select"><table><tr><th>Ask</th><th>' +
      'Claim</th><th>Label</th><th>LDAP attribute (defined by)</th><th>DCQL ' +
      'path (' + kit.esc(format) + ')</th><th>ldp_vc term</th>' +
      '<th>Issued now</th></tr>' + rows + '</table>' +
      VcVerifierConfigPage.vpExtraRows(format, json.extras) +
      '<div class="formrow"><button>Save this request</button>' +
      kit.note('It applies to the next Authorization Request. One already ' +
      'in flight keeps the claims it was built with — a Verifier that judged ' +
      'a presentation against a list changed after it asked would refuse a ' +
      'wallet for answering the question it was really ' +
      'asked.') + '</div></form>' +
      (omitted.length
        ? kit.note('<strong>' + kit.codeList(omitted) + '</strong> ' +
          (omitted.length === 1 ? 'is asked for and is' :
           'are asked for and are') +
          ' dropped from an <code>ldp_vc</code> query. That format is signed ' +
          'over canonicalized JSON-LD, so only terms the vendored context ' +
          'defines can be named at all, and asking under a name it does not ' +
          'define would fail canonicalization rather than return less. The ' +
          'two JOSE-secured formats ask for all of them.')
        : '') +
      '<div class="formrow"><form method="post" ' +
      'action="/admin/vc-verifier-config" class="inline"><input ' +
      'type="hidden" name="action" value="add"><label for="claim">Also ask ' +
      'for a claim that is not in the catalogue</label><input type="text" ' +
      'id="claim" name="claim" size="24" ' +
      'placeholder="drivers_licence_number"><button ' +
      'class="secondary">Add</button></form> <form method="post" ' +
      'action="/admin/vc-verifier-config" class="inline"><input ' +
      'type="hidden" name="action" value="defaults"><button ' +
      'class="secondary">Back to what this process started ' +
      'with</button></form></div>';
  }

  // The credential types a wallet may submit, and which one an unqualified
  // request asks for. One request is for ONE of them: a presentation cannot
  // convert between formats, so a wallet holding a jwt_vc_json credential has
  // nothing to answer a dc+sd-jwt query with — and the honest outcome is that
  // it says so rather than that this page pretends the choice does not matter.
  /**
   * Draws the form that chooses which credential format an unqualified
   * presentation request asks for, with what each format is.
   *
   * @param json - the page's view (`vpConfigJson()`)
   * @returns the form and notes as HTML
   */
  static vpFormatsSection(json) {
    const format = json.format;
    const rows = json.formats.map(function (item) {
      const configs = item.configurations.map(function (id) {
        return '<code>' + kit.esc(id) + '</code>';
      }).join('<br>');
      return '<tr><td><input type="radio" name="format" value="' +
             kit.esc(item.id) +
        '"' +
        (item.id === format ? ' checked' : '') + '></td>' +
        '<td><code>' + kit.esc(item.id) + '</code><br>' +
        kit.esc(item.label) + '</td>' +
        '<td><code>' + kit.esc(item.identifiedBy) + '</code><br><code>' +
        kit.esc(item.identifierText) + '</code></td>' +
        '<td>' + kit.esc(item.selectiveDisclosure) + '</td>' +
        '<td>' + kit.esc(item.holderBinding) + '</td>' +
        '<td>' + configs + '</td>' +
        '<td><a href="' + kit.esc('/oid4vp/verifier?format=' +
                                   encodeURIComponent(item.id)) +
        '">Present one</a></td></tr>';
    }).join('');
    return '<form method="post" action="/admin/vc-verifier-config"><input ' +
      'type="hidden" name="action" ' +
      'value="format"><table><tr><th>Default</th><th>Format</th><th>' +
      'Identified ' +
      'in DCQL by</th><th>Selective disclosure</th><th>Holder ' +
      'binding</th><th>Issued here as</th><th></th></tr>' +
      rows + '</table>' +
      '<div class="formrow"><button>Ask for this one by default</button>' +
      kit.note('The default is what <code>/oid4vp/start</code> asks for ' +
      'when the link that reached it names no format. The bar door\'s three ' +
      'format buttons name one explicitly, so they are unaffected — a button ' +
      'saying "present an SD-JWT VC" that asked for something else would be ' +
      'lying in the one place a reader is most likely to trust it.') +
      '</div></form>' +
      kit.note(json.formats.map(function (item) {
        return '<strong>' + kit.esc(item.id) + '</strong> — ' +
               kit.esc(item.what);
      }).join('<br><br>')) +
      kit.note('The identifying values are not settable here. They are what ' +
      'this service\'s own issuer mints (<code>vc_configs.js</code>), and a ' +
      'Verifier asking for a <code>vct</code> nobody here issues would be a ' +
      'request no wallet in this stack could ever satisfy — a negative worth ' +
      'having, but one that belongs to the issuer\'s configuration rather ' +
      'than to a text box on this page.');
  }

  // One catalogue row. The DCQL path column is shown for the format the next
  // unqualified request will use, because a path is not a property of the
  // claim: the same claim is ["given_name"], ["credentialSubject","given_name"]
  // or ["credentialSubject","birthDate"] depending on what is being asked for,
  // and a column that picked one silently would be wrong two-thirds of the
  // time.
  /**
   * Draws one Verifier catalogue row: its checkbox, attributes, DCQL paths
   * for the format, ldp_vc terms and whether the issuer carries it.
   *
   * @param row - the requestable claim row
   * @param format - the credential format the DCQL paths are shown for
   * @returns the table row as HTML
   */
  static vpClaimRow(row, format) {
    // The catalogue row as the view carries it (#446).
    const on = row.requested;
    const paths = row.paths;
    const attributes = row.attributes.map(function (member) {
      return '<code>' + kit.esc(member.ldap) + '</code> <span ' +
        'class="state-none">(' +
             kit.esc(member.schema) + ')</span>';
    }).join('<br>');
    return '<tr><td><input type="checkbox" name="claim" value="' +
      kit.esc(row.claim) + '"' +
      (on ? ' checked' : '') + '></td>' +
      '<td><code>' + kit.esc(row.claim) + '</code>' +
      (row.nested ?
       '<br><span class="state-none">one object, ' + row.attributes.length +
                    ' attributes</span>' : '') + '</td>' +
      '<td>' + kit.esc(row.label) + '</td>' +
      '<td>' + attributes + '</td>' +
      '<td>' + (paths.length
        ? paths.map(function (path) {
          return '<code>' + kit.esc(JSON.stringify(path)) + '</code>';
        }).join('<br>')
        : '<span class="state-expired">cannot be asked for in this ' +
          'format</span>') + '</td><td>' +
          (row.ldpTerms.length ? kit.codeList(row.ldpTerms)
                                    : '<span class="state-none">—</span>') +
      '</td>' +
      VcVerifierConfigPage.vpIssuedCell(row.issued) + '</tr>';
  }

  // The claims being asked for that are NOT in the catalogue. Rendered as
  // ticked checkboxes in the same form rather than as a separate list with its
  // own Save, because a form that dropped them the moment somebody saved the
  // table above would silently undo a deliberate configuration.
  /**
   * Draws the claims asked for that are not in the catalogue, as ticked
   * checkboxes inside the selection form so a save keeps them.
   *
   * @param format - the credential format the DCQL paths are shown for
   * @param extras - the view's `extras`
   * @returns the heading, note and table as HTML, or an empty string
   */
  static vpExtraRows(format, extras) {
    if (!extras.length) {
      return '';
    }
    return '<h3>Asked for, and not in the catalogue</h3>' +
      kit.note('Nothing this service issues carries these, which is what ' +
      'makes them worth asking for: it is the only way to see what a wallet ' +
      'does with a request it cannot satisfy, and what this Verifier says ' +
      'when it checks. They are ticked below so that saving the table above ' +
      'keeps them — untick one to stop asking for it.') +
      '<table><tr><th>In</th><th>Claim</th><th>DCQL path (' + kit.esc(format) +
      ')</th></tr>' +
      extras.map(function (row) {
        const paths = row.paths;
        return '<tr><td><input type="checkbox" name="claim" value="' +
          kit.esc(row.claim) + '" ' +
          'checked></td><td><code>' + kit.esc(row.claim) + '</code></td>' +
          '<td>' + paths.map(function (path) {
            return '<code>' + kit.esc(JSON.stringify(path)) + '</code>';
          }).join('<br>') + '</td></tr>';
      }).join('') + '</table>';
  }

  // Whether the ISSUER currently mints the claim this Verifier is asking for.
  // The two pages are separate settings on purpose (see the header), so the
  // disagreement is a state to report rather than one to prevent — and
  // reporting it is what stops "the wallet disclosed nothing" being
  // investigated as a wallet bug.
  /**
   * Draws the "Issued now" cell: whether this service's issuer currently
   * mints the claim the Verifier asks for, wholly, partly or not at all.
   *
   * @param carried - the catalogue row's `issued` (`carriedNow()`)
   * @returns the table cell as HTML
   */
  static vpIssuedCell(carried) {
    if (!carried.known) {
      return '<td><span class="state-none">not a claim this service ' +
             'issues</span></td>';
    }
    if (!carried.carried.length) {
      return '<td><span class="state-expired">no — not selected on ' +
             '<a href="/admin/vc">/admin/vc</a></span></td>';
    }
    if (carried.missing.length) {
      return '<td><span class="state-expired">partly — ' +
             kit.codeList(carried.missing) +
             ' not selected</span></td>';
    }
    return '<td><span class="state-valid">yes</span></td>';
  }
}

export = VcVerifierConfigPage;
