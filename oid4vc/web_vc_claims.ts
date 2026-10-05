// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_claims.ts
//
// ---------------------------------------------------------------------------
// CREDENTIAL CLAIMS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/vc` from the answer of `GET /admin-api/vc`: which directory
// attributes a Verifiable Credential carries, what they would say about one
// person, and the forms that change the selection.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/vc` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws `/admin/vc` from the answer of `GET /admin-api/vc`: which directory
 * attributes a Verifiable Credential carries, what they would say about one
 * person, and the forms that change the selection.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class VcClaimsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {

    const inner = kit.note('Which claims a Verifiable Credential issued by ' +
      'this ' +
      'service carries, <em>from now on</em>. Nothing already issued ' +
      'changes — a credential is a signed document and this page cannot ' +
      'reach inside one. It applies to all five OID4VCI configurations: ' +
      'the SD-JWT VC, the <code>jwt_vc_json</code> W3C credential, the ' +
      '<code>ldp_vc</code> one with a BBS proof, and the two whose only ' +
      'difference is that the issuer names itself by DID.') +

      kit.note('The list is of <strong>LDAP attribute types</strong> and ' +
      'not of claim names, because this service has a directory and a ' +
      'claim with a value nothing else can see is half a demonstration. A ' +
      'selected attribute becomes the claim named beside it, and the value ' +
      'is the one on that person\'s entry under <code>ou=users</code> — so ' +
      'an LDAP client and an OID4VCI wallet pointed at this service are ' +
      'shown the same person. Three rows are not RFC 4519/4524/2798: there ' +
      'is no standard attribute type for a birthdate or a nationality, so ' +
      'the SCHAC schema\'s names are borrowed rather than invented.') +

      kit.warn('<strong>None of this is verified, and the values are ' +
      'garbage on purpose.</strong> This service authenticates nobody — ' +
      'the username typed at the sign-in screen is the identity in every ' +
      'token and credential it issues — so there is no source of a real ' +
      'birthdate here and there had better not be. What a person is ' +
      'missing is invented from their username: the same invented person ' +
      'every time, across restarts, so that two credentials issued a ' +
      'minute apart describe one human being rather than two. A verifier ' +
      'that believed any of it would be believing this page.') +

      '<h2>The attributes</h2>' +
      VcClaimsPage.vcAttributeTable(json) +

      '<h2>What a credential would carry</h2>' +
      VcClaimsPage.vcPreviewSection(json) +

      '<h2>Where a value comes from</h2>' +
      kit.note('Three sources, in this order. <strong>The access ' +
      'token</strong>, where it carries a claim of that name — that is a ' +
      'statement this service already made about the person, from the ' +
      'sign-in or from the <a href="/admin/claims">custom claims</a> page, ' +
      'and a credential contradicting the token that authorised it would ' +
      'be indefensible. Then <strong>the directory entry</strong>, which ' +
      'is where the generated values live once an entry exists and also ' +
      'where an <code>ldapmodify</code> lands: change <code>mail</code> on ' +
      '<code>uid=alice,ou=users</code> and the next credential says so. ' +
      'Then <strong>the generated persona</strong>, for a person with no ' +
      'entry, or an entry without that attribute, or a directory that is ' +
      'not running.') +
      kit.note('Populating never overwrites. An attribute an entry ' +
      'already carries is left exactly as it is — which is why the three ' +
      'seeded people keep their names and only gain what they had nothing ' +
      'for, and why a sweep run twice does nothing the second time.') +

      '<h2>What these claims do not do</h2>' +
      kit.note('Nothing reads them back. No access token, ID Token, SAML ' +
      'assertion or Kerberos PAC carries a claim from this page, and no ' +
      'endpoint makes a decision on one — it reaches a credential and ' +
      'stops there. The <a href="/admin/users">users</a> page shows the ' +
      'directory entry each of these values was written onto.');

    return inner;
  }

  /**
   * Draws the /admin/vc selection form: a checkbox per credential attribute
   * with its value for the preview user, and the defaults and populate
   * forms.
   *
   * Saving the selection also fills in missing attributes on every person
   * under ou=users.
   *
   * @param previewUser - the username being previewed
   * @returns the forms as HTML
   */
  static vcAttributeTable(json) {
    const previewUser = json.preview.user;

    const rows = json.attributes.map(function (row) {
      const on = row.selected;
      return '<tr><td><input type="checkbox" name="attribute" value="' +
        kit.esc(row.ldap) + '"' +
        (on ? ' checked' : '') + '></td>' +
        '<td><code>' + kit.esc(row.ldap) + '</code></td>' +
        '<td>' + kit.esc(row.schema) + '</td>' +
        '<td><code>' + kit.esc(row.claim) + '</code></td>' +
        '<td>' + (row.ldpTerm ? '<code>' + kit.esc(row.ldpTerm) + '</code>' :
                  '<span ' +
            'class="state-none">—</span>') +
        '</td>' + VcClaimsPage.vcExampleCell(row.example) + '</tr>';
    }).join('');

    return '<form method="post" action="/admin/vc"><input type="hidden" ' +
      'name="action" value="select"><table><tr><th>In</th><th>LDAP ' +
      'attribute</th><th>Defined by</th><th>Claim</th><th>ldp_vc ' +
      'term</th><th>In a credential ' +
      'for ' + kit.esc(previewUser) + '</th><th>Source</th></tr>' +
      rows + '</table><div class="formrow"><button>Save this ' +
      'selection</button><span class="note">Saving also populates the ' +
      'directory: every person under <code>ou=users</code> gains the ' +
      'attributes they are missing.</span></div></form><div ' +
      'class="formrow"><form method="post" action="/admin/vc" ' +
      'class="inline"><input type="hidden" name="action" ' +
      'value="defaults"><button class="secondary">Restore the six default ' +
      'claims</button></form> <form method="post" action="/admin/vc" ' +
      'class="inline"><input type="hidden" name="action" ' +
      'value="populate"><button class="secondary">Populate the directory ' +
      'now</button></form></div>';
  }

  // What a credential for this person would actually assert, claim by claim. It
  // is built by the same function the issuer calls, not by a second walk of the
  // catalogue — a preview that agreed with the page and disagreed with the
  // credential would be worse than no preview.
  /**
   * Draws what a credential for the preview user would assert, claim by
   * claim, built by the function the issuer calls.
   *
   * @param previewUser - the username being previewed
   * @returns the preview form, notes and table as HTML
   */
  static vcPreviewSection(json) {
    const previewUser = json.preview.user;
    const built = json.preview.claims;
    const rows = built.report.map(function (item) {
      return '<tr><td><code>' + kit.esc(item.claim) + '</code></td>' +
        '<td><code>' + kit.esc(item.value) + '</code></td>' +
        '<td>' + kit.esc(item.source) + '</td>' +
        '<td>' + (item.ldpTerm ? 'yes' : '<span class="state-none">no</span>') +
        '</td></tr>';
    }).join('');
    const omitted = json.ldpOmitted;

    return '<form method="get" action="/admin/vc"><div class="formrow">' +
      '<label for="user">Preview the credential for</label>' +
      '<input type="text" id="user" name="user" size="20" value="' +
      kit.esc(previewUser) + '"><button ' +
      'class="secondary">Show</button></div></form>' +
      kit.note((built.entryFound
        ? 'This person has an entry in the directory, so the values below ' +
          'marked <em>directory</em> are what an LDAP client reads from it.'
        : 'This person has no entry in the directory — nobody has ' +
          'authenticated as them and nothing was added by hand — so every ' +
          'value below is generated. It will be the same one next time: the ' +
          'invented person is seeded from the username.')) +
      '<table><tr><th>Claim</th><th>Value</th><th>From</th><th>In ' +
      'ldp_vc</th></tr>' +
      (rows ||
       '<tr><td colspan="4">No attribute is selected, so a credential ' +
               'carries nothing but its subject identifier. That is a ' +
               'legitimate thing to test and is not a mistake this page will ' +
               'correct.</td></tr>') + '</table>' +
      (omitted.length
        ? kit.note('<strong>' + kit.codeList(omitted) + '</strong> ' +
          (omitted.length === 1 ? 'is selected and does' :
           'are selected and do') +
          ' not appear in an <code>ldp_vc</code> credential. That format is ' +
          'signed over canonicalized JSON-LD, so it can only carry terms the ' +
          'vendored context defines, and the context is vendored precisely ' +
          'because editing it would invalidate every credential already ' +
          'issued against it. The two JOSE-secured formats carry all of them.')
        : '');
  }

  // The one preview row's two cells, from `admin_views.vcExampleOf()`'s
  // answer (#446).
  /**
   * Draws the value and source cells of one credential attribute row for
   * the person being previewed.
   *
   * @param example - `{ value, source }`, from the page's answer
   * @returns two table cells as HTML
   */
  static vcExampleCell(example) {
    const one = example || { value: null, source: '' };
    return '<td>' + (one.value === null
                       ? '—'
                       : '<code>' + kit.esc(one.value) + '</code>') +
           '</td><td>' + kit.esc(one.source) + '</td>';
  }
}

export = VcClaimsPage;
