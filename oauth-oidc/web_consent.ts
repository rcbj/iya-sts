// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_consent.ts
//
// ---------------------------------------------------------------------------
// OAUTH 2.0 → CONSENT, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Consent from the answer of `GET /admin-api/consent`: the consent
// overrides per application and scope, every consent a person recorded, and
// the forms that change both.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/consent` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws Consent from the answer of `GET /admin-api/consent`: the consent
 * overrides per application and scope, every consent a person recorded, and
 * the forms that change both.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ConsentPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const register = json;
    const q = json.query.q;
    const listView = kit.listViewOf('/admin/consent', ctx.query);
    const navParams = kit.pageParamsOf(ctx.query);
    const globalsNav = kit.pageNavPair('/admin/consent', navParams,
                                        json.globalsPaging);
    const consentsNav = kit.pageNavPair('/admin/consent', navParams,
                                         json.usersPaging);

    const applicationOptions = json.applicationChoices.map(function (row) {
      return '<option value="' + kit.esc(row.identifier) + '">' +
             kit.esc(row.name && row.name !== row.identifier
               ? row.name + ' — ' + row.identifier : row.identifier) +
             '</option>';
    }).join('');

    const inner =
      '<h2>Consent</h2>' +
      kit.note('<strong>What a person agreed an application may ask for ' +
      'on their behalf.</strong> With <code>oauth2.consentRequired</code> ' +
      'ON &mdash; it is ON by default, and it is the one policy in this ' +
      'service that is &mdash; the authorization endpoint draws a screen ' +
      'the first time a given username signs in to a given ' +
      '<code>client_id</code> for a given scope, and issues nothing until ' +
      'they answer. Allow writes one <code>' + kit.esc(register.attribute) +
      '</code> value per scope onto that person\'s own entry under ' +
      '<code>ou=users</code>; Deny returns <code>access_denied</code> to ' +
      'the client and records nothing at all. A delegated permission is ' +
      'recorded by its WHOLE identifier &mdash; ' +
      '<code>https://example.com/write</code> and never the bare ' +
      '<code>write</code> &mdash; because two resources may both expose a ' +
      'permission of the same name and a consent to one must not cover the ' +
      'other.') +
      (register.required ? '' : kit.warn('<strong>Nothing is being ' +
        'asked.</strong> <code>oauth2.consentRequired</code> is OFF, so ' +
        'the authorization endpoint issues whatever is requested and this ' +
        'page is a record of what was agreed while it was on. Turning it ' +
        'back on asks again for anything not listed below &mdash; OFF does ' +
        'not mean everybody consented, it means nobody was asked. The ' +
        'switch is on <a href="/admin/oauth2">OAuth 2.0 / OIDC</a>.')) +
      (register.storable ? '' : kit.warn('<strong>Nothing can be written ' +
        'down.</strong> This process has no directory installed behind the ' +
        'consent register, so an answer given at the screen is honoured ' +
        'for that one request and forgotten &mdash; every sign-in draws ' +
        'the screen again. That is deliberate rather than a fallback to ' +
        'consenting silently: an agreement that cannot be remembered is ' +
        'one nobody gave.')) +

      '<h3 id="globals">Global consent &mdash; nobody is asked about ' +
      'these</h3>' +
      kit.note('<strong>Configuration, not a record.</strong> One value ' +
      'per (application, scope), held as <code>' +
      kit.esc(register.globalAttribute) +
      '</code> ' +
      'on the APPLICATION\'s own entry. Everybody who signs in to that ' +
      'application skips the prompt for that scope, and <strong>nothing is ' +
      'written about anybody</strong> &mdash; so removing a row here asks ' +
      'everybody again, including the people who would have said yes. That ' +
      'is the whole difference from the table below it, where removing a ' +
      'row asks one person. Removing a row also revokes every token of ' +
      'that application carrying the scope, except for people who agreed ' +
      'to it themselves, and this is the only door that removes one ' +
      '&mdash; on this service\'s own console, portal or debugger too, ' +
      'whose sessions standing on it then end at their next renewal.' +
      '<br><br>It is keyed on the PAIR and not on the ' +
      'scope alone: consenting <code>read</code> here consents it for this ' +
      'application, and an application registered five minutes from now ' +
      'that spells the same word is still asked. It is an ordinary ' +
      'attribute on an ordinary entry, so an <code>ldapmodify</code> ' +
      'reaches it exactly as it reaches a redirect URI, and it persists ' +
      'wherever the directory does.') +
      globalsNav.head +
      (json.globals.length
        ? '<table><thead><tr><th>Application</th><th>Scope</th><th>What it ' +
          'is</th><th></th></tr></thead><tbody>' +
          json.globals.map(function (one) {
            return ConsentPage.globalConsentRow(one, listView);
          }).join('') + '</tbody></table>'
        : kit.note('<strong>Nothing is globally consented.</strong> Every ' +
          'person is asked about every scope the first time an application ' +
          'requests it, which is what this service does out of the box.')) +
      globalsNav.foot +

      '<h4>Consent a scope for everybody</h4>' +
      kit.note('The scope is written exactly as a client puts it in a ' +
      '<code>scope</code> parameter: <code>openid</code>, ' +
      '<code>profile</code>, or a whole delegated permission identifier ' +
      'such as <code>https://example.com/write</code>. It must be a legal ' +
      'OAuth scope token (RFC 6749 section 3.3: any printable ASCII except ' +
      'space, double quote and backslash), because a value with a space in ' +
      'it is two scopes and could never match one. A scope no application ' +
      'here defines a permission for is accepted rather than refused ' +
      '&mdash; most scopes are not permissions.') +
      '<form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="grant-global-consent">' +
        '<label for="gc-client">Application</label>' +
        '<select id="gc-client" name="client">' + applicationOptions +
      '</select><label ' +
        'for="gc-scope">Scope</label><input type="text" id="gc-scope" ' +
        'name="scope" size="30" placeholder="openid"><button ' +
        'type="submit">Consent it for everybody</button></div></form><h3 ' +
        'id="recorded">Recorded consent &mdash; what people actually ' +
        'answered</h3>' +
      kit.note('<strong>One row per (person, application, scope), and ' +
      'that IS the answer.</strong> A person who agreed to five scopes for ' +
      'one application is five rows rather than one labelled <em>5</em>, ' +
      'because a client that later asks for a sixth is asked about the ' +
      'sixth alone &mdash; which is what the screen shows and what these ' +
      'rows have to be able to express. The timestamp is when they pressed ' +
      'Allow.<br><br>Revoking a row asks that one person again the next ' +
      'time that one application requests that one scope, and it ' +
      '<strong>WITHDRAWS</strong> it: every access and refresh token that ' +
      'application holds for them carrying the scope is revoked on every ' +
      'node, and the instant is written onto their entry as <code>' +
      kit.esc(json.withdrawnAttribute) + '</code>, so a refresh ' +
      'token granted before it is refused at the token endpoint even after ' +
      'they agree again. Withdrawing one scope revokes the whole refresh ' +
      'token. Removing a global consent above does the same for everybody ' +
      'it covered, and <code>oauth2.refreshRequiresConsent</code> refuses ' +
      'a refresh token from the authorization endpoint that no recorded ' +
      'consent covers.') +
      kit.sectionSearchForm({
        path: '/admin/consent', query: ctx.query, param: 'q',
        // The list this search narrows, so that a new search starts at page 1
        // rather than at whatever page the reader happened to be on when the
        // list was longer — which reads as "nothing matched".
        pageParam: 'usersPage', label: 'Search',
        placeholder: 'a person, an application or a scope'
      }) +
      consentsNav.head +
      (json.users.length
        ? '<table><thead><tr><th>Person</th><th>Application</th><th>Scope' +
          '</th>' +
          '<th></th></tr></thead><tbody>' +
          json.users.map(function (one) {
            return ConsentPage.recordedConsentRow(one, listView);
          }).join('') + '</tbody></table>'
        : kit.note(q
            ? '<strong>Nothing matches &ldquo;' + kit.esc(q) +
              '&rdquo;.</strong> ' +
              'The search is over the person, the application and the scope.'
            : '<strong>Nobody has consented anything yet.</strong> That is ' +
              'what a service nobody has signed in to looks like &mdash; ' +
              'and also what one looks like where every scope anybody has ' +
              'asked for is under global consent above, because an ' +
              'override writes nothing down.')) +
      consentsNav.foot +

      '<h4>Withdraw everything one person agreed to for one ' +
      'application</h4>' +
      kit.note('Every recorded consent between one person and one ' +
      'application, in one act &mdash; what the person can do themselves ' +
      'from <code>/portal/consents</code>. Every token that application ' +
      'holds for them under those scopes is revoked.') +
      '<form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<input type="hidden" name="from" value="recorded">' +
        '<div class="formrow">' +
        '<input type="hidden" name="action" ' +
          'value="revoke-application-consent">' +
        '<label for="ac-username">Person</label>' +
        '<input type="text" id="ac-username" name="username" size="24" ' +
          'placeholder="alice">' +
        '<label for="ac-client">Application</label>' +
        '<select id="ac-client" name="client">' + applicationOptions +
        '</select>' +
        '<button type="submit" class="danger">Withdraw</button>' +
      '</div></form>' +

      '<h4>Forget everything one person agreed to</h4>' +
      kit.note('Every recorded consent for one person, in one act, so ' +
      'that they are asked again by every application. It is a separate ' +
      'control rather than a loop over the Revoke buttons above because ' +
      'being asked again is the one thing somebody wants after testing ' +
      'this screen, and doing it a row at a time for a person with thirty ' +
      'consents is a chore rather than a control. It reaches nothing under ' +
      'global consent, because there is nothing on their entry to reach.') +
      '<form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="forget-user-consent">' +
        '<label for="fc-username">Person</label>' +
        '<input type="text" id="fc-username" name="username" size="24" ' +
          'placeholder="alice">' +
        '<button type="submit" class="danger">Forget them all</button>' +
      '</div></form>' +

      kit.note('<strong>Both halves are ordinary attributes on ordinary ' +
      'directory entries.</strong> <code>' +
      kit.esc(register.globalAttribute) + '</code> on ' +
      'an application under <code>ou=applications</code>, <code>' +
      kit.esc(register.attribute) + '</code> on a person under ' +
      '<code>ou=users</code> as <code>&lt;when&gt; &lt;scope&gt; ' +
      '&lt;client_id&gt;</code> &mdash; the client_id last, because it is ' +
      'the one field with no rule about what it may contain and therefore ' +
      'has to take the remainder of the value. <code>GET ' +
      '/admin/ldap/directory</code> shows them as they are, and they ' +
      'persist wherever the directory does.');

    return inner;
  }

  /**
   * Draws the hidden "back" field the consent page's forms carry.
   *
   * @param listView - the list view to return to, or nothing
   * @returns a hidden input as HTML
   */
  static consentBack(listView) {
    return '<input type="hidden" name="back" value="' +
           kit.esc(kit.queryWith(listView || {}, {})) + '">';
  }

  // One row of the overrides table.
  /**
   * Draws one row of the global consent table: the application, the scope,
   * what the scope is, and a Remove form.
   *
   * @param one - the global consent row
   * @param listView - the list view the links and form carry
   * @returns the table row as HTML
   */
  static globalConsentRow(one, listView) {
    const href = '/admin/applications' +
                 kit.queryWith(listView || {}, { application: one.client });
    return '<tr>' +
      '<td class="who"><a href="' + kit.esc(href) + '">' +
      kit.esc(one.clientName) +
      '</a>' +
        (one.clientName === one.client ? '' :
         '<br><code>' + kit.esc(one.client) + '</code>') +
      '</td>' +
      '<td><code>' + kit.esc(one.scope) + '</code></td>' +
      // WHAT THE SCOPE IS, in three states rather than two, which is the same
      // honesty the grants table applies to a name it cannot resolve. Most
      // scopes are not permissions and saying "not a permission" about `openid`
      // would be reporting a fault where there is none.
      '<td>' + (one.resource
        ? 'the permission <code>' + kit.esc(one.permission) + '</code> ' +
                                                          'exposed by <code>' +
          kit.esc(one.resource) + '</code>' +
          (one.granted ? '' : '<br><span class="state-none">and this client ' +
            'has NOT been granted it &mdash; in product mode, or with ' +
            '<code>oauth2.delegatedPermissionsEnforced</code> on, the ' +
            'request is refused anyway, consented or not</span>')
        : '<span class="state-none">an ordinary scope &mdash; no application ' +
          'here defines a permission by that name</span>') + '</td>' +
      '<td class="act"><form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<input type="hidden" name="action" value="revoke-global-consent">' +
        '<input type="hidden" name="client" value="' + kit.esc(one.client) +
        '"><input type="hidden" name="scope" value="' + kit.esc(one.scope) +
        '"><button type="submit" class="danger">Remove</button>' +
      '</form></td></tr>';
  }

  // One row of the recorded table.
  /**
   * Draws one row of the recorded consent table: the person, the
   * application, the scope and a Revoke form.
   *
   * A value not in the shape this service writes is shown as it is, with no
   * form, rather than dropped.
   *
   * @param one - the recorded consent row
   * @param listView - the list view the links and form carry
   * @returns the table row as HTML
   */
  static recordedConsentRow(one, listView) {
    const userHref = '/admin/users' +
                     kit.queryWith(listView || {}, { user: one.username });
    const appHref = '/admin/applications' +
                    kit.queryWith(listView || {}, { application: one.client });
    if (one.unreadable) {
      return '<tr><td class="who"><a href="' + kit.esc(userHref) + '">' +
        kit.esc(one.username) +
        '</a></td><td colspan="2"><span class="state-none">This value is not ' +
        'in the shape this service writes &mdash; something put it on the ' +
        'entry by hand: <code>' +
        kit.esc(one.raw) + '</code>. It is shown rather than dropped, ' +
        'because a value the page silently ignored would be one somebody ' +
        'wrote on purpose and could not find out was being ignored. It ' +
        'consents nothing.</span></td><td class="act"></td></tr>';
    }
    return '<tr>' +
      '<td class="who"><a href="' + kit.esc(userHref) + '">' +
      kit.esc(one.username) +
      '</a></td><td ' +
      'class="who"><a ' +
      'href="' + kit.esc(appHref) + '">' + kit.esc(one.client) +
      '</a></td><td><code>' +
      kit.esc(one.scope) + '</code>' +
        (one.at ?
         '<br><span class="state-none">agreed at ' + kit.esc(one.at) +
         '</span>' :
         '') +
      '</td>' +
      '<td class="act"><form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<input type="hidden" name="action" value="revoke-consent">' +
        '<input type="hidden" name="username" value="' +
        kit.esc(one.username) +
      '"><input ' +
        'type="hidden" name="client" value="' + kit.esc(one.client) + '">' +
        '<input type="hidden" name="scope" value="' + kit.esc(one.scope) +
        '"><button type="submit" class="danger">Revoke</button>' +
      '</form></td></tr>';
  }
}

export = ConsentPage;
