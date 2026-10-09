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
    const t = ctx.t;
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

    // Where a sentence runs into a link (a tag with an href, which a
    // message may not carry) it is split around the link (#539).
    const inner =
      '<h2>' + t.html('consoleConsent.heading') + '</h2>' +
      kit.note(t.html('consoleConsent.intro',
                      { attribute: register.attribute })) +
      (register.required ? '' : kit.warn(
        t.html('consoleConsent.notAsked') +
        '<a href="/admin/oauth2">OAuth 2.0 / OIDC</a>.')) +
      (register.storable ? '' : kit.warn(t.html('consoleConsent.notStored'))) +

      '<h3 id="globals">' + t.html('consoleConsent.globalsHeading') +
      '</h3>' +
      kit.note(t.html('consoleConsent.globalsNote',
                      { attribute: register.globalAttribute })) +
      globalsNav.head +
      (json.globals.length
        ? '<table><thead><tr><th>' + t.html('consoleConsent.colApplication') +
          '</th><th>' + t.html('consoleConsent.colScope') + '</th><th>' +
          t.html('consoleConsent.colWhat') + '</th><th></th></tr></thead>' +
          '<tbody>' +
          json.globals.map(function (one) {
            return ConsentPage.globalConsentRow(one, listView, t);
          }).join('') + '</tbody></table>'
        : kit.note(t.html('consoleConsent.noGlobals'))) +
      globalsNav.foot +

      '<h4>' + t.html('consoleConsent.grantHeading') + '</h4>' +
      kit.note(t.html('consoleConsent.grantNote')) +
      '<form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="grant-global-consent">' +
        '<label for="gc-client">' + t.html('consoleConsent.application') +
        '</label>' +
        '<select id="gc-client" name="client">' + applicationOptions +
      '</select><label ' +
        'for="gc-scope">' + t.html('consoleConsent.scope') +
        '</label><input type="text" id="gc-scope" ' +
        'name="scope" size="30" placeholder="openid"><button ' +
        'type="submit">' + t.html('consoleConsent.grantButton') +
        '</button></div></form><h3 ' +
        'id="recorded">' + t.html('consoleConsent.recordedHeading') +
        '</h3>' +
      kit.note(t.html('consoleConsent.recordedNote',
                      { attribute: json.withdrawnAttribute })) +
      kit.sectionSearchForm({
        path: '/admin/consent', query: ctx.query, param: 'q',
        // The list this search narrows, so that a new search starts at page 1
        // rather than at whatever page the reader happened to be on when the
        // list was longer — which reads as "nothing matched".
        pageParam: 'usersPage', label: t.text('consoleConsent.search'),
        placeholder: t.text('consoleConsent.searchPlaceholder')
      }) +
      consentsNav.head +
      (json.users.length
        ? '<table><thead><tr><th>' + t.html('consoleConsent.colPerson') +
          '</th><th>' + t.html('consoleConsent.colApplication') +
          '</th><th>' + t.html('consoleConsent.colScope') +
          '</th>' +
          '<th></th></tr></thead><tbody>' +
          json.users.map(function (one) {
            return ConsentPage.recordedConsentRow(one, listView, t);
          }).join('') + '</tbody></table>'
        : kit.note(q
            ? t.html('consoleConsent.noMatch', { q: q })
            : t.html('consoleConsent.noneRecorded'))) +
      consentsNav.foot +

      '<h4>' + t.html('consoleConsent.withdrawHeading') + '</h4>' +
      kit.note(t.html('consoleConsent.withdrawNote')) +
      '<form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<input type="hidden" name="from" value="recorded">' +
        '<div class="formrow">' +
        '<input type="hidden" name="action" ' +
          'value="revoke-application-consent">' +
        '<label for="ac-username">' + t.html('consoleConsent.person') +
        '</label>' +
        '<input type="text" id="ac-username" name="username" size="24" ' +
          'placeholder="alice">' +
        '<label for="ac-client">' + t.html('consoleConsent.application') +
        '</label>' +
        '<select id="ac-client" name="client">' + applicationOptions +
        '</select>' +
        '<button type="submit" class="danger">' +
        t.html('consoleConsent.withdraw') + '</button>' +
      '</div></form>' +

      '<h4>' + t.html('consoleConsent.forgetHeading') + '</h4>' +
      kit.note(t.html('consoleConsent.forgetNote')) +
      '<form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<div class="formrow">' +
        '<input type="hidden" name="action" value="forget-user-consent">' +
        '<label for="fc-username">' + t.html('consoleConsent.person') +
        '</label>' +
        '<input type="text" id="fc-username" name="username" size="24" ' +
          'placeholder="alice">' +
        '<button type="submit" class="danger">' +
        t.html('consoleConsent.forget') + '</button>' +
      '</div></form>' +

      kit.note(t.html('consoleConsent.bothHalves',
                      { globalAttribute: register.globalAttribute,
                        attribute: register.attribute }));

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
   * @param t - the page's translator (#539)
   * @returns the table row as HTML
   */
  static globalConsentRow(one, listView, t) {
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
        ? t.html('consoleConsent.permission',
                 { permission: one.permission, resource: one.resource }) +
          (one.granted ? '' : '<br><span class="state-none">' +
            t.html('consoleConsent.notGranted') + '</span>')
        : '<span class="state-none">' +
          t.html('consoleConsent.ordinaryScope') + '</span>') + '</td>' +
      '<td class="act"><form method="post" action="/admin/consent">' +
      ConsentPage.consentBack(listView) +
        '<input type="hidden" name="action" value="revoke-global-consent">' +
        '<input type="hidden" name="client" value="' + kit.esc(one.client) +
        '"><input type="hidden" name="scope" value="' + kit.esc(one.scope) +
        '"><button type="submit" class="danger">' +
        t.html('consoleConsent.remove') + '</button>' +
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
   * @param t - the page's translator (#539)
   * @returns the table row as HTML
   */
  static recordedConsentRow(one, listView, t) {
    const userHref = '/admin/users' +
                     kit.queryWith(listView || {}, { user: one.username });
    const appHref = '/admin/applications' +
                    kit.queryWith(listView || {}, { application: one.client });
    if (one.unreadable) {
      return '<tr><td class="who"><a href="' + kit.esc(userHref) + '">' +
        kit.esc(one.username) +
        '</a></td><td colspan="2"><span class="state-none">' +
        t.html('consoleConsent.unreadable', { raw: one.raw }) +
        '</span></td><td class="act"></td></tr>';
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
         '<br><span class="state-none">' +
         t.html('consoleConsent.agreedAt', { at: one.at }) +
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
        '"><button type="submit" class="danger">' +
        t.html('consoleConsent.revoke') + '</button>' +
      '</form></td></tr>';
  }
}

export = ConsentPage;
