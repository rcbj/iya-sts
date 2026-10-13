// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_scim_description.ts
//
// ---------------------------------------------------------------------------
// `GET /scim`, DRAWN IN THE BROWSER (#584, 2026-10-12).
//
// The SCIM surface's description page, from the view its shell carries
// (`scim.ts`'s `GET /scim`, `common/description_pages.ts`): the description
// document `?format=json` has always answered — the one `/admin/scim`
// draws too — beside the two facts the page drew that the document does
// not hold: whether this realm VERIFIES a credential (`mode.js`, #543's
// per-mode sentence) and the SCIM base path. `/scim/v2/*` is SCIM's and is
// unchanged.
//
// The words are the `describeScim` catalogs', whose English is what the
// server drew until #584. The store's sentence, the id's reasoning, the
// schemes' descriptions, the access-control policy, the endpoints, the
// "does not do" lines, the negatives and the mapping are the document's,
// in English.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import D = require('../common/web_description');

type Json = any;

const esc = D.esc;

/**
 * The SCIM description page's renderer. A static utility class.
 */
class WebScimDescription {
  /**
   * The page's title, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('describeScim.title');
  }

  /**
   * The page: what SCIM is here and what it writes into, the id, every
   * authentication scheme and the policy, the endpoints, and what it does
   * not do and how it fails.
   *
   * @param view - the `scim` view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const info = v.document || {};
    const base = String(v.base || '/scim/v2');
    const auth = info.authentication || {};
    const store = info.store || {};
    const list = function (value: Json): Json[] {
      return Array.isArray(value) ? value : [];
    };
    const tokenLink = { token: { href: '/oauth2/token',
                                 label: t.html('describeScim.tokenEndpoint') } };
    // WHICH SENTENCE: whether a credential is required at all, and — per
    // mode (#543 round 2) — whether it is verified.
    const credentialKey = 'describeScim.' +
      (v.verifiesCredentials ? 'verified' : 'development') +
      (auth.required ? '' : 'NotRequired');
    const schemes = list(auth.schemes).map(function (row: Json): string {
      return '<tr><td>' + esc(row.name) +
        (row.primary ? ' <em>' + t.html('describeScim.primary') + '</em>'
                     : '') + '</td><td>' + D.code(row.type) +
        (row.canonical ? ''
                       : ' <em>' + t.html('describeScim.noCanonical') +
                         '</em>') + '</td><td>' +
        (row.enabled ? t.html('describeScim.offered')
                     : t.html('describeScim.off')) +
        ' <span class="sub">(' + D.code(row.setting) + ')</span></td><td>' +
        (row.scoped ? t.html('describeScim.scopes')
                    : t.html('describeScim.everything')) + '</td><td>' +
        esc(row.spec) + '</td></tr><tr><td colspan="5" class="sub">' +
        esc(row.description) + '</td></tr>';
    }).join('');
    const endpoints = list(info.endpoints).map(function (row: Json) {
      return [D.code(row.method), D.code(row.path), esc(row.what)];
    });
    const negatives = list(info.reachableNegatives).map(function (row: Json) {
      return [esc(row.what), esc(row.answer)];
    });
    const mapping = list(info.mapping && info.mapping.user)
      .map(function (row: Json) {
        return [D.code(row.scim), D.code(row.ldap),
                esc(row.kind) +
                (row.readOnly ? t.html('describeScim.readOnly') : '')];
      });
    const identifiers = info.identifiers || {};
    const scopes = auth.scopes || {};
    return '<h1>' + t.html('describeScim.heading') + '</h1>' +
      D.p(t.html('describeScim.sub', { baseUrl: info.baseUrl }) + ' ' +
          (info.enabled ? '' : t.html('describeScim.turnedOff') + ' ') +
          t.html('describeScim.notAnEndpoint'), 'sub') +
      '<div class="warn">' + D.linked(t, credentialKey, {}, tokenLink) +
      ' ' + t.html('describeScim.active') + '</div>' +
      D.h2(t.html('describeScim.provisions')) +
      D.p(esc(store.what)) +
      D.list([t.html('describeScim.people', { dn: store.users,
                                              count: store.userCount }),
              t.html('describeScim.groups', { dn: store.groups,
                                              count: store.groupCount }),
              t.html('describeScim.directory',
                     { count: store.entryCount, max: store.maxEntries })]) +
      D.h2(t.html('describeScim.idIsDn')) +
      D.p(esc(identifiers.why)) +
      D.p(t.html('describeScim.example', { example: identifiers.example })) +
      D.h2(t.html('describeScim.authentication')) +
      D.p(auth.discoveryOpen
        ? t.html('describeScim.authOpen', { realm: auth.realm })
        : t.html('describeScim.authClosed', { realm: auth.realm })) +
      '<table><tr><th>' + t.html('describeScim.scheme') + '</th><th>' +
      t.html('describeScim.type') + '</th><th>' +
      t.html('describeScim.state') + '</th><th>' +
      t.html('describeScim.mayDo') + '</th><th>' +
      t.html('describeScim.definedBy') + '</th></tr>' + schemes +
      '</table>' +
      D.p(t.html('describeScim.scopesText',
                 { read: scopes.read, write: scopes.write,
                   algorithms: list(auth.digestAlgorithms).join(', '),
                   hoba: auth.hobaRegistration })) +
      '<h3>' + t.html('describeScim.policy') + '</h3>' +
      D.textList(auth.policy) +
      D.h2(t.html('describeScim.endpoints')) +
      D.table([t.html('describeScim.method'), t.html('describeScim.path'),
               t.html('describeScim.what')], endpoints) +
      D.h2(t.html('describeScim.doesNotDo')) +
      D.textList(info.doesNotDo) +
      D.h2(t.html('describeScim.fail')) +
      D.table([t.html('describeScim.doThis'), t.html('describeScim.getThis')],
              negatives) +
      D.h2(t.html('describeScim.mapping')) +
      D.table([t.html('describeScim.scim'), t.html('describeScim.ldap'),
               t.html('describeScim.how')], mapping) +
      D.foot([{ href: '/scim?format=json',
                label: t.html('describeScim.asJson') },
              { href: base + '/ServiceProviderConfig',
                label: 'ServiceProviderConfig' },
              { href: '/admin/scim', label: t.html('describeScim.console') },
              { href: '/admin/ldap/service',
                label: t.html('describeScim.directoryPage') }]);
  }
}

export = WebScimDescription;
