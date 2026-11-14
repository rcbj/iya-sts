// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_saml_description.ts
//
// ---------------------------------------------------------------------------
// `GET /saml2` AND `GET /saml11`, DRAWN IN THE BROWSER (#584, 2026-10-12).
//
// The two SAML identity providers' description pages, from the views their
// shells carry (`saml2_sso.ts`'s and `saml11_sso.ts`'s `descriptionView()`,
// `common/description_pages.ts`): what each profile is here, its endpoints
// and, for 2.0, how per-service-provider metadata is minted. The mock
// service provider and relying party they once listed were deleted (#592).
//
// The words are the `describeSaml2` and `describeSaml11` catalogs', and
// their English is what the server drew until #584; the paths, the
// entityID and the base are the view's.
//
// The bare `GET /saml2/sso`, `/saml2/ars`, `/saml11/sso` and
// `/saml11/responder` descriptions are NOT here: each is a specification's
// endpoint answering a parameterless GET, and #569's rule leaves those as
// they are.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import D = require('../common/web_description');

type Json = any;

const esc = D.esc;

/**
 * The SAML description pages' renderers. A static utility class.
 */
class WebSamlDescription {
  /**
   * The SAML 2.0 page's title, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static saml2Title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('describeSaml2.title');
  }

  /**
   * The SAML 2.0 page: the identity provider, its endpoints and the
   * per-service-provider metadata.
   *
   * @param view - the `saml2` view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static saml2(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const p = v.paths || {};
    const g = v.generic || {};
    const scoped = function (path: string): string {
      return String(path) + '/{sp}';
    };
    const rows: string[][] = [
      [D.link(p.sso, esc(p.sso)),
       t.html('describeSaml2.sso', { scoped: scoped(p.sso) })],
      [D.code(p.ars), t.html('describeSaml2.ars')],
      [D.link(p.slo, esc(p.slo)), t.html('describeSaml2.slo')],
      [D.code(p.unsolicited), t.html('describeSaml2.unsolicited')],
      [D.code(p.aa), t.html('describeSaml2.aa',
                            { element: '<samlp:AttributeQuery>' })],
      [D.link(p.metadata, esc(p.metadata)),
       t.html('describeSaml2.metadata', { scoped: scoped(p.metadata),
                                          sp: '{sp}' })]
    ];
    const example = String(p.metadata) + '/example-sp';
    return '<h1>' + t.html('describeSaml2.heading') + '</h1>' +
      D.p(t.html('describeSaml2.sub', { entityId: v.idpEntityId,
                                        base: v.base }), 'sub') +
      D.p(t.html('describeSaml2.lead')) +
      D.h2(t.html('describeSaml2.endpoints')) +
      D.table([t.html('describeSaml2.endpoint'),
               t.html('describeSaml2.what')], rows) +
      D.h2(t.html('describeSaml2.perSp')) +
      D.p(t.html('describeSaml2.perSpLead',
                 { path: String(p.metadata) + '/{anything}' })) +
      D.list([D.link(example, esc(example)),
              D.code(String(p.metadata) + '/' +
                     encodeURIComponent('https://sp.example.com/saml'))]) +
      '<div class="meta"><div>' +
      t.html('describeSaml2.generic', { sso: g.sso, slo: g.slo,
                                        ars: g.ars }) +
      '</div></div>';
  }

  /**
   * The SAML 1.1 page's title, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static saml11Title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('describeSaml11.title');
  }

  /**
   * The SAML 1.1 page: the two browser profiles, the responder, and what
   * makes it different from SAML 2.0.
   *
   * @param view - the `saml11` view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static saml11(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const p = v.paths || {};
    const rows: string[][] = [
      [D.link(p.sso, esc(p.sso)), t.html('describeSaml11.sso')],
      [D.code(p.responder), t.html('describeSaml11.responder')],
      [D.link(p.metadata, esc(p.metadata)), t.html('describeSaml11.metadata')]
    ];
    return '<h1>' + t.html('describeSaml11.heading') + '</h1>' +
      D.p(t.html('describeSaml11.sub'), 'sub') +
      D.p(D.linked(t, 'describeSaml11.lead', {}, {
        wsfed: { href: '/wsfed', label: 'WS-Federation' },
        wstrust: { href: '/sts', label: 'WS-Trust' } })) +
      D.h2(t.html('describeSaml11.endpoints')) +
      D.table([t.html('describeSaml11.endpoint'),
               t.html('describeSaml11.what')], rows) +
      D.h2(t.html('describeSaml11.different')) +
      D.list([t.html('describeSaml11.noRequest'),
              t.html('describeSaml11.noSlo'),
              t.html('describeSaml11.spellings'),
              t.html('describeSaml11.artifact')]) +
      '<div class="row">' +
      '<a href="' + esc(v.metadata) + '"><button class="secondary">'
      t.html('describeSaml11.theMetadata') + '</button></a></div>';
  }
}

export = WebSamlDescription;
