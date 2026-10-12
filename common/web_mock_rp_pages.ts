// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_mock_rp_pages.ts
//
// ---------------------------------------------------------------------------
// THE MOCK RELYING PARTIES' PAGE TABLE AND RENDERERS (#581, 2026-10-12).
//
// `/wsfed/rp`, `/saml2/sp` and `/saml11/rp` are one static surface
// (`common/CLAUDE.md` 3cm, `common/mock_rp_surface.ts`): each a start page,
// drawn from `GET <base>/api/start`, and a verdict, drawn from the state the
// receiving answer's shell carries — WS-Federation's sign-in response, a
// SAML 2.0 Response on any of its bindings or an artifact that did not
// resolve, a SAML 1.1 Browser/POST or Browser/Artifact verdict or a spent
// artifact.
//
// The markup is what the three modules' handlers drew, in the `mockRp`
// catalogs' words (#539), on the card (`/web/card.css`, `.card.mockrp`). A
// check's name and detail, an attribute, a claim, an artifact's refusal and
// the document as it arrived are the MODEL's — the relying party's own
// report — and are drawn as they come, escaped; refusals are English.
// (SAML 1.1's details were drawn unescaped until #581, so a detail naming
// `<DoNotCacheCondition>` lost the element's name; they are text now.)
//
// It is also the renderers' bundle, `common/mock-rp.bundle.js` under the
// global `StsMockRp`, which `tests/web_surfaces.js` loads to draw a page
// from a view after the wire and compare it, byte for byte, with this
// process's drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

type Json = any;

/**
 * Escapes text for HTML.
 *
 * @param value - anything
 * @returns the escaped text
 */
function esc(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Each family's base path: its page, and the base of its script and API.
 */
const BASES: Record<string, string> = {
  wsfed: '/wsfed/rp',
  saml2: '/saml2/sp',
  saml11: '/saml11/rp'
};

/**
 * The mock relying parties' pages. A static utility class.
 */
class MockRpPages {
  /**
   * A link in a list, with what follows it.
   *
   * @param href - the address
   * @param label - the link's words, as HTML
   * @param note - what follows, as HTML
   * @returns the list item
   */
  static item(href: string, label: string, note: string): string {
    return '<li><a href="' + esc(href) + '">' + label + '</a>' +
      (note ? ' ' + note : '') + '</li>';
  }

  /**
   * The checks a relying party made, one row each with its verdict.
   *
   * @param checks - `[{ name, ok, detail }]`
   * @param t - the translator
   * @returns the heading and table
   */
  static checks(checks: Json[], t: Json): string {
    return '<h2>' + t.html('mockRp.checks.heading') + '</h2><table><thead>' +
      '<tr><th>' + t.html('mockRp.checks.check') + '</th><th>' +
      t.html('mockRp.checks.verdict') + '</th><th>' +
      t.html('mockRp.checks.detail') + '</th></tr></thead><tbody>' +
      (checks || []).map(function (c: Json) {
        return '<tr><td>' + esc(c.name) + '</td><td class="' +
          (c.ok ? 'pass">' + t.html('mockRp.checks.pass')
                : 'fail">' + t.html('mockRp.checks.fail')) +
          '</td><td>' + esc(c.detail) + '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  /**
   * The document as it arrived.
   *
   * @param heading - the heading, as HTML
   * @param text - the document
   * @param t - the translator
   * @returns the heading and the block
   */
  static document(heading: string, text: string, t: Json): string {
    return '<h2>' + heading + '</h2><pre>' +
      (text ? esc(text) : t.html('mockRp.nothing')) + '</pre>';
  }

  /**
   * WS-Federation's start page.
   *
   * @param view - the start view
   * @param t - the translator
   * @returns the HTML
   */
  static wsfedStart(view: Json, t: Json): string {
    const href: Json = {};
    (view.requests || []).forEach(function (one: Json) {
      href[one.id] = one.href;
    });
    const request = function (id: string, note: boolean): string {
      return MockRpPages.item(href[id] || '',
        t.html('mockRp.wsfed.request.' + id),
        note ? t.html('mockRp.wsfed.request.' + id + 'Note') : '');
    };
    return '<h1>' + t.html('mockRp.wsfed.heading') + '</h1>' +
      '<p class="sub">' + t.html('mockRp.wsfed.sub') + '</p>' +
      '<p>' + t.html('mockRp.wsfed.realm', { realm: view.realm }) + '</p>' +
      '<h2>' + t.html('mockRp.start.heading') + '</h2><ul>' +
      request('saml11', true) + request('saml2', false) +
      request('trust13', true) + request('wfresh', true) +
      request('multifactor', true) + request('hardware', true) + '</ul>' +
      '<h2>' + t.html('mockRp.then.heading') + '</h2><ul>' +
      MockRpPages.item(view.signOut, t.html('mockRp.wsfed.signOut'),
                       t.html('mockRp.wsfed.signOutNote')) +
      MockRpPages.item(view.metadata, t.html('mockRp.wsfed.metadata'),
                       t.html('mockRp.wsfed.metadataNote')) + '</ul>' +
      '<div class="meta"><div>' +
      t.html('mockRp.wsfed.wctx', { wctx: view.wctx }) + '</div></div>';
  }

  /**
   * WS-Federation's verdict on a sign-in response.
   *
   * @param view - the verdict
   * @param t - the translator
   * @returns the HTML
   */
  static wsfedResult(view: Json, t: Json): string {
    const claims = view.claims || [];
    return '<h1>' + t.html('mockRp.wsfed.result.heading') + '</h1>' +
      '<p class="sub">' + t.html('mockRp.wsfed.result.sub',
                                 { realm: view.realm }) + '</p>' +
      (view.ok
        ? '<div class="ok">' + t.html('mockRp.wsfed.result.ok',
            { version: view.assertionVersion, subject: view.subject }) +
          '</div>'
        : '<div class="err">' + t.html('mockRp.result.notOk') + '</div>') +
      MockRpPages.checks(view.checks, t) +
      (claims.length
        ? '<h2>' + t.html('mockRp.wsfed.result.claims') + '</h2><table>' +
          '<thead><tr><th>' + t.html('mockRp.wsfed.result.claimUri') +
          '</th><th>' + t.html('mockRp.wsfed.result.value') + '</th></tr>' +
          '</thead><tbody>' + claims.map(function (c: Json) {
            return '<tr><td><code>' + esc(c.uri) + '</code></td><td>' +
              esc(c.value) + '</td></tr>';
          }).join('') + '</tbody></table>'
        : '') +
      MockRpPages.document(t.html('mockRp.wsfed.result.document'),
                           view.document, t) +
      '<p><a href="' + BASES.wsfed + '">' +
      t.html('mockRp.startAnother') + '</a> &middot; <a href="' +
      esc(view.signOut) + '">' + t.html('mockRp.wsfed.signOut') +
      '</a></p><div class="meta"><div>' +
      t.html('mockRp.wsfed.result.keepsNothing') + '</div></div>';
  }

  /**
   * SAML 2.0's start page.
   *
   * @param view - the start view
   * @param t - the translator
   * @returns the HTML
   */
  static saml2Start(view: Json, t: Json): string {
    const items = (view.requests || []).map(function (one: Json) {
      const binding = t.text('mockRp.saml2.binding.' + one.binding);
      const label = t.html(one.signed ? 'mockRp.saml2.request'
                                      : 'mockRp.saml2.requestUnsigned',
                           { binding: binding });
      const note = t.html(one.signed ? 'mockRp.saml2.requestSigned'
                                     : 'mockRp.saml2.requestNotSigned',
                          { binding: binding }) +
        (one.binding === 'artifact'
          ? ' ' + t.html('mockRp.saml2.artifactNote') : '') +
        (one.signed ? '' : ' ' + (view.requiresSigned
          ? t.html('mockRp.saml2.refused')
          : t.html('mockRp.saml2.answered')));
      return MockRpPages.item(one.href, label, note);
    }).join('');
    return '<h1>' + t.html('mockRp.saml2.heading') + '</h1>' +
      '<p class="sub">' + t.html('mockRp.saml2.sub') + '</p>' +
      '<p>' + t.html('mockRp.saml2.entity', { entityId: view.entityId }) +
      '</p><h2>' + t.html('mockRp.start.heading') + '</h2><ul>' + items +
      '</ul><h2>' + t.html('mockRp.then.heading') + '</h2><ul>' +
      MockRpPages.item(view.singleLogout, t.html('mockRp.saml2.slo'),
                       t.html('mockRp.saml2.sloNote')) +
      MockRpPages.item(view.metadata, t.html('mockRp.saml2.metadata'),
                       t.html('mockRp.saml2.metadataNote')) + '</ul>' +
      '<div class="meta"><div>' + t.html('mockRp.saml2.signedNote') +
      '</div></div>';
  }

  /**
   * SAML 2.0's verdict on a Response.
   *
   * @param view - the verdict
   * @param t - the translator
   * @returns the HTML
   */
  static saml2Result(view: Json, t: Json): string {
    const attributes = view.attributes || [];
    const arrived = ['post', 'redirect', 'artifact']
      .indexOf(view.arrived) >= 0 ? view.arrived : 'post';
    return '<h1>' + t.html('mockRp.saml2.result.heading') + '</h1>' +
      '<p class="sub">' + t.html('mockRp.saml2.result.sub.' + arrived,
                                 { entityId: view.entityId }) + '</p>' +
      (view.ok
        ? '<div class="ok">' + t.html('mockRp.saml2.result.ok',
                                      { subject: view.subject }) + '</div>'
        : '<div class="err">' + t.html('mockRp.result.notOk') + '</div>') +
      MockRpPages.checks(view.checks, t) +
      (attributes.length
        ? '<h2>' + t.html('mockRp.attributes') + '</h2><table><thead><tr>' +
          '<th>' + t.html('mockRp.saml2.result.name') + '</th><th>' +
          t.html('mockRp.saml2.result.value') + '</th><th>' +
          t.html('mockRp.saml2.result.nameFormat') + '</th></tr></thead>' +
          '<tbody>' + attributes.map(function (a: Json) {
            return '<tr><td><code>' + esc(a.name) + '</code></td><td>' +
              esc((a.values || []).join(', ')) + '</td><td>' +
              esc(a.nameFormat) + '</td></tr>';
          }).join('') + '</tbody></table><p class="sub">' +
          t.html('mockRp.saml2.result.custom') +
          ' <a href="/admin/saml-attributes">' +
          t.html('mockRp.saml2.result.customLink') + '</a></p>'
        : '') +
      MockRpPages.document(t.html('mockRp.saml2.result.document'),
                           view.document, t) +
      '<p><a href="' + BASES.saml2 + '">' + t.html('mockRp.startAnother') +
      '</a> &middot; <a href="' + esc(view.singleLogout) + '">' +
      t.html('mockRp.saml2.signOut') + '</a></p><div class="meta"><div>' +
      t.html('mockRp.saml2.result.keepsNothing') + '</div>' +
      (arrived === 'artifact'
        ? '<div>' + t.html('mockRp.saml2.result.inProcess',
                           { ars: view.artifactResolution }) + ' <a href="' +
          esc(view.artifactResolution) + '">' +
          t.html('mockRp.saml2.result.arsPage') + '</a></div>'
        : '') + '</div>';
  }

  /**
   * SAML 2.0's page for an artifact that did not resolve.
   *
   * @param view - `{ why }`, the model's English
   * @param t - the translator
   * @returns the HTML
   */
  static saml2Unresolved(view: Json, t: Json): string {
    return '<h1>' + t.html('mockRp.saml2.unresolved.heading') + '</h1>' +
      '<div class="err">' + esc(view.why) + '</div><p>' +
      t.html('mockRp.saml2.unresolved.note') + '</p><p><a href="' +
      BASES.saml2 + '">' + t.html('mockRp.startAnother') + '</a></p>';
  }

  /**
   * SAML 1.1's start page.
   *
   * @param view - the start view
   * @param t - the translator
   * @returns the HTML
   */
  static saml11Start(view: Json, t: Json): string {
    return '<h1>' + t.html('mockRp.saml11.heading') + '</h1>' +
      '<p class="sub">' + t.html('mockRp.saml11.sub') + '</p><p>' +
      t.html('mockRp.saml11.intro', { providerId: view.providerId }) +
      ' <a href="' + esc(view.transfer) + '">' +
      t.html('mockRp.saml11.transferPage') + '</a></p>' +
      '<div class="row"><a class="button" href="' + esc(view.post) + '">' +
      t.html('mockRp.saml11.post') + '</a><a class="button secondary" ' +
      'href="' + esc(view.artifact) + '">' + t.html('mockRp.saml11.artifact') +
      '</a></div><div class="meta"><div>' +
      t.html('mockRp.saml11.postNote') + '</div><div>' +
      t.html('mockRp.saml11.artifactNote') + '</div></div>';
  }

  /**
   * SAML 1.1's verdict, on either profile.
   *
   * @param view - the verdict
   * @param t - the translator
   * @returns the HTML
   */
  static saml11Result(view: Json, t: Json): string {
    const artifact = view.profile === 'artifact';
    const target = view.target === null || view.target === undefined
      ? t.text('mockRp.none') : String(view.target);
    const attributes = view.attributes || [];
    return '<h1>' + (artifact ? t.html('mockRp.saml11.result.artifact')
                              : t.html('mockRp.saml11.result.post')) +
      '</h1><p class="sub">' + t.html('mockRp.saml11.result.passed',
        { passed: view.passed, total: view.total }) + '</p>' +
      (view.subject
        ? '<p>' + t.html('mockRp.saml11.result.signedInAs',
                         { subject: view.subject }) + '</p>'
        : '<p class="fail">' + (artifact
            ? t.html('mockRp.saml11.result.noSubjectArtifact')
            : t.html('mockRp.saml11.result.noSubjectPost')) + '</p>') +
      (artifact
        ? '<p>' + t.html('mockRp.saml11.result.artifactWas',
                         { artifact: view.artifact }) + '</p><p>' +
          t.html('mockRp.saml11.result.targetArtifact', { target: target }) +
          '</p>'
        : '<p>' + t.html('mockRp.saml11.result.target', { target: target }) +
          '</p>') +
      MockRpPages.checks(view.checks, t) +
      (attributes.length
        ? '<h2>' + t.html('mockRp.attributes') + '</h2><table><thead><tr>' +
          '<th>AttributeNamespace</th><th>AttributeName</th><th>' +
          t.html('mockRp.saml11.result.values') + '</th></tr></thead><tbody>' +
          attributes.map(function (a: Json) {
            return '<tr><td><code>' + esc(a.namespace) + '</code></td>' +
              '<td><code>' + esc(a.name) + '</code></td><td>' +
              (a.values || []).map(function (v: unknown) {
                return esc(v);
              }).join('<br>') + '</td></tr>';
          }).join('') + '</tbody></table>'
        : '') +
      MockRpPages.document(artifact
        ? t.html('mockRp.saml11.result.documentArtifact')
        : t.html('mockRp.saml11.result.documentPost'), view.document, t) +
      '<div class="row"><a class="button secondary" href="' + BASES.saml11 +
      '">' + t.html('mockRp.saml11.again') + '</a>' +
      (artifact && view.again
        ? '<a class="button secondary" href="' +
          esc(view.again) + '">' + t.html('mockRp.saml11.reload') + '</a>'
        : '') + '</div>';
  }

  /**
   * SAML 1.1's page for a spent artifact.
   *
   * @param t - the translator
   * @returns the HTML
   */
  static saml11Spent(t: Json): string {
    return '<h1>' + t.html('mockRp.saml11.result.artifact') + '</h1>' +
      '<div class="err">' + t.html('mockRp.saml11.spent.err') + '</div><p>' +
      t.html('mockRp.saml11.spent.note') + '</p><div class="row"><a ' +
      'class="button" href="' + BASES.saml11 + '">' +
      t.html('mockRp.saml11.startAgain') + '</a></div>';
  }

  /**
   * Draws a family's page from its view, by the view's `kind`.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param view - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static page(family: string, view: Json, ctx: Json): string {
    const t = ctx.t;
    const kind = String((view && view.kind) || 'start');
    if (family === 'wsfed') {
      return kind === 'result' ? MockRpPages.wsfedResult(view, t)
                               : MockRpPages.wsfedStart(view, t);
    }
    if (family === 'saml2') {
      if (kind === 'result') {
        return MockRpPages.saml2Result(view, t);
      }
      return kind === 'unresolved' ? MockRpPages.saml2Unresolved(view, t)
                                   : MockRpPages.saml2Start(view, t);
    }
    if (kind === 'result') {
      return MockRpPages.saml11Result(view, t);
    }
    return kind === 'spent' ? MockRpPages.saml11Spent(t)
                            : MockRpPages.saml11Start(view, t);
  }

  /**
   * The document's title for a family's view, as text.
   *
   * @param family - `wsfed`, `saml2` or `saml11`
   * @param view - the view
   * @param ctx - the render context
   * @returns the title
   */
  static title(family: string, view: Json, ctx: Json): string {
    const kind = String((view && view.kind) || 'start');
    if (family === 'saml11' && kind === 'result') {
      return ctx.t.text(view.profile === 'artifact'
        ? 'mockRp.saml11.result.artifact' : 'mockRp.saml11.result.post');
    }
    return ctx.t.text('mockRp.' + family + '.title.' +
      (kind === 'start' ? 'start' : kind));
  }

  /**
   * Draws a page's body from its view, for the round trip.
   *
   * @param path - the page's path
   * @param view - its view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const row = PAGES.filter(function (one) {
      return one.path === path;
    })[0];
    return row ? row.render(view, ctx) : '';
  }
}

/**
 * A family's page row: its path, the start view's operation, and the
 * renderer and title for whichever view it is handed.
 *
 * @param family - `wsfed`, `saml2` or `saml11`
 * @returns the row
 */
function rowOf(family: string): Json {
  return {
    path: BASES[family],
    operation: BASES[family] + '/api/start',
    render: function (view: Json, ctx: Json): string {
      return MockRpPages.page(family, view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return MockRpPages.title(family, view, ctx);
    }
  };
}

/**
 * The surface's three pages, one per mock relying party.
 */
const PAGES = [rowOf('wsfed'), rowOf('saml2'), rowOf('saml11')];

/**
 * The page table, the bases, and the renderers by name for the round trip.
 * @namespace
 */
export = {
  PAGES: PAGES,
  BASES: BASES,
  MockRpPages: MockRpPages,
  render: MockRpPages.render
};
