// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_uma_description.ts
//
// ---------------------------------------------------------------------------
// `GET /uma`, DRAWN IN THE BROWSER (#1168, #584's shell): what User-Managed
// Access 2.0 is here, from the document `uma.ts`'s `description()` answers —
// on or off, the endpoints that answer, the resource servers declared in
// this realm, and the layers a permission is decided by.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import D = require('../common/web_description');

type Json = any;

const esc = D.esc;

/**
 * The UMA description page's renderer. A static utility class.
 */
class WebUmaDescription {
  /**
   * The page's title, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('describeUma.title');
  }

  /**
   * The page.
   *
   * @param view - the `uma` view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const info = (view && view.document) || {};
    const ends = info.endpoints || {};
    const rows: string[][] = [
      ['POST, GET', D.code(ends.resourceRegistration),
       t.html('describeUma.rreg')],
      ['POST', D.code(ends.permission), t.html('describeUma.perm')],
      ['GET', D.code(ends.discovery), t.html('describeUma.discovery')]
    ];
    if (ends.claimsInteraction) {
      rows.push(['GET', D.code(ends.claimsInteraction),
                 t.html('describeUma.claims')]);
    }
    const servers: string[] = info.resourceServers || [];
    return '<h1>' + t.html('describeUma.heading') + '</h1>' +
      D.p(t.html('describeUma.lead')) +
      D.p(info.enabled ? t.html('describeUma.on') : t.html('describeUma.off')) +
      (info.apiObject ? '' : D.p(t.html('describeUma.noObject'))) +
      D.table([t.html('describeUma.method'), t.html('describeUma.path'),
               t.html('describeUma.what')], rows) +
      D.p(t.html('describeUma.pat', { scope: esc(info.scope || '') })) +
      '<h2>' + t.html('describeUma.layersHeading') + '</h2>' +
      D.list([t.html('describeUma.layerRealm'),
              t.html('describeUma.layerOwner'),
              t.html('describeUma.layerFga'),
              t.html('describeUma.layerGate')]) +
      D.p(t.html('describeUma.absence')) +
      '<h2>' + t.html('describeUma.serversHeading') + '</h2>' +
      (servers.length ? D.p(D.codes(servers))
                      : D.p(t.html('describeUma.noServers'))) +
      (info.grantPerformed ? '' : D.p(t.html('describeUma.grantPending')));
  }
}

export = WebUmaDescription;
