// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_xacml_description.ts
//
// ---------------------------------------------------------------------------
// `GET /xacml`, DRAWN IN THE BROWSER (#584, 2026-10-12).
//
// The XACML surface's description, from the view its shell carries
// (`xacml.ts`'s `GET /xacml`, `common/description_pages.ts`): the
// description document `?format=json` has always answered, and the
// truststore door a caller's certificate must chain to. The shell, this
// script and the document are behind the SAME gate the page always was —
// a verified client certificate whose entry holds XACML_USER — so this
// module draws nothing a caller the gate refused could reach.
//
// The words are the `describeXacml` catalogs', whose English is what the
// server drew until #584. An endpoint's `what`, the roles, the groups and
// the "not here yet" lines are the document's, in English.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import D = require('../common/web_description');

type Json = any;

const esc = D.esc;

/**
 * The XACML description page's renderer. A static utility class.
 */
class WebXacmlDescription {
  /**
   * The page's title, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('describeXacml.title');
  }

  /**
   * The page: what the PDP is, the endpoints and what each requires, how
   * a caller gets in, the embedded and remote PEPs, the PIP over HTTP.
   *
   * @param view - the `xacml` view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const info = v.document || {};
    const repository = info.repository || {};
    const access = info.access || {};
    const remote = info.remotePeps || {};
    const nobody = t.text('describeXacml.nobody');
    const rows = (Array.isArray(info.endpoints) ? info.endpoints : [])
      .map(function (row: Json): string[] {
        return [D.code(row.method), D.code(row.path), esc(row.what),
                D.code(row.requires)];
      });
    return '<h1>' + t.html('describeXacml.heading') + '</h1>' +
      D.p(t.html('describeXacml.lead')) +
      D.p(info.enabled ? t.html('describeXacml.on')
                       : t.html('describeXacml.off')) +
      D.p(repository.root
        ? t.html('describeXacml.repositoryRoot',
                 { policies: repository.policies,
                   enabled: repository.enabledPolicies,
                   root: repository.root })
        : t.html('describeXacml.repositoryNoRoot',
                 { policies: repository.policies,
                   enabled: repository.enabledPolicies })) +
      D.table([t.html('describeXacml.method'), t.html('describeXacml.path'),
               t.html('describeXacml.what'),
               t.html('describeXacml.requires')], rows) +
      D.h2(t.html('describeXacml.gettingIn')) +
      D.p(access.enforced
        ? t.html('describeXacml.enforced',
                 { door: v.trustAnchorDoor,
                   userGroup: access.xacmlUserGroup || nobody,
                   pepGroup: access.remotePepGroup || nobody })
        : t.html('describeXacml.notEnforced')) +
      // The embedded demonstration PEP's section went with it to the
      // remote PEP (#596); the remote section below is where a PEP is.
      D.h2(t.html('describeXacml.remote')) +
      D.p(remote.enabled
        ? t.html('describeXacml.remoteOn',
                 { registered: remote.registered,
                   syncToken: remote.syncToken })
        : t.html('describeXacml.remoteOff')) +
      D.h2(t.html('describeXacml.pip')) +
      D.p(t.html('describeXacml.pipWhy')) +
      D.p(t.html('describeXacml.pipShape',
                 { pipRequest: '<PIPRequest>', request: '<Request>',
                   designator: '<AttributeDesignator>',
                   attributes: '<Attributes>' })) +
      D.p(t.html('describeXacml.pipUnresolved',
                 { attribute: '<Attribute>', unresolved: '<Unresolved>' })) +
      D.p(t.html('describeXacml.pipPull')) +
      D.h2(t.html('describeXacml.notYet')) +
      D.textList(info.notYetHere) +
      D.p(D.link('?format=json', t.html('describeXacml.asJson')));
  }
}

export = WebXacmlDescription;
