// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_ssf_description.ts
//
// ---------------------------------------------------------------------------
// `GET /ssf`, DRAWN IN THE BROWSER (#584, 2026-10-12).
//
// The Shared Signals transmitter's description page, from the view its
// shell carries (`ssf.ts`'s `GET /ssf`, `common/description_pages.ts`): the
// description document `?format=json` has always answered, and the name of
// each stream's delivery method. It is not an SSF endpoint — SSF defines
// `/.well-known/ssf-configuration` and the stream endpoints, which are
// unchanged — and says so on the page.
//
// The words are the `describeSsf` catalogs', whose English is what the
// server drew until #584. Every row's `what`, the authentication note, the
// "does not do" lines and the negatives are the document's, in English.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import D = require('../common/web_description');

type Json = any;

const esc = D.esc;

/**
 * The Shared Signals description page's renderer. A static utility class.
 */
class WebSsfDescription {
  /**
   * The page's title, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('describeSsf.title');
  }

  /**
   * The page: what SSF is here, discovery, the endpoints, the event
   * types, the subject formats, authentication, the streams, and what it
   * does not do and how it fails.
   *
   * @param view - the `ssf` view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const info = v.document || {};
    const names = v.deliveryNames || {};
    const list = function (value: Json): Json[] {
      return Array.isArray(value) ? value : [];
    };
    const endpoints = list(info.endpoints).map(function (row: Json) {
      return [D.code(row.method), D.code(row.path), esc(row.what)];
    });
    const events = list(info.eventTypes).map(function (row: Json) {
      return [esc(row.name), D.code(row.uri),
              row.offered ? t.html('describeSsf.offered')
                          : t.html('describeSsf.notOffered'),
              esc(row.what)];
    });
    const formats = list(info.subjectFormats).map(function (row: Json) {
      return [D.code(row.format), D.code(list(row.members).join(', ')),
              esc(row.what)];
    });
    const streams = list(info.streams).map(function (row: Json) {
      const counters = row.counters || {};
      return [D.code(row.stream_id), esc(row.status),
              esc(names[row.delivery] || row.delivery), esc(row.subjects),
              esc(row.queued),
              t.html('describeSsf.counters',
                     { delivered: counters.delivered,
                       failed: counters.failed })];
    });
    const negatives = list(info.reachableNegatives).map(function (row: Json) {
      return [esc(row.what), esc(row.answer)];
    });
    const authentication = info.authentication || {};
    const schemes = list(authentication.schemes).map(function (row: Json) {
      return [esc(row.name), D.code(row.spec_urn), esc(row.what)];
    });
    const complex = list(info.complexSubjectMembers).map(function (row: Json) {
      return row && row.name;
    });
    const critical = list(info.criticalSubjectMembers).join(', ');
    return '<h1>' + t.html('describeSsf.heading') + '</h1>' +
      D.p(t.html('describeSsf.sub', { issuer: info.issuer }) +
          (info.enabled ? '' : ' ' + t.html('describeSsf.off')) + ' ' +
          t.html('describeSsf.notAnEndpoint'), 'sub') +
      '<div class="warn">' +
      D.linked(t, 'describeSsf.pipe', {},
               { console: { href: '/admin/ssf',
                            label: t.html('describeSsf.consolePage') } }) +
      '</div>' +
      D.h2(t.html('describeSsf.discovery')) +
      D.p(t.html('describeSsf.discoveryText',
                 { metadataUrl: info.metadataUrl })) +
      D.h2(t.html('describeSsf.endpoints')) +
      D.table([t.html('describeSsf.method'), t.html('describeSsf.path'),
               t.html('describeSsf.what')], endpoints) +
      D.h2(t.html('describeSsf.eventTypes')) +
      D.table([t.html('describeSsf.name'), t.html('describeSsf.uri'),
               t.html('describeSsf.state'), t.html('describeSsf.what')],
              events) +
      D.p(t.html('describeSsf.signing', { alg: info.signingAlgorithm })) +
      D.h2(t.html('describeSsf.formats')) +
      D.table([t.html('describeSsf.format'), t.html('describeSsf.members'),
               t.html('describeSsf.what')], formats) +
      D.p(D.rich(t, 'describeSsf.complex',
                 { critical: critical || t.text('describeSsf.none') },
                 { members: D.codes(complex) })) +
      D.h2(t.html('describeSsf.authentication')) +
      D.p((authentication.required ? t.html('describeSsf.authOn')
                                   : t.html('describeSsf.authOff')) + ' ' +
          esc(authentication.note)) +
      D.table([t.html('describeSsf.scheme'), t.html('describeSsf.specUrn'),
               t.html('describeSsf.what')], schemes) +
      D.h2(t.html('describeSsf.streams')) +
      D.table([t.html('describeSsf.streamId'), t.html('describeSsf.status'),
               t.html('describeSsf.delivery'), t.html('describeSsf.subjects'),
               t.html('describeSsf.queued'), t.html('describeSsf.events')],
              streams, t.html('describeSsf.noStreams')) +
      D.h2(t.html('describeSsf.doesNotDo')) +
      D.textList(info.doesNotDo) +
      D.h2(t.html('describeSsf.fail')) +
      D.table([t.html('describeSsf.doThis'), t.html('describeSsf.getThis')],
              negatives) +
      D.foot([{ href: '/ssf?format=json', label: t.html('describeSsf.asJson') },
              { href: String(info.metadataUrl || ''),
                label: t.html('describeSsf.metadata') },
              { href: '/admin/ssf', label: t.html('describeSsf.consolePage') },
              { href: '/oauth2/jwks', label: t.html('describeSsf.jwks') }]);
  }
}

export = WebSsfDescription;
