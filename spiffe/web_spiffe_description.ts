// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_spiffe_description.ts
//
// ---------------------------------------------------------------------------
// `GET /spiffe`, DRAWN IN THE BROWSER (#584, 2026-10-12).
//
// The one page that describes all three server-side SPIFFE surfaces, from
// the view its shell carries (`spiffe_server.ts`'s `GET /spiffe`,
// `common/description_pages.ts`): the description document `?format=json`
// has always answered, the issuing authority's readiness and whether the
// main port is HTTPS — the two facts `page()` read beside the document.
// The bundle endpoints are SPIFFE's and are unchanged.
//
// WHAT IS ATTESTED HERE IS READ FROM THE VIEW, NEVER ASSERTED (the comment
// `page()` carried since 2026-09-22): the build's peer-credentials module
// and the TCP port's state decide which sentence is drawn.
//
// The words are the `describeSpiffe` catalogs', whose English is what the
// server drew until #584. Every method's `what`, the notes, the entities,
// SPIRE's per-method table, the lists of what is not checked and what is
// refused are the document's, in English.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import D = require('../common/web_description');

type Json = any;

const esc = D.esc;

/**
 * The SPIFFE description page's renderer. A static utility class.
 */
class WebSpiffeDescription {
  /**
   * The page's title, as text.
   *
   * @param view - the view
   * @param ctx - the context (`t`)
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('describeSpiffe.title');
  }

  // A listener, and WHAT A CALLER HAS TO PRESENT ON IT. The fourth column is
  // not decoration: the sockets have three different postures — plain, plain
  // and trusted as `local`, and mutual TLS — and a reader who cannot see which
  // is which meets the difference as a handshake failure (`page()` carried
  // this until #584).
  /**
   * A listener table's rows.
   *
   * @param bindings - the bindings
   * @param t - the translator
   * @returns the table
   */
  static listeners(bindings: Json, t: Json): string {
    const rows = (Array.isArray(bindings) ? bindings : [])
      .map(function (b: Json): string[] {
        return [esc(b.realm || 'default'),
                D.code(b.address) +
                (b.tls ? ' <span class="note">' +
                         t.html('describeSpiffe.mutualTls') + '</span>'
                       : ''),
                b.listening ? t.html('describeSpiffe.listening')
                            : t.html('describeSpiffe.didNotBind',
                                     { error: b.error }),
                esc(b.authentication || '')];
      });
    return D.table([t.html('describeSpiffe.realm'),
                    t.html('describeSpiffe.address'),
                    t.html('describeSpiffe.state'),
                    t.html('describeSpiffe.presents')], rows,
                   t.html('describeSpiffe.nothingBound'));
  }

  /**
   * A method table.
   *
   * @param methods - the methods
   * @param t - the translator
   * @returns the table
   */
  static methods(methods: Json, t: Json): string {
    const rows = (Array.isArray(methods) ? methods : [])
      .map(function (m: Json): string[] {
        return [D.code(m.name) +
                (m.streaming ? ' <span class="note">' +
                               t.html('describeSpiffe.stream') + '</span>'
                             : ''),
                m.implemented ? t.html('describeSpiffe.yes')
                              : t.html('describeSpiffe.no'),
                esc(m.what)];
      });
    return D.table([t.html('describeSpiffe.method'),
                    t.html('describeSpiffe.implemented'),
                    t.html('describeSpiffe.what')], rows);
  }

  /**
   * The page.
   *
   * @param view - the `spiffe` view
   * @param ctx - the context (`t`)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const doc = v.document || {};
    const authority = v.authority || {};
    const list = function (value: Json): Json[] {
      return Array.isArray(value) ? value : [];
    };
    const attestation = doc.workloadAttestation || {};
    const nativeModule = !!attestation.nativeModule;
    const tcpState = String((attestation.tcp && attestation.tcp.state) ||
                            'unknown');
    const auth = doc.authentication || {};
    const bundle = doc.bundle || {};
    const authorities = doc.authorities || {};
    const workload = doc.workloadApi || {};
    const server = doc.serverApi || {};
    const broker = doc.brokerApi || {};
    const registry = doc.registry || {};
    const links = doc.links || {};
    const x509 = list(authorities.x509).map(function (a: Json): string[] {
      return ['X.509', D.code(a.id), esc(a.keyType),
              t.html(a.active ? 'describeSpiffe.activeUntil'
                              : 'describeSpiffe.retiredUntil',
                     { until: a.notAfter })];
    });
    const jwt = list(authorities.jwt).map(function (a: Json): string[] {
      return ['JWT', D.code(a.kid), esc(a.keyType) + ' / ' + esc(a.alg),
              a.active ? t.html('describeSpiffe.active')
                       : t.html('describeSpiffe.retired')];
    });
    const chain = list(authorities.chainSubjects);
    const brokers = list(broker.brokers);
    const adminIds = list(auth.adminIds);
    return '<h1>SPIFFE</h1>' +
      D.p(t.html('describeSpiffe.lead', { trustDomain: doc.trustDomainId })) +
      (doc.enabled ? '' : D.p(t.html('describeSpiffe.off'), 'warn')) +
      (authority.ready ? ''
        : D.p(authority.error
                ? t.html('describeSpiffe.authorityFailed',
                         { error: authority.error })
                : t.html('describeSpiffe.authorityPending'), 'warn')) +
      D.p(t.html('describeSpiffe.attestedLead') + ' ' +
          (nativeModule
            ? t.html('describeSpiffe.attested')
            : t.html('describeSpiffe.notAttested',
                     { problem: String(attestation.problem || 'not built') })) +
          ' ' + t.html('describeSpiffe.tcp', { state: tcpState }),
          nativeModule ? 'note' : 'warn') +
      D.p(auth.enforced ? t.html('describeSpiffe.serverApiOn')
                        : t.html('describeSpiffe.serverApiOff'),
          auth.enforced ? 'note' : 'warn') +

      D.h2(t.html('describeSpiffe.bundle')) +
      D.p(D.link(bundle.url, D.code(bundle.url)) + ' ' +
          t.html('describeSpiffe.bundleText',
                 { sequence: bundle.sequence,
                   refreshHint: bundle.refreshHint })) +
      D.p(esc(bundle.schemeNote), v.https ? 'note' : 'warn') +

      D.h2(t.html('describeSpiffe.authorities')) +
      D.table([t.html('describeSpiffe.kind'), t.html('describeSpiffe.id'),
               t.html('describeSpiffe.key'), t.html('describeSpiffe.state')],
              x509.concat(jwt)) +
      (chain.length
        ? D.p(D.rich(t, 'describeSpiffe.chain', {},
                     { chain: D.codes(chain, ' &rarr; ') }))
        : '') +
      '<h3>' + t.html('describeSpiffe.trusts') + '</h3>' +
      D.table([t.html('describeSpiffe.anchor'),
               t.html('describeSpiffe.subject'),
               t.html('describeSpiffe.until')],
              list(authorities.trustAnchors).map(function (a: Json) {
                return [D.code(a.id), esc(a.subject), esc(a.notAfter)];
              })) +
      D.p(esc(authorities.note),
          authorities.source === 'pki' ? 'note' : 'warn') +

      D.h2(t.html('describeSpiffe.workloadApi')) +
      WebSpiffeDescription.listeners(workload.listeners, t) +
      D.p(workload.securityHeaderRequired
        ? t.html('describeSpiffe.headerEnforced',
                 { header: workload.securityHeader })
        : t.html('describeSpiffe.headerNotEnforced',
                 { header: workload.securityHeader })) +
      WebSpiffeDescription.methods(workload.methods, t) +

      D.h2(t.html('describeSpiffe.serverApi')) +
      WebSpiffeDescription.listeners(server.listeners, t) +
      list(server.services).map(function (service: Json): string {
        return '<h3>' + esc(service.name) + '</h3>' + D.p(esc(service.what)) +
          WebSpiffeDescription.methods(service.methods, t);
      }).join('') +

      D.h2(t.html('describeSpiffe.brokerApi')) +
      WebSpiffeDescription.listeners(broker.listeners, t) +
      D.p(brokers.length
        ? D.rich(t, 'describeSpiffe.brokers',
                 { header: broker.securityHeader },
                 { brokers: brokers.map(function (one: Json): string {
                     return D.code(one.id) + ' (' +
                       esc(one.problem || list(one.types).join(', ')) + ')';
                   }).join(', ') })
        : t.html('describeSpiffe.noBrokers',
                 { header: broker.securityHeader })) +

      D.h2(t.html('describeSpiffe.whoMayCall')) +
      D.p(esc(auth.what)) +
      D.p(esc(auth.bootstrapping), 'note') +
      D.p(esc(auth.identityNote), 'note') +
      D.p(esc(auth.credentialStatusNote || ''), 'note') +
      (adminIds.length
        ? D.p(D.rich(t, 'describeSpiffe.adminIds', {},
                     { ids: D.codes(adminIds) }))
        : D.p(D.linked(t, 'describeSpiffe.noAdminIds', {},
                       { entries: { href: '/admin/spiffe/entries',
                                    label: '/admin/spiffe/entries' } }))) +
      D.table([t.html('describeSpiffe.entity'),
               t.html('describeSpiffe.means')],
              list(auth.entities).map(function (e: Json) {
                return [D.code(e.id), esc(e.what)];
              })) +
      '<h3>' + t.html('describeSpiffe.perMethod') + '</h3>' +
      D.p(t.html('describeSpiffe.perMethodText')) +
      D.table([t.html('describeSpiffe.method'),
               t.html('describeSpiffe.allowedTo')],
              list(auth.policy).map(function (row: Json) {
                return [D.code(row.method), esc(list(row.allow).join(', '))];
              })) +

      D.h2(t.html('describeSpiffe.notChecked')) +
      D.textList(doc.notChecked) +
      D.h2(t.html('describeSpiffe.refused')) +
      D.p(t.html('describeSpiffe.refusedText')) +
      D.textList(doc.refused) +

      D.h2(t.html('describeSpiffe.registry')) +
      D.p(t.html('describeSpiffe.registryText',
                 { entries: registry.entries, agents: registry.agents }) +
          ' ' + esc(registry.note)) +

      D.h2(t.html('describeSpiffe.elsewhere')) +
      D.list(Object.keys(links).map(function (key: string): string {
        return D.link(links[key], esc(key)) + ' — ' + D.code(links[key]);
      })) +
      D.p(t.html('describeSpiffe.asJson'), 'note');
  }
}

export = WebSpiffeDescription;
