// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_sts_metadata.ts
//
// ---------------------------------------------------------------------------
// THE SERVICE METADATA PAGE, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws `/admin/sts-metadata` from the answer of
// `GET /admin-api/sts-metadata`: every protocol family, every endpoint the
// running router registers, every specification, and the drift between the
// router and the descriptions. The router is read on the server — that is
// the page's whole point — and the answer carries the rows it found.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was `sts_metadata.ts`'s `renderInner()` and its helpers, which that
// module still calls until the console's cutover, with its view passed
// through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

/**
 * Draws `/admin/sts-metadata` from its answer.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class StsMetadataPage {
  // WHERE THIS PAGE'S DOCUMENT COMES FROM, SINCE IT IS NO LONGER FROM HERE.
  //
  // This function builds the BODY of a console page and nothing else — no
  // doctype, no head, no <style>. `admin.respond()` wraps what comes back in
  // `admin.page()`, which is the console's two columns, its sidebar, its
  // breadcrumb, its gate banner and the ONE stylesheet it has. Two
  // consequences worth stating because both were the temptation while writing
  // this:
  //
  //   * **The classes used below live in admin.js.** `.lead`, `.m`, `.why`,
  //     `.eff`, `.bad`, `.none`, `.protos` and `a.btn` are that file's, marked
  //     there as this page's. A <style> block of this file's own would be
  //     markup inside <body>, which browsers accept and no validator does —
  //     and there would then be two stylesheets to keep in step.
  //   * **Still no script, and that is not this page's choice.** The
  //     Content-Security-Policy this service sets is `script-src 'none'`, so
  //     the download control below is an `<a download>` rather than anything
  //     that builds a blob.
  /**
   * Draws `/admin/sts-metadata` from its answer: the lead, the families,
   * the authorization servers, the drift, the endpoints by group and the
   * specifications.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of `GET /admin-api/sts-metadata`
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const t = ctx.t;
    const esc = kit.esc;
    const byId = {};
    json.specifications.forEach(function (one) {
      byId[one.id] = one;
    });
    const base = json.issuer;
    const rows = json.rows;

    // The lead is several messages (#539), one per clause the view decides
    // on, each carrying the spaces and punctuation it always had.
    let html = '<p class="lead">' + t.html('consoleStsMetadata.lead.intro',
      { issuer: base, wsTrustIssuer: json.wsTrustIssuer }) +
      // The build, in the lead paragraph rather than only in the console's
      // footer, because this is the page somebody reads to answer "what does
      // this service do" and the honest form of that answer names a release.
      // The footer says it on every page; this is the one page where it is
      // part of the subject rather than provenance in the margin.
      t.html('consoleStsMetadata.lead.version', { version: json.version }) +
      (json.build.commit ? t.html('consoleStsMetadata.lead.commit',
                                  { commit: json.build.commit }) : '') +
      (json.build.stamped ? ''
        : t.html('consoleStsMetadata.lead.unstamped')) +
      t.html('consoleStsMetadata.lead.port', { port: json.port }) +
      // The scheme, said out loud, because the issuer above and every endpoint
      // below are built from the URL this request arrived on — so they follow
      // the socket by themselves, and a reader comparing this page against a
      // configuration file needs to know which socket that was. It is also the
      // one requirement RFC 9700 mode cannot settle with a check.
      (json.https
        ? t.html('consoleStsMetadata.lead.https') +
          (json.rfc9700
            ? t.html('consoleStsMetadata.lead.rfc9700')
            : '') +
          t.html('consoleStsMetadata.lead.httpsRest')
        : t.html('consoleStsMetadata.lead.http')) + '</p>';

    // -----------------------------------------------------------------------
    // THE DOWNLOAD CONTROL, AT THE TOP BECAUSE IT IS ABOUT THE WHOLE PAGE.
    //
    // `download` on an anchor is the entire mechanism: the same URL the page
    // documents, asked for as an attachment. It is not a form and not a
    // button, for the reason in the header — nothing on this service may run
    // a script, so anything cleverer would be a control that did nothing. It
    // carries the session cookie because it is an ordinary same-origin GET,
    // which is what makes it work now that this page is behind the console's
    // gate.
    // -----------------------------------------------------------------------
    html += '<p><a class="btn" href="/admin/sts-metadata?format=json" ' +
      'download="sts-metadata.json" title="' +
      esc(t.text('consoleStsMetadata.download.title')) + '">' +
      t.html('consoleStsMetadata.download.link') + '</a> <span class="why">' +
      t.html('consoleStsMetadata.download.counts',
             { rows: rows.length, protocols: json.protocols.length,
               specs: json.specifications.length }) + '</span></p>';

    html += '<h2 id="protocols">' +
      t.html('consoleStsMetadata.protocols.heading') + '</h2>' +
      '<p class="lead">' + t.html('consoleStsMetadata.protocols.lead') +
      '</p>' +
      '<div class="protos">' +
      json.protocols.map(function (p) {
        const target = p.groups.length
          ? '#' + StsMetadataPage.groupAnchor(p.groups[0])
          : '';
        const title = target
          ? '<a href="' + esc(target) + '">' + esc(p.name) + '</a>'
          : '<span class="n">' + esc(p.name) + '</span>';
        const specs = StsMetadataPage.specLinks(p.specs, byId);
        return '<div class="proto">' + title +
          '<div class="d">' + esc(p.what) + '</div>' +
          (p.sockets ? '<div class="d"><em>' + esc(p.sockets) + '</em></div>'
                     : '') +
          '<div class="c">' +
          (p.endpoints
            ? t.html('consoleStsMetadata.protocols.endpoints',
                     { n: p.endpoints })
            : t.html('consoleStsMetadata.protocols.noEndpoint')) +
          ' &middot; ' + specs + '</div></div>';
      }).join('') + '</div>';

    html += '<p class="lead">' + t.html('consoleStsMetadata.testDouble') +
      '</p>';

    // -----------------------------------------------------------------------
    // THE NAMED AUTHORIZATION SERVERS, which this page cannot read off the
    // router.
    //
    // The same blind spot the Kerberos and LDAP listeners have, arrived at
    // from the other direction: those are sockets the walk cannot see, and
    // these are ONE route — `/:as/oauth2/…` — serving as many authorization
    // servers as have been asked for. A reader counting rows would conclude
    // there is one authorization server here, and there are as many as
    // somebody has named.
    //
    // Only the ones that have actually been ACCESSED are listed, because the
    // set is unbounded by construction: a name becomes an authorization server
    // by being asked for, so listing "all of them" would mean listing every
    // string. What is here is what this process has actually served.
    // -----------------------------------------------------------------------
    const namedServers = json.namedServers;
    if (namedServers.length) {
      html += '<h2>' + t.html('consoleStsMetadata.as.heading') + '</h2>' +
        '<p class="lead">' + t.html('consoleStsMetadata.as.lead',
          { n: namedServers.length + 1 }) +
        '</p><table><thead><tr><th class="p">' +
        t.html('consoleStsMetadata.as.thServer') + '</th><th>' +
        t.html('consoleStsMetadata.as.thMetadata') + '</th><th>' +
        t.html('consoleStsMetadata.as.thEndpoints') + '</th><th class="s">' +
        t.html('consoleStsMetadata.as.thAskedFor') +
        '</th></tr></thead><tbody><tr><td><code>' +
        esc(json.defaultServerId) + '</code><div class="why">' +
        t.html('consoleStsMetadata.as.unprefixed') + '</div></td><td><a ' +
        'href="/.well-known/oauth-authorization-server" target="_blank" ' +
        'rel="noopener noreferrer"><code>' +
        '/.well-known/oauth-authorization-server</code></a><br><a ' +
        'href="/.well-known/openid-configuration" target="_blank" ' +
        'rel="noopener noreferrer"><code>' +
        '/.well-known/openid-configuration</code></a></td><td><code>' +
        '/oauth2/authorize</code><br><code>/oauth2/token</code></td><td>' +
        t.html('consoleStsMetadata.as.always') + '</td></tr>' +
        namedServers.map(function (one) {
          return '<tr><td><code>' + esc(one.id) + '</code>' +
            (one.autoCreated
              ? '<div class="why">' +
                t.html('consoleStsMetadata.as.autoCreated') + '</div>'
              : '<div class="why">' +
                t.html('consoleStsMetadata.as.configured') + '</div>') +
            '</td>' +
            '<td><a href="' + esc(one.urls.oauth) + '" target="_blank" ' +
            'rel="noopener ' +
            'noreferrer"><code>' + esc(one.urls.oauth) + '</code></a><br>' +
            '<a href="' + esc(one.urls.oidc) + '" target="_blank" ' +
            'rel="noopener ' +
            'noreferrer"><code>' + esc(one.urls.oidc) + '</code></a></td>' +
            '<td><code>' + esc(one.urls.authorize) + '</code><br><code>' +
            esc(one.urls.token) + '</code></td>' +
            '<td>' + t.html('consoleStsMetadata.as.times',
                            { n: one.seen }) + '</td></tr>';
        }).join('') +
        '</tbody></table><p class="lead"><a ' +
        'href="/admin/authorization-servers">' +
        t.html('consoleStsMetadata.as.configure') + '</a>' +
        t.html('consoleStsMetadata.as.configureRest') + '</p>';
    }

    // Drift, if any. Shown at the top because it is the thing a reader most
    // needs to know about the rest of the page. Five kinds now rather than
    // three: the protocol list above is hand-written on a page that derives
    // everything else, so the checks that keep it honest report here beside
    // the others.
    if (json.undocumentedPaths.length || json.stalePaths.length ||
        json.unknownSpecIds.length || json.unknownProtocolGroups.length ||
        json.unknownProtocolSpecIds.length || json.unclaimedGroups.length) {
      // NOT FOLDED, AND IT IS THE ONE BLOCK ON THIS PAGE THAT IS NOT. Every
      // other paragraph here is prose a reader may skip; this one appears only
      // when the page disagrees with the router, which is the whole reason
      // this page exists (see the drift checks above). A report that has to be
      // clicked open to be read is a report somebody can close and forget. It
      // is also built across several statements rather than as one
      // expression, so it could not go through kit.warn() as it stands.
      html += '<div class="warn"><strong>This page is out of step with the ' +
              'router.</strong><ul>';
      if (json.undocumentedPaths.length) {
        html += '<li>Registered but not described here: ' +
          json.undocumentedPaths.map(function (p) {
            return '<code>' + esc(p) + '</code>';
          }).join(', ') +
          '. They are listed below under <em>Undocumented</em>.</li>';
      }
      if (json.stalePaths.length) {
        html += '<li>Described here but NOT registered: ' +
          json.stalePaths.map(function (p) {
            return '<code>' + esc(p) + '</code>';
          }).join(', ') +
          '. Either the route was renamed or the description is stale.</li>';
      }
      if (json.unknownSpecIds.length) {
        html += '<li>Endpoints reference specification ids that do not ' +
          'exist: ' +
          json.unknownSpecIds.map(function (i) {
            return '<code>' + esc(i) + '</code>';
          }).join(', ') +
          '.</li>';
      }
      if (json.unknownProtocolGroups.length) {
        html += '<li>The protocol list names endpoint groups that have no ' +
          'rows: ' +
          json.unknownProtocolGroups.map(function (i) {
            return '<code>' + esc(i) + '</code>';
          }).join(', ') + '. Either the group was renamed or the family is ' +
          'gone.</li>';
      }
      if (json.unknownProtocolSpecIds.length) {
        html += '<li>The protocol list references specification ids that do ' +
          'not exist: ' +
          json.unknownProtocolSpecIds.map(function (i) {
            return '<code>' + esc(i) + '</code>';
          }).join(', ') + '.</li>';
      }
      if (json.unclaimedGroups.length) {
        html += '<li>These endpoint groups are on the page and no protocol ' +
          'above claims them: ' +
          json.unclaimedGroups.map(function (i) {
            return '<code>' + esc(i) + '</code>';
          }).join(', ') + '. A family was added to this service and not to ' +
          'the list at the top of this page.</li>';
      }
      html += '</ul></div>';
    } else {
      html += '<div class="ok">' + t.html('consoleStsMetadata.inStep',
        { rows: rows.length, protocols: json.protocols.length }) + '</div>';
    }

    StsMetadataPage.groupsOf(rows, json.groupOrder).forEach(function (group) {
      html += '<h2 id="' + esc(StsMetadataPage.groupAnchor(group)) + '">' +
        esc(group) +
        '</h2><table><thead><tr><th class="p">' +
        t.html('consoleStsMetadata.th.path') + '</th><th>' +
        t.html('consoleStsMetadata.th.methods') + '</th><th ' +
        'class="n">' + t.html('consoleStsMetadata.th.name') + '</th><th>' +
        t.html('consoleStsMetadata.th.what') + '</th><th ' +
        'class="s">' + t.html('consoleStsMetadata.th.specs') +
        '</th></tr></thead><tbody>';
      rows.filter(function (r) {
        return r.group === group;
      })
        .sort(function (a, b) {
          return a.path < b.path ? -1 : (a.path > b.path ? 1 : 0);
        })
        .forEach(function (r) {
          html += '<tr><td class="p">' + StsMetadataPage.pathCell(r, t) +
            '</td>' +
            '<td class="m">' + esc(r.methods.join(', ')) + '</td>' +
            '<td class="n">' +
            (r.documented === false
              ? '<span class="bad">' + esc(r.name) + '</span>'
              : esc(r.name)) + '</td>' +
            // WHAT AN ENDPOINT IS, FOLDED. This table is every route the
            // router has — around 250 of them — and this column is a
            // paragraph on most rows, which made the one page in this console
            // that lists everything the one page nobody could skim.
            // kit.note() leaves a short description alone and folds a long
            // one behind its first sentence; see the block above it in
            // ../admin-ui/admin.ts.
            '<td>' + kit.note(esc(r.what)) + '</td>' +
            '<td class="s">' +
            StsMetadataPage.specLinks(r.specs, byId) +
            '</td></tr>';
        });
      html += '</tbody></table>';
    });

    html += '<h2 id="specifications">' +
      t.html('consoleStsMetadata.specs.heading') + '</h2>' +
      '<table><thead><tr><th class="n">' +
      t.html('consoleStsMetadata.specs.thSpec') + '</th>' +
      '<th>' + t.html('consoleStsMetadata.specs.thWhere') + '</th><th>' +
      t.html('consoleStsMetadata.specs.thCoverage') + '</th></tr></thead>' +
      '<tbody>';
    json.specifications.forEach(function (s) {
      html += '<tr id="spec-' + esc(s.id) + '"><td class="n"><a href="' +
        esc(s.url) +
        '" target="_blank" rel="noopener noreferrer">' + esc(s.name) +
        '</a></td><td>' + esc(s.where) + '</td><td>' +
        kit.note(esc(s.coverage)) +
        '</td></tr>';
    });
    html += '</tbody></table>';

    html += kit.note(t.html('consoleStsMetadata.machineReadable',
                            { base: base }));
    return html;
  }

  // Called once per page, but named beside `groupAnchor()` as one of the
  // helpers with no entering/leaving pair — the exception stated there.
  static groupsOf(rows, order) {
    const seen = [];
    order.forEach(function (g) {
      if (rows.some(function (r) {
        return r.group === g;
      })) {
        seen.push(g);
      }
    });
    rows.forEach(function (r) {
      if (seen.indexOf(r.group) === -1) {
        seen.push(r.group);
      }
    });
    return seen;
  }

  // A stable html id for a group heading, so the protocol list above can link
  // into the table below it. Derived from the group name rather than typed
  // beside it: a hand-kept id is one more thing to get out of step with the
  // heading it names.
  //
  // No entering/leaving pair, like `esc()`, `groupsOf()` and `specLinks()`
  // beside it: it is called once per group heading and once per protocol card
  // while a page is being built, and a trace of the page is what the callers
  // already log.
  static groupAnchor(group) {
    return 'group-' + String(group).toLowerCase().replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  // -------------------------------------------------------------------------
  // Whether a path can be turned into a link a reader can actually follow.
  //
  // The temptation is to link all of them, and it produces a page with 22 dead
  // links out of 41. A path is followable from a browser only if it answers a
  // GET and is a concrete URL:
  //
  //   * no GET — a link on POST /oauth2/token issues a GET, and the router has
  //     no GET for it, so the reader lands on Express's "Cannot GET
  //     /oauth2/token". That reads as a broken service rather than as a wrong
  //     link.
  //   * a parameter — "/oauth2/register/:client_id" is a route pattern. The
  //     literal string with the colon in it is not an address of anything.
  //   * a wildcard — same, and the concrete form of each of these is already
  //     listed as its own row (the well-known documents), so nothing is lost.
  //
  // So the ones that work become links and the rest say why not. The reason
  // is worth showing rather than hiding: "POST only" is the single most useful
  // thing to know about an endpoint you were about to click.
  //
  // `t` is the page's translator (#539); a reason is plain text, escaped
  // where it is drawn.
  static linkabilityOf(row, t) {
    const methods = row.methods || [];
    if (methods.indexOf('GET') === -1) {
      return { linkable: false,
               reason: methods.length === 1
                 ? t.text('consoleStsMetadata.reason.only',
                          { method: methods[0] })
                 : t.text('consoleStsMetadata.reason.noGet',
                          { methods: methods.join(', ') }) };
    }
    if (row.path.indexOf(':') !== -1) {
      const name = (/:([A-Za-z0-9_]+)/.exec(row.path) || [])[0] ||
        t.text('consoleStsMetadata.reason.aParameter');
      return { linkable: false,
               reason: t.text('consoleStsMetadata.reason.takes',
                              { name: name }) };
    }
    if (row.path.indexOf('*') !== -1) {
      return { linkable: false,
               reason: t.text('consoleStsMetadata.reason.wildcard') };
    }
    return { linkable: true, reason: '' };
  }

  // The path column: a link where that is honest, the bare path where it is
  // not.
  //
  // Links are root-relative, so they follow the host this page was reached at
  // — localhost:8081, sts:8081 on the compose network, or a published port —
  // without this document having to know which. They open in a new tab so the
  // index survives the click, which matters because most of these return a
  // document to read and compare against the row it came from.
  static pathCell(row, t) {
    const link = StsMetadataPage.linkabilityOf(row, t);
    if (!link.linkable) {
      return '<code>' + kit.esc(row.path) + '</code> <span class="why" ' +
             'title="' +
             kit.esc(t.text('consoleStsMetadata.path.unfollowable')) + '">' +
             kit.esc(link.reason) + '</span>';
    }
    const title = t.text('consoleStsMetadata.path.newTab',
                         { path: row.path }) +
                  (row.effect ? ' — ' + row.effect : '');
    return '<a href="' + kit.esc(row.path) + '" target="_blank" ' +
           'rel="noopener noreferrer" title="' +
           kit.esc(title) + '"><code>' + kit.esc(row.path) + '</code></a>' +
           (row.effect
             ? ' <span class="eff" title="' + kit.esc(row.effect) +
               '">&#8599;</span>'
             : '');
  }

  // Called once per table row and per protocol card, so no entering/leaving
  // pair — the exception `groupAnchor()` states.
  // The drift flag for an unknown id stays English (#539: a problem report),
  // so this draws no words of its own and takes no translator.
  static specLinks(ids, byId) {
    if (!ids || !ids.length) {
      return '<span class="none">&mdash;</span>';
    }
    return ids.map(function (id) {
      const spec = byId[id];
      if (!spec) {
        return '<span class="bad">unknown spec id "' + kit.esc(id) +
               '"</span>';
      }
      return '<a href="#spec-' + kit.esc(id) + '">' +
             kit.esc(spec.name.split(' — ')[0].split(' (')[0]) + '</a>';
    }).join(', ');
  }
}

export = StsMetadataPage;
