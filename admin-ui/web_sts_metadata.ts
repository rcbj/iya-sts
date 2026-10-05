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
    const esc = kit.esc;
    const byId = {};
    json.specifications.forEach(function (one) {
      byId[one.id] = one;
    });
    const base = json.issuer;
    const rows = json.rows;

    let html = '<p class="lead">Every protocol this service speaks, every ' +
      'endpoint it registers and every specification it implements. The ' +
      'endpoint list is read from the running Express router on each ' +
      'request, not from a list kept by hand, so it cannot claim an endpoint ' +
      'that is not there or miss one that is. Issuer identifier <code>' +
      esc(base) + '</code>; WS-Trust issuer <code>' +
      esc(json.wsTrustIssuer) + '</code>.' +
      // The build, in the lead paragraph rather than only in the console's
      // footer, because this is the page somebody reads to answer "what does
      // this service do" and the honest form of that answer names a release.
      // The footer says it on every page; this is the one page where it is
      // part of the subject rather than provenance in the margin.
      ' This is <strong>iya-sts ' + esc(json.version) + '</strong>' +
      (json.build.commit ? ', built from commit <code>' +
       esc(json.build.commit) + '</code>' : '') +
      (json.build.stamped ? '' : ' — computed at startup rather than ' +
       'stamped into a build, so this process is a checkout rather than an ' +
       'artifact') +
      '. It is listening on port ' + esc(json.port) +
      // The scheme, said out loud, because the issuer above and every endpoint
      // below are built from the URL this request arrived on — so they follow
      // the socket by themselves, and a reader comparing this page against a
      // configuration file needs to know which socket that was. It is also the
      // one requirement RFC 9700 mode cannot settle with a check.
      (json.https
        ? ' over <strong>HTTPS</strong> (global.https' +
          (json.rfc9700
            ? ', which RFC 9700 mode turns on — section 2.1 says an ' +
              'authorization response must not be sent over an unencrypted ' +
              'connection'
            : '') +
          '), with the same certificate LDAPS 636 serves, issued under this ' +
          'service\'s own Root. It is regenerated on every start unless ' +
          'tls.certificateFile supplies one, so fetch it from ' +
          '<code>/tls/server-certificate</code> and trust it — without ' +
          'verification the first time, since there is no plain port left ' +
          'to fetch it from.'
        : ' over plain HTTP.') + '</p>';

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
      'download="sts-metadata.json" title="The whole of this page as JSON: ' +
      'every protocol, every endpoint, every specification, and the drift ' +
      'report">Download all of this as JSON</a> <span class="why">' +
      esc(rows.length) + ' endpoints, ' + esc(json.protocols.length) +
      ' protocol families, ' + esc(json.specifications.length) +
      ' specifications</span></p>';

    html += '<h2 id="protocols">Protocols this service speaks</h2>' +
      '<p class="lead">Thirteen families. The count on each card is how many ' +
      'rows that family has in the tables below, and it is not a measure of ' +
      'how much of the protocol is here: <strong>four of these live mostly ' +
      'on a raw socket and two register no route at all</strong>, and this ' +
      'page is built by walking the Express router. Where that is the case ' +
      'the card says where the protocol really is.</p>' +
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
            ? esc(p.endpoints) + ' endpoint(s) below'
            : 'no endpoint of its own') +
          ' &middot; ' + specs + '</div></div>';
      }).join('') + '</div>';

    html += '<p class="lead"><strong>This is a test double.</strong> It ' +
      'signs everything with a key generated fresh at each start, it never ' +
      'checks ' +
      'a password, and it does not validate access tokens issued by a ' +
      'separate authorization server. The <em>coverage</em> column below ' +
      'says where each specification is implemented in full and where the ' +
      'shape is right but the enforcement is deliberately absent.</p>';

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
      html += '<h2>Authorization servers</h2>' +
        '<p class="lead">This process publishes <strong>' +
        (namedServers.length + 1) +
        '</strong> authorization servers, and only the endpoint PATTERN is ' +
        'on the list below — the walk that builds this page sees ' +
        '<code>/:as/oauth2/…</code> as one route however many names have ' +
        'been served through it. Each has its own metadata, its own ' +
        'capabilities and its own issuer, and <strong>what its document ' +
        'advertises is what its endpoints do</strong>. A name that has never ' +
        'been asked for is not here: a name becomes an authorization server ' +
        'BY being asked for, with the same capabilities the default one has, ' +
        'so the set of possible ones is every string and the set of real ' +
        'ones is this.</p><table><thead><tr><th class="p">Authorization ' +
        'server</th><th>Metadata</th><th>Endpoints</th><th class="s">Asked ' +
        'for</th></tr></thead><tbody><tr><td><code>' +
        esc(json.defaultServerId) + '</code><div class="why">the ' +
        'unprefixed endpoints</div></td><td><a ' +
        'href="/.well-known/oauth-authorization-server" target="_blank" ' +
        'rel="noopener noreferrer"><code>' +
        '/.well-known/oauth-authorization-server</code></a><br><a ' +
        'href="/.well-known/openid-configuration" target="_blank" ' +
        'rel="noopener noreferrer"><code>' +
        '/.well-known/openid-configuration</code></a></td><td><code>' +
        '/oauth2/authorize</code><br><code>/oauth2/token</code></td><td>' +
        'always</td></tr>' +
        namedServers.map(function (one) {
          return '<tr><td><code>' + esc(one.id) + '</code>' +
            (one.autoCreated
              ? '<div class="why">created by being asked for</div>'
              : '<div class="why">configured here</div>') + '</td>' +
            '<td><a href="' + esc(one.urls.oauth) + '" target="_blank" ' +
            'rel="noopener ' +
            'noreferrer"><code>' + esc(one.urls.oauth) + '</code></a><br>' +
            '<a href="' + esc(one.urls.oidc) + '" target="_blank" ' +
            'rel="noopener ' +
            'noreferrer"><code>' + esc(one.urls.oidc) + '</code></a></td>' +
            '<td><code>' + esc(one.urls.authorize) + '</code><br><code>' +
            esc(one.urls.token) + '</code></td>' +
            '<td>' + esc(one.seen) + ' time(s)</td></tr>';
        }).join('') +
        '</tbody></table><p class="lead"><a ' +
        'href="/admin/authorization-servers">Configure them</a> — what a ' +
        'profile publishes is what that authorization server enforces, so ' +
        'narrowing <code>code_challenge_methods_supported</code> there ' +
        'refuses the other method at that server\'s own authorization ' +
        'endpoint and nowhere else.</p>';
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
      html += '<div class="ok">Every registered route is described, every ' +
        'description matches a registered route (' + rows.length +
        ' endpoints), and every one of the ' + json.protocols.length +
        ' protocol families above names a group that is here and a ' +
        'specification that exists.</div>';
    }

    StsMetadataPage.groupsOf(rows, json.groupOrder).forEach(function (group) {
      html += '<h2 id="' + esc(StsMetadataPage.groupAnchor(group)) + '">' +
        esc(group) +
        '</h2><table><thead><tr><th class="p">Path</th><th>Methods</th><th ' +
        'class="n">Name</th><th>What it is</th><th ' +
        'class="s">Specifications</th></tr></thead><tbody>';
      rows.filter(function (r) {
        return r.group === group;
      })
        .sort(function (a, b) {
          return a.path < b.path ? -1 : (a.path > b.path ? 1 : 0);
        })
        .forEach(function (r) {
          html += '<tr><td class="p">' + StsMetadataPage.pathCell(r) + '</td>' +
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
            '<td class="s">' + StsMetadataPage.specLinks(r.specs, byId) +
            '</td></tr>';
        });
      html += '</tbody></table>';
    });

    html += '<h2 id="specifications">Specifications implemented</h2>' +
      '<table><thead><tr><th class="n">Specification</th>' +
      '<th>Published by</th><th>Coverage in this mock</th></tr></thead>' +
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

    html += kit.note('Machine-readable: <code>' + esc(base) +
      '/admin/sts-metadata?format=json</code>, which is what the button at ' +
      'the top hands you as a file. It is behind the console gate like the ' +
      'page, so a program fetching it signs in at <code>/authn/login</code> ' +
      'first, or reads the same service through <code>/admin-api</code>, ' +
      'which is not gated. This document is not a specification-defined ' +
      'discovery document &mdash; for those, see ' +
      '<code>/.well-known/openid-configuration</code>, ' +
      '<code>/.well-known/oauth-authorization-server</code>, ' +
      '<code>/.well-known/openid-credential-issuer</code>, ' +
      '<code>/.well-known/jwt-vc-issuer</code>, ' +
      '<code>/.well-known/did.json</code> and ' +
      '<code>/.well-known/did-configuration.json</code>.');
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
  static linkabilityOf(row) {
    const methods = row.methods || [];
    if (methods.indexOf('GET') === -1) {
      return { linkable: false,
               reason: methods.length === 1
                 ? methods[0] + ' only'
                 : 'no GET (' + methods.join(', ') + ')' };
    }
    if (row.path.indexOf(':') !== -1) {
      const name = (/:([A-Za-z0-9_]+)/.exec(row.path) || [])[0] ||
        'a parameter';
      return { linkable: false, reason: 'takes ' + name };
    }
    if (row.path.indexOf('*') !== -1) {
      return { linkable: false, reason: 'wildcard' };
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
  static pathCell(row) {
    const link = StsMetadataPage.linkabilityOf(row);
    if (!link.linkable) {
      return '<code>' + kit.esc(row.path) + '</code> <span class="why" ' +
             'title="This path is listed because it is registered, but it ' +
             'cannot be followed from a browser.">' +
             kit.esc(link.reason) + '</span>';
    }
    const title = 'GET ' + row.path + ' in a new tab' +
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
