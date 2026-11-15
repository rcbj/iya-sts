// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_picture.js
//
// ===========================================================================
// THE REVERSE PROXY TAB'S VISUAL SUB-TAB (rcbj, 2026-11-15), held in node
// against `xacml/web_pep_picture.ts`, the drawing the console bundles, from
// a fixture PEP answer with nested paths, every authorization kind, and
// enabled, disabled and unreported listeners of both sources:
//
//   P. THE TREE: `/pep-app`, `/pep-app/api` and `/pep-app/api/admin` nest;
//      a run of segments no route stops at is one chip; the routes on `/`
//      hang off the proxy; a line comes from a node's last row.
//   L. THE LABELS: each route's id, path, methods or "deny all", its
//      application, and who may reach it — a simple route's roles per
//      action (an action with none "nobody"), "Public", an existing
//      policy's name, "nobody" for no methods; why the PEP refuses one.
//   K. THE LINKS: a route's box to its page, a listener's to its page, the
//      application, each role and the policy.
//   N. THE LISTENERS: id, protocol, address:port, purpose, source; off and
//      not reported dashed; environment and defined told apart; a line from
//      each reverse-proxy listener to the proxy.
//   A. THE TEXT ALTERNATIVE and the SVG's title and desc; the key.
//   E. ESCAPING: hostile names in every place a name is drawn; the SVG is
//      well-formed XML.
//   T. THE TAB: Visual last among the Reverse proxy sub-tabs, its trail
//      (… › Reverse proxy › Visual) and its highlight at every level.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'xacml_pep_picture',
  level: process.env.LOG_LEVEL || 'info' });

// The fixture: a PEP's row as `GET /admin-api/xacml/peps?pep=` answers it.
function fixture() {
  log.debug("Entering fixture().");
  const env = function (id, protocol, purpose, enable, reported, port) {
    return { id: id, source: 'environment', protocol: protocol,
             purpose: purpose, env: 'PEP_PORT', enable: enable,
             defaultPort: port, definition: null, reported: reported };
  };
  const simple = function (id, path, methods, app, roles, model) {
    return { id: id, path: path, match: 'prefix', methods: methods,
             mechanisms: ['oauth2'], application: app,
             authorization: { kind: 'simple', policy: 'pep-p-' + id,
                              actionModel: model || 'read-write',
                              roles: roles } };
  };
  const routes = [
    simple('pep-app', '/pep-app', ['GET'], 'pep-app',
           { read: ['pep-app-users'] }),
    simple('pep-app-api', '/pep-app/api', ['GET', 'POST'], 'pep-app-api',
           { read: ['pep-app-users', 'auditors'],
             write: ['pep-app-admins'] }),
    simple('pep-app-admin', '/pep-app/api/admin', ['GET', 'DELETE'],
           'pep-app-api', { read: ['auditors'],
                            delete: ['security-officers'] }, 'crud'),
    { id: 'health', path: '/pep-app/health', match: 'exact',
      methods: ['GET'], mechanisms: [],
      authorization: { kind: 'public', policy: 'pep-p-health',
                       actionModel: 'method', roles: {} } },
    simple('legacy', '/pep-app/legacy', [], 'pep-app',
           { read: ['pep-app-users'] }),
    { id: 'orders', path: '/shop/v2/orders', match: 'prefix',
      methods: ['GET'], mechanisms: ['oauth2'], application: 'orders-api',
      authorization: { kind: 'policy', policy: 'orders-by-region',
                       actionModel: 'method', roles: {} } },
    { id: 'catalog', path: '/shop/v2/catalog', match: 'prefix',
      methods: ['GET'], mechanisms: [],
      authorization: { kind: 'public', policy: 'pep-p-catalog',
                       actionModel: 'method', roles: {} } },
    { id: 'deep', path: '/a/b/c/deep', match: 'prefix', methods: ['GET'],
      mechanisms: [], authorization: { kind: 'public', policy: 'pep-p-deep',
                                       actionModel: 'method', roles: {} } },
    { id: 'home', path: '/', match: 'exact', methods: ['GET'],
      mechanisms: [], authorization: { kind: 'public', policy: 'pep-p-home',
                                       actionModel: 'method', roles: {} } },
    simple('<script>alert(1)</script>', '/x"><img src=x onerror=alert(1)>',
           ['GET'], 'evil&app', { read: ['"><svg onload=alert(2)>'] })
  ];
  log.debug("Leaving fixture().");
  return {
    name: 'pep-<b>1</b>', hostname: 'pep1.example.test',
    listenerRows: [
      env('api-http', 'http', 'api', 'PEP_HTTP',
          { state: 'off', reason: 'http-off', port: 9090 }, 9090),
      env('api-https', 'https', 'api', '',
          { state: 'listening', reason: 'none', address: '0.0.0.0',
            port: 9443 }, 9443),
      env('proxy-http', 'http', 'proxy', 'PEP_PROXY_HTTP', null, 9580),
      env('proxy-https', 'https', 'proxy', '',
          { state: 'listening', reason: 'none', address: '0.0.0.0',
            port: 9543 }, 9543),
      { id: 'pub<i>', source: 'service', protocol: 'https',
        purpose: 'proxy', definition: { address: '0.0.0.0', port: 8443 },
        reported: { state: 'failed', reason: 'address-in-use',
                    address: '0.0.0.0', port: 8443 } },
      { id: 'quiet-api', source: 'service', protocol: 'https',
        purpose: 'api', definition: { address: '127.0.0.1', port: 9444 },
        reported: null }
    ],
    proxy: { enabled: true, upstream: 'http://app:8080', routes: routes },
    proxyRoutes: [{ route: 'orders', usable: true, why: null,
                    policyProblem: 'missing' }]
  };
}

async function run(t) {
  log.debug("Entering run().");
  const PepPicture = require('../xacml/web_pep_picture');
  const XacmlPage = require('../xacml/web_xacml');
  const kit = require('../admin-ui/web_kit');
  require('../common/i18n');
  const tr = kit.context({}, true).t;
  const row = fixture();
  const links = {
    pep: '/admin/xacml/pep?pep=p#xacml-pep-tab-overview',
    proxy: '/admin/xacml/pep?pep=p#xacml-pep-proxy-routes',
    route: function (id) {
      return XacmlPage.routeHref('p', id);
    },
    listener: function (id) {
      return XacmlPage.listenerHref('p', id);
    }
  };
  const drawn = PepPicture.draw(tr, row, links);
  const svg = drawn.svg;
  // A route's own group: the `<a class="pp-route" data-route=...>`.
  const boxOf = function (id) {
    log.debug("Entering boxOf(). " + id);
    const at = svg.indexOf('data-route="' + kit.esc(id) + '"');
    const end = svg.indexOf('class="pp-', at + 10);
    log.debug("Leaving boxOf().");
    return at < 0 ? '' : svg.slice(at, end < 0 ? svg.length : end);
  };

  // -------------------------------------------------------------------------
  t.log.info('=== P. the tree ===');
  // -------------------------------------------------------------------------
  const tree = PepPicture.tree(row.proxy.routes);
  const shape = function (node) {
    return node.label + (node.routes.length
      ? '[' + node.routes.map(function (one) {
          return one.route.id;
        }).join(',') + ']' : '') +
      (node.children.length
        ? '(' + node.children.map(shape).join(' ') + ')' : '');
  };
  t.equal(shape(tree),
          '/[home](/pep-app[pep-app](/api[pep-app-api]' +
          '(/admin[pep-app-admin]) ' +
          '/health[health] /legacy[legacy]) ' +
          '/shop/v2(/orders[orders] /catalog[catalog]) ' +
          '/a/b/c/deep[deep] ' +
          '/x"><img src=x onerror=alert(1)>[<script>alert(1)</script>])',
          'P1. /pep-app, /pep-app/api and /pep-app/api/admin nest; /shop/v2 ' +
          'is one chip; a run with one route under it is that route\'s; ' +
          'the route on / is the root\'s');
  const rows = drawn.rows;
  const depthOf = function (id) {
    return rows.filter(function (one) {
      return one.route && one.route.id === id;
    }).map(function (one) {
      return one.depth + '<' + (rows[one.parent].route
        ? rows[one.parent].route.id : rows[one.parent].kind + ':' +
          rows[one.parent].label);
    })[0];
  };
  t.equal(['pep-app', 'pep-app-api', 'pep-app-admin', 'health', 'orders',
           'home'].map(depthOf).join(' | '),
          '1<root:/ | 2<pep-app | 3<pep-app-api | 2<pep-app | ' +
          '2<chip:/shop/v2 | 1<root:/',
          'P2. each row\'s depth and the row its line comes from');
  t.check(rows[0].kind === 'root' && rows.every(function (one, i) {
    return i === 0 || (one.parent < i &&
                       one.x > rows[one.parent].x &&
                       one.y > rows[one.parent].y);
  }), 'P3. a child is drawn below and to the right of its parent');
  const dup = PepPicture.rows(PepPicture.tree([
    { id: 'a', path: '/a', match: 'prefix' },
    { id: 'a2', path: '/a', match: 'exact' },
    { id: 'b', path: '/a/b', match: 'prefix' }]));
  t.check(dup[3].route.id === 'b' && dup[3].parent === 2 &&
          dup[2].parent === 0 && dup[1].parent === 0,
          'P4. two routes on one path are siblings, and a child\'s line ' +
          'comes from the last of them');

  // -------------------------------------------------------------------------
  t.log.info('=== L. the labels ===');
  // -------------------------------------------------------------------------
  t.check(boxOf('pep-app-api').indexOf('#2  pep-app-api') >= 0 &&
          boxOf('pep-app-api').indexOf('/pep-app/api · prefix') >= 0 &&
          boxOf('pep-app-api').indexOf('methods: GET, POST') >= 0,
          'L1. a route\'s position, id, path and match, and methods',
          boxOf('pep-app-api'));
  const after = function (id) {
    const at = svg.indexOf('data-route="' + kit.esc(id) + '"');
    const next = svg.indexOf('data-route="', at + 10);
    return svg.slice(at, next < 0 ? svg.length : next);
  };
  t.check(/>read:<\/text>[\s\S]*>pep-app-users,<\/text>[\s\S]*>auditors<\/text>[\s\S]*>write:<\/text>[\s\S]*>pep-app-admins<\/text>/
            .test(after('pep-app-api')) &&
          />write:<\/text><text[^>]*>nobody<\/text>/.test(after('pep-app')),
          'L2. a simple route: the roles per action; an action with none ' +
          'reads nobody', after('pep-app'));
  t.check(/>create:<\/text><text[^>]*>nobody<\/text>[\s\S]*>read:<\/text>[\s\S]*>auditors<\/text>[\s\S]*>update:<\/text><text[^>]*>nobody<\/text>[\s\S]*>delete:<\/text>[\s\S]*>security-officers<\/text>/
            .test(after('pep-app-admin')),
          'L3. a crud route: every action of the model, in order',
          after('pep-app-admin'));
  t.check(/>access:<\/text><text[^>]*>Public<\/text>/
            .test(after('health')) &&
          after('health').indexOf('none (public)') >= 0,
          'L4. a public route: Public, and no application',
          after('health'));
  t.check(/>policy:<\/text>[\s\S]*>orders-by-region<\/text>/
            .test(after('orders')) &&
          after('orders').indexOf('auditors') < 0 &&
          after('orders').indexOf('the PEP refuses this route now') >= 0,
          'L5. an existing policy: its name, no roles invented, and the ' +
          'refusal its missing policy means', after('orders'));
  t.check(after('legacy').indexOf('deny all (no methods)') >= 0 &&
          />access:<\/text><text[^>]*>nobody<\/text>/
            .test(after('legacy')) &&
          after('legacy').indexOf('pep-app-users') < 0,
          'L6. no methods: deny all, and nobody, whatever the kind',
          after('legacy'));
  t.check(svg.indexOf('→ http://app:8080') >= 0 &&
          svg.indexOf('enabled · 10 route(s)') >= 0 &&
          svg.indexOf('pep1.example.test') >= 0,
          'L7. the proxy\'s upstream and count, the PEP\'s hostname');

  // -------------------------------------------------------------------------
  t.log.info('=== K. the links ===');
  // -------------------------------------------------------------------------
  const hrefs = svg.match(/href="[^"]*"/g) || [];
  const has = function (href) {
    return hrefs.indexOf('href="' + kit.esc(href) + '"') >= 0;
  };
  const missing = [
    '/admin/xacml/pep/route?pep=p&route=pep-app-api',
    '/admin/xacml/pep/route?pep=p&route=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
    '/admin/xacml/pep/listener?pep=p&listener=proxy-https',
    '/admin/xacml/pep/listener?pep=p&listener=pub%3Ci%3E',
    '/admin/applications?application=pep-app-api',
    '/admin/applications?application=evil%26app',
    '/admin/roles?q=pep-app-admins#roles',
    '/admin/roles?q=security-officers#roles',
    '/admin/roles?q=' + encodeURIComponent('"><svg onload=alert(2)>') +
      '#roles',
    '/admin/xacml?policy=orders-by-region#xacml-tab-editor',
    links.pep, links.proxy
  ].filter(function (href) {
    return !has(href);
  });
  t.check(missing.length === 0, 'K1. every box and every name links to ' +
          'its page', missing.join('\n'));
  t.check(!/<a [^>]*>(?:(?!<\/a>)[\s\S])*<a /.test(svg),
          'K2. no link is nested in another');
  t.check(PepPicture.draw(tr, row, null).svg.indexOf('<a ') < 0,
          'K3. without links, none is drawn');

  // -------------------------------------------------------------------------
  t.log.info('=== N. the listeners ===');
  // -------------------------------------------------------------------------
  const groups = svg.match(/<a href="[^"]*listener=[^"]*" class="[^"]*"/g) ||
    [];
  const classOf = function (id) {
    return (groups.filter(function (g) {
      return g.indexOf('listener=' + encodeURIComponent(id)) >= 0;
    })[0] || '').replace(/^.*class="/, '').replace(/"$/, '');
  };
  t.equal(['api-http', 'api-https', 'proxy-http', 'proxy-https', 'pub<i>',
           'quiet-api'].map(classOf).join(' | '),
          'pp-listener pp-off pp-env | pp-listener pp-env | ' +
          'pp-listener pp-serves pp-off pp-env | ' +
          'pp-listener pp-serves pp-env | ' +
          'pp-listener pp-serves pp-defined | pp-listener pp-off pp-defined',
          'N1. each listener: serving the proxy or not, off (or not ' +
          'reported), environment or defined here');
  t.check(svg.indexOf('HTTP · 0.0.0.0:9090') >= 0 &&
          svg.indexOf('HTTPS · 0.0.0.0:9543') >= 0 &&
          svg.indexOf('HTTP · *:9580') >= 0 &&
          svg.indexOf('HTTPS · 127.0.0.1:9444') >= 0 &&
          svg.indexOf('reverse proxy · defined here') >= 0 &&
          svg.indexOf('decision API · environment') >= 0 &&
          svg.indexOf('off (PEP_HTTP unset)') >= 0 &&
          svg.indexOf('off (PEP_PROXY_HTTP unset)') >= 0 &&
          svg.indexOf('>failed<') >= 0 && svg.indexOf('>not reported<') >= 0,
          'N2. protocol, address:port, purpose, source and state');
  const serves = svg.match(/<path class="pp-serve"[^>]*>/g) || [];
  t.check(serves.length === 3 &&
          serves.filter(function (one) {
            return one.indexOf('stroke-dasharray') >= 0;
          }).length === 1,
          'N3. a line from each of the three reverse-proxy listeners to the ' +
          'proxy, the one that is off dashed', serves.join('\n'));

  // -------------------------------------------------------------------------
  t.log.info('=== A. the text alternative ===');
  // -------------------------------------------------------------------------
  t.check(/^<svg [^>]*role="img" aria-labelledby="pp-title pp-desc"/
            .test(svg) &&
          svg.indexOf('<title id="pp-title">Remote PEP ' +
                      'pep-&lt;b&gt;1&lt;/b&gt;' +
                      ': its listeners and its reverse proxy&apos;s routes' +
                      '</title>') >= 0 &&
          svg.indexOf('<desc id="pp-desc">6 listener(s), 3 of them serving ' +
                      'the reverse proxy, and 10 route(s).</desc>') >= 0,
          'A1. the SVG\'s title and desc', svg.slice(0, 600));
  const text = PepPicture.textAlternative(tr, row, links);
  const nested = text.indexOf('/pep-app/api/admin') >
      text.indexOf('/pep-app/api<') &&
    /\/pep-app\/api<\/code> \(prefix\)[^]*?<ul><li>[^]*?\/pep-app\/api\/admin/
      .test(text);
  t.check(nested && text.indexOf(kit.esc(links.route('legacy'))) >= 0 &&
          text.indexOf('/admin/roles?q=auditors#roles') >= 0 &&
          text.indexOf('deny all (no methods)') >= 0 &&
          text.indexOf('<code>/shop/v2</code> — no route') >= 0 &&
          text.indexOf(kit.esc(links.listener('api-http'))) >= 0 &&
          text.indexOf('off (PEP_HTTP unset)') >= 0,
          'A2. the text alternative: the same tree as nested lists, with ' +
          'the same links', text);
  const panel = PepPicture.panel(tr, row, links);
  t.check(panel.indexOf('<div class="diagram pep-picture-wide" ' +
                        'tabindex="0" role="region"') >= 0 &&
          panel.indexOf('<div class="diagram pep-picture-stacked" ' +
                        'tabindex="0" role="region"') >= 0 &&
          panel.indexOf('id="pps-title"') >= 0 &&
          (panel.match(/id="pp-title"/g) || []).length === 1 &&
          (panel.match(/<td class="art">/g) || []).length === 9 &&
          panel.indexOf('<details class="sub"><summary>The picture as ' +
                        'text</summary><ul class="pp-text">') >= 0,
          'A3. the panel: the wide and the stacked drawing (ids apart), the ' +
          'key and the text alternative', panel.slice(0, 800));
  const stacked = PepPicture.draw(tr, row, links, true);
  t.check(stacked.width < drawn.width && stacked.height > drawn.height,
          'A4. the stacked drawing is narrower and taller');

  // -------------------------------------------------------------------------
  t.log.info('=== E. escaping ===');
  // -------------------------------------------------------------------------
  const raw = /<script|<img|<svg onload|<b>|<i>|onerror=alert\(1\)>|"><svg/;
  [['E1. the wide drawing', svg], ['E2. the stacked drawing', stacked.svg],
   ['E3. the text alternative', text], ['E4. the panel', panel]]
    .forEach(function (one) {
      t.check(!raw.test(one[1].replace(/^<svg xmlns[^>]*>/, '')
                .replace(/<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"[^>]*>/g,
                         '')),
              one[0] + ': no hostile name is drawn as markup',
              (one[1].match(raw) || [''])[0]);
    });
  t.check(svg.indexOf('&lt;script&gt;alert(1)&lt;/script&gt;') >= 0 &&
          svg.indexOf('&quot;&gt;&lt;svg onload=alert(2)&gt;') >= 0 &&
          svg.indexOf('>evil&amp;app<') >= 0,
          'E5. the hostile names are drawn, escaped');
  const xmldom = require('@xmldom/xmldom');
  const parseErrors = [];
  [svg, stacked.svg].forEach(function (one) {
    try {
      new xmldom.DOMParser({ onError: function (level, msg) {
        parseErrors.push(level + ': ' + msg);
      } }).parseFromString(one, 'image/svg+xml');
    } catch (e) {
      // xmldom 0.9 throws on a fatal error as well as reporting it.
      log.debug("Caught in run(): " + ((e && e.message) || e));
      parseErrors.push('fatal: ' + ((e && e.message) || e));
    }
  });
  t.check(parseErrors.length === 0, 'E6. both drawings are well-formed XML',
          parseErrors.join('\n'));

  // -------------------------------------------------------------------------
  t.log.info('=== T. the tab ===');
  // -------------------------------------------------------------------------
  const writer = kit.context({}, true);
  const section = XacmlPage.proxySection(writer, row);
  t.check(/<nav class="tabbar subbar"[^>]*><a class="first" href="#xacml-pep-proxy-routes">Configured Routes<\/a><a href="#xacml-pep-proxy-new-route">Create a New Route<\/a><a href="#xacml-pep-proxy-manifest">Manifest<\/a><a href="#xacml-pep-proxy-visual">Visual<\/a><\/nav>/
            .test(section) &&
          /<div class="subpanel[^"]*" id="xacml-pep-proxy-visual"><p class="note">|<div class="subpanel[^"]*" id="xacml-pep-proxy-visual"><details class="note fold">/
            .test(section) &&
          section.indexOf('pep-picture-wide') >
            section.indexOf('id="xacml-pep-proxy-visual"'),
          'T1. Visual is the fourth sub-tab, and its panel holds the picture',
          section.slice(0, 1200));
  const reader = XacmlPage.proxySection(kit.context({}, false), row);
  t.check(reader.indexOf('href="#xacml-pep-proxy-visual">Visual</a>') >= 0 &&
          reader.indexOf('pep-picture-wide') >= 0,
          'T2. a reader sees it too');
  const WebPages = require('../admin-ui/web_pages');
  const WebShell = require('../admin-ui/web_shell');
  const ConsoleRuntime = require('../admin-ui/web_runtime');
  const answer = { found: true, pep: row.name,
                   peps: [Object.assign({}, row, { name: 'p' })],
                   listenersCatalogue: { keyAlgorithms: [] } };
  const page = XacmlPage.pepDetail(writer, answer);
  // The trail the runtime draws for a fragment (drawView(), then
  // redrawTrail() from the body's tab tree), as `xacml_pep_console.js` TR
  // asks it.
  const crumbsOf = function (html) {
    const out = [];
    const re = /<a href="([^"]*)"[^>]*>([^<]*)<\/a>|<span class="leaf"[^>]*>([^<]*)<\/span>/g;
    let m = re.exec(html);
    while (m) {
      out.push(m[3] !== undefined ? m[3] : m[2] + ' -> ' +
               m[1].replace(/&amp;/g, '&'));
      m = re.exec(html);
    }
    return out.join(' | ');
  };
  const trail = function (hash) {
    log.debug("Entering trail(). " + hash);
    const drawnView = {};
    const render = WebPages.render;
    WebPages.render = function () {
      return page;
    };
    try {
      ConsoleRuntime.prototype.drawView.call({
        view: { page: WebPages.pageFor('/admin/xacml/pep'),
                query: { pep: 'p' }, json: {} },
        me: { write: false }, t: tr,
        shell: { navLabels: { '/admin/xacml': 'XACML' } },
        draw: function (title, active, html, up) {
          drawnView.title = title;
          drawnView.active = active;
          drawnView.html = html;
          drawnView.up = up;
        } }, null);
    } finally {
      WebPages.render = render;
    }
    const element = { outerHTML: '<p class="crumb"></p>' };
    ConsoleRuntime.prototype.redrawTrail.call({
      trailOf: { title: drawnView.title, active: drawnView.active,
                 up: drawnView.up, tree: WebShell.tabTreeOf(drawnView.html) },
      env: { location: { pathname: '/admin/xacml/pep', search: '?pep=p',
                         hash: hash },
             document: { querySelector: function (sel) {
               return sel === '.card p.crumb' ? element : null;
             } } },
      shell: { navLabels: { '/admin/xacml': 'XACML' } }, t: tr, prefix: '',
      openTabsNow: ConsoleRuntime.prototype.openTabsNow,
      here: ConsoleRuntime.prototype.here,
      consolePath: ConsoleRuntime.prototype.consolePath });
    log.debug("Leaving trail().");
    return crumbsOf(element.outerHTML);
  };
  t.equal(trail('#xacml-pep-proxy-visual'),
          'Admin console -> /admin | XACML -> /admin/xacml | ' +
          'Remote PEPs -> /admin/xacml#xacml-tab-peps | ' +
          'p -> /admin/xacml/pep?pep=p | ' +
          'Reverse proxy -> #xacml-pep-tab-proxy | Visual',
          'T3. the trail: … › Remote PEPs › the PEP › Reverse proxy › Visual');
  // THE HIGHLIGHT, by the runtime's own markOpenTabs() over the panels and
  // bars of the page drawn: Remote PEPs, Reverse proxy and Visual.
  const tabsOf = function (html) {
    log.debug("Entering tabsOf().");
    const roots = [];
    const byId = {};
    const stack = [];
    const token = /<(\/?)(div|section|nav|a)\b((?:[^>"']|"[^"]*")*)>/g;
    let m = token.exec(html);
    while (m) {
      if (m[1]) {
        stack.pop();
      } else {
        const attrs = {};
        const re = /([\w-]+)="([^"]*)"/g;
        let a = re.exec(m[3]);
        while (a) {
          attrs[a[1]] = a[2];
          a = re.exec(m[3]);
        }
        const classes = String(attrs.class || '').split(/\s+/);
        const parent = stack[stack.length - 1] || null;
        const el = {
          tagName: m[2].toUpperCase(), attrs: attrs, children: [],
          parent: parent, classes: classes,
          classList: {
            contains: function (c) { return classes.indexOf(c) >= 0; },
            add: function (c) { classes.push(c); },
            remove: function (c) {
              const at = classes.indexOf(c);
              if (at >= 0) {
                classes.splice(at, 1);
              }
            }
          },
          getAttribute: function (n) {
            return n in attrs ? attrs[n] : null;
          },
          setAttribute: function (n, v) {
            attrs[n] = v;
          },
          removeAttribute: function (n) {
            delete attrs[n];
          },
          contains: function (other) {
            let at = other;
            while (at) {
              if (at === el) {
                return true;
              }
              at = at.parent;
            }
            return false;
          }
        };
        if (parent) {
          parent.children.push(el);
        }
        if (attrs.id) {
          byId[attrs.id] = el;
        }
        if (m[2] === 'div' && (classes.indexOf('tabs') >= 0 ||
                               classes.indexOf('subtabs') >= 0)) {
          roots.push(el);
        }
        stack.push(el);
      }
      m = token.exec(html);
    }
    log.debug("Leaving tabsOf().");
    return { roots: roots, byId: byId };
  };
  const dom = tabsOf(page);
  const rt = Object.create(ConsoleRuntime.prototype);
  rt.env = { document: {
    querySelectorAll: function () {
      return dom.roots;
    },
    querySelector: function () {
      return dom.byId['xacml-pep-proxy-visual'] || null;
    },
    getElementById: function (id) {
      return dom.byId[id] || null;
    } } };
  rt.markOpenTabs();
  const marked = dom.roots.map(function (root) {
    const bar = root.children.filter(function (el) {
      return el.classList.contains('tabbar');
    })[0];
    return (bar ? bar.children : []).filter(function (el) {
      return el.classList.contains('tab-current');
    }).map(function (el) {
      return el.attrs.href;
    }).join('+');
  }).join(' | ');
  // Four bars: the XACML page's, the PEP page's, and the two sub-bars —
  // the Listener tab's, hidden, keeps its first; the Reverse proxy's marks
  // Visual.
  t.equal(marked, '/admin/xacml#xacml-tab-peps | #xacml-pep-tab-proxy | ' +
          '#xacml-pep-listeners-configured | #xacml-pep-proxy-visual',
          'T4. the highlight: Remote PEPs, Reverse proxy and Visual, one at ' +
          'each level');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_pep_picture',
  describe: 'The Reverse proxy tab\'s Visual sub-tab: the PEP, its listeners ' +
            'and its routes as a tree by path, with each route\'s ' +
            'application and who may reach it, drawn from the PEP page\'s ' +
            'answer',
  run: run
};
