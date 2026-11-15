// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_console.js
//
// ===========================================================================
// WHAT THE REMOTE PEPS TAB DRAWS ABOUT A PEP'S NOTIFY URL AND ITS LISTENERS
// (2026-11-14), held in node against `xacml/web_xacml.ts`, the renderer the
// console bundles. Two defects found on the 8081 demo:
//
//   N. THE NOTIFY COLUMN drew the service's whole sentence about an unusable
//      URL, and what the last nudge met, inline. It now draws a short status
//      — usable, unusable with a one-line reason, or not set — and the long
//      sentences in a `<details>`, collapsed, which needs no script.
//   L. THE LISTENER TAB drew a listener whose state the PEP never reported
//      as "listening". A missing report, or a state that is not one of the
//      four, reads "not reported"; an environment plain-HTTP listener with
//      no report reads as its default, off, labelled as the default; and a
//      reported `http-off` reads "off (PEP_HTTP=false)".
//   R. THE REVERSE PROXY TAB draws no "Edit route <id>" section per route
//      (rcbj): each route's id in the table links to its own page, which
//      holds the one edit form. The add form and the document editor
//      stay. The "Map an application to a route" form left too: the
//      route's own page edits its application, the current one linked,
//      with the same chooser, through set-pep-route.
//   S. THE TAB'S THREE SUB-TABS (rcbj): Configured Routes (the summary and
//      the table), Create a New Route (the add form) and Manifest (the
//      document and Clear), each an anchor.
//   W. THE ROUTE PAGE KEEPS THE PEP PAGE'S TABS (rcbj): Reverse proxy
//      current, its sub-tabs with Configured Routes current, the others
//      links to the PEP page at their anchors.
//   F. ONE FIELD PER LINE (rcbj): the route page's form and the add form,
//      each field a `.formrow` of its own, under fieldset legends.
//   T. THE TRAILS (rcbj): a PEP's page is Admin console › XACML › Remote
//      PEPs › the PEP, and a route's adds › Reverse proxy › the route, each
//      tab a crumb linking to that tab, built by the runtime's drawView().
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'xacml_pep_console',
  level: process.env.LOG_LEVEL || 'info' });

// A row of `listenerRows` as the service answers it.
function envRow(id, protocol, enable, reported) {
  log.debug("Entering envRow(). " + id);
  log.debug("Leaving envRow().");
  return { id: id, source: 'environment', protocol: protocol,
           purpose: 'api', env: protocol === 'http' ? 'PEP_PORT'
             : 'PEP_HTTPS_PORT',
           enable: enable, defaultPort: protocol === 'http' ? 9090 : 9443,
           definition: null, reported: reported };
}

async function run(t) {
  log.debug("Entering run().");
  const XacmlPage = require('../xacml/web_xacml');
  const kit = require('../admin-ui/web_kit');
  // The English catalogs as the renderers' default translator: run alone,
  // nothing else in the process loads them, and every check would read a
  // message key.
  require('../common/i18n');
  const tr = kit.context({}, true).t;

  // -------------------------------------------------------------------------
  t.log.info('=== N. the notify column ===');
  // -------------------------------------------------------------------------
  const long = 'This notify URL is plain http, and a nudge is sent over ' +
    'https only: register the PEP\'s HTTPS notify URL, ' +
    'https://<host>:<PEP_HTTPS_PORT>/notify. Until then it converges by ' +
    'polling.';
  const plain = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'http://pep:9090/notify', notifyProblem: long,
    lastNotify: '2026-11-14T00:00:00.000Z — The nudge could not be ' +
      'delivered: a long sentence about a certificate.' });
  const shortPart = plain.split('<details')[0];
  t.check(shortPart.indexOf('plain http') >= 0 &&
          shortPart.indexOf('HTTPS only') >= 0 &&
          shortPart.indexOf('converges by polling') < 0,
          'N1. an http URL is "unusable" with a one-line reason, and the ' +
          'long sentence is not in the cell itself', shortPart);
  t.check(/<details class="sub"><summary>Details<\/summary>/.test(plain) &&
          plain.indexOf(' open') < 0 &&
          plain.split('<details')[1].indexOf('converges by polling') >= 0 &&
          plain.split('<details')[1].indexOf('a long sentence') >= 0,
          'N2. the long sentences are in a <details>, collapsed', plain);
  t.check(shortPart.indexOf('last nudge: not delivered') >= 0,
          'N3. the last nudge is two words in the cell', shortPart);
  const fine = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'https://pep:9443/notify', notifyProblem: null,
    lastNotify: '2026-11-14T00:00:00.000Z — The PEP answered 204.' });
  t.check(fine.indexOf('usable') >= 0 && fine.indexOf('unusable') < 0 &&
          fine.indexOf('last nudge: delivered') >= 0 &&
          fine.indexOf('<details') >= 0,
          'N4. an https URL is "usable", its last delivery said briefly',
          fine);
  const quiet = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'https://pep:9443/notify', notifyProblem: null });
  t.check(quiet.indexOf('<details') < 0,
          'N5. with nothing long to say there is no <details>', quiet);
  const host = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'https://pep:9443/notify',
    notifyProblem: 'The host "pep" is not in xacml.pepNotifyAllowedHosts ' +
      '(other.test).' });
  t.check(host.split('<details')[0].indexOf('AllowedHosts') >= 0,
          'N6. a host off the allowlist says so in one line', host);
  const derivedUrl = 'https://pep.example:9443/notify';
  const derived = XacmlPage.pepNotify(tr, {
    notifyUrl: derivedUrl, notifyProblem: null,
    settingsInUse: { values: { notifyUrl: { value: derivedUrl,
                                            source: 'derived' } } } });
  t.check(derived.indexOf('derived by the PEP') >= 0 &&
          derived.indexOf('usable') >= 0 &&
          quiet.indexOf('derived') < 0,
          'N8. a notify URL the PEP derived says so in the cell, and one ' +
          'it did not derive does not', derived);
  const stale = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'https://set-here:9443/notify', notifyProblem: null,
    settingsInUse: { values: { notifyUrl: { value: derivedUrl,
                                            source: 'derived' } } } });
  t.check(stale.indexOf('derived') < 0,
          'N9. a URL set here is not called derived when the PEP last ' +
          'reported a derived one', stale);
  const none = XacmlPage.pepNotify(tr, {});
  t.check(none.indexOf('never nudged') >= 0 && none.indexOf('<details') < 0,
          'N7. no notify URL is "none"', none);

  // -------------------------------------------------------------------------
  t.log.info('=== L. the listener tab\'s state cell ===');
  // -------------------------------------------------------------------------
  const words = XacmlPage.listenerWords(tr);
  const unreported = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP', null));
  t.check(unreported.indexOf('listening') < 0 &&
          unreported.indexOf('not reported') >= 0 &&
          unreported.indexOf('PEP_HTTP') >= 0,
          'L1. an unreported plain-HTTP listener is "off" by its default and ' +
          '"not reported", never "listening"', unreported);
  const nullState = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP', { state: null, reason: null }));
  t.check(nullState.indexOf('listening') < 0 &&
          nullState.indexOf('not reported') >= 0,
          'L2. a report whose state is null is "not reported"', nullState);
  const httpsNull = XacmlPage.listenerState(tr, words,
    envRow('api-https', 'https', '', { state: 'bogus' }));
  t.check(httpsNull.indexOf('listening') < 0 &&
          httpsNull.indexOf('not reported') >= 0 &&
          httpsNull.indexOf('by default') < 0,
          'L3. an unknown state on the HTTPS listener is "not reported", ' +
          'with no plain-HTTP default', httpsNull);
  const off = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP',
           { state: 'off', reason: 'http-off', port: 9090 }));
  t.check(off.indexOf('listening') < 0 &&
          off.indexOf('PEP_HTTP=false') >= 0,
          'L4. a reported http-off reads "off (PEP_HTTP=false)"', off);
  const crl = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP',
           { state: 'listening', reason: 'crl-only', port: 9090 }));
  t.check(crl.indexOf('listening') >= 0 && crl.indexOf('CRLs only') >= 0,
          'L5. the CRL-only listener reads "listening — CRLs only"', crl);
  const on = XacmlPage.listenerState(tr, words,
    envRow('api-https', 'https', '',
           { state: 'listening', reason: 'none', port: 9443 }));
  t.check(on.indexOf('listening') >= 0 && on.indexOf('not reported') < 0,
          'L6. a reported listening listener reads "listening"', on);

  // -------------------------------------------------------------------------
  t.log.info('=== R. the Reverse proxy tab edits no route itself ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-14): a collapsed "Edit route <id>" form per route, below
  // the add form, repeated the route's own page, which the id links to.
  const proxy = {
    upstream: 'http://companion:9700', enabled: true,
    routes: [
      { id: 'orders-api', path: '/api', match: 'prefix', methods: ['GET'],
        public: false, mechanisms: ['session'], application: 'orders-app',
        resource: '', action: '', forwardCredentials: false, signals: true },
      { id: 'health', path: '/health', match: 'exact', methods: [],
        public: true, mechanisms: [], application: '', resource: '',
        action: '', forwardCredentials: false, signals: true }] };
  const writer = kit.context({}, true);
  writer.json = {};
  const tab = XacmlPage.proxySection(writer,
    { name: 'pep-1', proxy: proxy, proxyRoutes: [] });
  t.check(tab.indexOf('<details><summary>') < 0 &&
          tab.indexOf('Edit route') < 0 &&
          tab.indexOf('name="id" value="orders-api"') < 0 &&
          tab.indexOf('name="id" value="health"') < 0,
          'R1. the tab draws no per-route edit section', tab);
  const adds = tab.split('name="action" value="set-pep-route"').length - 1;
  t.check(adds === 1 && tab.indexOf('Add the route') >= 0 &&
          tab.indexOf('Save the route') < 0,
          'R2. one set-pep-route form, the add form', String(adds));
  t.check(proxy.routes.every(function (route) {
    return tab.indexOf('<a href="' +
      XacmlPage.routeHref('pep-1', route.id).replace(/&/g, '&amp;') +
      '"><code>' + route.id + '</code></a>') >= 0;
  }), 'R3. each route row links its id to the route\'s own page', tab);
  t.check(tab.indexOf('set-pep-route-application') < 0 &&
          tab.indexOf('Map an application') < 0 &&
          tab.indexOf('set-pep-proxy') >= 0,
          'R4. no "Map an application to a route" form; the document ' +
          'editor stays', tab);

  // THE THREE SUB-TABS (rcbj, 2026-11-14): Configured Routes holds the
  // summary and the table, Create a New Route the add form, Manifest the
  // document editor and Clear; each its own anchor.
  const panelOf = function (html, id) {
    log.debug("Entering panelOf(). " + id);
    const at = html.indexOf('<div class="subpanel');
    const start = html.indexOf('id="' + id + '">', at);
    if (at < 0 || start < 0) {
      log.debug("Leaving panelOf(). None.");
      return '';
    }
    const next = html.indexOf('<div class="subpanel', start);
    log.debug("Leaving panelOf().");
    return html.slice(start, next < 0 ? html.length : next);
  };
  proxy.publicBaseUrl = 'https://orders.example.test';
  const split = XacmlPage.proxySection(writer,
    { name: 'pep-1', proxy: proxy, proxyRoutes: [] });
  delete proxy.publicBaseUrl;
  const routesPanel = panelOf(split, 'xacml-pep-proxy-routes');
  const newPanel = panelOf(split, 'xacml-pep-proxy-new-route');
  const manifest = panelOf(split, 'xacml-pep-proxy-manifest');
  t.check(/<nav class="tabbar subbar"[^>]*><a class="first" href="#xacml-pep-proxy-routes">Configured Routes<\/a><a href="#xacml-pep-proxy-new-route">Create a New Route<\/a><a href="#xacml-pep-proxy-manifest">Manifest<\/a><\/nav>/
            .test(split),
          'S1. the Reverse proxy tab is three sub-tabs, Configured Routes ' +
          'first', split);
  t.check(routesPanel.indexOf('/admin/xacml/pep/route?pep=pep-1&amp;' +
                              'route=orders-api') >= 0 &&
          routesPanel.indexOf('http://companion:9700') >= 0 &&
          routesPanel.indexOf('Enabled.') >= 0 &&
          routesPanel.indexOf('https://orders.example.test') >= 0 &&
          routesPanel.indexOf('set-pep-route"') < 0 &&
          routesPanel.indexOf('set-pep-proxy') < 0,
          'S2. Configured Routes: the summary (upstream, enabled, ' +
          'publicBaseUrl) and the table, no add form or document',
          routesPanel);
  t.check(newPanel.indexOf('value="set-pep-route"') >= 0 &&
          newPanel.indexOf('Add the route') >= 0 &&
          newPanel.indexOf('set-pep-proxy') < 0,
          'S3. Create a New Route: the add form alone', newPanel);
  t.check(manifest.indexOf('value="set-pep-proxy"') >= 0 &&
          manifest.indexOf('value="clear-pep-proxy"') >= 0 &&
          manifest.indexOf('<textarea name="proxy"') >= 0 &&
          manifest.indexOf('set-pep-route"') < 0,
          'S4. Manifest: the whole document and Clear', manifest);

  // The route's own page maps its application: the current one linked,
  // the same chooser in the one edit form, saved by set-pep-route.
  const page = XacmlPage.routeDetail(writer, {
    pep: 'pep-1', route: 'orders-api', found: true,
    peps: [{ name: 'pep-1', proxy: proxy }],
    applicationChoices: [{ identifier: 'orders-app', name: 'Orders' },
                         { identifier: 'billing-app', name: 'billing-app' }],
    routeDetail: { found: true, route: proxy.routes[0], usable: true,
                   position: 0, count: 2, servedBy: [],
                   application: { identifier: 'orders-app', name: 'Orders',
                                  found: true } } });
  const form = page.split('name="action" value="set-pep-route"')[1] || '';
  t.check(page.indexOf('<a href="/admin/applications?application=' +
                       'orders-app"><code>orders-app</code></a>') >= 0,
          'R5. the route page links the application it fronts', page);
  t.check(/<input type="text" name="application"[^>]* list="pep-route-apps-page-orders-api" value="orders-app">/
            .test(form) &&
          form.indexOf('<datalist id="pep-route-apps-page-orders-api">' +
                       '<option value="orders-app">') >= 0 &&
          form.indexOf('<option value="billing-app">') >= 0 &&
          form.indexOf('set-pep-route-application') < 0,
          'R6. its set-pep-route form edits the application with the ' +
          'realm\'s applications as the chooser', form);
  t.check(form.indexOf('make the route public') >= 0 &&
          /name="public"/.test(form),
          'R7. the form says a public route clears the application, and ' +
          'offers public', form);

  // -------------------------------------------------------------------------
  t.log.info('=== W. the route page keeps the PEP page\'s tabs ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-14): the PEP page's bar with Reverse proxy current, its
  // sub-tabs with Configured Routes current, the route inside; every other
  // tab a link to the PEP page at that tab's anchor.
  const bars = page.match(/<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) ||
    [];
  const pepUrl = '/admin/xacml/pep?pep=pep-1#';
  t.equal(bars[0] || '', '<nav class="tabbar" aria-label="Sections of this ' +
          'page"><a href="' + pepUrl + 'xacml-pep-tab-overview">Overview</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-decisions">Decisions</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-settings">Settings</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-listener">Listener</a>' +
          '<a class="first" href="#xacml-pep-tab-proxy">Reverse proxy</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-signals">Signal streams</a>' +
          '</nav>',
          'W1. the PEP page\'s tabs, Reverse proxy current, the others ' +
          'links to the PEP page');
  t.equal(bars[1] || '', '<nav class="tabbar subbar" aria-label="Reverse ' +
          'proxy"><a class="first" href="#xacml-pep-proxy-routes">Configured ' +
          'Routes</a><a href="' + pepUrl + 'xacml-pep-proxy-new-route">Create ' +
          'a New Route</a><a href="' + pepUrl + 'xacml-pep-proxy-manifest">' +
          'Manifest</a></nav>',
          'W2. the Reverse proxy sub-tabs, Configured Routes current');
  t.check(bars.length === 2 &&
          (page.match(/<section class="tabpanel/g) || []).length === 1 &&
          page.indexOf('<section class="tabpanel first" ' +
                      'id="xacml-pep-tab-proxy">') >= 0 &&
          (page.match(/<div class="subpanel/g) || []).length === 1 &&
          page.indexOf('<div class="subpanel first" ' +
                      'id="xacml-pep-proxy-routes">') >= 0 &&
          panelOf(page, 'xacml-pep-proxy-routes')
            .indexOf('value="set-pep-route"') >= 0,
          'W3. one panel drawn in each, the route inside Configured Routes',
          page);
  const reader = XacmlPage.routeDetail(kit.context({}, false), {
    pep: 'pep-1', route: 'orders-api', found: true,
    peps: [{ name: 'pep-1', proxy: proxy }],
    routeDetail: { found: true, route: proxy.routes[0], usable: true,
                   position: 0, count: 2, servedBy: [] } });
  t.check(reader.indexOf('xacml-pep-proxy-new-route') < 0 &&
          reader.indexOf('xacml-pep-proxy-manifest') >= 0 &&
          reader.indexOf('<a class="first" href="#xacml-pep-tab-proxy">') >= 0,
          'W4. a reader\'s route page keeps the tabs, without Create a New ' +
          'Route', reader);

  // -------------------------------------------------------------------------
  t.log.info('=== F. one field per line, under legends ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-14): each field a `.formrow` of its own, grouped under
  // Matching, Authentication, Authorization, Identity sent to the
  // application and Order; one header (name, claim) per line.
  const fieldsOf = function (html) {
    log.debug("Entering fieldsOf().");
    const rows = html.split('<div class="formrow">').slice(1);
    const named = rows.map(function (one) {
      const names = [];
      const re = /<(?:input|select)\b[^>]*\bname="([^"]+)"/g;
      let m = re.exec(one.split('</div>')[0]);
      while (m) {
        if (names.indexOf(m[1]) < 0) {
          names.push(m[1]);
        }
        m = re.exec(one.split('</div>')[0]);
      }
      return names.join('+');
    });
    log.debug("Leaving fieldsOf().");
    return named.filter(function (one) {
      return one !== '';
    }).join(' | ');
  };
  const legendsOf = function (html) {
    log.debug("Entering legendsOf().");
    const out = [];
    const re = /<fieldset><legend>([^<]*)<\/legend>/g;
    let m = re.exec(html);
    while (m) {
      out.push(m[1]);
      m = re.exec(html);
    }
    log.debug("Leaving legendsOf().");
    return out.join(' | ');
  };
  t.equal(fieldsOf(form), 'id | path | match | methods | public | ' +
          'mechanisms | forwardCredentials | signals | multipleAccounts | ' +
          'application | resource | routeAction | position | mode | ' +
          'headerName+headerClaim | headerName+headerClaim | separator',
          'F1. the route page\'s form: one field per line, one header ' +
          '(name, claim) per line');
  t.equal(legendsOf(form), 'Matching | Authentication | Authorization | ' +
          'Order | Identity sent to the application',
          'F2. the route page\'s fields under their legends');
  t.equal(fieldsOf(newPanel), 'id | path | match | methods | public | ' +
          'mechanisms | forwardCredentials | signals | multipleAccounts | ' +
          'application | resource | routeAction | position',
          'F4. Create a New Route: the same one field per line');
  t.equal(legendsOf(newPanel), 'Matching | Authentication | ' +
          'Authorization | Order',
          'F5. Create a New Route: the same legends');

  // -------------------------------------------------------------------------
  t.log.info('=== T. the trails name the tab each page was opened from ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-14): Admin console › XACML › Remote PEPs › the PEP, and
  // Admin console › XACML › Remote PEPs › the PEP › Reverse proxy › the
  // route. The runtime's own drawView() builds `up` from the page row;
  // the page body is not what is under test, so render is stubbed.
  const WebPages = require('../admin-ui/web_pages');
  const WebShell = require('../admin-ui/web_shell');
  const ConsoleRuntime = require('../admin-ui/web_runtime');
  const trailOf = function (path, query) {
    log.debug("Entering trailOf(). " + path);
    const drawn = {};
    const render = WebPages.render;
    WebPages.render = function () {
      return '';
    };
    try {
      ConsoleRuntime.prototype.drawView.call({
        view: { page: WebPages.pageFor(path), query: query, json: {} },
        me: { write: false }, t: tr,
        shell: { navLabels: { '/admin/xacml': 'XACML' } },
        draw: function (title, active, html, up) {
          drawn.title = title;
          drawn.active = active;
          drawn.up = up;
        } }, null);
    } finally {
      WebPages.render = render;
    }
    log.debug("Leaving trailOf().");
    return WebShell.trailBar(drawn.active, drawn.up, drawn.title,
                             { '/admin/xacml': 'XACML' }, tr);
  };
  // Each crumb as `label -> href`, the leaf as `label`.
  const crumbsOf = function (html) {
    log.debug("Entering crumbsOf().");
    const out = [];
    const re = /<a href="([^"]*)"[^>]*>([^<]*)<\/a>|<span class="leaf"[^>]*>([^<]*)<\/span>/g;
    let m = re.exec(html);
    while (m) {
      out.push(m[3] !== undefined ? m[3]
        : m[2] + ' -> ' + m[1].replace(/&amp;/g, '&'));
      m = re.exec(html);
    }
    log.debug("Leaving crumbsOf().");
    return out.join(' | ');
  };
  const pepTrail = crumbsOf(trailOf('/admin/xacml/pep', { pep: 'pep-1' }));
  t.equal(pepTrail, 'Admin console -> /admin | XACML -> /admin/xacml | ' +
          'Remote PEPs -> /admin/xacml#xacml-tab-peps | pep-1',
          'T1. a PEP\'s page: Admin console › XACML › Remote PEPs › the PEP');
  const routeTrail = crumbsOf(trailOf('/admin/xacml/pep/route',
    { pep: 'pep-1', route: 'orders-api' }));
  t.equal(routeTrail, 'Admin console -> /admin | XACML -> /admin/xacml | ' +
          'Remote PEPs -> /admin/xacml#xacml-tab-peps | ' +
          'pep-1 -> /admin/xacml/pep?pep=pep-1 | ' +
          'Reverse proxy -> ' +
          '/admin/xacml/pep?pep=pep-1#xacml-pep-proxy-routes | ' +
          'orders-api',
          'T2. a route\'s page: Admin console › XACML › Remote PEPs › the ' +
          'PEP › Reverse proxy › the route');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_pep_console',
  describe: 'The Remote PEPs tab: the notify column\'s short status with the ' +
            'long sentences collapsed, and a listener state never drawn as ' +
            'listening unless the PEP reported it, and a Reverse proxy tab ' +
            'that leaves editing a route to the route\'s own page',
  run: run
};
