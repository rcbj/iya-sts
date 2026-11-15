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
//   D. THREE DEFECTS on the 8081 demo: the route page's Upstream note
//      names the Manifest sub-tab and links to it; every table on the PEP
//      page and the route page scrolls sideways in `.wide` at phone width;
//      Methods and Mechanisms are `.formlabel` row labels naming a
//      role="group", drawn like the other `.formrow` labels.
//   A. THE APPLICATION FIELD IS A SEARCH CHOOSER (rcbj, 2026-11-15) on
//      both route forms: the chosen application linked, Clear, a box and
//      Find over GET /admin-api/applications, each result a Use that fills
//      the hidden `application`, the rest of the form kept as typed.
//   X. THE XACML PAGE'S TABS FIRST (rcbj, 2026-11-15): three rows on a
//      route's page (XACML with Remote PEPs current, the PEP's, the Reverse
//      proxy sub-tabs), two on a PEP's page.
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
  // REJECTED BY THE PEP (2026-11-14, STS-XPEP-0113): it advertises none,
  // so the row has no URL, and the cell says why, naming what was set.
  const rejectedUse = { values: { notifyUrl: {
    value: 'http://old:9090/notify', source: 'environment',
    rejected: true } } };
  const rejected = XacmlPage.pepNotify(tr, { notifyUrl: '',
                                            settingsInUse: rejectedUse });
  t.check(rejected.indexOf('never nudged') >= 0 &&
          rejected.indexOf('rejected by the PEP') >= 0 &&
          rejected.indexOf('http://old:9090/notify') >= 0 &&
          rejected.indexOf('xacml-alert') >= 0 &&
          none.indexOf('rejected') < 0 && derived.indexOf('rejected') < 0,
          'N10. a notify URL the PEP rejected is said so in the cell, with ' +
          'the value; one it did not reject is not', rejected);
  const settingsTab = XacmlPage.settingsBody({ t: tr, write: false }, {
    settingsCatalogue: { settings: [
      { key: 'notifyUrl', env: 'PEP_NOTIFY_URL', type: 'url',
        group: 'registration', default: '', applies: 'nextRound' },
      { key: 'resource', env: 'PEP_RESOURCE', type: 'text',
        group: 'registration', default: '', applies: 'nextRound' }],
      bootstrap: [] } },
    { settings: {}, settingsInUse: { at: '', token: 't', values: {
      notifyUrl: rejectedUse.values.notifyUrl,
      resource: { value: 'r', source: 'environment' } } } });
  const notifyCells = settingsTab.split('PEP_RESOURCE')[0];
  t.check(notifyCells.indexOf('http://old:9090/notify') >= 0 &&
          notifyCells.indexOf('rejected: not https') >= 0 &&
          settingsTab.split('PEP_RESOURCE')[1].indexOf('rejected') < 0,
          'N11. the Settings tab shows the rejected notify URL as ' +
          'rejected, and no other row', settingsTab);

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
  t.check(form.indexOf('<input type="hidden" name="application" ' +
                       'value="orders-app">') >= 0 &&
          form.indexOf('<datalist') < 0 &&
          form.indexOf('list="pep-route-apps') < 0 &&
          form.indexOf('set-pep-route-application') < 0,
          'R6. its set-pep-route form holds the application in the ' +
          'chooser\'s hidden field, no datalist', form);
  t.check(form.indexOf('make the route public') >= 0 &&
          /name="public"/.test(form),
          'R7. the form says a public route clears the application, and ' +
          'offers public', form);

  // -------------------------------------------------------------------------
  t.log.info('=== A. the Application field is a search chooser ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): "an application name search field, results field,
  // and the ability to choose a search result" on Create a New Route and
  // on the route page — the field search (#459) in a plain form, the push
  // destination's arrangement (#602): the chosen application linked, a box
  // and Find, a page of results each with a Use, and Clear.
  const chooserParts = function (html) {
    log.debug("Entering chooserParts().");
    log.debug("Leaving chooserParts().");
    return {
      hidden: (html.match(/<input type="hidden" name="application" value="([^"]*)">/) || [])[1],
      box: /<input type="search" id="fgq-application" name="fgfind\.application" data-fg-find="application"[^>]*title="[^"]+"/.test(html),
      find: /<button type="submit" class="secondary fg-findbtn" name="fgsearch" value="application" formnovalidate title="[^"]+">Find<\/button>/.test(html),
      results: html.indexOf('<div class="fg-found"') >= 0,
      uses: (html.match(/name="fgadd" value="application\|[^"]+"/g) || [])
        .map(function (one) {
          return one.replace(/^.*\|/, '').replace(/"$/, '');
        }),
      clear: html.indexOf('name="fgadd" value="application|"') >= 0,
      link: (html.match(/<a href="\/admin\/applications\?application=([^"]+)"><code>/) || [])[1],
      defaultFirst: /^[\s\S]*?<button type="submit" class="default-submit" tabindex="-1" aria-hidden="true">[^<]+<\/button>[\s\S]*$/.test(html) &&
        html.indexOf('class="default-submit"') <
          html.indexOf('<button type="submit" class="secondary')
    };
  };
  const pageForm = chooserParts(form);
  const newForm = chooserParts(newPanel);
  t.check(pageForm.box && pageForm.find && pageForm.hidden === 'orders-app' &&
          pageForm.link === 'orders-app' && pageForm.clear &&
          pageForm.defaultFirst && form.indexOf(' Orders ') >= 0,
          'A1. the route page: the application linked with its name and ' +
          'Clear, a search box and Find, the save the default button',
          JSON.stringify(pageForm));
  t.check(newForm.box && newForm.find && newForm.hidden === '' &&
          !newForm.link && !newForm.clear && newForm.defaultFirst &&
          newPanel.indexOf('none chosen') >= 0,
          'A2. Create a New Route: the same chooser, nothing chosen yet',
          JSON.stringify(newForm));

  // A Find, then a Use, as the runtime answers them in the browser: the
  // Applications list asked for a page of five, the results drawn under
  // the box, and the Use filling the hidden field with the rest of the
  // form kept as typed.
  const Runtime = require('../admin-ui/web_runtime');
  const asked = [];
  const pepJson = { pep: 'pep-1', found: true,
                    peps: [{ name: 'pep-1', proxy: proxy }],
                    applicationChoices: [] };
  const fakeRuntime = {
    view: { json: pepJson },
    apiJson: async function (method, path) {
      asked.push(method + ' ' + path);
      return { status: 200, json: {
        applications: [{ identifier: 'billing-app', name: 'Billing' },
                       { identifier: 'orders-app', name: 'Orders' }],
        page: 1, pages: 3, matched: 12 } };
    },
    drawView: function () {
      return null;
    },
    env: { document: { getElementById: function () {
      return null;
    } } }
  };
  const typed = { action: 'set-pep-route', name: 'pep-1', id: 'typed-id',
                  path: '/typed', match: 'exact', methods: ['GET', 'POST'],
                  public: 'false', mechanisms: 'oauth2',
                  application: '', resource: 'urn:typed',
                  routeAction: 'write', position: '1',
                  'fgfind.application': 'bill' };
  const WebAnswersModule = require('../admin-ui/web_answers');
  t.check(WebAnswersModule.isFieldSearch('/admin/xacml/peps',
            Object.assign({ fgsearch: 'application' }, typed)) &&
          !WebAnswersModule.isFieldSearch('/admin/xacml/peps', typed),
          'A3. a chooser press on a route form is a field search; the ' +
          'save is not');
  await Runtime.prototype.pepRouteSearch.call(fakeRuntime,
    Object.assign({ fgsearch: 'application' }, typed));
  t.equal(asked.join(' ; '),
          'GET /admin-api/applications?q=bill&per=5&page=1',
          'A4. Find asks the Applications list operation, five to a page');
  writer.json = fakeRuntime.view.json;
  const searched = panelOf(XacmlPage.proxySection(writer,
    { name: 'pep-1', proxy: proxy, proxyRoutes: [] }),
    'xacml-pep-proxy-new-route');
  const afterFind = chooserParts(searched);
  t.check(afterFind.results &&
          afterFind.uses.join(',') === 'billing-app,orders-app' &&
          searched.indexOf('<code>billing-app</code> Billing') >= 0 &&
          searched.indexOf('page 1 of 3') >= 0 &&
          searched.indexOf('value="typed-id"') >= 0 &&
          searched.indexOf('value="/typed"') >= 0 &&
          afterFind.hidden === '',
          'A5. the results drawn, each with a Use, paged, and the typed ' +
          'fields kept', searched);
  await Runtime.prototype.pepRouteSearch.call(fakeRuntime,
    Object.assign({}, typed, { fgadd: 'application|billing-app',
                               'fgpage.application': '1' }));
  writer.json = fakeRuntime.view.json;
  const chosenHtml = panelOf(XacmlPage.proxySection(writer,
    { name: 'pep-1', proxy: proxy, proxyRoutes: [] }),
    'xacml-pep-proxy-new-route');
  const afterUse = chooserParts(chosenHtml);
  t.check(asked.length === 1 && afterUse.hidden === 'billing-app' &&
          afterUse.link === 'billing-app' &&
          chosenHtml.indexOf('</code></a> Billing') >= 0 &&
          !afterUse.results && afterUse.clear &&
          chosenHtml.indexOf('value="typed-id"') >= 0 &&
          chosenHtml.indexOf('value="urn:typed"') >= 0 &&
          /<option value="exact" selected>/.test(chosenHtml) &&
          /name="methods" value="POST" checked/.test(chosenHtml) &&
          /name="mechanisms" value="oauth2" checked/.test(chosenHtml) &&
          !/name="mechanisms" value="session" checked/.test(chosenHtml),
          'A6. Use fills the application, links it with its name, and ' +
          'keeps every typed field', chosenHtml);
  await Runtime.prototype.pepRouteSearch.call(fakeRuntime,
    Object.assign({}, fakeRuntime.view.json.state.pepRoute.draft,
                  { fgadd: 'application|' }));
  writer.json = fakeRuntime.view.json;
  const cleared = chooserParts(panelOf(XacmlPage.proxySection(writer,
    { name: 'pep-1', proxy: proxy, proxyRoutes: [] }),
    'xacml-pep-proxy-new-route'));
  t.check(cleared.hidden === '' && !cleared.link && !cleared.clear,
          'A7. Clear empties the application', JSON.stringify(cleared));
  // The route page's draft is its own: a press there carries `from`.
  const pageState = WebAnswersModule.pepRouteState(
    { from: 'orders-api', fgadd: 'application|billing-app' }, null, null);
  const pageAfter = XacmlPage.routeDetail(writer, {
    pep: 'pep-1', route: 'orders-api', found: true,
    peps: [{ name: 'pep-1', proxy: proxy }], applicationChoices: [],
    state: { pepRoute: Object.assign(pageState, {
      draft: Object.assign({}, proxy.routes[0], pageState.draft,
                           { id: 'orders-api', public: 'false',
                             mechanisms: ['session'], methods: ['GET'] }) }) },
    routeDetail: { found: true, route: proxy.routes[0], usable: true,
                   position: 0, count: 2, servedBy: [],
                   application: { identifier: 'orders-app', name: 'Orders',
                                  found: true } } });
  const pageChosen = chooserParts(pageAfter.split(
    'name="action" value="set-pep-route"')[1] || '');
  t.check(pageState.key === 'page-orders-api' &&
          pageChosen.hidden === 'billing-app' &&
          pageChosen.link === 'billing-app',
          'A8. the route page\'s Use fills its own form\'s application',
          JSON.stringify(pageChosen));
  writer.json = {};

  // -------------------------------------------------------------------------
  t.log.info('=== W. the route page keeps the PEP page\'s tabs ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-14): the PEP page's bar with Reverse proxy current, its
  // sub-tabs with Configured Routes current, the route inside; every other
  // tab a link to the PEP page at that tab's anchor.
  const bars = page.match(/<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) ||
    [];
  const pepUrl = '/admin/xacml/pep?pep=pep-1#';
  // rcbj (2026-11-15): three rows on the route page — the XACML page's
  // tabs with Remote PEPs current, the PEP page's, the Reverse proxy
  // sub-tabs — and two on a PEP's page, the sub-tabs inside its tab.
  const x = '/admin/xacml#';
  const xacmlBar = '<nav class="tabbar" aria-label="Sections of this ' +
    'page"><a href="' + x + 'xacml-tab-metadata">Metadata</a>' +
    '<a href="' + x + 'xacml-tab-settings">Global settings</a>' +
    '<a href="' + x + 'xacml-tab-policies">Policies</a>' +
    '<a href="' + x + 'xacml-tab-editor">Policy editor</a>' +
    '<a class="first" href="#xacml-tab-peps">Remote PEPs</a>' +
    '<a href="' + x + 'xacml-tab-decide">Try a decision</a>' +
    '<a href="' + x + 'xacml-tab-authzen">AuthZEN</a></nav>';
  t.equal(bars[0] || '', xacmlBar,
          'X1. the route page\'s first row: the XACML page\'s tabs, ' +
          'Remote PEPs current, the others links to /admin/xacml');
  t.check(page.indexOf('<section class="tabpanel first" ' +
                       'id="xacml-tab-peps"><div class="tabs ' +
                       'xacml-pep-pages">') >= 0,
          'X2. the PEP page\'s tabs drawn inside Remote PEPs', page);
  bars.shift();
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
          (page.match(/<section class="tabpanel/g) || []).length === 2 &&
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
  const readerBars = reader.match(
    /<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) || [];
  t.check(readerBars.length === 3 && readerBars[0] === xacmlBar,
          'X3. a reader\'s route page draws the same three rows',
          String(readerBars.length));
  // A PEP's own page: two rows, the XACML page's tabs with Remote PEPs
  // current, then its own six as panels, the sub-tabs inside Reverse
  // proxy.
  const pepPage = XacmlPage.pepDetail(writer, {
    pep: 'pep-1', found: true, applicationChoices: [],
    listenersCatalogue: {},
    listenerCertificates: { keyAlgorithms: ['ES256'],
                            defaultKeyAlg: 'ES256' },
    peps: [{ name: 'pep-1', proxy: proxy, proxyRoutes: [], listeners: [],
             listenerRows: [] }] });
  const pepBars = pepPage.match(
    /<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) || [];
  t.equal(pepBars[0] || '', xacmlBar,
          'X4. a PEP\'s page\'s first row: the XACML page\'s tabs, Remote ' +
          'PEPs current');
  t.equal(pepBars[1] || '', '<nav class="tabbar" aria-label="Sections of ' +
          'this page"><a class="first" href="#xacml-pep-tab-overview">' +
          'Overview</a><a href="#xacml-pep-tab-decisions">Decisions</a>' +
          '<a href="#xacml-pep-tab-settings">Settings</a>' +
          '<a href="#xacml-pep-tab-listener">Listener</a>' +
          '<a href="#xacml-pep-tab-proxy">Reverse proxy</a>' +
          '<a href="#xacml-pep-tab-signals">Signal streams</a></nav>',
          'X5. its second row: its own tabs, each a panel of the page');
  t.check(pepBars.length === 3 &&
          /^<nav class="tabbar subbar" aria-label="Reverse proxy">/
            .test(pepBars[2] || '') &&
          panelOf(pepPage.split('id="xacml-pep-tab-proxy">')[1] || '',
                  'xacml-pep-proxy-routes') !== '' &&
          pepPage.indexOf('<section class="tabpanel first" ' +
                          'id="xacml-tab-peps"><div class="tabs ' +
                          'xacml-pep-pages">') >= 0,
          'X6. two rows of tabs; the Reverse proxy sub-tabs inside its tab',
          String(pepBars.length));

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
  t.log.info('=== D. three defects on the 8081 demo (fc561497d) ===');
  // -------------------------------------------------------------------------
  // D1-D2: the route page's Upstream note named the document's old place,
  // "on the Reverse proxy tab"; it is on that tab's Manifest sub-tab, and
  // the note links there.
  const upstream = page.split('<div class="sub">').filter(function (one) {
    return one.indexOf('<code>upstream</code>') >= 0;
  })[0] || '';
  t.check(upstream.indexOf('Reverse proxy tab\'s <a href="' +
          '/admin/xacml/pep?pep=pep-1#xacml-pep-proxy-manifest">Manifest' +
          '</a> sub-tab') >= 0 && upstream.indexOf('\u0001') < 0,
          'D1. the Upstream note names the Manifest sub-tab and links to ' +
          'it on the PEP\'s page', upstream);
  // D3-D5: a table wider than a 390px card scrolls sideways in the
  // console's own `.wide` box (`kit.wideTable()`) instead of being clipped.
  const bareTables = function (html) {
    log.debug("Entering bareTables().");
    const parts = html.split('<table');
    let bare = 0;
    for (let i = 1; i < parts.length; i++) {
      if (!/<div class="wide" tabindex="0" role="region" aria-label="[^"]+">$/
          .test(parts[i - 1])) {
        bare++;
      }
    }
    log.debug("Leaving bareTables().");
    return { tables: parts.length - 1, bare: bare };
  };
  const routesTables = bareTables(routesPanel);
  t.check(routesTables.tables === 1 && routesTables.bare === 0 &&
          routesPanel.indexOf('aria-label="Configured Routes"><table') >= 0,
          'D3. the Configured Routes table sits in the scrollable wrapper',
          JSON.stringify(routesTables));
  const pageTables = bareTables(page.split('<form')[0]);
  t.check(pageTables.tables >= 1 && pageTables.bare === 0,
          'D4. every table on the route page sits in the wrapper',
          JSON.stringify(pageTables));
  const listenerTab = XacmlPage.listenersBody(writer,
    { listenersCatalogue: {},
      listenerCertificates: { keyAlgorithms: ['ES256'],
                              defaultKeyAlg: 'ES256' } },
    { name: 'pep-1', listeners: [], listenerRows: [] });
  const listenerTables = bareTables(listenerTab);
  t.check(listenerTables.bare === 0,
          'D5. the Listener tab\'s table sits in the wrapper',
          JSON.stringify(listenerTables));
  // D6-D7: Methods and Mechanisms are row labels like their neighbours'
  // (`.formlabel`, styled as `.formrow label`), naming a role="group" of
  // their checkboxes.
  [['route page', form, 'pep-route-apps-page-orders-api'],
   ['Create a New Route', newPanel, 'pep-route-apps-new']]
    .forEach(function (one) {
      ['methods', 'mechanisms'].forEach(function (field) {
        const id = one[2] + '-' + field + '-label';
        const label = field === 'methods' ? 'Methods' : 'Mechanisms';
        t.check(new RegExp('<div class="formrow"><span class="formlabel ' +
                           'tipword" id="' + id + '"[^>]*>' + label +
                           '</span>' +
                           '<span role="group" aria-labelledby="' + id +
                           '"><label').test(one[1]),
                'D6. ' + one[0] + ': ' + label + ' is a row label naming ' +
                'the group of its boxes', one[1]);
      });
    });

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
