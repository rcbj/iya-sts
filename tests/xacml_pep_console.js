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
//   M. THE MANIFEST'S BUTTONS IN ONE ROW (rcbj, 2026-11-15): Save, Remove
//      behind a confirmation, Download (the stored document as
//      <pep>-proxy.json) and Load from file (into the editor, unsent).
//   B. NONE AND ALL AMONG THE METHODS (rcbj, 2026-11-15) on both route
//      forms: helpers with no name, never posted; the runtime's
//      wireCheckAll() ticks and unticks, and keeps both showing the state.
//   T. THE TRAILS (rcbj): a PEP's page is Admin console › XACML › Remote
//      PEPs › the PEP, and a route's adds › Reverse proxy › Configured
//      Routes › the route, each tab a crumb linking to that tab, built by
//      the runtime's drawView().
//   LS/LD/LT. THE LISTENER TAB'S SUB-TABS AND A LISTENER'S OWN PAGE (rcbj,
//      2026-11-15): Configured Listeners and Create a new listener; each
//      listener id, the environment's too, a link to a page laid out as a
//      route's, with its full configuration and the edit, renew and
//      remove controls; its trail; where a save and a removal land.
//   TR. THE TRAIL NAMES THE OPEN TAB (rcbj, 2026-11-15): a PEP's page's
//      trail ends at the tab and sub-tab its fragment opens, drawn again by
//      the runtime on every fragment change; /admin/xacml's too; the route
//      and listener pages keep theirs.
//   LF. CREATE A NEW LISTENER LAID OUT AS CREATE A NEW ROUTE (rcbj,
//      2026-11-15): one field per row under legends, the certificate fields
//      shown only for HTTPS, the environment's pair below in the same
//      layout, the listener page's edit form the same; ids kept whole.
//   K. NO TAB TRAPS (rcbj, 2026-11-15): every tab of a route page's three
//      rows links to the page it names, the current ones too, and the
//      runtime navigates on it; the panel opens with Back to routes, then
//      Route detail: <id> with the path beside it.
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
        mechanisms: ['session'], application: 'orders-app',
        authorization: { kind: 'policy', policy: 'orders-policy',
                         resource: '', actionModel: 'method', roles: {} },
        forwardCredentials: false, signals: true },
      { id: 'health', path: '/health', match: 'exact', methods: [],
        mechanisms: [], application: '',
        authorization: { kind: 'public', policy: 'pep-pep-1-health',
                         resource: 'https://pep.example:9543/health',
                         actionModel: 'method', roles: {} },
        forwardCredentials: false, signals: true }] };
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

  // -------------------------------------------------------------------------
  t.log.info('=== M. the Manifest\'s buttons, one row ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): "add a download button ... easy to save and transfer
  // between remote PEPs. Put all of the buttons on the same row."
  const actionRow = (manifest.match(
    /<div class="formrow pep-proxy-actions">([\s\S]*)<\/div>/) || [])[1] ||
    '';
  const hrefOf = (actionRow.match(
    /<a class="btn" download="pep-1-proxy\.json" href="data:application\/json;base64,([^"]+)"/) ||
    [])[1];
  const downloaded = hrefOf
    ? Buffer.from(hrefOf, 'base64').toString('utf8') : '';
  t.check(/<button type="submit" form="pep-proxy-edit" title="[^"]+">Save the configuration<\/button>/
            .test(actionRow) &&
          /<form method="post" action="\/admin\/xacml\/peps" class="inline"><input type="hidden" name="action" value="clear-pep-proxy">[\s\S]*<input type="checkbox" required>[\s\S]*>Remove the configuration<\/button><\/form>/
            .test(actionRow) &&
          !!hrefOf &&
          /<button type="button" class="secondary" data-load-file="pep-proxy-file" title="[^"]+">Load from file<\/button><input type="file" id="pep-proxy-file" hidden accept="\.json,application\/json" data-load-into="pep-proxy-doc">/
            .test(actionRow) &&
          manifest.indexOf('<form method="post" action="/admin/xacml/peps" ' +
                           'id="pep-proxy-edit">') >= 0 &&
          manifest.indexOf('<textarea name="proxy" id="pep-proxy-doc"') >= 0,
          'M1. Save, Remove (behind its confirmation), Download and Load ' +
          'from file in one row', actionRow);
  // `manifest` was drawn while the document had its publicBaseUrl.
  t.equal(downloaded, JSON.stringify(Object.assign({}, proxy,
    { publicBaseUrl: 'https://orders.example.test' }), null, 2) + '\n',
          'M2. Download is the stored document, pretty-printed, as ' +
          'pep-1-proxy.json');
  const noProxy = panelOf(XacmlPage.proxySection(writer,
    { name: 'pep-1', proxy: null, proxyRoutes: [] }),
    'xacml-pep-proxy-manifest');
  t.check(noProxy.indexOf('download=') < 0 &&
          noProxy.indexOf('clear-pep-proxy') < 0 &&
          noProxy.indexOf('data-load-file="pep-proxy-file"') >= 0,
          'M3. with nothing stored: nothing to download or remove; Load ' +
          'from file stays', noProxy);
  // Load from file, as the runtime wires it: the button opens the input,
  // and the chosen file's text is put in the editor, nothing sent.
  const listeners = {};
  const listenOn = function (who) {
    log.debug("Entering listenOn(). " + who);
    log.debug("Leaving listenOn().");
    return function (kind, fn) {
      listeners[who + ':' + kind] = fn;
    };
  };
  const box = { value: 'old' };
  let opened = 0;
  const fileInput = {
    files: null, value: 'C:\\fakepath\\pep-2-proxy.json',
    getAttribute: function () {
      return 'pep-proxy-doc';
    },
    click: function () {
      opened++;
    },
    addEventListener: listenOn('input')
  };
  const loadButton = {
    getAttribute: function () {
      return 'pep-proxy-file';
    },
    addEventListener: listenOn('button')
  };
  const LoadRuntime = require('../admin-ui/web_runtime');
  const loader = { dirty: false, env: { document: {
    querySelectorAll: function () {
      return [loadButton];
    },
    getElementById: function (id) {
      return id === 'pep-proxy-file' ? fileInput
        : id === 'pep-proxy-doc' ? box : null;
    } } } };
  LoadRuntime.prototype.wireFileLoads.call(loader);
  listeners['button:click']();
  fileInput.files = [{ name: 'pep-2-proxy.json', text: async function () {
    return downloaded;
  } }];
  await listeners['input:change']();
  t.check(opened === 1 && box.value === downloaded && loader.dirty &&
          fileInput.value === '',
          'M4. Load from file puts the chosen file in the editor and ' +
          'sends nothing', JSON.stringify({ opened: opened,
                                            dirty: loader.dirty }));

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
  // Every set-pep-route form of the page, its four editing tabs in order
  // (rcbj, 2026-11-15: one form per tab).
  const form = page.split('name="action" value="set-pep-route"').slice(1)
    .join('');
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
  t.check(form.indexOf('accepted on save only for a public route') >= 0 &&
          /<select name="authzKind" data-panels="authz">/.test(form) &&
          /<option value="public"/.test(form) && !/name="public"/.test(form),
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
    apiJson: async function apiJson(method, path) {
      log.debug("Entering apiJson(). " + path);
      asked.push(method + ' ' + path);
      log.debug("Leaving apiJson().");
      return { status: 200, json: {
        applications: [{ identifier: 'billing-app', name: 'Billing' },
                       { identifier: 'orders-app', name: 'Orders' }],
        page: 1, pages: 3, matched: 12 } };
    },
    drawView: function drawView() {
      log.debug("Entering drawView().");
      log.debug("Leaving drawView().");
      return null;
    },
    env: { document: { getElementById: function () {
      return null;
    } } }
  };
  const typed = { action: 'set-pep-route', name: 'pep-1', id: 'typed-id',
                  path: '/typed', match: 'exact', methods: ['GET', 'POST'],
                  mechanisms: 'oauth2', application: '',
                  authzKind: 'policy', authzResource: 'urn:typed',
                  authzPolicyActionModel: 'crud', position: '1',
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
          /<option value="crud" selected>/.test(chosenHtml) &&
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
                           { id: 'orders-api', authzKind: 'policy',
                             authzPolicy: 'orders-policy',
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
    '<a class="first" href="' + x + 'xacml-tab-peps">Remote PEPs</a>' +
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
          '<a class="first" href="' + pepUrl + 'xacml-pep-tab-proxy">' +
          'Reverse proxy</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-signals">Signal streams</a>' +
          '</nav>',
          'W1. the PEP page\'s tabs, Reverse proxy current, the others ' +
          'links to the PEP page');
  t.equal(bars[1] || '', '<nav class="tabbar subbar" aria-label="Reverse ' +
          'proxy"><a class="first" href="' + pepUrl +
          'xacml-pep-proxy-routes">Configured ' +
          'Routes</a><a href="' + pepUrl + 'xacml-pep-proxy-new-route">Create ' +
          'a New Route</a><a href="' + pepUrl + 'xacml-pep-proxy-manifest">' +
          'Manifest</a></nav>',
          'W2. the Reverse proxy sub-tabs, Configured Routes current');
  // The fourth row is the route's own tabs (RT, below): three sub-panels
  // inside Configured Routes, the route's sections.
  t.check(bars.length === 3 &&
          (page.match(/<section class="tabpanel/g) || []).length === 2 &&
          page.indexOf('<section class="tabpanel first" ' +
                      'id="xacml-pep-tab-proxy">') >= 0 &&
          (page.match(/<div class="subpanel/g) || []).length === 7 &&
          page.indexOf('<div class="subpanel first" ' +
                      'id="xacml-pep-proxy-routes">') >= 0 &&
          page.slice(page.indexOf('id="xacml-pep-proxy-routes"'))
            .indexOf('value="set-pep-route"') >= 0,
          'W3. one panel drawn in each row above, the route inside ' +
          'Configured Routes', page);
  const reader = XacmlPage.routeDetail(kit.context({}, false), {
    pep: 'pep-1', route: 'orders-api', found: true,
    peps: [{ name: 'pep-1', proxy: proxy }],
    routeDetail: { found: true, route: proxy.routes[0], usable: true,
                   position: 0, count: 2, servedBy: [] } });
  t.check(reader.indexOf('xacml-pep-proxy-new-route') < 0 &&
          reader.indexOf('xacml-pep-proxy-manifest') >= 0 &&
          reader.indexOf('<a class="first" href="' + pepUrl +
                         'xacml-pep-tab-proxy">') >= 0,
          'W4. a reader\'s route page keeps the tabs, without Create a New ' +
          'Route', reader);
  const readerBars = reader.match(
    /<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) || [];
  t.check(readerBars.length === 4 && readerBars[0] === xacmlBar,
          'X3. a reader\'s route page draws the same three rows, and the ' +
          'route\'s own',
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
  t.check(pepBars.length === 4 &&
          /^<nav class="tabbar subbar" aria-label="Listener">/
            .test(pepBars[2] || '') &&
          /^<nav class="tabbar subbar" aria-label="Reverse proxy">/
            .test(pepBars[3] || '') &&
          panelOf(pepPage.split('id="xacml-pep-tab-proxy">')[1] || '',
                  'xacml-pep-proxy-routes') !== '' &&
          pepPage.indexOf('<section class="tabpanel first" ' +
                          'id="xacml-tab-peps"><div class="tabs ' +
                          'xacml-pep-pages">') >= 0,
          'X6. two rows of tabs; the Listener and Reverse proxy sub-tabs ' +
          'inside their tabs',
          String(pepBars.length));

  // -------------------------------------------------------------------------
  t.log.info('=== K. no tab on a route\'s page traps the reader ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): "clicking on that leaves you trapped on the route
  // detail sub-subtab". The current tabs were `#<id>`, fragments of the
  // route's own page; every tab of the three rows now links to the page
  // it names, and the runtime navigates on each.
  const ConsoleRuntimeK = require('../admin-ui/web_runtime');
  const tabHrefs = function (html) {
    log.debug("Entering tabHrefs().");
    const out = [];
    (html.match(/<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) || [])
      .forEach(function (bar) {
        const re = /<a[^>]* href="([^"]*)"[^>]*>([^<]*)<\/a>/g;
        let m = re.exec(bar);
        while (m) {
          out.push({ href: m[1].replace(/&amp;/g, '&'), label: m[2] });
          m = re.exec(bar);
        }
      });
    log.debug("Leaving tabHrefs().");
    return out;
  };
  // The three rows the page was opened from; the fourth, the route's own
  // tabs, is fragments of this page (RT, below).
  const routeTabs = tabHrefs(page).filter(function (one) {
    return one.href.charAt(0) !== '#';
  });
  const ownTabs = tabHrefs(page).filter(function (one) {
    return one.href.charAt(0) === '#';
  });
  t.check(routeTabs.length === 16 && routeTabs.every(function (one) {
    return one.href.indexOf('/admin/xacml') === 0;
  }) && ownTabs.map(function (one) {
    return one.href;
  }).join() === '#xacml-route-tab-metadata,#xacml-route-tab-settings,' +
    '#xacml-route-tab-authentication,#xacml-route-tab-authorization,' +
    '#xacml-route-tab-identity,#xacml-route-tab-remove',
  'K1. every tab of the route page\'s three rows is a link to another ' +
          'page, the current ones included; the route\'s own row is its ' +
          'fragments', JSON.stringify(routeTabs.concat(ownTabs)));
  t.check(routeTabs.some(function (one) {
    return one.label === 'Configured Routes' &&
      one.href === '/admin/xacml/pep?pep=pep-1#xacml-pep-proxy-routes';
  }) && routeTabs.some(function (one) {
    return one.label === 'Remote PEPs' &&
      one.href === '/admin/xacml#xacml-tab-peps';
  }), 'K2. Configured Routes links to the PEP page\'s sub-tab, Remote PEPs ' +
          'to the XACML page\'s list');
  // The runtime's click handler, against a route page's address.
  const clicked = function (href) {
    log.debug("Entering clicked(). " + href);
    const went = [];
    let prevented = false;
    const at = new URL('https://sts.example.test/admin/xacml/pep/route' +
                       '?pep=pep-1&route=orders-api');
    const link = { tagName: 'A', target: '', parentElement: null,
                   getAttribute: function (name) {
                     return name === 'href' ? href : null;
                   },
                   hasAttribute: function () {
                     return false;
                   } };
    ConsoleRuntimeK.prototype.onClick.call({
      env: { location: at }, prefix: '', accounts: { enabled: false },
      view: null, consolePath: ConsoleRuntimeK.prototype.consolePath,
      go: function (to) {
        went.push(to);
      } }, { defaultPrevented: false, button: 0, target: link,
             preventDefault: function () {
               prevented = true;
             } });
    log.debug("Leaving clicked().");
    return { went: went, prevented: prevented, hash: at.hash };
  };
  t.check(routeTabs.every(function (one) {
    const done = clicked(one.href);
    return done.prevented && done.went.length === 1 &&
      done.went[0] === one.href;
  }), 'K3. the runtime navigates on every tab with an href, to its page ' +
          'and fragment');
  t.check(ownTabs.length === 6 && ownTabs.every(function (one) {
    const done = clicked(one.href);
    return done.went.length === 0 && done.hash === one.href;
  }), 'K3b. a tab of the route\'s own row only moves the fragment, so the ' +
          'trail and the marks follow it (RT)');
  const fragmentOnly = clicked('#xacml-pep-proxy-routes');
  t.check(fragmentOnly.went.length === 0 &&
          fragmentOnly.hash === '#xacml-pep-proxy-routes',
          'K4. a fragment of the route page only moves the fragment: the ' +
          'trap the hrefs replace');
  const routesPanelK = panelOf(page, 'xacml-pep-proxy-routes');
  const backAt = routesPanelK.indexOf('<p class="drillback"><a href="' +
    '/admin/xacml/pep?pep=pep-1#xacml-pep-proxy-routes">' +
    '← Back to routes</a></p>');
  const titleAt = routesPanelK.indexOf('<div class="drilltitle"><h2>' +
    'Route detail: orders-api</h2><span class="drillaside"><code>/api' +
    '</code></span></div>');
  t.check(backAt >= 0 && titleAt > backAt &&
          routesPanelK.slice(0, backAt).indexOf('<form') < 0 &&
          routesPanelK.slice(0, backAt).indexOf('<h') < 0 &&
          routesPanelK.indexOf('One route of this PEP') > titleAt,
          'K5. the route\'s panel opens with Back to routes, then its title ' +
          'and path, then the lead', routesPanelK.slice(0, 900));
  const readerPanel = panelOf(reader, 'xacml-pep-proxy-routes');
  t.check(readerPanel.indexOf('class="drillback"') >= 0 &&
          readerPanel.indexOf('Route detail: orders-api') >= 0 &&
          tabHrefs(reader).filter(function (one) {
            return one.href.charAt(0) === '#';
          }).map(function (one) {
            return one.href;
          }).join() === '#xacml-route-tab-metadata',
          'K6. a reader\'s route page: the same title, back link and tabs');
  // The kit, for any drill-down drawn inside a parent's tabs: a panel with
  // both `href` and `html` is drawn and its tab links back.
  const kitTabs = kit.tabbedPanels('k', [
    { id: 'k-a', label: 'A', href: '/admin/p#k-a' },
    { id: 'k-b', label: 'B', href: '/admin/p#k-b', html: '<p>here</p>' }]);
  t.check(kitTabs.indexOf('<a class="first" href="/admin/p#k-b">B</a>') >= 0 &&
          kitTabs.indexOf('<section class="tabpanel first" id="k-b">') >= 0 &&
          kitTabs.indexOf('id="k-a"') < 0,
          'K7. the kit draws a panel with an href and links its tab there',
          kitTabs);

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
  // The route page's four forms, one per tab (rcbj, 2026-11-15): Settings
  // (id, Matching, the application, Order), Authentication, Authorization
  // (Methods with the choice), Identity sent to backend (forwarding and
  // the identity), each its own Save.
  t.equal(fieldsOf(form), 'id | path | match | application | position | ' +
          'mechanisms | signals | multipleAccounts | ' +
          'methods+methodsGiven | authzKind | authzResource | authzPolicy | ' +
          'authzPolicyActionModel | authzActionModel | ' +
          'forwardCredentials | mode | ' +
          'headerName+headerClaim | headerName+headerClaim | separator',
          'F1. the route page\'s forms: one field per line, one header ' +
          '(name, claim) per line, each on its tab');
  t.equal(legendsOf(form), 'Matching | Order',
          'F2. the route page\'s Settings groups Matching and Order; the ' +
          'other tabs are one subject each');
  t.equal(fieldsOf(newPanel), 'id | path | match | methods+methodsGiven | ' +
          'mechanisms | forwardCredentials | signals | multipleAccounts | ' +
          'application | authzKind | authzResource | authzPolicy | ' +
          'authzPolicyActionModel | authzActionModel | position',
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
  t.log.info('=== B. None and All among the route forms\' Methods ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): "Add a None checkbox and an All checkbox. Clicking
  // None deselects everything else. Clicking All deselects None and selects
  // all other options." Helpers only: never posted as a method.
  const helperOf = function (html, attr) {
    log.debug("Entering helperOf(). " + attr);
    const m = new RegExp('<label[^>]*><input type="checkbox" ' + attr +
                         '="methods"[^>]*> ([^<]*)</label>').exec(html);
    log.debug("Leaving helperOf().");
    return m;
  };
  const methodsGroup = function (html) {
    log.debug("Entering methodsGroup().");
    const part = html.split('-methods-label"><label')[1];
    log.debug("Leaving methodsGroup().");
    return part === undefined ? '' : '<label' + part.split('</span>')[0];
  };
  [['route page', form], ['Create a New Route', newPanel]]
    .forEach(function (one) {
      const group = methodsGroup(one[1]);
      const none = helperOf(group, 'data-check-none');
      const all = helperOf(group, 'data-check-all');
      t.check(none && none[1] === 'None' && all && all[1] === 'All' &&
              group.indexOf('data-check-none') <
                group.indexOf('data-check-all') &&
              group.indexOf('data-check-all') < group.indexOf('value="GET"'),
              'B1. ' + one[0] + ': Methods draws None, then All, then the ' +
              'methods', group);
      const helpers = group.match(/<input[^>]*data-check-[^>]*>/g) || [];
      const posted = (group.match(/<input[^>]*name="methods"[^>]*>/g) || [])
        .map(function (input) {
          return /value="([^"]*)"/.exec(input)[1];
        });
      t.check(helpers.length === 2 && helpers.every(function (input) {
        return input.indexOf(' name=') < 0 && input.indexOf('value=') < 0;
      }) && posted.join(',') === 'GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS',
              'B2. ' + one[0] + ': None and All carry no name, so the only ' +
              'methods posted are the seven real ones',
              JSON.stringify({ helpers: helpers, posted: posted }));
      const noneLabel = /<label([^>]*)><input type="checkbox" data-check-none/
        .exec(group);
      t.check(!!noneLabel &&
              noneLabel[1].indexOf('deny-all') >= 0 &&
              noneLabel[1].indexOf('any method') < 0,
              'B3. ' + one[0] + ': None\'s tooltip says the validator ' +
              'takes no method as deny-all, not any method', group);
    });
  const checkedOf = function (html, attr) {
    log.debug("Entering checkedOf(). " + attr);
    const m = new RegExp('<input type="checkbox" ' + attr +
                         '="methods"( checked)?>').exec(html);
    log.debug("Leaving checkedOf().");
    return !!(m && m[1]);
  };
  const drawnWith = function (methods) {
    log.debug("Entering drawnWith().");
    log.debug("Leaving drawnWith().");
    return methodsGroup(XacmlPage.routeFields(tr, {},
      { path: '/', match: 'prefix', methods: methods, mechanisms: [] }, 0,
      'b', false));
  };
  const allSeven = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE',
                    'OPTIONS'];
  t.check(checkedOf(drawnWith([]), 'data-check-none') &&
          !checkedOf(drawnWith([]), 'data-check-all') &&
          !checkedOf(drawnWith(['GET']), 'data-check-none') &&
          !checkedOf(drawnWith(['GET']), 'data-check-all') &&
          checkedOf(drawnWith(allSeven), 'data-check-all') &&
          !checkedOf(drawnWith(allSeven), 'data-check-none'),
          'B4. drawn ticked to match: None for no method, All for every ' +
          'one, neither for some', drawnWith(['GET']));
  // The runtime's wiring, on a fake form: the seven boxes, None and All.
  const CheckRuntime = require('../admin-ui/web_runtime');
  const fakeBox = function (name, attrs) {
    log.debug("Entering fakeBox(). " + name);
    const handlers = [];
    const box = { name: name, checked: false, form: null,
      getAttribute: function (a) {
        return Object.prototype.hasOwnProperty.call(attrs, a)
          ? attrs[a] : null;
      },
      addEventListener: function (kind, fn) {
        if (kind === 'change') {
          handlers.push(fn);
        }
      },
      click: function () {
        box.checked = !box.checked;
        handlers.forEach(function (fn) {
          fn();
        });
      } };
    log.debug("Leaving fakeBox().");
    return box;
  };
  const methodBoxes = allSeven.map(function () {
    return fakeBox('methods', {});
  });
  const noneBox = fakeBox('', { 'data-check-none': 'methods' });
  const allBox = fakeBox('', { 'data-check-all': 'methods' });
  const mechanismBox = fakeBox('mechanisms', {});
  const fakeForm = { querySelectorAll: function () {
    return [noneBox, allBox].concat(methodBoxes, [mechanismBox]);
  } };
  [noneBox, allBox].concat(methodBoxes, [mechanismBox])
    .forEach(function (b) {
      b.form = fakeForm;
    });
  methodBoxes[0].checked = true;
  mechanismBox.checked = true;
  // The page's query answers only the switches its selector names.
  CheckRuntime.prototype.wireCheckAll.call({ env: { document: {
    querySelectorAll: function (selector) {
      return [noneBox, allBox].filter(function (sw) {
        return sw === noneBox
          ? selector.indexOf('input[data-check-none]') >= 0
          : selector.indexOf('input[data-check-all]') >= 0;
      });
    } } } });
  const state = function () {
    log.debug("Entering state().");
    log.debug("Leaving state().");
    return (noneBox.checked ? 'N' : '-') + (allBox.checked ? 'A' : '-') +
      ' ' + methodBoxes.map(function (b) {
        return b.checked ? '1' : '0';
      }).join('');
  };
  const atStart = state();
  allBox.click();
  const afterAll = state();
  noneBox.click();
  const afterNone = state();
  t.check(atStart === '-- 1000000' && afterAll === '-A 1111111' &&
          afterNone === 'N- 0000000' && mechanismBox.checked,
          'B5. All ticks every method and unticks None; None unticks ' +
          'every method and All; another field\'s boxes are untouched',
          JSON.stringify([atStart, afterAll, afterNone]));
  methodBoxes[2].click();
  const oneByHand = state();
  methodBoxes.forEach(function (b) {
    if (!b.checked) {
      b.click();
    }
  });
  const everyByHand = state();
  methodBoxes[6].click();
  const oneOff = state();
  t.check(oneByHand === '-- 0010000' && everyByHand === '-A 1111111' &&
          oneOff === '-- 1111110',
          'B6. ticking a method by hand unticks None; ticking the last ' +
          'ticks All; unticking one unticks All',
          JSON.stringify([oneByHand, everyByHand, oneOff]));
  methodBoxes.forEach(function (b) {
    if (b.checked) {
      b.click();
    }
  });
  const noneByHand = state();
  noneBox.click();
  const noneUnticked = state();
  t.check(noneByHand === 'N- 0000000' && noneUnticked === 'N- 0000000',
          'B7. unticking every method by hand ticks None, and None stays ' +
          'ticked while no method is', JSON.stringify([noneByHand,
                                                       noneUnticked]));

  // The route page's note under the application names Clear, and says it
  // is accepted on save only for a public route (Clear's own tooltip).
  t.check(page.indexOf('make the route public') < 0 &&
          page.indexOf('Clear empties it, but a route that checks ' +
                       'credentials must name an application, so Clear is ' +
                       'accepted on save only for a public route.') >= 0,
          'B8. the application note names Clear, and when a save takes it',
          page);

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
          '/admin/xacml/pep?pep=pep-1#xacml-pep-tab-proxy | ' +
          'Configured Routes -> ' +
          '/admin/xacml/pep?pep=pep-1#xacml-pep-proxy-routes | ' +
          'orders-api',
          'T2. a route\'s page: Admin console › XACML › Remote PEPs › the ' +
          'PEP › Reverse proxy › Configured Routes › the route');

  // -------------------------------------------------------------------------
  t.log.info('=== LS/LD/LT. the Listener sub-tabs and a listener\'s page ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): Configured Listeners and Create a new listener, laid
  // out as the Reverse proxy sub-tabs; each listener id a link to its own
  // page, the environment's four read-only, drawn as a route's page is.
  const pub = { id: 'public-https', protocol: 'https', purpose: 'proxy',
                address: '0.0.0.0', port: 8443,
                dnsNames: ['app.example.test'], ipAddresses: ['10.0.0.5'],
                keyAlg: 'ec-p384', renew: 1 };
  const pubRow = { id: 'public-https', source: 'service', protocol: 'https',
    purpose: 'proxy', definition: pub,
    reported: { state: 'listening', reason: 'none', address: '0.0.0.0',
      port: 8443, renew: 1,
      certificate: { subject: 'CN=pep-1', subjectAltName: 'DNS:app.example.test',
        issuer: 'CN=Remote PEP listeners', validFrom: '2026-11-01',
        validTo: '2027-11-01', serialHex: '0A1B', fingerprint256: 'AB:CD' } } };
  const envHttp = envRow('api-http', 'http', 'PEP_HTTP', null);
  const lpep = { name: 'pep-1', proxy: proxy, proxyRoutes: [],
                 listeners: [pub], listenersInUse: { at: 'x' },
                 listenerRows: [envHttp, pubRow] };
  const lJson = { pep: 'pep-1', found: true, applicationChoices: [],
    listenersCatalogue: { keyAlgorithms: ['ec-p256', 'ec-p384'],
                          defaultKeyAlg: 'ec-p256' },
    listenerCertificates: { keyAlgorithms: ['ES256'],
                            defaultKeyAlg: 'ES256' },
    peps: [lpep] };
  const lTab = XacmlPage.listenersBody(writer, lJson, lpep);
  const lSub = (lTab.match(/<nav class="tabbar subbar"[^>]*>[\s\S]*?<\/nav>/) ||
                [''])[0];
  t.equal(lSub, '<nav class="tabbar subbar" aria-label="Listener"><a ' +
          'class="first" href="#xacml-pep-listeners-configured">Configured ' +
          'Listeners</a><a href="#xacml-pep-listeners-new">Create a new ' +
          'listener</a></nav>',
          'LS1. the Listener tab\'s sub-tabs on the PEP page, each its anchor');
  const lConfigured = panelOf(lTab, 'xacml-pep-listeners-configured');
  const lNew = panelOf(lTab, 'xacml-pep-listeners-new');
  t.check(lConfigured.indexOf('<a href="/admin/xacml/pep/listener?pep=pep-1' +
                              '&amp;listener=public-https"><code>' +
                              'public-https</code></a>') >= 0 &&
          lConfigured.indexOf('<a href="/admin/xacml/pep/listener?pep=pep-1' +
                              '&amp;listener=api-http"><code>api-http' +
                              '</code></a>') >= 0 &&
          lConfigured.indexOf('<form') < 0,
          'LS2. Configured Listeners: the table, every id (the environment\'s ' +
          'too) a link to its page, no form', lConfigured);
  t.check(lNew.indexOf('value="set-pep-listener"') >= 0 &&
          lNew.indexOf('Define a listener') >= 0 &&
          lNew.indexOf('The environment\'s HTTPS pair') >
            lNew.indexOf('Define a listener') &&
          lNew.indexOf('remove-pep-listener') < 0 &&
          lNew.indexOf('renew-pep-listener-certificate') < 0,
          'LS3. Create a new listener: the definition form, then the ' +
          'environment\'s HTTPS pair; no edit, renew or remove', lNew);
  const lReaderTab = XacmlPage.listenersBody(kit.context({}, false), lJson,
                                             lpep);
  t.check(panelOf(lReaderTab, 'xacml-pep-listeners-new')
            .indexOf('set-pep-listener') < 0 &&
          panelOf(lReaderTab, 'xacml-pep-listeners-new')
            .indexOf('The environment\'s HTTPS pair') >= 0,
          'LS4. a reader\'s Create a new listener holds the pair, no form');

  const lPage = XacmlPage.listenerDetail(
    kit.context({ pep: 'pep-1', listener: 'public-https' }, true), lJson);
  const lBars = lPage.match(/<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) ||
    [];
  t.equal(lBars[0] || '', xacmlBar,
          'LD1. a listener\'s page: the XACML page\'s tabs first');
  t.equal(lBars[1] || '', '<nav class="tabbar" aria-label="Sections of this ' +
          'page"><a href="' + pepUrl + 'xacml-pep-tab-overview">Overview</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-decisions">Decisions</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-settings">Settings</a>' +
          '<a class="first" href="' + pepUrl + 'xacml-pep-tab-listener">' +
          'Listener</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-proxy">Reverse proxy</a>' +
          '<a href="' + pepUrl + 'xacml-pep-tab-signals">Signal streams</a>' +
          '</nav>',
          'LD2. the PEP page\'s tabs, Listener current, every one a link');
  t.equal(lBars[2] || '', '<nav class="tabbar subbar" aria-label="Listener">' +
          '<a class="first" href="' + pepUrl + 'xacml-pep-listeners-configured">' +
          'Configured Listeners</a><a href="' + pepUrl +
          'xacml-pep-listeners-new">Create a new listener</a></nav>',
          'LD3. the Listener sub-tabs, Configured Listeners current, both ' +
          'links to the PEP page');
  t.check(lBars.length === 3 && tabHrefs(lPage).every(function (one) {
    return one.href.indexOf('/admin/xacml') === 0;
  }) && tabHrefs(lPage).every(function (one) {
    const done = clicked(one.href);
    return done.prevented && done.went[0] === one.href;
  }), 'LD4. three rows, every tab a link the runtime navigates on');
  const lPanel = panelOf(lPage, 'xacml-pep-listeners-configured');
  const lBack = lPanel.indexOf('<p class="drillback"><a href="' +
    '/admin/xacml/pep?pep=pep-1#xacml-pep-listeners-configured">' +
    '← Back to listeners</a></p>');
  const lTitle = lPanel.indexOf('<div class="drilltitle"><h2>Listener ' +
    'detail: public-https</h2><span class="drillaside">HTTPS <code>' +
    '0.0.0.0:8443</code></span></div>');
  t.check(lBack >= 0 && lTitle > lBack &&
          lPanel.slice(0, lBack).indexOf('<h') < 0,
          'LD5. the panel opens with Back to listeners, then the title',
          lPanel.slice(0, 700));
  t.check(['app.example.test', '10.0.0.5', 'ec-p384', 'CN=pep-1',
           'CN=Remote PEP listeners', '2027-11-01', '0A1B', 'AB:CD',
           'listening', 'defined here', 'reverse proxy', '8443']
    .every(function (bit) {
      return lPanel.indexOf(bit) >= 0;
    }), 'LD6. the full configuration and what the PEP reported: names, ' +
          'key, certificate, state, source, purpose, port', lPanel);
  const lForms = lPanel.match(/<form\b[\s\S]*?<\/form>/g) || [];
  t.check(lForms.length === 3 &&
          /value="set-pep-listener"[\s\S]*name="id" value="public-https"/
            .test(lForms[0]) &&
          lForms[0].indexOf('value="0.0.0.0"') >= 0 &&
          lForms[0].indexOf('value="8443"') >= 0 &&
          lForms[0].indexOf('app.example.test') >= 0 &&
          lForms[1].indexOf('value="renew-pep-listener-certificate"') >= 0 &&
          lForms[2].indexOf('value="remove-pep-listener"') >= 0 &&
          /<input type="checkbox" required>/.test(lForms[2]),
          'LD7. the edit form filled from the definition, Renew, and Remove ' +
          'behind a required confirmation', lForms.join('\n'));
  const lEnv = XacmlPage.listenerDetail(
    kit.context({ pep: 'pep-1', listener: 'api-http' }, true), lJson);
  const lEnvPanel = panelOf(lEnv, 'xacml-pep-listeners-configured');
  t.check(lEnvPanel.indexOf('class="drillback"') >= 0 &&
          lEnvPanel.indexOf('Listener detail: api-http') >= 0 &&
          lEnvPanel.indexOf('<form') < 0 &&
          lEnvPanel.indexOf('PEP_PORT') >= 0 &&
          lEnvPanel.indexOf('PEP_HTTP') >= 0 &&
          lEnvPanel.indexOf('read-only') >= 0,
          'LD8. an environment listener\'s page: the same layout, read-only, ' +
          'naming the variables that set it', lEnvPanel);
  const lGone = XacmlPage.listenerDetail(
    kit.context({ pep: 'pep-1', listener: 'gone' }, true), lJson);
  t.check(lGone.indexOf('has no listener called gone') >= 0 &&
          lGone.indexOf('#xacml-pep-listeners-configured') >= 0,
          'LD9. a listener that is not there says so and leads back', lGone);
  t.equal(JSON.stringify(WebPages.operationQuery('/admin/xacml/pep/listener',
          { pep: 'pep-1', listener: 'public-https' })),
          JSON.stringify({ pep: 'pep-1' }),
          'LD10. the page asks its operation for the PEP alone: `listener` ' +
          'is the page\'s own (rule 7, #1476)');
  const lTrail = crumbsOf(trailOf('/admin/xacml/pep/listener',
    { pep: 'pep-1', listener: 'public-https' }));
  t.equal(lTrail, 'Admin console -> /admin | XACML -> /admin/xacml | ' +
          'Remote PEPs -> /admin/xacml#xacml-tab-peps | ' +
          'pep-1 -> /admin/xacml/pep?pep=pep-1 | ' +
          'Listener -> /admin/xacml/pep?pep=pep-1#xacml-pep-tab-listener | ' +
          'Configured Listeners -> ' +
          '/admin/xacml/pep?pep=pep-1#xacml-pep-listeners-configured | ' +
          'public-https',
          'LT1. a listener\'s page: Admin console › XACML › Remote PEPs › ' +
          'the PEP › Listener › Configured Listeners › the listener');
  const landed = function (back, action, fields) {
    log.debug("Entering landed(). " + action);
    log.debug("Leaving landed().");
    return WebAnswersModule.landing('/admin/xacml/peps', action, { ok: true },
                                    back, fields);
  };
  t.check(landed('/admin/xacml/pep?pep=pep-1#xacml-pep-listeners-new',
                 'set-pep-listener', { name: 'pep-1', id: 'pub2' }) ===
            '/admin/xacml/pep/listener?pep=pep-1&listener=pub2' &&
          landed('/admin/xacml/pep/listener?pep=pep-1&listener=pub2',
                 'set-pep-listener', { name: 'pep-1', id: 'pub2' }) ===
            '/admin/xacml/pep/listener?pep=pep-1&listener=pub2' &&
          landed('/admin/xacml/pep/listener?pep=pep-1&listener=pub2',
                 'remove-pep-listener', { name: 'pep-1', listener: 'pub2' }) ===
            '/admin/xacml/pep?pep=pep-1#xacml-pep-listeners-configured' &&
          landed('/admin/xacml/pep/listener?pep=pep-1&listener=pub2',
                 'renew-pep-listener-certificate',
                 { name: 'pep-1', listener: 'pub2' }) === null,
          'LT2. a new listener lands on its page, a save stays there, a ' +
          'removal lands on Configured Listeners, a renew stays put');

  // -------------------------------------------------------------------------
  t.log.info('=== TR. the trail names the open tab and sub-tab ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15), reversing "a tabbed page's own trail names no open
  // tab": Admin console › XACML › Remote PEPs › the PEP › Listener › Create
  // a new listener. The runtime reads the tab tree from the body it drew
  // (WebShell.tabTreeOf()) and draws the trail again for the fragment
  // (redrawTrail(), on every draw, hashchange and fragment popstate).
  const runtimeTrail = function (path, query, body, hash) {
    log.debug("Entering runtimeTrail(). " + path + hash);
    const drawn = {};
    const render = WebPages.render;
    WebPages.render = function () {
      return body;
    };
    try {
      ConsoleRuntime.prototype.drawView.call({
        view: { page: WebPages.pageFor(path), query: query, json: {} },
        me: { write: false }, t: tr,
        shell: { navLabels: { '/admin/xacml': 'XACML' } },
        draw: function (title, active, html, up) {
          drawn.title = title;
          drawn.active = active;
          drawn.html = html;
          drawn.up = up;
        } }, null);
    } finally {
      WebPages.render = render;
    }
    // The trail element the frame drew, which redrawTrail() replaces.
    const element = { outerHTML: '<p class="crumb"></p>' };
    const search = Object.keys(query).map(function (k) {
      return k + '=' + query[k];
    }).join('&');
    ConsoleRuntime.prototype.redrawTrail.call({
      trailOf: { title: drawn.title, active: drawn.active, up: drawn.up,
                 tree: WebShell.tabTreeOf(drawn.html) },
      env: { location: { pathname: path, search: search ? '?' + search : '',
                         hash: hash },
             document: { querySelector: function (sel) {
               return sel === '.card p.crumb' ? element : null;
             } } },
      shell: { navLabels: { '/admin/xacml': 'XACML' } }, t: tr, prefix: '',
      openTabsNow: ConsoleRuntime.prototype.openTabsNow,
      here: ConsoleRuntime.prototype.here,
      consolePath: ConsoleRuntime.prototype.consolePath });
    log.debug("Leaving runtimeTrail().");
    return crumbsOf(element.outerHTML);
  };
  const pepBase = 'Admin console -> /admin | XACML -> /admin/xacml | ' +
    'Remote PEPs -> /admin/xacml#xacml-tab-peps | ' +
    'pep-1 -> /admin/xacml/pep?pep=pep-1 | ';
  const pepQ = { pep: 'pep-1' };
  t.equal(runtimeTrail('/admin/xacml/pep', pepQ, pepPage,
                       '#xacml-pep-listeners-new'),
          pepBase + 'Listener -> #xacml-pep-tab-listener | ' +
          'Create a new listener',
          'TR1. Listener › Create a new listener: the PEP a link to its ' +
          'page, Listener to its anchor, the sub-tab the leaf');
  t.equal(runtimeTrail('/admin/xacml/pep', pepQ, pepPage,
                       '#xacml-pep-proxy-manifest'),
          pepBase + 'Reverse proxy -> #xacml-pep-tab-proxy | Manifest',
          'TR2. Reverse proxy › Manifest');
  const subPaths = {
    '': 'Overview',
    '#xacml-pep-tab-overview': 'Overview',
    '#xacml-pep-tab-decisions': 'Decisions',
    '#xacml-pep-tab-settings': 'Settings',
    '#xacml-pep-tab-listener': 'Listener -> #xacml-pep-tab-listener | ' +
      'Configured Listeners',
    '#xacml-pep-listeners-configured': 'Listener -> ' +
      '#xacml-pep-tab-listener | Configured Listeners',
    '#xacml-pep-tab-proxy': 'Reverse proxy -> #xacml-pep-tab-proxy | ' +
      'Configured Routes',
    '#xacml-pep-proxy-routes': 'Reverse proxy -> #xacml-pep-tab-proxy | ' +
      'Configured Routes',
    '#xacml-pep-proxy-new-route': 'Reverse proxy -> #xacml-pep-tab-proxy | ' +
      'Create a New Route',
    '#xacml-pep-tab-signals': 'Signal streams',
    '#no-such-anchor': 'Overview'
  };
  const subMisses = Object.keys(subPaths).filter(function (hash) {
    return runtimeTrail('/admin/xacml/pep', pepQ, pepPage, hash) !==
      pepBase + subPaths[hash];
  });
  t.check(subMisses.length === 0,
          'TR3. every tab and sub-tab of a PEP\'s page is named; with no ' +
          'fragment, or one the page lacks, the first (Overview), and a ' +
          'tab alone names its first sub-tab', subMisses.map(function (h) {
            return h + ' => ' + runtimeTrail('/admin/xacml/pep', pepQ,
                                             pepPage, h);
          }).join('\n'));
  // AN ANCHOR INSIDE A PANEL opens that panel's tabs: a listener's row.
  const lPepPage = XacmlPage.pepDetail(writer, lJson);
  t.equal(runtimeTrail('/admin/xacml/pep', pepQ, lPepPage,
                       '#pep-listener-public-https'),
          pepBase + 'Listener -> #xacml-pep-tab-listener | ' +
          'Configured Listeners',
          'TR4. an anchor inside a sub-tab names the tab and sub-tab that ' +
          'hold it');
  // /admin/xacml's own tabs: XACML › the tab.
  const xacmlBody = kit.tabbedPanels('xacml-pages',
    XacmlPage.xacmlTabs(tr).map(function (one) {
      return Object.assign({}, one, { html: '<p>' + one.id + '</p>' });
    }));
  t.equal(runtimeTrail('/admin/xacml', {}, xacmlBody, '#xacml-tab-peps'),
          'Admin console -> /admin | XACML -> /admin/xacml | Remote PEPs',
          'TR5. /admin/xacml: XACML › Remote PEPs, XACML a link to the page');
  t.equal(runtimeTrail('/admin/xacml', {}, xacmlBody, ''),
          'Admin console -> /admin | XACML -> /admin/xacml | Metadata',
          'TR6. /admin/xacml with no fragment: its first tab');
  // A DRILL-DOWN'S TABS ARE LINKS TO OTHER PAGES: its trail is already
  // full and gains nothing from them, whatever the fragment. A route's page
  // has a fourth row of its own (RT, below), whose open tab ends the trail.
  const routeOwn = routeTrail.replace(/orders-api$/, 'orders-api -> ' +
    '/admin/xacml/pep/route?pep=pep-1&route=orders-api | Metadata');
  t.check(runtimeTrail('/admin/xacml/pep/route',
            { pep: 'pep-1', route: 'orders-api' }, page, '') === routeOwn &&
          runtimeTrail('/admin/xacml/pep/route',
            { pep: 'pep-1', route: 'orders-api' }, page,
            '#xacml-pep-proxy-routes') === routeOwn &&
          runtimeTrail('/admin/xacml/pep/listener',
            { pep: 'pep-1', listener: 'public-https' }, lPage, '') ===
            lTrail,
          'TR7. the route and listener pages keep their trails (T2, LT1), ' +
          'the route\'s ending in its first tab',
          runtimeTrail('/admin/xacml/pep/route',
            { pep: 'pep-1', route: 'orders-api' }, page, ''));
  // A page with no tabs keeps its one leaf.
  t.equal(runtimeTrail('/admin/xacml', {}, '<p>no tabs</p>', '#x'),
          'Admin console -> /admin | XACML',
          'TR8. a page with no tabs: the trail ends at the page');
  // The handlers that call it: a fragment change draws the trail again.
  const runtimeSource = require('fs').readFileSync(require.resolve(
    '../admin-ui/web_runtime'), 'utf8');
  const onHash = /addEventListener\('hashchange', function \(\) \{([\s\S]*?)\}\);/
    .exec(runtimeSource);
  t.check(!!onHash && /redrawTrail\(\)/.test(onHash[1]) &&
          /tabTreeOf\(inner\)/.test(runtimeSource) &&
          /tabs: this\.openTabsNow\(\)/.test(runtimeSource),
          'TR9. the runtime draws the trail from the body\'s tab tree, and ' +
          'again on every hashchange', onHash ? onHash[1] : '');

  // -------------------------------------------------------------------------
  t.log.info('=== LF. Create a new listener laid out as Create a New ' +
             'Route ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): "the UI on the 'Create a new listener' is terrible.
  // Organize and style it similar to the 'Create a route' sub-subtab".
  const lNewForms = lNew.match(/<form\b[\s\S]*?<\/form>/g) || [];
  const defForm = lNewForms[0] || '';
  const legendsIn = function (html) {
    log.debug("Entering legendsIn().");
    const out = [];
    const re = /<legend>([^<]*)<\/legend>/g;
    let m = re.exec(html);
    while (m) {
      out.push(m[1]);
      m = re.exec(html);
    }
    log.debug("Leaving legendsIn().");
    return out.join(' | ');
  };
  // Each row's one control, by its name.
  const rowsOf = function (html) {
    log.debug("Entering rowsOf().");
    const out = [];
    (html.match(/<div class="formrow">[\s\S]*?<\/div>/g) || [])
      .forEach(function (one) {
        const names = one.match(/ name="[^"]*"/g) || [];
        out.push(names.length === 1 ? names[0].slice(7, -1)
          : (/<button type="submit"/.test(one) ? 'button'
             : names.length + ' controls'));
      });
    log.debug("Leaving rowsOf().");
    return out.join(' ');
  };
  t.equal(legendsIn(defForm), 'Listener | Address | Certificate (HTTPS only)',
          'LF1. the definition form\'s legends: Listener, Address, ' +
          'Certificate (HTTPS only)');
  t.equal(rowsOf(defForm),
          'id protocol purpose address port dnsNames ipAddresses keyAlg ' +
          'button',
          'LF2. one field per .formrow, then the button in a row of its own',
          defForm);
  t.check(/^<form [^>]*><input type="hidden" name="action" value="set-pep-listener"><input type="hidden" name="name" value="pep-1"><button type="submit" class="default-submit"/
            .test(defForm) &&
          (defForm.match(/<div class="formrow"><label title="[^"]+"/g) ||
           []).length === 8,
          'LF3. the hidden default submit first, every label with its ' +
          'tooltip', defForm.slice(0, 600));
  const certSet = /<fieldset class="pep-listener-cert"([^>]*)>/.exec(defForm);
  t.check(/<select name="protocol" data-panels="listenerProtocol">/
            .test(defForm) && !!certSet &&
          /data-panel-of="listenerProtocol" data-panel="https"$/
            .test(certSet[1]),
          'LF4. the certificate fields are the protocol select\'s HTTPS ' +
          'panel, shown for HTTPS', certSet ? certSet[1] : defForm);
  const plainForm = XacmlPage.listenerForm(tr, lJson, 'pep-1',
    { id: 'plain', protocol: 'http', purpose: 'api', address: '0.0.0.0',
      port: 8080 });
  t.check(/<fieldset class="pep-listener-cert"[^>]* hidden>/
            .test(plainForm) &&
          plainForm.indexOf('<input type="hidden" name="id" value="plain">') >=
            0 &&
          /<span class="formlabel tipword" title="[^"]+">Id<\/span> <code>plain<\/code>/
            .test(plainForm) &&
          legendsIn(plainForm) ===
            'Listener | Address | Certificate (HTTPS only)',
          'LF5. a defined HTTP listener\'s form: the certificate fields ' +
          'hidden, the id fixed, the same legends', plainForm);
  const pairAt = lNew.indexOf('<h3>The environment\'s HTTPS pair</h3>');
  const pairForm = lNewForms[1] || '';
  t.check(pairAt > lNew.indexOf(defForm) &&
          lNew.indexOf(pairForm) > pairAt &&
          /value="issue-pep-certificate"[\s\S]*class="default-submit"/
            .test(pairForm) &&
          legendsIn(pairForm) ===
            'Certificate issued | Issue a new certificate' &&
          rowsOf(pairForm) === '0 controls dnsNames ipAddresses keyAlg button',
          'LF6. the environment\'s HTTPS pair below it, titled, laid out ' +
          'the same way', pairForm);
  const readerNew = panelOf(lReaderTab, 'xacml-pep-listeners-new');
  t.check(readerNew.indexOf('<form') < 0 &&
          legendsIn(readerNew) === 'Certificate issued' &&
          readerNew.indexOf('none issued') >= 0,
          'LF7. a reader sees the pair as issued, under its legend', readerNew);
  const editForm = (lPanel.match(/<form\b[\s\S]*?<\/form>/g) || [])[0] || '';
  t.check(legendsIn(editForm) ===
            'Listener | Address | Certificate (HTTPS only)' &&
          rowsOf(editForm) === '0 controls protocol purpose address port ' +
            'dnsNames ipAddresses keyAlg button' &&
          editForm.indexOf('Save the listener</button></div></form>') > 0,
          'LF8. a listener\'s page edits it in the same layout', editForm);
  const adminSource = require('fs').readFileSync(require.resolve(
    '../admin-ui/admin'), 'utf8');
  t.check(lConfigured.indexOf('<th class="pep-listener-id"><a href=') >= 0 &&
          adminSource.indexOf('th.pep-listener-id{white-space:nowrap}') >= 0,
          'LF9. Configured Listeners keeps each id whole (nowrap), inside ' +
          'the table\'s sideways scroller');

  // -------------------------------------------------------------------------
  t.log.info('=== Z. the Authorization section (#1760) ===');
  // -------------------------------------------------------------------------
  // rcbj 2026-11-15: two approaches and Public, one selector with the
  // matching fields below it; a search for the policy and for each
  // action's role, the Application field's pattern.
  writer.json = { peps: [{ name: 'pep-1',
    proxyResourceBase: { base: 'https://pep.example:9543',
                         source: 'publicBaseUrl' } }] };
  const newZ = panelOf(XacmlPage.proxySection(writer,
    { name: 'pep-1', proxy: proxy, proxyRoutes: [],
      proxyResourceBase: { base: 'https://pep.example:9543',
                           source: 'publicBaseUrl' } }),
    'xacml-pep-proxy-new-route');
  const kindSelect = /<select name="authzKind" data-panels="authz">([\s\S]*?)<\/select>/
    .exec(newZ);
  t.check(!!kindSelect &&
          /^<option value="" selected>/.test(kindSelect[1]) &&
          (kindSelect[1].match(/<option /g) || []).length === 4 &&
          /value="policy"/.test(kindSelect[1]) &&
          /value="simple"/.test(kindSelect[1]) &&
          /value="public"/.test(kindSelect[1]),
          'Z1. a new route\'s authorization is one selector, nothing chosen: ' +
          'an existing policy, a simple policy, Public',
          kindSelect ? kindSelect[1] : newZ);
  const panels = newZ.match(/data-panel-of="authz" data-panel="[^"]*"[^>]*>/g)
    || [];
  t.check(panels.length === 4 && panels.every(function (one) {
    return / hidden>$/.test(one);
  }) && newZ.indexOf('placeholder="https://pep.example:9543/"') >= 0,
          'Z2. with nothing chosen every panel is hidden, and the resource ' +
          'box shows the default (the base URL and the path)',
          panels.join(' '));
  const simpleRoute = Object.assign({}, proxy.routes[0], {
    authorization: { kind: 'simple', policy: 'pep-pep-1-orders-api',
                     resource: 'https://pep.example:9543/api',
                     actionModel: 'crud',
                     roles: { read: ['orders-users'],
                              delete: ['orders-admins', 'orders-ops'] } } });
  writer.json = {};
  const simpleHtml = XacmlPage.routeFields(writer.t, { peps: [{}] },
                                           simpleRoute, 1, 'new', true);
  const readRow = /data-panel="crud read-write">([\s\S]*?)<\/div><\/div>/
    .exec(simpleHtml);
  t.check(/<select name="authzActionModel" data-panels="authzModel">/
            .test(simpleHtml) &&
          /<option value="crud" selected>/.test(simpleHtml) &&
          /name="authzActions" value="read" checked/.test(simpleHtml) &&
          /name="authzActions" value="delete" checked/.test(simpleHtml) &&
          !/name="authzActions" value="update" checked/.test(simpleHtml) &&
          /data-panel="read-write" hidden>/.test(simpleHtml) &&
          simpleHtml.indexOf('<input type="hidden" name="authzRole.delete" ' +
                             'value="orders-ops">') >= 0 &&
          simpleHtml.indexOf('value="authzRole.delete|!orders-ops"') >= 0 &&
          !!readRow && readRow[1].indexOf('fgq-authzRole.read') >= 0,
          'Z3. a simple route: the model selected, a box per action, each ' +
          'ticked action\'s roles held with a Remove, and a role search per ' +
          'action; the other model\'s actions hidden', simpleHtml);
  const zAsked = [];
  const zRuntime = Object.assign({}, fakeRuntime, {
    view: { json: Object.assign({}, pepJson) },
    apiJson: async function apiJson(method, path) {
      log.debug("Entering apiJson(). " + path);
      zAsked.push(method + ' ' + path);
      log.debug("Leaving apiJson().");
      return { status: 200, json: path.indexOf('/roles') >= 0
        ? { shownRoles: [{ name: 'orders-users', description: 'Readers' },
                         { name: 'orders-admins' }],
            paging: { page: 1, pages: 2 }, matched: 7 }
        : { policies: [{ name: 'orders-policy', description: 'Orders' },
                       { name: 'pep-pep-1-health', pepRoute: 'pep-1/health' }],
            page: 1, pages: 1, matched: 2 } };
    } });
  const zTyped = Object.assign({}, typed, { authzKind: 'simple',
    authzActionModel: 'read-write', 'fgfind.authzPolicy': 'ord',
    'fgfind.authzRole.read': 'users' });
  await Runtime.prototype.pepRouteSearch.call(zRuntime,
    Object.assign({ fgsearch: 'authzPolicy' }, zTyped));
  await Runtime.prototype.pepRouteSearch.call(zRuntime,
    Object.assign({ fgsearch: 'authzRole.read' }, zTyped));
  t.equal(zAsked.join(' ; '),
          'GET /admin-api/xacml/policies?q=ord&per=5&page=1&routable=true ; ' +
          'GET /admin-api/roles?q=users&per=5&rolesPage=1',
          'Z4. the policy chooser asks the repository\'s search (routable, ' +
          'five to a page) and a role chooser the Roles list');
  const zFound = zRuntime.view.json.state.pepRoute;
  t.check(zFound.find.attribute === 'authzRole.read' &&
          zFound.find.rows[0].value === 'orders-users' &&
          zFound.find.pages === 2,
          'Z5. the results say which chooser they answer',
          JSON.stringify(zFound.find));
  await Runtime.prototype.pepRouteSearch.call(zRuntime,
    Object.assign({ fgadd: 'authzRole.read|orders-users',
                    'fgpage.authzRole.read': '1' }, zTyped));
  const added = zRuntime.view.json.state.pepRoute.draft;
  await Runtime.prototype.pepRouteSearch.call(zRuntime,
    Object.assign({ fgadd: 'authzPolicy|orders-policy' }, zTyped));
  const chosenPolicy = zRuntime.view.json.state.pepRoute.draft;
  const removed = WebAnswersModule.pepRouteState(Object.assign({},
    added, { fgadd: 'authzRole.read|!orders-users' }), null, null).draft;
  t.check([].concat(added['authzRole.read']).join(',') === 'orders-users' &&
          [].concat(added.authzActions).indexOf('read') >= 0 &&
          chosenPolicy.authzPolicy === 'orders-policy' &&
          chosenPolicy.authzKind === 'policy' &&
          [].concat(removed['authzRole.read']).length === 0 &&
          zAsked.length === 2,
          'Z6. a role\'s Use adds it and ticks its action, its Remove takes ' +
          'it off, a policy\'s Use chooses it and the existing-policy kind, ' +
          'and none of them asks anything', JSON.stringify([added,
            chosenPolicy, removed]));
  const tableZ = XacmlPage.proxyRoutesTable(writer.t, proxy, [
    { route: 'health', usable: true, authorization: 'public',
      policy: 'pep-pep-1-health', policyProblem: 'missing' }], writer,
    'pep-1');
  t.check(tableZ.indexOf('none (deny all)') >= 0 &&
          tableZ.indexOf('<code>pep-pep-1-health</code>') >= 0 &&
          tableZ.indexOf('no policy of this name') >= 0 &&
          tableZ.indexOf('name="removePolicy" value="true" required') >= 0,
          'Z7. the routes table: an empty methods list is none (deny all), ' +
          'each route\'s policy linked and its problem said, and a ' +
          'generated policy\'s route removed only with its box ticked',
          tableZ);

  // -------------------------------------------------------------------------
  t.log.info('=== XL. no dead /admin/xacml/<tab> link on an XACML page ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): the Deciding policy link on a route's page answered
  // "/admin/xacml/editor is not a page of this console". Policies, the
  // editor, Remote PEPs, Try a decision and AuthZEN are TABS of
  // /admin/xacml; the renderers write them as paths and
  // `WebPages.render()` moves every link and GET form onto the tab, on
  // every page. A POST form keeps its action: it navigates nowhere, and
  // the runtime resolves it by that page (`WebAnswers.PEP_ROUTES_PAGE`).
  const DEAD = /\b(href|action)="(\/admin\/xacml\/(?:policies|editor|peps|decide|authzen))(?=[?#"])/g;
  const deadIn = function (html) {
    log.debug("Entering deadIn().");
    const found = [];
    const forms = /<form\b[^>]*>/gi;
    let f = forms.exec(html);
    const posts = [];
    while (f) {
      if (/\bmethod="post"/i.test(f[0])) {
        posts.push(f.index);
      }
      f = forms.exec(html);
    }
    let m = DEAD.exec(html);
    while (m) {
      const at = m.index;
      // An action inside a POST form's own start tag is that form's.
      const ownPost = m[1] === 'action' && posts.some(function (p) {
        return p <= at && html.indexOf('>', p) > at;
      });
      if (!ownPost) {
        found.push(html.slice(Math.max(0, at - 40), at + 80));
      }
      m = DEAD.exec(html);
    }
    log.debug("Leaving deadIn().");
    return found;
  };
  const xlProxy = {
    upstream: 'http://companion:9700', enabled: true,
    routes: [
      { id: 'r-policy', path: '/p', match: 'prefix', methods: ['GET'],
        mechanisms: ['session'], application: 'orders-app',
        authorization: { kind: 'policy', policy: 'orders-policy',
                         resource: '', actionModel: 'method', roles: {} },
        forwardCredentials: false, signals: true },
      { id: 'r-simple', path: '/s', match: 'prefix', methods: ['GET'],
        mechanisms: ['session'], application: 'orders-app',
        authorization: { kind: 'simple', policy: 'pep-pep-1-r-simple',
                         resource: 'https://pep.example:9543/s',
                         actionModel: 'crud',
                         roles: { read: ['orders-users'] } },
        forwardCredentials: false, signals: true },
      { id: 'r-public', path: '/h', match: 'exact', methods: [],
        mechanisms: [], application: '',
        authorization: { kind: 'public', policy: 'pep-pep-1-r-public',
                         resource: 'https://pep.example:9543/h',
                         actionModel: 'method', roles: {} },
        forwardCredentials: false, signals: true },
      { id: 'r-none', path: '/n', match: 'exact', methods: ['GET'],
        mechanisms: ['session'], application: '',
        authorization: {}, forwardCredentials: false, signals: true }] };
  const xlStatus = xlProxy.routes.map(function (r) {
    return { route: r.id, usable: true,
             authorization: r.authorization.kind || '',
             policy: r.authorization.policy || '',
             policyProblem: r.authorization.policy ? '' : 'missing' };
  });
  const xlPep = { name: 'pep-1', proxy: xlProxy, proxyRoutes: xlStatus,
                  listeners: [],
                  listenerRows: [envRow('api-https', 'https', '',
                                        { state: 'listening',
                                          reason: 'none', port: 9443 })] };
  const xlBase = {
    pep: 'pep-1', found: true, listenersCatalogue: {},
    listenerCertificates: { keyAlgorithms: ['ES256'],
                            defaultKeyAlg: 'ES256' },
    applicationChoices: [{ identifier: 'orders-app', name: 'Orders' }],
    policyChoices: { policies: [{ name: 'orders-policy' },
                                { name: 'pep-pep-1-r-simple' }] },
    peps: [xlPep] };
  const xlDrawn = [];
  const xlDraw = function (path, query, view) {
    log.debug("Entering xlDraw(). " + path);
    const ctx = kit.context(query, true);
    const html = WebPages.render(path, view, ctx);
    xlDrawn.push({ label: path + ' ' + JSON.stringify(query),
                   html: String(html) });
    log.debug("Leaving xlDraw().");
    return String(html);
  };
  xlDraw('/admin/xacml/pep', { pep: 'pep-1' }, xlBase);
  const routePages = {};
  xlProxy.routes.forEach(function (r) {
    routePages[r.id] = xlDraw('/admin/xacml/pep/route',
      { pep: 'pep-1', route: r.id },
      Object.assign({}, xlBase, { route: r.id,
        routeDetail: { found: true, route: r, usable: true, position: 0,
                       count: xlProxy.routes.length, servedBy: [],
                       application: r.application
                         ? { identifier: r.application, name: 'Orders',
                             found: true }
                         : null,
                       authorization: { policy: r.authorization.policy
                         ? { name: r.authorization.policy,
                             generated: r.authorization.kind !== 'policy',
                             problem: '' }
                         : null } } }));
  });
  xlDraw('/admin/xacml/pep/route', { pep: 'pep-1' }, xlBase);
  xlDraw('/admin/xacml/pep/listener',
         { pep: 'pep-1', listener: 'api-https' },
         Object.assign({}, xlBase, { listener: 'api-https' }));
  const xlDead = [];
  xlDrawn.forEach(function (one) {
    deadIn(one.html).forEach(function (bit) {
      xlDead.push(one.label + ': ' + bit);
    });
  });
  t.check(xlDrawn.length === 7 && xlDrawn.every(function (one) {
    return one.html.length > 200;
  }) && xlDead.length === 0,
          'XL1. the PEP page, a route\'s page in each authorization kind ' +
          '(policy, simple, public, none), the routes index and a ' +
          'listener\'s page link to no /admin/xacml/<tab> path, and no GET ' +
          'form goes to one', xlDead.join('\n'));
  const decidingHref = 'href="/admin/xacml?policy=orders-policy' +
    '#xacml-tab-editor"';
  t.check(routePages['r-policy'].indexOf(decidingHref) >= 0 &&
          routePages['r-simple'].indexOf('href="/admin/xacml?policy=' +
            'pep-pep-1-r-simple#xacml-tab-editor"') >= 0,
          'XL2. the deciding policy, and a generated one, link to the ' +
          'editor tab with the policy named in the query',
          routePages['r-policy']);
  const editorAsked = WebPages.composeRequests(
    WebPages.pageFor('/admin/xacml'), { policy: 'orders-policy' })
    .filter(function (one) {
      return one.member === 'xacmlEditor';
    })[0];
  t.check(!!editorAsked && editorAsked.params.policy === 'orders-policy' &&
          XacmlPage.xacmlTabs(tr).some(function (one) {
            return one.id === 'xacml-tab-editor';
          }),
          'XL3. /admin/xacml?policy=<id> asks the editor for that policy, ' +
          'and #xacml-tab-editor is the editor\'s tab',
          JSON.stringify(editorAsked));
  // THE REWRITE ITSELF, on a page outside the section (the Roles and
  // Applications pages write these paths too): a link and a GET form move,
  // a plain link to the section and a POST form stay.
  const moved = WebPages.xacmlTabLinks(
    '<a href="/admin/xacml/decide">d</a>' +
    '<a href="/admin/xacml/policies#fga-policies">f</a>' +
    '<a href="/admin/xacml">x</a>' +
    '<a href="/admin/xacml/pep?pep=a">p</a>' +
    '<form method="get" action="/admin/xacml/editor"></form>' +
    '<form method="post" action="/admin/xacml/peps"></form>', false);
  t.equal(moved,
          '<a href="/admin/xacml#xacml-tab-decide">d</a>' +
          '<a href="/admin/xacml#fga-policies">f</a>' +
          '<a href="/admin/xacml">x</a>' +
          '<a href="/admin/xacml/pep?pep=a">p</a>' +
          '<form method="get" action="/admin/xacml#xacml-tab-editor"></form>' +
          '<form method="post" action="/admin/xacml/peps"></form>',
          'XL4. off the section\'s own page, links and GET forms move onto ' +
          'the tab; a section link, a PEP page link and a POST form stay');

  // -------------------------------------------------------------------------
  t.log.info('=== RT. a route\'s page is tabs of its own ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): every section of the route's page its own tab, in
  // order and by name, Effective state and Listeners that serve it together
  // on Metadata; the rows above keep their tabs marked, the trail ends at
  // the open one, and a save comes back to the tab its form is on.
  // And (rcbj, 2026-11-15) "Split the 'Edit the route' into a Settings tab
  // (containing route id, Matching, and Order), Authentication tab,
  // authorization tab, and Identity Sent To Backend tab".
  const ROUTE_TABS = [['xacml-route-tab-metadata', 'Metadata'],
                      ['xacml-route-tab-settings', 'Settings'],
                      ['xacml-route-tab-authentication', 'Authentication'],
                      ['xacml-route-tab-authorization', 'Authorization'],
                      ['xacml-route-tab-identity',
                       'Identity sent to backend'],
                      ['xacml-route-tab-remove', 'Remove the route']];
  const rtBars = page.match(
    /<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) || [];
  t.equal(rtBars.length === 4 ? rtBars[3] : '',
          '<nav class="tabbar subbar" aria-label="Route detail: orders-api">' +
          ROUTE_TABS.map(function (one, n) {
            return '<a' + (n === 0 ? ' class="first"' : '') + ' href="#' +
              one[0] + '">' + one[1] + '</a>';
          }).join('') + '</nav>',
          'RT1. a route\'s page draws a fourth row: Metadata, Settings, ' +
          'Authentication, Authorization, Identity sent to backend, Remove ' +
          'the route, Metadata first');
  const routePanel = function (html, id) {
    log.debug("Entering routePanel(). " + id);
    const start = html.indexOf('<div class="subpanel' +
      (id === ROUTE_TABS[0][0] ? ' first' : '') + '" id="' + id + '">');
    const next = start < 0 ? -1
      : html.indexOf('<div class="subpanel', start + 10);
    log.debug("Leaving routePanel().");
    return start < 0 ? '' : html.slice(start, next < 0 ? html.length : next);
  };
  const metaPanel = routePanel(page, 'xacml-route-tab-metadata');
  const settingsPanel = routePanel(page, 'xacml-route-tab-settings');
  const authnPanel = routePanel(page, 'xacml-route-tab-authentication');
  const authzPanel = routePanel(page, 'xacml-route-tab-authorization');
  const identityPanel = routePanel(page, 'xacml-route-tab-identity');
  const removePanel = routePanel(page, 'xacml-route-tab-remove');
  // Each editing tab: ONE set-pep-route form, its `part`, its own Save,
  // and only its own fields (`fieldsOf()`, F above).
  const partOf = function (html) {
    log.debug("Entering partOf().");
    const forms = html.match(/<form method="post"[\s\S]*?<\/form>/g) || [];
    const saves = forms.filter(function (one) {
      return one.indexOf('name="action" value="set-pep-route"') >= 0;
    });
    const m = saves.length === 1
      ? /name="part" value="([^"]+)"/.exec(saves[0]) : null;
    log.debug("Leaving partOf().");
    return { part: m ? m[1] : '', fields: saves.length === 1
      ? fieldsOf(saves[0]) : '', saveButton: saves.length === 1 &&
        /<button type="submit" title="[^"]*">Save the route<\/button>/
          .test(saves[0]),
      keepsId: saves.length === 1 &&
        saves[0].indexOf('name="from" value="orders-api"') >= 0 };
  };
  const tabParts = [[settingsPanel, 'settings',
                     'id | path | match | application | position'],
                    [authnPanel, 'authentication',
                     'mechanisms | signals | multipleAccounts'],
                    [authzPanel, 'authorization',
                     'methods+methodsGiven | authzKind | authzResource | ' +
                     'authzPolicy | authzPolicyActionModel | ' +
                     'authzActionModel'],
                    [identityPanel, 'identity',
                     'forwardCredentials | mode | headerName+headerClaim | ' +
                     'headerName+headerClaim | separator']];
  const partMisses = tabParts.filter(function (one) {
    const got = partOf(one[0]);
    return got.part !== one[1] || got.fields !== one[2] || !got.saveButton ||
      !got.keepsId;
  }).map(function (one) {
    return one[1] + ' => ' + JSON.stringify(partOf(one[0]));
  });
  t.check(metaPanel.indexOf('>Effective state</h3>') >= 0 &&
          metaPanel.indexOf('>Listeners that serve it</h4>') >= 0 &&
          metaPanel.indexOf('<form') < 0 && partMisses.length === 0 &&
          settingsPanel.indexOf('Effective state') < 0 &&
          (settingsPanel + authnPanel + authzPanel + identityPanel)
            .indexOf('remove-pep-route') < 0 &&
          removePanel.indexOf('value="remove-pep-route"') >= 0 &&
          removePanel.indexOf('set-pep-route') < 0,
          'RT2. Metadata holds the state and the listeners; Settings, ' +
          'Authentication, Authorization and Identity sent to backend each ' +
          'hold one form of their own fields with its own Save and `part`; ' +
          'the removal on Remove the route', partMisses.join('\n'));
  t.check(settingsPanel.indexOf('<span id="xacml-route-tab-edit"></span>') >
            0 &&
          authzPanel.indexOf('generate-pep-route-policy') >= 0 ===
            (proxy.routes[0].authorization.kind !== 'policy') &&
          settingsPanel.indexOf('name="part" value="settings"') >= 0 &&
          settingsPanel.indexOf('<input type="hidden" name="id"') < 0 &&
          authnPanel.indexOf('<input type="hidden" name="id" ' +
                             'value="orders-api">') >= 0,
          'RT2b. the old Edit the route fragment is an anchor at the top of ' +
          'Settings; Generate the policy again is on Authorization; only ' +
          'Settings renames, the other tabs carry the id unchanged',
          settingsPanel.slice(0, 300));
  const readerRoute = reader.match(
    /<nav class="tabbar[^"]*"[^>]*>[\s\S]*?<\/nav>/g) || [];
  t.check(readerRoute.length === 4 && /href="#xacml-route-tab-metadata"/
            .test(readerRoute[3]) &&
          !/xacml-route-tab-(edit|settings|authentication|authorization|identity|remove)/.test(reader),
          'RT3. a reader\'s route page: Metadata alone',
          readerRoute[3] || '');
  // THE TRAIL'S TAIL for each fragment: the route a link to its own page,
  // the open tab the leaf; none and an unknown one name Metadata, an
  // anchor inside a tab names that tab.
  const routeQ = { pep: 'pep-1', route: 'orders-api' };
  const routeHere = routeTrail.replace(/orders-api$/, 'orders-api -> ' +
    '/admin/xacml/pep/route?pep=pep-1&route=orders-api | ');
  // An anchor inside Authorization (its policy chooser), and the old
  // single tab's fragment, which is an anchor inside Settings.
  const authzInner = (/ id="([^"]+)"/.exec(authzPanel.slice(40)) || [])[1];
  const tails = {
    '': 'Metadata',
    '#no-such-tab': 'Metadata',
    '#xacml-route-tab-edit': 'Settings'
  };
  ROUTE_TABS.forEach(function (one) {
    tails['#' + one[0]] = one[1];
  });
  if (authzInner) {
    tails['#' + authzInner] = 'Authorization';
  }
  const tailMisses = Object.keys(tails).filter(function (hash) {
    return runtimeTrail('/admin/xacml/pep/route', routeQ, page, hash) !==
      routeHere + tails[hash];
  });
  t.check(!!authzInner && tailMisses.length === 0,
          'RT4. the trail ends Configured Routes › <route> › <tab> for every ' +
          'tab, Metadata with no fragment or an unknown one, Settings for ' +
          'the old Edit the route fragment, and the tab holding an anchor', tailMisses.map(function (h) {
            return h + ' => ' + runtimeTrail('/admin/xacml/pep/route',
                                             routeQ, page, h);
          }).join('\n'));
  // THE MARK AT EVERY LEVEL, by the runtime's own markOpenTabs() over a
  // DOM built from the page drawn: the three rows above keep Remote PEPs,
  // Reverse proxy and Configured Routes, and the fourth marks the open tab.
  const domOf = function (html) {
    log.debug("Entering domOf().");
    const VOID = ['br', 'hr', 'img', 'input', 'link', 'meta', 'wbr', 'col',
                  'area', 'base', 'source', 'track', 'embed', 'param'];
    const byId = {};
    const roots = [];
    const make = function (tag, attrs, parent) {
      const set = {};
      String(attrs.class || '').split(/\s+/).forEach(function (c) {
        if (c) {
          set[c] = true;
        }
      });
      const el = {
        tagName: tag.toUpperCase(), attrs: attrs, children: [],
        parent: parent,
        classList: { contains: function (c) { return !!set[c]; },
                     add: function (c) { set[c] = true; },
                     remove: function (c) { delete set[c]; } },
        getAttribute: function (n) {
          return Object.prototype.hasOwnProperty.call(this.attrs, n)
            ? this.attrs[n] : null;
        },
        setAttribute: function (n, v) {
          this.attrs[n] = v;
        },
        removeAttribute: function (n) {
          delete this.attrs[n];
        },
        contains: function (other) {
          let at = other;
          while (at) {
            if (at === this) {
              return true;
            }
            at = at.parent;
          }
          return false;
        }
      };
      if (attrs.id) {
        byId[attrs.id] = el;
      }
      if (/(^|\s)(tabs|subtabs)(\s|$)/.test(String(attrs.class || '')) &&
          tag === 'div') {
        roots.push(el);
      }
      return el;
    };
    const top = make('body', {}, null);
    let at = top;
    const token = /<(\/?)([a-zA-Z][\w-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
    let m = token.exec(html);
    while (m) {
      const tag = m[2].toLowerCase();
      if (m[1] === '/') {
        let up = at;
        while (up && up.tagName !== tag.toUpperCase()) {
          up = up.parent;
        }
        at = up && up.parent ? up.parent : at;
      } else {
        const attrs = {};
        const re = /([^\s"'=\/>]+)(?:\s*=\s*"([^"]*)")?/g;
        let a = re.exec(m[3]);
        while (a) {
          attrs[a[1].toLowerCase()] = (a[2] || '').replace(/&amp;/g, '&');
          a = re.exec(m[3]);
        }
        const el = make(tag, attrs, at);
        at.children.push(el);
        if (VOID.indexOf(tag) < 0 && !/\/\s*$/.test(m[3])) {
          at = el;
        }
      }
      m = token.exec(html);
    }
    log.debug("Leaving domOf().");
    return { roots: roots, byId: byId };
  };
  const marksFor = function (hash) {
    log.debug("Entering marksFor(). " + hash);
    const dom = domOf(page);
    const target = dom.byId[String(hash).replace(/^#/, '')] || null;
    const rt = Object.create(ConsoleRuntime.prototype);
    rt.env = { document: {
      querySelectorAll: function () { return dom.roots; },
      querySelector: function () { return target; },
      getElementById: function (id) { return dom.byId[id] || null; }
    } };
    rt.markOpenTabs();
    const out = dom.roots.map(function (root) {
      const bar = root.children.filter(function (el) {
        return el.classList.contains('tabbar');
      })[0];
      const marked = (bar ? bar.children : []).filter(function (el) {
        return el.classList.contains('tab-current');
      });
      return marked.map(function (el) {
        return el.attrs.href;
      }).join('+');
    });
    log.debug("Leaving marksFor().");
    return out.join(' / ');
  };
  const above = '/admin/xacml#xacml-tab-peps / ' +
    '/admin/xacml/pep?pep=pep-1#xacml-pep-tab-proxy / ' +
    '/admin/xacml/pep?pep=pep-1#xacml-pep-proxy-routes / ';
  const marks = {
    '': '#xacml-route-tab-metadata',
    '#no-such-tab': '#xacml-route-tab-metadata',
    '#xacml-route-tab-edit': '#xacml-route-tab-settings'
  };
  ROUTE_TABS.forEach(function (one) {
    marks['#' + one[0]] = '#' + one[0];
  });
  if (authzInner) {
    marks['#' + authzInner] = '#xacml-route-tab-authorization';
  }
  const markMisses = Object.keys(marks).filter(function (hash) {
    return marksFor(hash) !== above + marks[hash];
  });
  t.check(markMisses.length === 0,
          'RT5. every fragment marks Remote PEPs, Reverse proxy and ' +
          'Configured Routes above, and the open tab of the route\'s own row, ' +
          'one mark per row', markMisses.map(function (h) {
            return h + ' => ' + marksFor(h);
          }).join('\n'));
  // A SAVE KEEPS ITS TAB: each tab's set-pep-route lands back on that
  // tab, the route as it is now called; a form with no part (an older
  // page) on Settings; a refused save is drawn where it was (the runtime
  // keeps the fragment), and so is the regenerate.
  const WebAnswersRt = require('../admin-ui/web_answers');
  const routeBackRt = '/admin/xacml/pep/route?pep=pep-1&route=orders-api';
  const landedRt = function (fields) {
    log.debug("Entering landedRt().");
    log.debug("Leaving landedRt().");
    return WebAnswersRt.landing('/admin/xacml/peps', 'set-pep-route',
      { ok: true }, routeBackRt, fields);
  };
  const landMisses = ['settings', 'authentication', 'authorization',
                      'identity'].filter(function (part) {
    return landedRt({ from: 'orders-api', id: part === 'settings'
      ? 'orders-v2' : 'orders-api', part: part }) !==
      '/admin/xacml/pep/route?pep=pep-1&route=' +
      (part === 'settings' ? 'orders-v2' : 'orders-api') +
      '#xacml-route-tab-' + part;
  });
  t.check(landMisses.length === 0 &&
          landedRt({ from: 'orders-api', id: 'orders-api' }) ===
            routeBackRt + '#xacml-route-tab-settings' &&
          landedRt({ from: 'orders-api', id: 'orders-api', part: 'x' }) ===
            routeBackRt + '#xacml-route-tab-settings' &&
          WebAnswersRt.landing('/admin/xacml/peps', 'set-pep-route',
            { ok: false }, routeBackRt, { id: 'orders-api',
                                          part: 'identity' }) === null &&
          WebAnswersRt.landing('/admin/xacml/peps',
            'generate-pep-route-policy', { ok: true }, routeBackRt,
            { route: 'orders-api' }) === null,
          'RT6. each tab\'s save lands back on that tab (a rename on the ' +
          'new id), one with no part on Settings; a refusal and a ' +
          'regenerate stay on the tab they were pressed on',
          landMisses.join());
  // A PRESS ON ONE TAB'S CHOOSER KEEPS WHAT WAS TYPED ON ANOTHER: the
  // state holds a draft per tab, each laid over the route for its own
  // members only.
  const draftOf = function (part, extra) {
    log.debug("Entering draftOf().");
    log.debug("Leaving draftOf().");
    return Object.assign({ action: 'set-pep-route', name: 'pep-1',
      from: 'orders-api', id: 'orders-api', part: part }, extra);
  };
  const typedSettings = WebAnswersRt.pepRouteState(
    draftOf('settings', { path: '/typed', match: 'exact',
                          application: proxy.routes[0].application,
                          fgsearch: 'application',
                          'fgfind.application': 'x' }), null, null);
  const thenAuthz = WebAnswersRt.pepRouteState(
    draftOf('authorization', { methods: ['GET'], methodsGiven: 'true',
                               authzKind: 'public',
                               fgsearch: 'authzPolicy' }),
    typedSettings, null);
  const redrawn = XacmlPage.routeOfDraft(proxy.routes[0], thenAuthz);
  t.check(Object.keys(thenAuthz.drafts).sort().join() ===
            'authorization,settings' &&
          redrawn.route.path === '/typed' &&
          redrawn.route.match === 'exact' &&
          redrawn.route.methods.join() === 'GET' &&
          redrawn.route.authorization.kind === 'public' &&
          JSON.stringify(redrawn.route.mechanisms) ===
            JSON.stringify(proxy.routes[0].mechanisms) &&
          redrawn.route.application === proxy.routes[0].application &&
          redrawn.route.signals === proxy.routes[0].signals &&
          JSON.stringify(redrawn.identity) ===
            JSON.stringify(proxy.routes[0].identity),
          'RT7. a chooser press keeps a draft per tab: what was typed on ' +
          'Settings survives a press on Authorization, and the tabs never ' +
          'drafted show the route as stored', JSON.stringify(redrawn.route));

  // -------------------------------------------------------------------------
  t.log.info('=== PE. the Policy editor: no overall Save, and a route\'s ' +
             'generated policy ===');
  // -------------------------------------------------------------------------
  // rcbj (2026-11-15): a note above the chooser that there is no overall
  // Save, and for a policy generated for a route, that a regenerate or a
  // route save replaces what is edited here.
  const editorAnswer = function (pepRoute) {
    log.debug("Entering editorAnswer().");
    log.debug("Leaving editorAnswer().");
    return { policies: ['p1'], serviceOwn: [], problem: null, tree: [],
             problems: [], xpathVersionGaps: [], menus: null,
             document: '<Policy/>', alfa: '',
             policy: { name: 'p1', enabled: true, isRoot: false,
                       policyId: 'p1', kind: 'Policy', version: '1.0',
                       combiningAlgId: '', description: '',
                       pepRoute: pepRoute } };
  };
  const plainEditor = XacmlPage.editorBody(writer, editorAnswer(null));
  const routeEditor = XacmlPage.editorBody(writer,
    editorAnswer('pep-1/orders-api'));
  const readerEditor = XacmlPage.editorBody(kit.context({}, false),
    editorAnswer(null));
  const noSaveAt = plainEditor.indexOf('There is no overall Save');
  t.check(noSaveAt >= 0 &&
          noSaveAt < plainEditor.indexOf('<form method="get" ' +
                                         'action="/admin/xacml/editor">') &&
          /class="note[^"]*"/.test(plainEditor.slice(0, noSaveAt)) &&
          plainEditor.indexOf('An Update saves only the fields in its own ' +
                              'row.') > noSaveAt &&
          plainEditor.indexOf('nudged to pull it') > noSaveAt &&
          readerEditor.indexOf('There is no overall Save') < 0,
          'PE1. above the chooser, a note: no overall Save, each Update ' +
          'writes its own row to the live policy at once and the PEPs are ' +
          'nudged; a reader, with no Update, is not told',
          plainEditor.slice(0, 900));
  const warned = 'Changes made here are replaced whenever the route\'s ' +
    'policy is generated again';
  t.check(plainEditor.indexOf(warned) < 0 &&
          routeEditor.indexOf(warned) >= 0 &&
          routeEditor.indexOf('route <code>orders-api</code> of remote PEP ' +
                              '<code>pep-1</code>') >= 0 &&
          routeEditor.indexOf('<a href="/admin/xacml/pep/route?pep=pep-1' +
                              '&amp;route=orders-api#xacml-route-tab-' +
                              'authorization">') >= 0 &&
          routeEditor.indexOf(warned) <
            routeEditor.indexOf('<form method="get" ' +
                                'action="/admin/xacml/editor">'),
          'PE2. a route\'s generated policy carries the warning, naming the ' +
          'route and linking its Authorization tab; an ordinary policy ' +
          'does not', routeEditor.slice(0, 1600));
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
