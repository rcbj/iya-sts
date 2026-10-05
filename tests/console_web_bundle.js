// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/console_web_bundle.js
// ===========================================================================
// THE STATIC CONSOLE'S RENDERERS, HELD NODE-SIDE (#446, 2026-10-05).
//
// The admin console is being converted into a static application that draws
// its pages in the browser. Its renderers are the `admin-ui/web_*.ts`
// modules, bundled by `build-typescript.sh` (esbuild) into
// `admin-ui/console.bundle.js`. Nothing serves that bundle until the
// console's one cutover — rcbj's decision — so until then this file is what
// holds it, in node:
//
//   A. THE SOURCES. Every `web_` module requires other `web_` modules and
//      nothing else, and names nothing of node's.
//   B. THE KIT IS THE CONSOLE'S OWN. `web_kit.ts`'s `esc()` is
//      `helpers.xmlEscape()` to the byte; `note()`, `warn()`, `tip()`,
//      `tile()`, `shortened()`, `clipped()`, `clippedValues()` and
//      `whenText()` answer what the console's methods of those names do;
//      `queryWith()` is `admin_views`'s; and `pageNavPair()` draws from the
//      paging a caller of the API RECEIVES exactly what the console draws
//      from its own paging object.
//   C. THE BUNDLE. It was built, and it runs in a context that has NO
//      `require`, `process`, `module` or `Buffer` — a stand-in for a browser
//      — and answers the page table.
//   D. A CONVERTED PAGE IS ONE PAGE. Every page of the table, drawn by the
//      bundle from its view passed through JSON, is to the byte what this
//      process's own module draws — from the view its operation's HANDLER
//      answers, called here, so a page whose operation lacks something the
//      page draws fails rather than agreeing with itself.
//      `/admin/mode` is also held to carrying every requirement and setting
//      of the report.
//   E. THE TABLE IS TRUE. Every converted page is a page of the console, and
//      names a management API operation that exists.
//   F. THE SETTINGS BLOCK IS ONE BLOCK. On every page `SETTING_HOMES` names,
//      with two overrides in force, what the console draws is to the byte
//      what `web_settings.ts` draws — in this process and in the bundle —
//      from that page's `settings` member passed through JSON: nothing the
//      block says comes from anywhere but the answer a browser would be
//      given. Both persistence notes are drawn from the block's `context`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'console_web_bundle',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  const OUT = process.env.AG_OUT;
  const fsC = require('fs');
  const pathC = require('path');
  const vm = require('vm');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const mode = require(ROOT_DIR + '/common/mode');
    const admin = require(ROOT_DIR + '/admin-ui/admin');
    const adminApi = require(ROOT_DIR + '/mgmt-api/admin_api');
    const WebKit = require(ROOT_DIR + '/admin-ui/web_kit');
    const WebPages = require(ROOT_DIR + '/admin-ui/web_pages');
    // THE VIEW OF EVERY CONVERTED PAGE IS WHAT ITS OPERATION'S HANDLER
    // ANSWERS — the handler itself, called with a request that carries
    // nothing but a query, and not the function this test supposes the
    // handler calls. It was a table of those functions until a page was
    // found whose console JSON carried `settings` and whose operation did
    // not (`/admin/attribute-sources`): a table like that agrees with the
    // page module and proves nothing about the API. The gate is not in the
    // way here; it is `tests/vendored/admin_api.js`'s to hold.
    function apiAnswer(operation, query) {
      return new Promise(function (resolve, reject) {
        const entry = adminApi.ROUTES.filter(function (one) {
          return one.method === 'GET' && one.path === operation &&
                 typeof one.handler === 'function';
        })[0];
        if (!entry) {
          reject(new Error('no GET operation at ' + operation));
          return;
        }
        const headers = { host: 'sts.example', accept: 'application/json' };
        const req = {
          method: 'GET', query: query || {}, headers: headers, body: {},
          protocol: 'https', secure: true, hostname: 'sts.example',
          path: operation, url: operation, originalUrl: operation,
          socket: { encrypted: true }, connection: {},
          get: function (name) {
            return headers[String(name).toLowerCase()];
          }
        };
        const res = {
          locals: {}, statusCode: 200,
          status: function (code) {
            this.statusCode = code;
            return this;
          },
          type: function () {
            return this;
          },
          set: function () {
            return this;
          },
          setHeader: function () {
            return this;
          },
          json: function (body) {
            resolve({ status: this.statusCode, body: body });
            return this;
          },
          send: function (body) {
            let parsed = body;
            try {
              parsed = typeof body === 'string' ? JSON.parse(body) : body;
            } catch (e) {
              // Not JSON: answered as the text it is, and D0 reports it.
              parsed = { notJson: String((e && e.message) || e) };
            }
            resolve({ status: this.statusCode, body: parsed });
            return this;
          },
          end: function () {
            resolve({ status: this.statusCode, body: null });
            return this;
          }
        };
        Promise.resolve().then(function () {
          return entry.handler(req, res);
        }).catch(reject);
      });
    }
    async function viewOf(page, query) {
      const answer = await apiAnswer(page.operation,
                                     WebPages.operationQuery(page.path, query));
      if (answer.status !== 200 || !answer.body ||
          typeof answer.body !== 'object') {
        throw new Error(page.operation + ' answered ' + answer.status);
      }
      return JSON.parse(JSON.stringify(answer.body));
    }
    const dir = pathC.join(ROOT_DIR, 'admin-ui');

    // --- A. the sources ---------------------------------------------------
    // In every directory of the service: a page's renderer may sit beside
    // the module whose page it draws. Names are relative to the root.
    const sources = [];
    fsC.readdirSync(ROOT_DIR, { withFileTypes: true }).forEach(function (d) {
      if (!d.isDirectory() || /^(node_modules|tests|\.git)$/.test(d.name)) {
        return;
      }
      fsC.readdirSync(pathC.join(ROOT_DIR, d.name)).forEach(function (name) {
        if (/^web_.*\.ts$/.test(name)) {
          sources.push(d.name + '/' + name);
        }
      });
    });
    note(sources.length >= 3 &&
         sources.indexOf('admin-ui/web_kit.ts') >= 0 &&
         sources.indexOf('admin-ui/web_pages.ts') >= 0,
         'A1. the web_ sources are in the tree this test reads',
         sources.join(', '));
    const foreign = [];
    const nodeNames = [];
    sources.forEach(function (name) {
      const text = fsC.readFileSync(pathC.join(ROOT_DIR, name), 'utf8');
      const code = text.split('\n').filter(function (line) {
        return !/^\s*(\/\/|\*|\/\*)/.test(line);
      }).join('\n');
      // Without its quoted strings, for A3: a page's prose says "this
      // process." and is not naming node's `process`.
      const unquoted = code.replace(/'(?:[^'\\\n]|\\.)*'/g, "''");
      const requires = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
      let found = requires.exec(code);
      while (found) {
        if (!/^(\.\/|\.\.\/[a-z0-9-]+\/)web_[a-z0-9_]+$/.test(found[1])) {
          foreign.push(name + ' requires ' + found[1]);
        }
        found = requires.exec(code);
      }
      // As identifiers: `global.mode`, the setting, is prose in a page.
      // Node's own, not a member of a view (`json.process`).
      [/(^|[^.\w$])process\./, /(^|[^.\w$])Buffer\./, /\b__dirname\b/,
       /\b__filename\b/,
       /\bglobalThis\b/].forEach(function (one) {
        if (one.test(unquoted)) {
          nodeNames.push(name + ' names ' + String(one));
        }
      });
    });
    note(foreign.length === 0,
         'A2. every web_ module requires other web_ modules and nothing else',
         foreign.join('; '));
    note(nodeNames.length === 0,
         'A3. and names nothing of node\'s', nodeNames.join('; '));

    // --- B. the kit is the console's own -------------------------------------
    const samples = ['', 'plain', '<b>&"\'</b>', 'a & b < c > d',
                     'it\'s "quoted"', null, undefined, 0, 42,
                     '&amp; already', 'café — dash'];
    const escDiffers = samples.filter(function (one) {
      return WebKit.esc(one) !== helpers.xmlEscape(one);
    });
    note(escDiffers.length === 0,
         'B1. WebKit.esc() is helpers.xmlEscape(), to the byte',
         JSON.stringify(escDiffers));
    const short = 'A short note.';
    const long = '<strong>A note that runs on.</strong> ' + new Array(12)
      .join('It explains itself at some length, as every page here does. ');
    const proseDiffers = [];
    [short, long, 'An <code>inline</code> thing &mdash; and more.']
      .forEach(function (one) {
        if (admin.note(one) !== WebKit.note(one)) {
          proseDiffers.push('note');
        }
        if (admin.warn(one) !== WebKit.warn(one)) {
          proseDiffers.push('warn');
        }
        if (admin.tip(one) !== WebKit.tip(one)) {
          proseDiffers.push('tip');
        }
      });
    if (admin.note(long, 'A label') !== WebKit.note(long, 'A label')) {
      proseDiffers.push('note with a label');
    }
    if (admin.tile(3, 'things') !== WebKit.tile(3, 'things')) {
      proseDiffers.push('tile');
    }
    // The paging, clipping and timestamp helpers, moved later (#446).
    const adminViews = require(ROOT_DIR + '/admin-core/admin_views');
    const opaque = 'urn:uuid:0123456789abcdef-0123456789abcdef-0123456789' +
                   'abcdef-with-a-<tag>-and-an-&-in-it';
    [['clipped', [opaque, undefined]], ['clipped', [null, undefined]],
     ['clipped', ['short', 10]], ['clippedValues', [[opaque, 'b', ''], 20]],
     ['clippedValues', ['one']]]
      .forEach(function (one) {
        if (admin[one[0]].apply(admin, one[1]) !==
            WebKit[one[0]].apply(WebKit, one[1])) {
          proseDiffers.push(one[0] + ' ' + JSON.stringify(one[1]));
        }
      });
    // The two the console's module does not export, held to what they draw.
    if (WebKit.whenText(0) !== '\u2014' ||
        WebKit.whenText(1790000000123) !==
          new Date(1790000000123).toISOString().replace('T', ' ')
            .replace(/\.\d+Z$/, 'Z')) {
      proseDiffers.push('whenText');
    }
    if (WebKit.shortened('short', 18) !==
          '<code title="short">short</code>' ||
        WebKit.shortened(opaque, 12) !== '<code title="' +
          WebKit.esc(opaque) + '">' + WebKit.esc(opaque.slice(0, 12)) +
          '&hellip;</code>') {
      proseDiffers.push('shortened');
    }
    [[{ a: 1, b: '', c: null, q: 'x y&z' }, { page: 3 }],
     [{}, {}], [{ user: 'a/b' }, { user: undefined }]]
      .forEach(function (one) {
        if (adminViews.queryWith(one[0], one[1]) !==
            WebKit.queryWith(one[0], one[1])) {
          proseDiffers.push('queryWith ' + JSON.stringify(one));
        }
      });
    [3, 1, 9].forEach(function (pageNumber) {
      const paging = adminViews.pagingOf({ jobsPage: String(pageNumber) }, 431,
                                         { noun: 'jobs', name: 'jobs' });
      const wire = JSON.parse(JSON.stringify(adminViews.pagingJson(paging)));
      const params = { q: 'a b', per: '' };
      const mine = admin.pageNavPair('/admin/x', params, paging);
      const fromWire = WebKit.pageNavPair('/admin/x', params, wire);
      if (mine.head !== fromWire.head || mine.foot !== fromWire.foot ||
          (paging.pages > 1 && mine.head.indexOf('class="pagenav"') < 0)) {
        proseDiffers.push('pageNavPair from the paging JSON, page ' +
                          pageNumber);
      }
    });
    // The paging sizes the kit writes out, since it may not require the
    // module that decides them.
    if (WebKit.DEFAULT_PER_PAGE !== adminViews.DEFAULT_PER_PAGE ||
        WebKit.MAX_ROWS !== adminViews.MAX_ROWS) {
      proseDiffers.push('DEFAULT_PER_PAGE or MAX_ROWS');
    }
    note(proseDiffers.length === 0 &&
         WebKit.note(long).indexOf('<details class="note fold">') === 0 &&
         WebKit.note(short) === '<p class="note">' + short + '</p>',
         'B2. the kit\'s helpers answer what the console\'s own do — ' +
         'prose folded past a line and not before, values clipped, the ' +
         'paging control drawn from the paging JSON',
         proseDiffers.join(', '));

    // --- C. the bundle -------------------------------------------------------
    const bundlePath = pathC.join(dir, 'console.bundle.js');
    let code = '';
    try {
      code = fsC.readFileSync(bundlePath, 'utf8');
    } catch (e) {
      // No bundle: C1 reports it.
      code = '';
    }
    note(code.length > 500,
         'C1. the image build wrote the browser bundle',
         bundlePath + ' ' + code.length + ' byte(s)');
    let StsConsole = null;
    let loadProblem = '';
    try {
      // No require, process, module or Buffer: what a browser has not.
      const sandbox = vm.createContext({});
      StsConsole = vm.runInContext(code + '\n;StsConsole;', sandbox,
                                   { filename: 'console.bundle.js' });
    } catch (e) {
      loadProblem = String((e && e.message) || e);
    }
    note(!!StsConsole && Array.isArray(StsConsole.PAGES) &&
         typeof StsConsole.render === 'function',
         'C2. it runs with no require, process, module or Buffer, and ' +
         'answers the page table', loadProblem);
    note(!/\brequire\(/.test(code),
         'C3. and it calls no require() of its own',
         (/\brequire\([^)]*\)/.exec(code) || [''])[0]);

    // --- D. a converted page is one page -------------------------------------
    // SOMETHING FOR THE DRILL-DOWNS TO OPEN: a fresh process names no
    // authorization server, so one is made with an override and a removal,
    // and its drill-down is drawn with rows rather than only as missing.
    const servers = require(ROOT_DIR + '/oauth-oidc/authorization_servers');
    servers.create({ id: 'webcheck', label: 'drawn by the bundle check' });
    servers.setMember('webcheck', 'code_challenge_methods_supported',
                      '["S256"]');
    servers.removeMember('webcheck', 'request_uri_parameter_supported');
    // And a SAML 2.0 service provider and a SAML 1.1 relying party, for
    // the two identity providers' drill-downs.
    const applications = require(ROOT_DIR + '/common/applications');
    const seeded = applications.createApplication({
      identifier: 'https://sp.webcheck.example/saml2',
      kind: 'saml2-service-provider', protocol: 'SAML 2.0',
      note: 'drawn by the bundle check',
      // What it may do and nothing it has done: an entry is refused one
      // carrying a field the protocol endpoints accumulate.
      fields: { samlEntityId: 'https://sp.webcheck.example/saml2' }
    });
    const seeded11 = applications.createApplication({
      identifier: 'urn:webcheck:saml11',
      kind: 'saml11-relying-party', protocol: 'SAML 1.1',
      note: 'drawn by the bundle check'
    });
    // And a federation relationship of each direction, for its drill-down.
    const federation = require(ROOT_DIR + '/federation/federation');
    const fedSp = federation.create({ id: 'webcheck-sp',
                                      role: 'service-provider',
                                      protocol: 'saml2',
                                      peer: 'https://idp.webcheck.example' });
    note(fedSp && fedSp.ok !== false, 'D-seed-fed. a relationship is made',
         JSON.stringify((fedSp && fedSp.errors) || []));
    // And a SPIFFE registration entry. No agent is made: one exists only
    // by attesting, and its drill-down is drawn as missing.
    const spiffeCa = require(ROOT_DIR + '/spiffe/spiffe_ca');
    const spiffeRegistry = require(ROOT_DIR + '/spiffe/spiffe_registry');
    const td = spiffeCa.trustDomain();
    const seededEntry = spiffeRegistry.createEntry({
      spiffeId: 'spiffe://' + td + '/webcheck',
      parentId: 'spiffe://' + td + '/spire/server',
      selectors: [{ type: 'unix', value: 'uid:1000' }] }, 'test', td, 'test');
    note(seededEntry && seededEntry.ok, 'D-seed-spiffe. an entry is made',
         JSON.stringify((seededEntry && seededEntry.errors) || []));
    note(seeded && seeded.ok && seeded11 && seeded11.ok,
         'D-seed. the service provider and the relying party are made',
         JSON.stringify([(seeded && seeded.errors) || [],
                         (seeded11 && seeded11.errors) || []]));
    // A DELEGATION ACT, so the pictures are drawn with something in them —
    // a chain, an application in two roles, a person — and not only as the
    // page that says nothing has been delegated yet (#446).
    const delegationReg = require(ROOT_DIR + '/common/delegation');
    const dKind = delegationReg.TYPES[0];
    const dAct = delegationReg.record({
      protocol: dKind.protocol, type: dKind.type,
      outcome: delegationReg.OUTCOMES[0],
      initial: { presented: 'webcheck-alice' },
      intermediary: { presented: 'webcheck-front',
                      application: 'webcheck-front' },
      target: { presented: 'webcheck-api', application: 'webcheck-api' },
      authorizedBy: 'the bundle check', note: 'recorded by the bundle check' });
    note(!!(dAct && dAct.chainKey), 'D-seed-delegation. an act is recorded',
         JSON.stringify(dAct || null).slice(0, 200));
    // THE QUERIES A PAGE IS ALSO DRAWN WITH, beside its bare one: a page
    // whose interesting half needs a parameter no list of its own names.
    const EXAMPLES = {
      '/admin/delegation/chain': { chain: dAct ? dAct.chainKey : '' },
      // The person the act named, rather than the catalogue's first.
      '/admin/delegation/user': { user: 'webcheck-alice' },
      // An identifier neither register holds is a lineage of one generation
      // that says so, which draws every section but the picture's content.
      '/admin/tokens/credential': { id: 'webcheck-credential' },
      // A name the permissions register does not hold: the group page's
      // other answer, with the chooser and the groups.
      '/admin/delegation/cluster': { application: 'webcheck-no-group' }
    };
    const exampled = [];
    const unviewed = [];
    const differing = [];
    const drilled = [];
    for (let i = 0; i < WebPages.PAGES.length; i++) {
      const page = WebPages.PAGES[i];
      let view = null;
      try {
        view = await viewOf(page, { per: '10' });
      } catch (e) {
        unviewed.push(page.path + ': ' + String((e && e.message) || e));
        continue;
      }
      const ctx = WebKit.context({ per: '10', q: 'a b' }, true);
      const mine = WebPages.render(page.path, view, ctx);
      const theirs = StsConsole
        ? StsConsole.render(page.path, view, ctx) : null;
      if (typeof mine !== 'string' || mine.length < 100 || mine !== theirs) {
        differing.push(page.path + ' (' + String(mine).length + ' against ' +
                       String(theirs).length + ')');
      }
      // A PAGE WHOSE QUERY THE OPERATION NAMES OTHERWISE, asked with its
      // own names for an item that is not there: the mapping has to reach
      // the operation, or the page is drawn from the list instead.
      if (page.params) {
        const own = { per: '10' };
        own[Object.keys(page.params)[0]] = 'not-there-' + i;
        const mapped = await viewOf(page, own).catch(function (e) {
          unviewed.push(page.path + ' (mapped): ' +
                        String((e && e.message) || e));
          return null;
        });
        if (mapped) {
          const pctx = WebKit.context(own, true);
          const a = WebPages.render(page.path, mapped, pctx);
          const b = StsConsole ? StsConsole.render(page.path, mapped, pctx)
                               : null;
          if (typeof a !== 'string' || a !== b ||
              a.indexOf('not-there-' + i) < 0) {
            differing.push(page.path + ' (mapped query)');
          }
        }
      }
      if (EXAMPLES[page.path]) {
        const query = Object.assign({ per: '10' }, EXAMPLES[page.path]);
        const label = page.path + ' (example)';
        const one = await viewOf(page, query).catch(function (e) {
          unviewed.push(label + ': ' + String((e && e.message) || e));
          return null;
        });
        if (one) {
          const ectx = WebKit.context(query, true);
          const a = WebPages.render(page.path, one, ectx);
          const b = StsConsole ? StsConsole.render(page.path, one, ectx)
                               : null;
          if (typeof a !== 'string' || a.length < 100 || a !== b ||
              a === mine) {
            differing.push(label + ' (' + String(a).length + ' against ' +
                           String(b).length + ')');
          }
          exampled.push(page.path);
        }
      }
      if (!page.drill) {
        continue;
      }
      // THE DRILL-DOWN, twice: of an item the list named, when it named
      // one, and of one that is not there — the answer a link drawn a
      // moment ago gets once somebody deleted what it names.
      const sampled = page.drill.sample(view);
      drilled.push(page.path + (sampled ? '' : ' (nothing to sample)'));
      const items = [sampled, 'cn=not-there-' + i].filter(Boolean);
      for (let k = 0; k < items.length; k++) {
        const query = { per: '10' };
        query[page.drill.param] = items[k];
        const label = page.path + '?' + page.drill.param + '=' + items[k];
        let one = null;
        try {
          one = await viewOf(page, query);
        } catch (e) {
          unviewed.push(label + ': ' + String((e && e.message) || e));
          continue;
        }
        const dctx = WebKit.context(query, true);
        const a = WebPages.render(page.path, one, dctx);
        const b = StsConsole ? StsConsole.render(page.path, one, dctx) : null;
        // Not the list again: a drill that fell through to the list's
        // renderer would draw the same page for every item.
        if (typeof a !== 'string' || a.length < 100 || a !== b ||
            a === mine) {
          differing.push(label + ' (' + String(a).length + ' against ' +
                         String(b).length + ')');
        }
      }
    }
    // THE DRIFT CHECK, IN PROCESS (#446): `/admin/sts-metadata`'s answer
    // reports a route registered and undescribed, and a description of a
    // route that is not registered. Every page converted here owes its
    // operation a row there, and the protocol job that fails on the drift
    // runs only against a container; this is the same check, here.
    const metaPage = WebPages.PAGES.filter(function (page) {
      return page.path === '/admin/sts-metadata';
    })[0];
    const meta = metaPage ? await viewOf(metaPage, {}).catch(function () {
      return null;
    }) : null;
    note(!!meta && meta.undocumentedPaths.length === 0 &&
         meta.stalePaths.length === 0,
         'D-drift. no route is registered and undescribed, and no ' +
         'description ' +
         'names a route that is not registered',
         meta ? JSON.stringify({ undocumented: meta.undocumentedPaths,
                                 stale: meta.stalePaths }).slice(0, 600)
              : 'no metadata answer');
    note(unviewed.length === 0,
         'D0. the operation of every converted page answers a view, ' +
         'called as a handler', unviewed.join('; '));
    note(differing.length === 0,
         'D1. every converted page drawn by the bundle is, to the byte, ' +
         'what this process draws from the same view (' +
         WebPages.PAGES.length + ' page(s), and the drill-downs of ' +
         drilled.length + ', and ' + exampled.length + ' example(s))',
         differing.join(', ') ||
         'drill-downs: ' + drilled.join(', ') + '; examples: ' +
         exampled.join(', '));
    const report = mode.report();
    const here = WebPages.render('/admin/mode',
                                 JSON.parse(JSON.stringify(report)));
    const missing = report.requirements.filter(function (row) {
      return here.indexOf('id="requirement-' + WebKit.esc(row.id) + '"') < 0;
    }).concat(report.developmentOnlySettings.filter(function (row) {
      return here.indexOf('id="setting-' + WebKit.esc(row.key) + '"') < 0;
    }));
    note(missing.length === 0 && here.indexOf('<div class="tiles">') === 0 &&
         report.requirements.length > 10,
         'D2. and it carries every requirement and every development-only ' +
         'setting of the report', missing.length + ' missing of ' +
         (report.requirements.length +
          report.developmentOnlySettings.length));
    note(WebPages.render('/admin/not-converted', {}) === null,
         'D3. a page that is not converted is not drawn', '');
    // THE RENDER CONTEXT: what a page draws that is the reader's and not
    // the service's — the query it was asked with and whether they may
    // write.
    const made = WebKit.context({ page: '2' }, 'yes');
    const bare = WebKit.context();
    const monitorView = await viewOf(
      WebPages.pageFor('/admin/oauth2/monitor'), {});
    const parSection = monitorView.sections.filter(function (section) {
      return section.id === 'par';
    })[0];
    parSection.pushedRequests.items = [{
      request_uri: 'urn:ietf:params:oauth:request_uri:abcdefghijklmnop',
      client_id: 'client-<1>', authorization_server: '', state: 'live',
      created_at: '2026-10-05T00:00:00Z', expires_at: '2026-10-05T00:01:00Z',
      expires_in: 60, reads: 1, client_authenticated: true,
      authentication_method: 'private_key_jwt', source: 'form',
      redirect_uri: 'https://rp.example/cb', response_type: 'code',
      scope: 'openid', dpop_jkt: '' }];
    const heldPage = WebPages.render('/admin/oauth2/monitor', monitorView,
      WebKit.context({ state: 'live', page: '2', notAListParameter: 'x',
                       client_id: 'a&b' }, true));
    const backField = (/name="back" value="([^"]*)"/.exec(heldPage) ||
                       ['', ''])[1];
    note(made.write === false && made.query.page === '2' &&
         bare.write === false && Object.keys(bare.query).length === 0 &&
         WebKit.context({}, true).write === true &&
         backField.indexOf('state=live') >= 0 &&
         backField.indexOf('page=2') >= 0 &&
         backField.indexOf('client_id=a%26b') >= 0 &&
         backField.indexOf('notAListParameter') < 0 &&
         heldPage.indexOf('client-&lt;1&gt;') > 0 &&
         heldPage.indexOf('value="delete-pushed-request"') > 0,
         'D4. the render context is the query and a boolean and nothing ' +
         'else, and a page that takes it draws from it — a Withdraw on ' +
         'the OAuth activity page carries back the list parameters of the ' +
         'query it was drawn with and no other', backField);

    // --- E. the table is true ------------------------------------------------
    const consolePages = admin.consoleJson().pages;
    const operations = adminApi.operationSummaries().map(function (one) {
      return one.method + ' ' + one.path;
    });
    // A page of the console, or a page drawn under one of its tabs
    // (`/admin/keys/history` under Key pairs).
    const consolePage = function (path) {
      return consolePages.indexOf(path) >= 0 ||
        consolePages.some(function (one) {
          return path.indexOf(one + '/') === 0;
        });
    };
    const untrue = WebPages.PAGES.filter(function (page) {
      return !consolePage(page.path) ||
             operations.indexOf('GET ' + page.operation) < 0 ||
             typeof page.render !== 'function' || !page.title;
    }).map(function (page) { return page.path; });
    note(WebPages.PAGES.length >= 1 && untrue.length === 0,
         'E. every converted page is a page of the console and names a ' +
         'management API operation that exists', untrue.join(', ') + ' ' +
         operations.length + ' operation(s)');

    // --- F. the settings block is one block ----------------------------------
    const config = require(ROOT_DIR + '/common/config');
    const SettingsForms = require(ROOT_DIR + '/admin-ui/web_settings');
    // Two overrides, so the Reset buttons, the bold Source and the
    // "runtime override in force" note are all drawn somewhere.
    const overrideProblems = [
      config.setOverride('oauth2.consentRequired', 'false'),
      config.setOverride('totp.window', '0')
    ].filter(function (answer) { return !answer || answer.ok === false; });
    const settingPages = [];
    admin.settingHomes().forEach(function (row) {
      row.pages.forEach(function (page) {
        if (settingPages.indexOf(page) < 0) {
          settingPages.push(page);
        }
      });
    });
    const blockDiffers = [];
    let drawn = 0;
    let resets = 0;
    let sharedNotes = 0;
    let orderedChoices = 0;
    settingPages.forEach(function (page) {
      const theirs = admin.configFormsFor(page);
      const block = JSON.parse(JSON.stringify(admin.configSettingsJson(page)));
      const mine = SettingsForms.forms(block, page);
      const bundled = StsConsole && StsConsole.settings
        ? StsConsole.settings.forms(block, page) : null;
      if (mine !== theirs || mine !== bundled) {
        blockDiffers.push(page + ' (' + String(theirs).length + ', ' +
                          String(mine).length + ', ' +
                          String(bundled).length + ')');
      }
      drawn += mine ? 1 : 0;
      resets += mine.split('formaction="/admin/config?reset=').length - 1;
      sharedNotes += mine.indexOf('These are the same settings') >= 0 ? 1 : 0;
      orderedChoices += mine.indexOf('class="cfg-ordered"') >= 0 ? 1 : 0;
      // A page that draws a subset: each group alone, as /admin/listeners
      // draws its tabs.
      block.groups.forEach(function (group) {
        if (admin.configFormsFor(page, [group.group]) !==
            SettingsForms.forms(block, page, [group.group])) {
          blockDiffers.push(page + ' [' + group.group + ']');
        }
      });
    });
    note(overrideProblems.length === 0 && settingPages.length >= 20 &&
         drawn === settingPages.length && blockDiffers.length === 0,
         'F1. on every page that owns settings, the console\'s block is to ' +
         'the byte what web_settings.ts and the bundle draw from the ' +
         'page\'s settings member (' + settingPages.length + ' page(s))',
         blockDiffers.slice(0, 6).join('; ') + ' ' +
         JSON.stringify(overrideProblems));
    note(resets >= 2 && sharedNotes >= 2 && orderedChoices >= 1,
         'F2. and what was compared includes a Reset per override, the ' +
         'note on a group two pages share, and an ordered choice',
         resets + ' reset(s), ' + sharedNotes + ' shared note(s), ' +
         orderedChoices + ' ordered choice(s)');
    const sample = JSON.parse(JSON.stringify(
      admin.configSettingsJson('/admin/oauth2')));
    const kept = SettingsForms.forms(Object.assign({}, sample, {
      context: Object.assign({}, sample.context, {
        persistsAppconfig: true, persistenceMode: 'postgres',
        configFile: 'env/<mine>.js' }) }), '/admin/oauth2');
    const lost = SettingsForms.forms(Object.assign({}, sample, {
      context: Object.assign({}, sample.context, {
        persistsAppconfig: false, configFile: null }) }), '/admin/oauth2');
    note(sample.context && typeof sample.context.defaultsFile === 'string' &&
         kept.indexOf('Changes here SURVIVE A RESTART') > 0 &&
         kept.indexOf('<code>persistence.mode=postgres</code>') > 0 &&
         kept.indexOf('<code>env/&lt;mine&gt;.js</code>') > 0 &&
         kept.indexOf('gone on restart') < 0 &&
         lost.indexOf('are in memory and are gone on restart') > 0 &&
         lost.indexOf('<code>env/local.js</code>') > 0 &&
         lost.indexOf('SURVIVE A RESTART') < 0 &&
         SettingsForms.forms({ groups: [] }, '/admin/x') === '',
         'F3. the persistence note is drawn from the block\'s context, ' +
         'either way, and a page with no group draws nothing',
         JSON.stringify(sample.context));
    config.clearOverride('oauth2.consentRequired');
    config.clearOverride('totp.window');

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'wb-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  AG_ROOT: ROOT, AG_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console_web_bundle',
  describe: 'the console\'s web_ modules require nothing a browser lacks, ' +
            'and the browser bundle draws a converted page as this ' +
            'process does (#446)',
  run: run
};
