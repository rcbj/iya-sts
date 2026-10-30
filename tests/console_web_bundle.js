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
//
//   D-notdo (#753): `/admin`'s *What it deliberately does not do* is drawn
//   in development mode and not in product mode, by both renderers.
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
    const protocolEndpoints =
      require(ROOT_DIR + '/admin-core/protocol_endpoints');
    const WebKit = require(ROOT_DIR + '/admin-ui/web_kit');
    const WebPages = require(ROOT_DIR + '/admin-ui/web_pages');
    const WebForms = require(ROOT_DIR + '/admin-ui/web_forms');
    // THE VIEW OF EVERY CONVERTED PAGE IS WHAT ITS OPERATION'S HANDLER
    // ANSWERS — the handler itself, called with a request that carries
    // nothing but a query, and not the function this test supposes the
    // handler calls. It was a table of those functions until a page was
    // found whose console JSON carried `settings` and whose operation did
    // not (`/admin/attribute-sources`): a table like that agrees with the
    // page module and proves nothing about the API. The gate is not in the
    // way here; it is `tests/protocol/admin_api.js`'s to hold.
    function apiAnswer(operation, query) {
      return new Promise(function (resolve, reject) {
        const entry = adminApi.ROUTES.filter(function (one) {
          return one.method === 'GET' && one.path === operation &&
                 typeof one.handler === 'function';
        })[0];
        const page = WebPages.PAGES.filter(function (one) {
          return one.operation === operation &&
            protocolEndpoints.pages().indexOf(one.path) >= 0;
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
            // The direct handler call skips admin-api's route wrapper, which
            // adds protocol endpoints to mirrored Protocols page answers.
            if (page && body && typeof body === 'object' &&
                !Array.isArray(body)) {
              body = Object.assign({}, body, {
                protocolEndpoints: protocolEndpoints.forPage(req, page.path)
              });
            }
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
            // The direct handler call skips admin-api's route wrapper, which
            // adds protocol endpoints to mirrored Protocols page answers.
            if (page && parsed && typeof parsed === 'object' &&
                !Array.isArray(parsed)) {
              parsed = Object.assign({}, parsed, {
                protocolEndpoints: protocolEndpoints.forPage(req, page.path)
              });
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
      const view = JSON.parse(JSON.stringify(answer.body));
      if (page.compose) {
        // The members as the runtime asks them (`composeRequests()`), each
        // under the names its own operation reads.
        const asked = WebPages.composeRequests(page, query || {});
        const answers = await Promise.all(asked.map(function (one) {
          return apiAnswer(one.operation, one.params);
        }));
        answers.forEach(function (one, index) {
          if (one.status !== 200 || !one.body ||
              typeof one.body !== 'object') {
            throw new Error(asked[index].operation + ' answered ' +
                            one.status);
          }
          view[asked[index].member] = JSON.parse(JSON.stringify(one.body));
        });
      }
      return view;
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
    // Loaded by the round-trip harness every static surface shares (#570):
    // no require, process, module or Buffer, which is what a browser has
    // not.
    const harness = require(ROOT_DIR + '/tests/tools/web_round_trip');
    const bundlePath = pathC.join(dir, 'console.bundle.js');
    const loaded = harness.loadBundle(bundlePath, 'StsConsole');
    const code = loaded.code;
    note(code.length > 500,
         'C1. the image build wrote the browser bundle',
         bundlePath + ' ' + code.length + ' byte(s)');
    const StsConsole = loaded.value;
    const loadProblem = loaded.problem;
    // THE DEFAULT TRANSLATOR (#539): in a browser the runtime sets it to
    // the page's own (`applyLocale()`), so a helper handed no translator
    // draws in the reader's language. Here there is no runtime, so the
    // bundle is given node's — English — and the two draw the same words.
    if (StsConsole && StsConsole.messages) {
      StsConsole.messages.WebTranslator.setDefault(function () {
        return WebKit.context().t;
      });
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
    const applications = require(ROOT_DIR + '/common/applications');
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
      // `api`: an origin a real door records, so the page's origin filter
      // offers only values its operation takes (F2).
      selectors: [{ type: 'unix', value: 'uid:1000' }] }, 'api', td, 'test');
    note(seededEntry && seededEntry.ok, 'D-seed-spiffe. an entry is made',
         JSON.stringify((seededEntry && seededEntry.errors) || []));
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
    // Every page drawn, kept for the form check below (F1).
    const drawnPages = [];
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
      drawnPages.push({ path: page.path, html: mine });
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
          drawnPages.push({ path: label, html: a });
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
        drawnPages.push({ path: label, html: a });
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
    // EVERY POST FORM A CONVERTED PAGE DRAWS IS ONE /admin-api OPERATION
    // (#446). The static console sends a submitted form to the operation
    // that mirrors it (`web_forms.ts`), read off `GET
    // /admin-api/console/operations` — both kinds since #454, because a
    // form helper is the console's own operation; a form that resolves to
    // none, or to two, is a control the static console could not work.
    const formTable = WebForms.table(adminApi.operationSummaries('all'));
    const unresolved = {};
    let forms = 0;
    drawnPages.forEach(function (one) {
      const re = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
      let m = re.exec(one.html);
      while (m) {
        const form = m[0];
        const head = /^<form\b[^>]*>/i.exec(form)[0];
        if (/method="post"/i.test(head)) {
          const target = (/action="([^"]*)"/i.exec(head) || [])[1] || '';
          const targetUrl = new URL(target, 'https://sts.example');
          const path = targetUrl.pathname + targetUrl.hash;
          const actions = [];
          const fields = /<(?:input|button)\b[^>]*\bname="action"[^>]*>/gi;
          let f = fields.exec(form);
          while (f) {
            const v = (/value="([^"]*)"/i.exec(f[0]) || [])[1];
            if (v !== undefined && actions.indexOf(v) < 0) {
              actions.push(v);
            }
            f = fields.exec(form);
          }
          // A <select name="action"> offers its options as the action.
          const select = /<select\b[^>]*\bname="action"[^>]*>([\s\S]*?)<\/select>/i
            .exec(form);
          if (select) {
            const opts = /<option\b[^>]*value="([^"]*)"/gi;
            let o = opts.exec(select[1]);
            while (o) {
              if (o[1] && actions.indexOf(o[1]) < 0) {
                actions.push(o[1]);
              }
              o = opts.exec(select[1]);
            }
          }
          (actions.length ? actions : ['']).forEach(function (action) {
            forms++;
            if (!WebForms.resolve(formTable, path, action)) {
              const key = path + (action ? ' ' + action : '');
              unresolved[key] = unresolved[key] || one.path;
            }
          });
        }
        m = re.exec(one.html);
      }
    });
    // A SUBMIT BUTTON WITH A NAME OF ITS OWN was an act of its own on the
    // server (#446): the handler read the pressed button's name before the
    // form's hidden `action` — "+" and the bin, the workbench's Generate,
    // Fill. Sent as the form, each would be the form's action (a create, an
    // issue). So each is a round trip `web_answers.ts` draws, or names its
    // own act in a `formaction`, or is one the runtime asks for (Fill), or
    // is listed here with what it is.
    const WebAnswersMod = require(ROOT_DIR + '/admin-ui/web_answers');
    const BUTTON_NAMES_SENT_AS_FIELDS = {
      // The pressed button's value is a field the operation reads: the
      // signing keys' Rotate all is `units=all`, which `rotate` takes.
      units: '/admin/keys/rotate\'s units'
    };
    const unhandledButtons = {};
    drawnPages.forEach(function (one) {
      const re = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
      let m = re.exec(one.html);
      while (m) {
        const form = m[0];
        const head = /^<form\b[^>]*>/i.exec(form)[0];
        const path = ((/action="([^"]*)"/i.exec(head) || [])[1] || '')
          .replace(/\?.*$/, '');
        const hiddenAction = (/<input\b[^>]*\bname="action"[^>]*\bvalue="([^"]*)"/i
          .exec(form) || [])[1] || '';
        const buttons = /<button\b[^>]*>/gi;
        let b = buttons.exec(form);
        while (b) {
          const name = (/\bname="([^"]*)"/i.exec(b[0]) || [])[1];
          // A BUTTON THAT POSTS ELSEWHERE resolves where it posts: its
          // `formaction`'s path, with the action its query names in place
          // of the form's (the PKI workbench's Download was refused for
          // want of this).
          const formaction = (/\bformaction="([^"]*)"/i.exec(b[0]) || [])[1];
          if (formaction) {
            const fa = new URL(formaction.replace(/&amp;/g, '&'),
                               'https://sts.example');
            const faAction = fa.searchParams.get('action') || hiddenAction;
            if (!WebForms.resolve(formTable, fa.pathname, faAction)) {
              const key = fa.pathname + ' ' + faAction + ' (formaction)';
              unhandledButtons[key] = unhandledButtons[key] || one.path;
            }
          }
          if (name && name !== 'action' &&
              !/\bformaction="/i.test(b[0]) &&
              !(path === '/admin/users/new' && name === 'fill') &&
              !BUTTON_NAMES_SENT_AS_FIELDS[name]) {
            const fieldsOf = {};
            fieldsOf[name] = 'x';
            if (!WebAnswersMod.isRoundTrip(path, fieldsOf)) {
              const key = path + ' ' + name;
              unhandledButtons[key] = unhandledButtons[key] || one.path;
            }
          }
          b = buttons.exec(form);
        }
        m = re.exec(one.html);
      }
    });
    note(Object.keys(unhandledButtons).length === 0,
         'F0b. no named button is sent as its form\'s action by mistake, ' +
         'and every formaction resolves to an operation',
         Object.keys(unhandledButtons).map(function (k) {
           return k + ' (on ' + unhandledButtons[k] + ')';
         }).join('; '));
    note(forms > 300 && Object.keys(unresolved).length === 0,
         'F0. every POST form a converted page draws resolves to one ' +
         '/admin-api operation (web_forms.ts, off GET ' +
         '/admin-api/console/operations)',
         forms + ' form action(s), ' + Object.keys(unresolved).length +
         ' unresolved: ' + Object.keys(unresolved).map(function (k) {
           return k + ' (on ' + unresolved[k] + ')';
         }).join('; '));

    // AND WHAT EACH FORM SENDS IS A BODY ITS OPERATION TAKES (#446): the
    // fields the browser would send — every named input as drawn, a
    // checkbox only when checked, a select's selected option — shaped by
    // the runtime's own `shapeFields()` against this process's OpenAPI
    // document, and asked of the API's own `checkRequestBody()`. A member
    // the schema does not name, or a value of a type it does not take, is a
    // form the static console could not send. A missing REQUIRED value is
    // not counted: a form drawn empty is filled in by its reader.
    //
    // AND FILLED IN (F1c, 2026-10-05): the same forms with every checkbox
    // ticked and every empty box typed in. Drawn empty, a form hid three
    // defects from F1 and F1b — the combined `vc` protocol choice
    // applications/create refused, and the new-user and new-application
    // field grids a closed schema dropped — because an unticked box sends
    // nothing and an empty one is an absent value.
    const ConsoleRuntime = require(ROOT_DIR + '/admin-ui/web_runtime');
    // A JOINED FIELD (#219) is sent as its parts, as the runtime sends it
    // (`splitJoinedFields()`): Monitoring → Risk's `dataset|format`.
    const asSent = function (fields) {
      const data = new FormData();
      Object.keys(fields).forEach(function (name) {
        [].concat(fields[name]).forEach(function (value) {
          data.append(name, String(value));
        });
      });
      ConsoleRuntime.splitJoinedFields(data);
      return ConsoleRuntime.fieldsOf(data);
    };
    const specModule = require(ROOT_DIR + '/mgmt-api/admin_api_spec');
    const shaper = new ConsoleRuntime({ location: { pathname: '/admin' } });
    shaper.spec = specModule.buildSpec(adminApi.ROUTES, adminApi.specOptions({
      headers: { host: 'sts.example' }, protocol: 'https', secure: true,
      get: function () { return ''; } }));
    const routeOf = function (operation) {
      const action = operation.split('/').pop();
      const entry = adminApi.ROUTES.filter(function (one) {
        return one.method === 'POST' && (one.path === operation ||
          (!!one.route && (one.actions || []).some(function (a) {
            return one.route.replace(':action', a.action) === operation;
          })));
      })[0];
      return entry ? { route: entry.route || entry.path,
                       action: entry.route ? action : '',
                       owns: !!entry.handlerOwnsBody } : null;
    };
    // `filled`: the form as a reader who ticked every box and typed in
    // every empty one would send it (F1c), where the default is the form as
    // drawn.
    const fieldsOfForm = function (form, action, filled) {
      const fields = {};
      const add = function (name, value) {
        if (Object.prototype.hasOwnProperty.call(fields, name)) {
          fields[name] = [].concat(fields[name], [value]);
        } else {
          fields[name] = value;
        }
      };
      const inputs = /<input\b[^>]*>/gi;
      let m = inputs.exec(form);
      while (m) {
        const tag = m[0];
        const name = (/\bname="([^"]*)"/i.exec(tag) || [])[1];
        const type = ((/\btype="([^"]*)"/i.exec(tag) || [])[1] || 'text')
          .toLowerCase();
        const value = (/\bvalue="([^"]*)"/i.exec(tag) || [])[1];
        const typed = type === 'text' || type === 'email' ||
                      type === 'url' || type === 'tel';
        if (name && name !== 'action' && type !== 'submit' &&
            type !== 'file' &&
            ((type !== 'checkbox' && type !== 'radio') ||
             /\bchecked\b/i.test(tag) || (filled && type === 'checkbox'))) {
          add(name, filled && typed && !value ? 'filled'
            : value === undefined ? (type === 'checkbox' ? 'on' : '')
                                  : value.replace(/&amp;/g, '&')
                                          .replace(/&quot;/g, '"')
                                          .replace(/&lt;/g, '<')
                                          .replace(/&gt;/g, '>'));
        }
        m = inputs.exec(form);
      }
      const selects = /<select\b[^>]*\bname="([^"]*)"[^>]*>([\s\S]*?)<\/select>/gi;
      m = selects.exec(form);
      while (m) {
        if (m[1] !== 'action') {
          const chosen = /<option\b[^>]*\bselected\b[^>]*value="([^"]*)"|<option\b[^>]*value="([^"]*)"[^>]*\bselected\b/i.exec(m[2]) ||
            /<option\b[^>]*value="([^"]*)"/i.exec(m[2]);
          if (chosen) {
            add(m[1], chosen[1] !== undefined ? chosen[1] : chosen[2]);
          }
        }
        m = selects.exec(form);
      }
      const areas = /<textarea\b[^>]*\bname="([^"]*)"[^>]*>([\s\S]*?)<\/textarea>/gi;
      m = areas.exec(form);
      while (m) {
        add(m[1], m[2]);
        m = areas.exec(form);
      }
      fields.action = action;
      return fields;
    };
    const refusedBodies = {};
    // The fields only the server-rendered console read: where to send the
    // browser after, and its CSRF token. The static console needs none.
    const CONSOLE_ONLY = ['back', 'from', 'csrf_token', 'where', 'anchor'];
    // And per operation: the tab a field grid's Save came back to, and the
    // view a create form or a sub-tab (#500, `WebKit.viewSwitch()`) was
    // drawn in, which only a redraw reads.
    const CONSOLE_ONLY_AT = {
      '/admin-api/users/update-fields': ['group', 'view'],
      '/admin-api/applications/update-fields': ['group', 'view'],
      '/admin-api/users/create': ['view'],
      '/admin-api/applications/create': ['view'],
      // Directory → Policies' New passkey profile (#841). The hidden
      // field tells a refused create apart from a save of a stored
      // profile; web_answers.ts reads it and the API does not take it.
      '/admin-api/policies/save-passkey-policy': ['newProfile'],
      // And the locale policy's, tabbed since #1238.
      '/admin-api/policies/save-locale-policy': ['newProfile'],
      // And the New service-account policy (#1240), for the same reason.
      '/admin-api/policies/save-serviceAccount-policy': ['newProfile']
    };
    // AND A FIELD'S SEARCH (#459, #461): its box, its page and its people
    // / applications toggle are read by the runtime's round trip and never
    // sent — `fgfind.<attribute>`, `fgpage.<attribute>`, `fgkind.<...>`.
    const SEARCH_CONTROL = /^fg(find|page|kind)\./;
    const droppedFields = {};
    const droppedFilled = {};
    const refusedChoicesPosted = {};
    let bodies = 0;
    for (let i = 0; i < drawnPages.length; i++) {
      const one = drawnPages[i];
      const re = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
      let m = re.exec(one.html);
      while (m) {
        const form = m[0];
        const head = /^<form\b[^>]*>/i.exec(form)[0];
        if (/method="post"/i.test(head) &&
            !/multipart\/form-data/i.test(head)) {
          const path = ((/action="([^"]*)"/i.exec(head) || [])[1] || '')
            .replace(/\?.*$/, '');
          const hidden = /<input\b[^>]*\bname="action"[^>]*\bvalue="([^"]*)"/i
            .exec(form);
          const action = hidden ? hidden[1] : '';
          const operation = WebForms.resolve(formTable, path, action);
          const route = operation ? routeOf(operation) : null;
          if (route && !route.owns) {
            bodies++;
            const sent = asSent(fieldsOfForm(form, action));
            const shaped = shaper.shapeFields(sent,
              await shaper.requestSchema(operation));
            delete shaped.action;
            // WHAT THE SHAPING DROPPED, beside what it refused: a member the
            // schema does not name is left out without a word, and a box the
            // reader typed in that is left out is a value lost.
            Object.keys(sent).forEach(function (name) {
              // A column of checkboxes is carried into the list member its
              // operation takes (`attribute` into `attributes`).
              if (name === 'action' || CONSOLE_ONLY.indexOf(name) >= 0 ||
                  SEARCH_CONTROL.test(name) ||
                  (CONSOLE_ONLY_AT[operation] || []).indexOf(name) >= 0 ||
                  Object.prototype.hasOwnProperty.call(shaped, name) ||
                  Object.prototype.hasOwnProperty.call(shaped, name + 's')) {
                return;
              }
              // An empty box is left out on purpose where the schema could
              // not take an empty string: it is an absent value.
              const carried = [].concat(sent[name]).filter(function (v) {
                return String(v) !== '';
              });
              if (!carried.length) {
                return;
              }
              const key = operation + ': ' + name.replace(/\.\d+$/, '.N');
              droppedFields[key] = droppedFields[key] || one.path;
            });
            // FILLED IN (F1c): every checkbox ticked and every empty box
            // typed in. A box is dropped only where the schema does not
            // name it, and a ticked box is refused only where its value is
            // not in the member's enum — the two ways a form drawn empty
            // hides a control its operation cannot take.
            const full = asSent(fieldsOfForm(form, action, true));
            const fullShaped = shaper.shapeFields(full,
              await shaper.requestSchema(operation));
            Object.keys(full).forEach(function (name) {
              if (name === 'action' || CONSOLE_ONLY.indexOf(name) >= 0 ||
                  SEARCH_CONTROL.test(name) ||
                  (CONSOLE_ONLY_AT[operation] || []).indexOf(name) >= 0 ||
                  Object.prototype.hasOwnProperty.call(fullShaped, name) ||
                  Object.prototype.hasOwnProperty.call(fullShaped,
                                                       name + 's')) {
                return;
              }
              if (![].concat(full[name]).some(function (v) {
                return String(v) !== '';
              })) {
                return;
              }
              const key = operation + ': ' + name.replace(/\.\d+$/, '.N');
              droppedFilled[key] = droppedFilled[key] || one.path;
            });
            delete fullShaped.action;
            const fullChecked = adminApi.checkRequestBody({
              __adminApiRoute: route.route,
              params: { action: route.action },
              body: JSON.stringify(fullShaped),
              headers: { 'content-type': 'application/json' } });
            (fullChecked.errors || []).filter(function (e) {
              // `common/closed_sets.ts`'s sentence names the values the
              // set accepts; ajv's own wording is kept for a schema it words.
              // A box typed in is not a choice the form offers: a confirm
              // word, a country code, are the reader's to type right.
              return / it accepts: |allowed values|must be equal to one of/i
                .test(e) && !/ is "filled"/.test(e);
            }).forEach(function (e) {
              const key = operation + ': ' + e;
              refusedChoicesPosted[key] = refusedChoicesPosted[key] ||
                                          one.path;
            });
            const checked = adminApi.checkRequestBody({
              __adminApiRoute: route.route,
              params: { action: route.action },
              body: JSON.stringify(shaped),
              headers: { 'content-type': 'application/json' } });
            const real = (checked.errors || []).filter(function (e) {
              return !/(?:is required\.|must have required property)/.test(e);
            });
            if (!checked.ok && real.length) {
              const key = operation + ': ' + real[0];
              refusedBodies[key] = refusedBodies[key] || one.path;
            }
          }
        }
        m = re.exec(one.html);
      }
    }
    note(Object.keys(droppedFields).length === 0,
         'F1b. and nothing a form carries is dropped on the way',
         Object.keys(droppedFields).length + ' dropped: ' +
         Object.keys(droppedFields).map(function (k) {
           return k + ' (on ' + droppedFields[k] + ')';
         }).join('; '));
    note(Object.keys(droppedFilled).length === 0 &&
         Object.keys(refusedChoicesPosted).length === 0,
         'F1c. and a form filled in — every box ticked, every empty one ' +
         'typed in — loses nothing and offers no choice its operation refuses',
         Object.keys(droppedFilled).length + ' dropped: ' +
         Object.keys(droppedFilled).map(function (k) {
           return k + ' (on ' + droppedFilled[k] + ')';
         }).join('; ') + '; ' + Object.keys(refusedChoicesPosted).length +
         ' refused: ' + Object.keys(refusedChoicesPosted).map(function (k) {
           return k + ' (on ' + refusedChoicesPosted[k] + ')';
         }).join('; '));
    // AND EVERY GET FORM'S CHOICES ARE VALUES ITS OPERATION TAKES (#446):
    // a filter's <select> offers values, and since the cutover each is sent
    // to the page's operation, which refuses a query value its declared
    // enum does not name. The server-rendered page never validated its own
    // query, so an option the API refuses (the Devices page's attestation
    // `bearer`) was a filter that silently did nothing; now it is a 400.
    const refusedChoices = {};
    let choicesChecked = 0;
    drawnPages.forEach(function (one) {
      const re = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
      let m = re.exec(one.html);
      while (m) {
        const form = m[0];
        const head = /^<form\b[^>]*>/i.exec(form)[0];
        const method = ((/method="([^"]*)"/i.exec(head) || [])[1] || 'get')
          .toLowerCase();
        const target = ((/action="([^"]*)"/i.exec(head) || [])[1] ||
                        one.path).replace(/[?#].*$/, '');
        const page = method === 'get' ? WebPages.pageFor(target) : null;
        const op = page && shaper.spec.paths[page.operation] &&
                   shaper.spec.paths[page.operation].get;
        if (op) {
          const params = {};
          (op.parameters || []).forEach(function (p) {
            params[p.name] = shaper.deref(p.schema || {}) || {};
          });
          const selects = /<select\b[^>]*\bname="([^"]*)"[^>]*>([\s\S]*?)<\/select>/gi;
          let sel = selects.exec(form);
          while (sel) {
            const mapped = Object.keys(WebPages.operationQuery(page.path,
              (function () {
                const q = {};
                q[sel[1]] = 'x';
                return q;
              })())).filter(function (k) {
                return k !== 'rows';
              })[0];
            const schema = params[mapped];
            const opts = /<option\b[^>]*value="([^"]*)"/gi;
            let o = opts.exec(sel[2]);
            while (o) {
              if (o[1] !== '' && schema && Array.isArray(schema.enum)) {
                choicesChecked++;
                if (schema.enum.indexOf(o[1]) < 0) {
                  const key = page.operation + ' ' + mapped + '=' + o[1];
                  refusedChoices[key] = refusedChoices[key] || one.path;
                }
              }
              o = opts.exec(sel[2]);
            }
            sel = selects.exec(form);
          }
        }
        m = re.exec(one.html);
      }
    });
    note(choicesChecked > 0 && Object.keys(refusedChoices).length === 0,
         'F2. every choice a GET form offers is a value its operation takes',
         choicesChecked + ' choice(s) checked, ' +
         Object.keys(refusedChoices).length + ' refused: ' +
         Object.keys(refusedChoices).map(function (k) {
           return k + ' (on ' + refusedChoices[k] + ')';
         }).join('; '));
    note(bodies > 300 && Object.keys(refusedBodies).length === 0,
         'F1. what each form sends is a body its operation takes',
         bodies + ' form(s) checked, ' +
         Object.keys(refusedBodies).length + ' refused: ' +
         Object.keys(refusedBodies).map(function (k) {
           return k + ' (on ' + refusedBodies[k] + ')';
         }).join('; '));

    // Seed the SAML applications after checking every form: a registered
    // SAML 1.1 relying party changes the provider page's registration form.
    // These entries exist only to verify the application's own nested tabs.
    const seeded = applications.createApplication({
      identifier: 'https://sp.webcheck.example/saml2',
      kind: 'saml2-service-provider', protocol: 'SAML 2.0',
      protocols: ['saml2'],
      note: 'drawn by the bundle check',
      fields: { samlEntityId: 'https://sp.webcheck.example/saml2' }
    });
    const seeded11 = applications.createApplication({
      identifier: 'urn:webcheck:saml11',
      kind: 'saml11-relying-party', protocol: 'SAML 1.1',
      protocols: ['saml11'],
      note: 'drawn by the bundle check'
    });
    const seededDual = applications.createApplication({
      identifier: 'https://sp.webcheck.example/dual',
      kind: 'saml2-service-provider', protocol: 'SAML 2.0 and SAML 1.1',
      protocols: ['saml2', 'saml11'],
      note: 'drawn by the bundle check',
      fields: { samlEntityId: 'https://sp.webcheck.example/dual' }
    });
    note(seeded && seeded.ok && seeded11 && seeded11.ok &&
         seededDual && seededDual.ok,
         'D-seed. the SAML 2.0, SAML 1.1 and dual-family applications are made',
         JSON.stringify([(seeded && seeded.errors) || [],
                        (seeded11 && seeded11.errors) || [],
                        (seededDual && seededDual.errors) || []]));
    const applicationPage = WebPages.PAGES.filter(function (one) {
      return one.path === '/admin/applications';
    })[0];
    const applicationTabs = [
      { id: 'saml2', query: 'https://sp.webcheck.example/saml2',
        want: ['cfg-saml2'], omit: ['cfg-saml11'] },
      { id: 'saml11', query: 'urn:webcheck:saml11',
        want: ['cfg-saml11'], omit: ['cfg-saml2'] },
      { id: 'dual', query: 'https://sp.webcheck.example/dual',
        want: ['cfg-saml2', 'cfg-saml11'], omit: [] }
    ];
    for (let i = 0; i < applicationTabs.length; i++) {
      const one = applicationTabs[i];
      const detail = await viewOf(applicationPage, {
        application: one.query, per: '10'
      });
      const html = WebPages.render(applicationPage.path, detail,
        WebKit.context({ application: one.query }, true));
      const present = one.want.every(function (id) {
        return html.indexOf('id="' + id + '"') >= 0;
      });
      const absent = one.omit.every(function (id) {
        return html.indexOf('id="' + id + '"') < 0;
      });
      note(present && absent &&
          (one.id !== 'dual' ||
            (html.indexOf('name="family" value="saml2"') >= 0 &&
             html.indexOf('name="family" value="saml11"') >= 0)) &&
          html.indexOf('name="file"') >= 0 &&
          html.indexOf('name="document"') >= 0,
          'D-SAML-' + one.id + '. the matching metadata sub-tabs offer paste ' +
          'and file import for their family',
          'want=' + one.want.join(',') + '; omit=' + one.omit.join(','));
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
                                 stale: meta.stalePaths }).slice(0, 20000)
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
    const oauthPage = WebPages.pageFor('/admin/oauth2');
    const oauthView = oauthPage ? await viewOf(oauthPage, {}) : null;
    const oauthHtml = oauthView
      ? WebPages.render('/admin/oauth2', oauthView, WebKit.context({}, true))
      : '';
    const oauthTabIds = [
      'oauth-tab-metadata', 'oauth-tab-global-settings',
      'oauth-tab-authorization-servers',
      'oauth-tab-token-lifetimes', 'oauth-tab-claims',
      'oauth-tab-userinfo-claims'
    ];
    const metadataTab =
      /<section class="tabpanel first" id="oauth-tab-metadata">([\s\S]*?)<\/section>/
        .exec(oauthHtml);
    const globalTab =
      /<section class="tabpanel" id="oauth-tab-global-settings">([\s\S]*?)<\/section>/
        .exec(oauthHtml);
    // THE ENDPOINT TABLE, NOT THE PATH: a setting's description may name
    // the authorization endpoint in prose (oauth2.spInitiatedSso, #426, is
    // about what /oauth2/authorize answers), so what must be on Metadata and
    // nowhere on Global settings is the endpoint table's row — the URL in a
    // <code> of its own (`WebPages.endpointTable()`).
    const endpointRow = /<code>[^<]*\/oauth2\/authorize<\/code>/;
    const metadataWarnings = metadataTab
      ? (metadataTab[1].match(/<details class="warn fold">/g) || []).length
      : 0;
    note(oauthTabIds.every(function (id) {
      return oauthHtml.indexOf('id="' + id + '"') >= 0;
    }) && oauthHtml.indexOf('consoleAuthorizationServers') < 0 &&
         oauthHtml.indexOf('openid-configuration') >= 0 &&
         !!metadataTab && !!globalTab &&
         metadataTab[1].indexOf('<details class="note fold">') >= 0 &&
         metadataWarnings === oauthView.alsoHtml.length &&
         metadataTab[1].indexOf('The authorization server') >= 0 &&
         metadataTab[1].indexOf('is a MODE, and so is') >= 0 &&
         endpointRow.test(metadataTab[1]) &&
         globalTab[1].indexOf('The authorization server') < 0 &&
         globalTab[1].indexOf('is a MODE, and so is') < 0 &&
         !endpointRow.test(globalTab[1]),
         'D-OAuth. Metadata is the first peer tab and contains the notes and ' +
         'endpoints, separate from Global settings',
         'tabs missing: ' + oauthTabIds.filter(function (id) {
           return oauthHtml.indexOf('id="' + id + '"') < 0;
         }).join(', ') + '; warning folds: ' + metadataWarnings + '/' +
         (oauthView ? oauthView.alsoHtml.length : 0) +
         '; endpoint table on Metadata: ' + (!!metadataTab &&
           endpointRow.test(metadataTab[1])) +
         '; on Global: ' + (!!globalTab && endpointRow.test(globalTab[1])) +
         '; notes on Global: ' + (!!globalTab &&
           (globalTab[1].indexOf('The authorization server') >= 0 ||
            globalTab[1].indexOf('is a MODE, and so is') >= 0)));
    const samlPage = WebPages.pageFor('/admin/saml2');
    const samlView = samlPage ? await viewOf(samlPage, {}) : null;
    const samlHtml = samlView
      ? WebPages.render('/admin/saml2', samlView,
                        WebKit.context({}, true))
      : '';
    const samlTabIds = [
      'saml-tab-metadata', 'saml-tab-global-settings',
      'saml-tab-shared-settings', 'saml-tab-saml2', 'saml-tab-saml11',
      'saml-tab-idp-initiated', 'saml-tab-assertions', 'saml-tab-attributes'
    ];
    const samlMetadataTab =
      /<section class="tabpanel first" id="saml-tab-metadata">([\s\S]*?)<\/section>/
        .exec(samlHtml);
    const samlGlobalTab =
      /<section class="tabpanel" id="saml-tab-global-settings">([\s\S]*?)<\/section>/
        .exec(samlHtml);
    const samlSharedTab =
      /<section class="tabpanel" id="saml-tab-shared-settings">([\s\S]*?)<\/section>/
        .exec(samlHtml);
    const saml2Tab =
      /<section class="tabpanel" id="saml-tab-saml2">([\s\S]*?)<\/section>/
        .exec(samlHtml);
    const saml11Tab =
      /<section class="tabpanel" id="saml-tab-saml11">([\s\S]*?)<\/section>/
        .exec(samlHtml);
    const samlTabLabels = samlHtml.match(
      /<a[^>]+href="#saml-tab-saml(?:2|11)"[^>]*>[^<]*<\/a>/g) || [];
    const samlAssertionTab =
      /<section class="tabpanel" id="saml-tab-assertions">([\s\S]*?)<\/section>/
        .exec(samlHtml);
    const samlAttributeTab =
      /<section class="tabpanel" id="saml-tab-attributes">([\s\S]*?)<\/section>/
        .exec(samlHtml);
    const settingKeys = function (settings, groups) {
      return (settings.groups || []).filter(function (group) {
        return groups.indexOf(group.group) >= 0;
      }).reduce(function (keys, group) {
        return keys.concat(group.settings.map(function (setting) {
          return setting.key;
        }));
      }, []);
    };
    const hasSettings = function (tab, keys) {
      return !!tab && keys.length > 0 && keys.every(function (key) {
        return tab[1].indexOf('name="' + WebKit.esc(key) + '"') >= 0;
      });
    };
    const lacksSettings = function (tab, keys) {
      return !!tab && keys.every(function (key) {
        return tab[1].indexOf('name="' + WebKit.esc(key) + '"') < 0;
      });
    };
    const samlGlobalKeys = samlView
      ? settingKeys(samlView.settings, ['SAML 2.0', 'SAML 1.1']) : [];
    const samlSharedKeys = samlView
      ? settingKeys(samlView.settings, ['SAML']) : [];
    const samlAssertionKeys = samlView && samlView.assertions
      ? samlView.assertions.settings.map(function (setting) {
        return setting.key;
      }).filter(function (key) {
        return key !== 'saml.clockSkewS';
      }) : [];
    let samlExpectedEndpoints = samlView
      ? [samlView, samlView.saml11, samlView.assertions, samlView.attributes]
        .reduce(function (rows, answer) {
          return rows.concat(answer.protocolEndpoints || []);
        }, []) : [];
    const samlEndpointKeys = {};
    samlExpectedEndpoints = samlExpectedEndpoints.filter(function (row) {
      const key = String(row.name) + '\n' + String(row.url);
      if (samlEndpointKeys[key]) {
        return false;
      }
      samlEndpointKeys[key] = true;
      return true;
    });
    const saml2Intro = WebKit.context({}, true).t.html(
      'consoleSaml.saml2.intro');
    const saml11Intro = WebKit.context({}, true).t.html(
      'consoleSaml.saml11.intro');
    note(samlTabIds.every(function (id, n) {
      return samlHtml.indexOf('id="' + id + '"') >= 0 &&
        (n === 0 || samlHtml.indexOf('id="' + samlTabIds[n - 1] + '"') <
                    samlHtml.indexOf('id="' + id + '"'));
    }) && !!samlMetadataTab && !!samlGlobalTab && !!samlSharedTab &&
         !!saml2Tab && !!saml11Tab && !!samlAssertionTab &&
         !!samlAttributeTab,
         'D-SAML-tabs. the combined SAML page has all eight peer tabs, in ' +
         'order',
         samlTabIds.filter(function (id) {
           return samlHtml.indexOf('id="' + id + '"') < 0;
         }).join(', '));
    note(samlTabLabels.some(function (label) {
      return label === '<a href="#saml-tab-saml2">SAML 2.0 IdP</a>';
    }) && samlTabLabels.some(function (label) {
      return label === '<a href="#saml-tab-saml11">SAML 1.1 IdP</a>';
    }), 'D-SAML-tab-labels. profile tabs identify their identity providers',
    samlTabLabels.join(' '));
    note(!!samlMetadataTab &&
         samlMetadataTab[1].indexOf(saml2Intro) >= 0 &&
         samlMetadataTab[1].indexOf(saml11Intro) >= 0 &&
         samlMetadataTab[1].indexOf('saml-tab-saml2') >= 0 &&
         samlExpectedEndpoints.length > 0 &&
         samlExpectedEndpoints.every(function (row) {
           return samlMetadataTab[1].indexOf(WebKit.esc(row.url)) >= 0;
         }),
         'D-SAML-metadata. Metadata is first/default and holds the profile ' +
         'notes, SAML 2.0 link and all four endpoint lists',
         'first=' + !!samlMetadataTab + '; notes=' +
         (!!samlMetadataTab &&
           samlMetadataTab[1].indexOf(saml2Intro) >= 0) + '/' +
         (!!samlMetadataTab &&
           samlMetadataTab[1].indexOf(saml11Intro) >= 0) +
         '; endpoints=' + samlExpectedEndpoints.filter(function (row) {
           return samlMetadataTab &&
             samlMetadataTab[1].indexOf(WebKit.esc(row.url)) >= 0;
         }).length + '/' + samlExpectedEndpoints.length);
    note(hasSettings(samlGlobalTab, samlGlobalKeys) &&
         hasSettings(samlSharedTab, samlSharedKeys) &&
         hasSettings(samlAssertionTab, samlAssertionKeys),
         'D-SAML-settings. global, shared, and assertion settings render in ' +
         'their respective tabs',
         'settings=' + samlGlobalKeys.length + '/' + samlSharedKeys.length +
         '/' + samlAssertionKeys.length + '; present=' +
         hasSettings(samlGlobalTab, samlGlobalKeys) + '/' +
         hasSettings(samlSharedTab, samlSharedKeys) + '/' +
         hasSettings(samlAssertionTab, samlAssertionKeys));
    note(lacksSettings(samlSharedTab, samlGlobalKeys) &&
         lacksSettings(samlAssertionTab,
                       samlGlobalKeys.concat(samlSharedKeys)),
         'D-SAML-separation. Global, shared and assertion settings do not ' +
         'bleed into sibling tabs',
         'shared omits global=' +
         lacksSettings(samlSharedTab, samlGlobalKeys) +
         '; assertions omit others=' +
         lacksSettings(samlAssertionTab,
                       samlGlobalKeys.concat(samlSharedKeys)) +
         '; found=' +
         samlGlobalKeys.concat(samlSharedKeys).filter(function (key) {
           return samlAssertionTab &&
             samlAssertionTab[1].indexOf('name="' + WebKit.esc(key) +
                                          '"') >= 0;
         }).join(', '));
    note(!!samlAttributeTab &&
         samlAttributeTab[1].indexOf(WebKit.context({}, true).t.html(
           'consoleClaims.samlSetsHeading')) >= 0,
         'D-SAML-attributes. Custom SAML attributes has its own content tab',
         !!samlAttributeTab);
    note(!!saml2Tab && !!saml11Tab &&
         saml2Tab[1].indexOf(saml2Intro) < 0 &&
         saml11Tab[1].indexOf(saml11Intro) < 0 &&
         saml2Tab[1].indexOf('action="/admin/saml2#saml-tab-saml2"') >= 0 &&
         saml11Tab[1].indexOf(
           'action="/admin/saml2#saml-tab-saml11"') >= 0,
         'D-SAML-links. profile notes stay on Metadata and list forms keep ' +
         'submissions on their respective tabs',
         'SAML 2.0=' + (!!saml2Tab &&
           saml2Tab[1].indexOf(
             'action="/admin/saml2#saml-tab-saml2"') >= 0) +
         '; SAML 1.1=' + (!!saml11Tab &&
           saml11Tab[1].indexOf(
             'action="/admin/saml2#saml-tab-saml11"') >= 0));

    const vcPage = WebPages.pageFor('/admin/vc');
    const vcView = vcPage ? await viewOf(vcPage, {}) : null;
    const vcHtml = vcView
      ? WebPages.render('/admin/vc', vcView, WebKit.context({}, true))
      : '';
    // FIVE TABS SINCE #752: Credential status left for Monitoring →
    // Verifiable Credentials (D-VC-monitor, below).
    const vcTabIds = [
      'vc-tab-metadata', 'vc-tab-oid4vci', 'vc-tab-claims',
      'vc-tab-oid4vp', 'vc-tab-verifier-request'
    ];
    const vcTabs = {};
    vcTabIds.forEach(function (id) {
      vcTabs[id] = new RegExp(
        '<section class="tabpanel(?: first)?" id="' + id +
        '">([\\s\\S]*?)<\\/section>').exec(vcHtml);
    });
    const vcExpectedEndpoints = vcView
      ? vcView.protocolEndpoints || [] : [];
    note(vcTabIds.every(function (id) {
      return !!vcTabs[id];
    }) && /<section class="tabpanel first" id="vc-tab-metadata">/.test(
      vcHtml),
      'D-VC-tabs. the combined Verifiable Credentials page has five peer ' +
      'tabs with Metadata first',
      vcTabIds.filter(function (id) { return !vcTabs[id]; }).join(', '));
    note(!!vcView && vcView.vcStatus === undefined &&
         vcHtml.indexOf('id="vc-tab-status"') < 0 &&
         vcHtml.indexOf('id="vc-status-suspend-') < 0,
         'D-VC-no-status. the combined page neither asks for the status ' +
         'lists nor draws a Credential status tab (#752)');
    note(vcExpectedEndpoints.length > 0 &&
         vcExpectedEndpoints.every(function (row) {
           return vcTabs['vc-tab-metadata'] &&
             vcTabs['vc-tab-metadata'][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') >= 0;
         }) &&
         vcTabIds.slice(1).every(function (id) {
           return vcExpectedEndpoints.every(function (row) {
             return !vcTabs[id] || vcTabs[id][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') < 0;
           });
         }),
         'D-VC-metadata. the combined issuer and verifier endpoints appear ' +
         'on Metadata only',
         'endpoints=' + vcExpectedEndpoints.length);
    note(vcTabs['vc-tab-metadata'][1].indexOf(
           'The OpenID4VCI credential issuer,') >= 0 &&
         vcTabs['vc-tab-metadata'][1].indexOf(
           'The OpenID4VP Verifier, whose') >= 0 &&
         vcTabs['vc-tab-metadata'][1].indexOf(
           'href="/.well-known/openid-credential-issuer"') >= 0 &&
         vcTabs['vc-tab-metadata'][1].indexOf(
           'href="/issuer/offer"') < 0 &&
         vcTabs['vc-tab-oid4vci'][1].indexOf(
           'The OpenID4VCI credential issuer,') < 0 &&
         vcTabs['vc-tab-oid4vp'][1].indexOf(
           'The OpenID4VP Verifier, whose') < 0,
         'D-VC-metadata. issuer and verifier guidance and endpoint links are ' +
         'preserved on Metadata, not repeated in settings tabs');
    const issuerFold = vcTabs['vc-tab-metadata'][1].match(
      /<details class="fold vc-metadata"><summary>OpenID4VCI<\/summary>[\s\S]*?<\/details>/);
    const verifierFold = vcTabs['vc-tab-metadata'][1].match(
      /<details class="fold vc-metadata"><summary>OpenID4VP<\/summary>[\s\S]*?<\/details>/);
    note(!!issuerFold && !!verifierFold &&
         !/<details[^>]*\bopen\b/.test(issuerFold[0]) &&
         !/<details[^>]*\bopen\b/.test(verifierFold[0]) &&
         issuerFold[0].indexOf('The OpenID4VCI credential issuer,') >= 0 &&
         verifierFold[0].indexOf('The OpenID4VP Verifier, whose') >= 0,
         'D-VC-metadata-folds. issuer and verifier guidance is collapsed by ' +
         'default in native disclosure sections',
         'issuer=' + !!issuerFold + '; verifier=' + !!verifierFold);
    const vciKeys = vcView
      ? settingKeys(vcView.oid4vciSettings.settings, ['OID4VCI']) : [];
    const vpKeys = vcView
      ? settingKeys(vcView.oid4vpSettings.settings, ['OID4VP']) : [];
    note(hasSettings(vcTabs['vc-tab-oid4vci'], vciKeys) &&
         hasSettings(vcTabs['vc-tab-oid4vp'], vpKeys) &&
         lacksSettings(vcTabs['vc-tab-oid4vci'], vpKeys) &&
         lacksSettings(vcTabs['vc-tab-oid4vp'], vciKeys),
         'D-VC-settings. OpenID4VCI and OpenID4VP configuration stays in ' +
         'separate tabs',
         'settings=' + vciKeys.length + '/' + vpKeys.length);
    note(!!vcTabs['vc-tab-claims'] &&
         vcTabs['vc-tab-claims'][1].indexOf(
           'action="/admin/vc#vc-tab-claims"') >= 0 &&
         !!vcTabs['vc-tab-verifier-request'] &&
         vcTabs['vc-tab-verifier-request'][1].indexOf(
           'action="/admin/vc#vc-tab-verifier-request"') >= 0,
         'D-VC-forms. claim and verifier-request actions return to their ' +
         'own tabs',
         'claims=' + (vcTabs['vc-tab-claims']
           ? vcTabs['vc-tab-claims'][1].indexOf(
             'action="/admin/vc#vc-tab-claims"') : -1) +
         '; verifier=' + (vcTabs['vc-tab-verifier-request']
           ? vcTabs['vc-tab-verifier-request'][1].indexOf(
             'action="/admin/vc#vc-tab-verifier-request"') : -1));

    // MONITORING → VERIFIABLE CREDENTIALS (#752): what the Credential status
    // tab drew, on a page of its own, cut into tabs as its neighbours are —
    // the tiles, the note and where the lists are served on Metadata, the
    // credentials (one row fixed here, since a fresh realm has issued none)
    // on their own tab with their controls posting to the page.
    const vcMonitorPage = WebPages.pageFor('/admin/vc/monitor');
    const vcMonitorView = vcMonitorPage
      ? await viewOf(vcMonitorPage, {}) : null;
    if (vcMonitorView) {
      vcMonitorView.rows = [{
        idx: 1,
        format: 'dc+sd-jwt',
        configId: 'IdentityCredential',
        status: 'VALID',
        explicit: 'VALID',
        via: 'fixture',
        changedAt: 0,
        expiresAt: 1
      }];
    }
    const vcMonitorHtml = vcMonitorView
      ? WebPages.render('/admin/vc/monitor', vcMonitorView,
                        WebKit.context({}, true))
      : '';
    const vcMonitorTab = function (id) {
      const found = new RegExp(
        '<section class="tabpanel(?: first)?" id="' + id +
        '">([\\s\\S]*?)<\\/section>').exec(vcMonitorHtml);
      return found ? found[1] : null;
    };
    const vcMonitorMeta = vcMonitorTab('vc-monitor-tab-metadata');
    const vcMonitorCreds = vcMonitorTab('vc-monitor-tab-credentials');
    note(!!vcMonitorPage &&
         vcMonitorPage.operation === '/admin-api/vc-status' &&
         WebPages.titleOf(vcMonitorPage) ===
           'Verifiable Credentials (monitoring)' &&
         !!vcMonitorMeta && !!vcMonitorCreds &&
         vcMonitorMeta.indexOf(WebKit.esc(vcMonitorView.tokenStatusList)) >=
           0 &&
         vcMonitorMeta.indexOf('Bitstring Status Lists') >= 0 &&
         vcMonitorMeta.indexOf('id="vc-status-publish-revocation"') >= 0 &&
         vcMonitorCreds.indexOf('id="vc-status-suspend-1"') >= 0 &&
         vcMonitorCreds.indexOf('id="vc-status-revoke-1"') >= 0 &&
         vcMonitorCreds.indexOf('action="/admin/vc/monitor"') >= 0 &&
         vcMonitorCreds.indexOf('IdentityCredential') >= 0,
         'D-VC-monitor. Monitoring → Verifiable Credentials draws the status ' +
         'lists on Metadata and the credentials, with their Suspend and ' +
         'Revoke posting to the page, on their own tab',
         'metadata=' + !!vcMonitorMeta + '; credentials=' +
         !!vcMonitorCreds);

    const xacmlPage = WebPages.pageFor('/admin/xacml');
    const xacmlView = xacmlPage ? await viewOf(xacmlPage, {}) : null;
    const xacmlHtml = xacmlView
      ? WebPages.render('/admin/xacml', xacmlView,
                        WebKit.context({}, true))
      : '';
    const xacmlTabIds = [
      'xacml-tab-metadata', 'xacml-tab-settings', 'xacml-tab-policies',
      'xacml-tab-editor', 'xacml-tab-peps', 'xacml-tab-decide',
      'xacml-tab-authzen'
    ];
    const xacmlTabs = {};
    xacmlTabIds.forEach(function (id) {
      xacmlTabs[id] = new RegExp(
        '<section class="tabpanel(?: first)?" id="' + id +
        '">([\\s\\S]*?)<\\/section>').exec(xacmlHtml);
    });
    const xacmlEndpoints = xacmlView
      ? xacmlView.protocolEndpoints || [] : [];
    note(xacmlTabIds.every(function (id) {
      return !!xacmlTabs[id];
    }) && /<section class="tabpanel first" id="xacml-tab-metadata">/.test(
      xacmlHtml),
      'D-XACML-tabs. the combined XACML page has six peer tabs with ' +
      'Metadata first',
      xacmlTabIds.filter(function (id) {
        return !xacmlTabs[id];
      }).join(', '));
    note(xacmlEndpoints.length > 0 &&
         xacmlEndpoints.every(function (row) {
           return xacmlTabs['xacml-tab-metadata'] &&
             xacmlTabs['xacml-tab-metadata'][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') >= 0;
         }) &&
         xacmlTabIds.slice(1).every(function (id) {
           return xacmlEndpoints.every(function (row) {
             return !xacmlTabs[id] || xacmlTabs[id][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') < 0;
           });
         }),
         'D-XACML-metadata. the XACML endpoint inventory appears on ' +
         'Metadata only',
         'endpoints=' + xacmlEndpoints.length);
    const xacmlLinks = WebPages.xacmlTabLinks(
      '<a href="/admin/xacml/policies#service-own">Policies</a>' +
      '<a href="/admin/xacml/editor?policy=sample">Editor</a>' +
      '<form action="/admin/xacml/peps"></form>');
    note(xacmlLinks.indexOf(
           'href="/admin/xacml#service-own"') >= 0 &&
         xacmlLinks.indexOf(
           'href="/admin/xacml?policy=sample#xacml-tab-editor"') >= 0 &&
         xacmlLinks.indexOf(
           'action="/admin/xacml#xacml-tab-peps"') >= 0,
         'D-XACML-links. links and forms target their combined-page tabs',
         xacmlLinks);
    const xacmlFormTable = WebForms.table(
      adminApi.operationSummaries('all'));
    note(WebForms.resolve(xacmlFormTable,
             '/admin/xacml#xacml-tab-settings', 'set-many') ===
             '/admin-api/config/set-many' &&
         WebForms.resolve(xacmlFormTable,
             '/admin/xacml#xacml-tab-policies',
             'create-from-template') ===
             '/admin-api/xacml/create-from-template' &&
         WebForms.resolve(xacmlFormTable,
             '/admin/xacml#xacml-tab-editor', 'edit-policy') ===
             '/admin-api/xacml/edit-policy' &&
         WebForms.resolve(xacmlFormTable,
             '/admin/xacml#xacml-tab-peps', 'issue-pep-certificate') ===
             '/admin-api/xacml/issue-pep-certificate',
         'D-XACML-actions. each tab resolves forms through its mirrored API ' +
         'operation');

    const scimPage = WebPages.pageFor('/admin/scim');
    const scimView = scimPage ? await viewOf(scimPage, {}) : null;
    const scimHtml = scimView
      ? WebPages.render('/admin/scim', scimView,
                        WebKit.context({}, true))
      : '';
    // METADATA FIRST (2026-10-12): the endpoints and everything the page
    // explains or reports; Server is its settings.
    const scimServerTab =
      /<section class="tabpanel(?: first)?" id="server">([\s\S]*?)<\/section>/
        .exec(scimHtml);
    const scimMetadataTab =
      /<section class="tabpanel first" id="scim-tab-metadata">([\s\S]*?)<\/section>/
        .exec(scimHtml);
    const scimEndpoints = scimView
      ? scimView.protocolEndpoints || [] : [];
    note(!!scimServerTab && !!scimMetadataTab &&
         scimMetadataTab[1].indexOf('<h2>Endpoints</h2>') >= 0 &&
         scimEndpoints.length > 0 &&
         scimEndpoints.every(function (row) {
           return scimMetadataTab[1].indexOf(
             'data-copy="' + WebKit.esc(row.url) + '"') >= 0 &&
             scimServerTab[1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') < 0;
         }),
         'D-SCIM-endpoints. the SCIM endpoint inventory is on Metadata, the ' +
         'first tab', 'endpoints=' + scimEndpoints.length);
    note(!!scimMetadataTab && !!scimServerTab &&
         scimMetadataTab[1].indexOf('What each operation does') >= 0 &&
         scimMetadataTab[1].indexOf('/scim/v2/Users') >= 0 &&
         scimServerTab[1].indexOf('What each operation does') < 0 &&
         scimServerTab[1].indexOf('action="/admin/config"') >= 0,
         'D-SCIM-server. operation descriptions are on Metadata and the ' +
         'Server tab is its settings');

    const ssfPage = WebPages.pageFor('/admin/ssf');
    const ssfView = ssfPage ? await viewOf(ssfPage, {}) : null;
    const ssfHtml = ssfView
      ? WebPages.render('/admin/ssf', ssfView,
                        WebKit.context({}, true))
      : '';
    const ssfTabIds = [
      'ssf-tab-metadata', 'ssf-tab-ssf', 'ssf-tab-caep', 'ssf-tab-risc'
    ];
    const ssfTabs = {};
    ssfTabIds.forEach(function (id) {
      ssfTabs[id] = new RegExp(
        '<section class="tabpanel(?: first)?" id="' + id +
        '">([\\s\\S]*?)<\\/section>').exec(ssfHtml);
    });
    const ssfEndpoints = ssfView
      ? ssfView.protocolEndpoints || [] : [];
    note(ssfTabIds.every(function (id) {
      return !!ssfTabs[id];
    }) && /<section class="tabpanel first" id="ssf-tab-metadata">/.test(
      ssfHtml) &&
      !WebPages.pageFor('/admin/caep') &&
      !WebPages.pageFor('/admin/risc'),
      'D-SSF-tabs. Shared Signals, CAEP and RISC are tabs on one page, ' +
      'with Metadata first',
      ssfTabIds.filter(function (id) {
        return !ssfTabs[id];
      }).join(', '));
    note(ssfEndpoints.length > 0 &&
         ssfEndpoints.every(function (row) {
           return ssfTabs['ssf-tab-metadata'][1].indexOf(
             'data-copy="' + WebKit.esc(row.url) + '"') >= 0;
         }) &&
         ssfTabIds.slice(1).every(function (id) {
           return ssfEndpoints.every(function (row) {
             return ssfTabs[id][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') < 0;
           });
         }),
         'D-SSF-metadata. the protocol endpoint inventory appears on ' +
         'Metadata only',
         'endpoints=' + ssfEndpoints.length);
    const ssfSettings = {
      ssf: settingKeys(ssfView.settings, ['SSF']),
      caep: settingKeys(ssfView.caep.settings, ['CAEP']),
      risc: settingKeys(ssfView.risc.settings, ['RISC'])
    };
    note(hasSettings(ssfTabs['ssf-tab-ssf'], ssfSettings.ssf) &&
         hasSettings(ssfTabs['ssf-tab-caep'], ssfSettings.caep) &&
         hasSettings(ssfTabs['ssf-tab-risc'], ssfSettings.risc) &&
         lacksSettings(ssfTabs['ssf-tab-ssf'], ssfSettings.caep) &&
         lacksSettings(ssfTabs['ssf-tab-ssf'], ssfSettings.risc) &&
         lacksSettings(ssfTabs['ssf-tab-caep'], ssfSettings.risc) &&
         lacksSettings(ssfTabs['ssf-tab-risc'], ssfSettings.caep),
         'D-SSF-settings. SSF, CAEP and RISC settings stay on their own tabs',
         Object.keys(ssfSettings).map(function (name) {
           return name + '=' + ssfSettings[name].length;
         }).join(', ') + '; ssf=' +
         hasSettings(ssfTabs['ssf-tab-ssf'], ssfSettings.ssf) +
         ', caep=' +
         hasSettings(ssfTabs['ssf-tab-caep'], ssfSettings.caep) +
         ', risc=' +
         hasSettings(ssfTabs['ssf-tab-risc'], ssfSettings.risc));
    const ssfFormTable = WebForms.table(
      adminApi.operationSummaries('all'));
    note(WebForms.resolve(ssfFormTable, '/admin/ssf', 'status') ===
           '/admin-api/ssf/status' &&
         WebForms.resolve(ssfFormTable, '/admin/caep', 'emit') ===
           '/admin-api/caep/emit' &&
         WebForms.resolve(ssfFormTable, '/admin/risc', 'emit') ===
           '/admin-api/risc/emit',
         'D-SSF-actions. forms retain each vocabulary API operation');

    const kerberosPage = WebPages.pageFor('/admin/kerberos');
    const kerberosView = kerberosPage
      ? await viewOf(kerberosPage, {}) : null;
    const kerberosHtml = kerberosView
      ? WebPages.render('/admin/kerberos', kerberosView,
                        WebKit.context({}, true))
      : '';
    const kerberosTabIds = [
      'kerberos-tab-metadata', 'kerberos-tab-settings',
      'kerberos-tab-claims', 'kerberos-tab-principals',
      'kerberos-tab-trusts'
    ];
    const kerberosTabs = {};
    kerberosTabIds.forEach(function (id) {
      kerberosTabs[id] = new RegExp(
        '<section class="tabpanel(?: first)?" id="' + id +
        '">([\\s\\S]*?)<\\/section>').exec(kerberosHtml);
    });
    note(kerberosTabIds.every(function (id) {
      return !!kerberosTabs[id];
    }) &&
         /<section class="tabpanel first" id="kerberos-tab-metadata">/.test(
           kerberosHtml),
         'D-Kerberos-tabs. Metadata, Settings, PAC claims, Principals and ' +
         'Trusts are tabs on one page, Metadata first',
         kerberosTabIds.filter(function (id) {
           return !kerberosTabs[id];
         }).join(', '));
    const kerberosEndpoints = kerberosView
      ? kerberosView.protocolEndpoints || [] : [];
    note(kerberosEndpoints.length > 0 &&
         kerberosEndpoints.every(function (row) {
           return kerberosTabs['kerberos-tab-metadata'] &&
             kerberosTabs['kerberos-tab-metadata'][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') >= 0;
         }) &&
         kerberosTabIds.slice(1).every(function (id) {
           return kerberosEndpoints.every(function (row) {
             return !kerberosTabs[id] || kerberosTabs[id][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') < 0;
           });
         }),
         'D-Kerberos-metadata. endpoint inventory appears on Metadata only',
         'endpoints=' + kerberosEndpoints.length);
    const kerberosLinks = WebPages.kerberosTabLinks(
      '<a href="/admin/kerberos/principals?peoplePage=2">Next</a>' +
      '<form action="/admin/kerberos/claims">' +
      '<input type="hidden" name="back" ' +
      'value="/admin/kerberos/principals?servicesPage=2"></form>');
    note(kerberosLinks.indexOf(
           'href="/admin/kerberos?peoplePage=2#kerberos-tab-principals"') >=
             0 &&
         kerberosLinks.indexOf(
           'action="/admin/kerberos#kerberos-tab-claims"') >= 0 &&
         kerberosLinks.indexOf(
           'value="/admin/kerberos?servicesPage=2#' +
           'kerberos-tab-principals"') >= 0,
         'D-Kerberos-links. links and forms stay on the selected tab',
         kerberosLinks);
    const kerberosFormTable = WebForms.table(
      adminApi.operationSummaries('all'));
    note(WebForms.resolve(kerberosFormTable,
             '/admin/kerberos#kerberos-tab-claims', 'add') ===
             '/admin-api/kerberos/claims/add' &&
         WebForms.resolve(kerberosFormTable,
             '/admin/kerberos#kerberos-tab-principals',
             'rotate-krbtgt') ===
             '/admin-api/kerberos/principals/rotate-krbtgt' &&
         // #430 Phase 4: the Trusts tab's seven controls.
         ['add', 'update', 'enable', 'disable', 'rotate-key', 'remove',
          'pair'].every(function (action) {
           return WebForms.resolve(kerberosFormTable,
               '/admin/kerberos#kerberos-tab-trusts', action) ===
               '/admin-api/kerberos/trusts/' + action;
         }),
         'D-Kerberos-actions. each data tab resolves through its API operation');

    // PROTOCOLS → CERT ISSUANCE (2026-10-12): ACME, EST, SCEP and SPIFFE's
    // four pages as one page of tabs, Metadata first, SPIFFE's as sub-tabs.
    const certPage = WebPages.pageFor('/admin/cert-issuance');
    const certView = certPage ? await viewOf(certPage, {}) : null;
    const certHtml = certView
      ? WebPages.render('/admin/cert-issuance', certView,
                        WebKit.context({}, true))
      : '';
    const certTabIds = ['cert-tab-metadata', 'cert-tab-acme', 'cert-tab-est',
                        'cert-tab-scep', 'cert-tab-spiffe'];
    const certSubIds = ['cert-spiffe-overview', 'cert-spiffe-entries',
                        'cert-spiffe-agents', 'cert-spiffe-brokers'];
    const certTabs = {};
    certTabIds.forEach(function (id) {
      certTabs[id] = new RegExp(
        '<section class="tabpanel(?: first)?" id="' + id +
        '">([\\s\\S]*?)<\\/section>').exec(certHtml);
    });
    const spiffeTab = certTabs['cert-tab-spiffe']
      ? certTabs['cert-tab-spiffe'][1] : '';
    note(certTabIds.every(function (id) {
      return !!certTabs[id];
    }) && /<section class="tabpanel first" id="cert-tab-metadata">/.test(
           certHtml) &&
         certSubIds.every(function (id) {
           return new RegExp('<div class="subpanel(?: first)?" id="' + id +
                             '">').test(spiffeTab);
         }),
         'D-Cert-tabs. Metadata, ACME, EST, SCEP and SPIFFE are tabs on one ' +
         'page, Metadata first, and SPIFFE\'s four pages are its sub-tabs',
         certTabIds.concat(certSubIds).filter(function (id) {
           return certHtml.indexOf('id="' + id + '"') < 0;
         }).join(', '));
    const certEndpoints = certView ? certView.protocolEndpoints || [] : [];
    note(certEndpoints.length > 0 &&
         ['/enroll/acme/directory', '/.well-known/est/cacerts',
          '/enroll/scep', '/spiffe/bundle'].every(function (route) {
           return certEndpoints.some(function (row) {
             return row.route === route;
           });
         }) &&
         certEndpoints.every(function (row) {
           return certTabs['cert-tab-metadata'] &&
             certTabs['cert-tab-metadata'][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') >= 0;
         }) &&
         certTabIds.slice(1).every(function (id) {
           return certEndpoints.every(function (row) {
             return !certTabs[id] || certTabs[id][1].indexOf(
               'data-copy="' + WebKit.esc(row.url) + '"') < 0;
           });
         }),
         'D-Cert-metadata. all four families\' endpoints are on Metadata, ' +
         'and only there', 'endpoints=' + certEndpoints.length);
    // ONE SECTION PER PROTOCOL (2026-10-12): each family's routes under
    // its own heading, and none of the four tabs listing its endpoints.
    const certMeta = certTabs['cert-tab-metadata']
      ? certTabs['cert-tab-metadata'][1] : '';
    const metaSection = function (key) {
      const at = certMeta.indexOf('<h2 id="cert-metadata-' + key + '">');
      const next = certMeta.indexOf('<h2', at + 4);
      return at < 0 ? '' : certMeta.slice(at, next < 0 ? undefined : next);
    };
    const certFamilies = { acme: '/enroll/acme', est: '/.well-known/est',
                           scep: '/enroll/scep', spiffe: '/spiffe' };
    const misfiled = certEndpoints.filter(function (row) {
      const key = Object.keys(certFamilies).filter(function (one) {
        const prefix = certFamilies[one];
        return row.route === prefix || String(row.route || '')
          .indexOf(prefix + '/') === 0;
      })[0];
      return row.route && (!key || metaSection(key).indexOf(
        'data-copy="' + WebKit.esc(row.url) + '"') < 0);
    });
    note(Object.keys(certFamilies).every(function (key) {
           return metaSection(key) !== '';
         }) && misfiled.length === 0 &&
         // An endpoint drawn is a URL in a <code>; a setting's description
         // naming a path is not one.
         ['/enroll/acme/new-nonce</code>',
          '/.well-known/est/simpleenroll</code>',
          '/enroll/scep/pkiclient.exe</code>'].every(function (path) {
           return ['cert-tab-acme', 'cert-tab-est', 'cert-tab-scep']
             .every(function (id) {
               return certTabs[id] && certTabs[id][1].indexOf(path) < 0;
             });
         }) && spiffeTab.indexOf('>The gRPC listeners</h') < 0 &&
         metaSection('spiffe').indexOf('>The gRPC listeners</h3>') >= 0,
         'D-Cert-sections. Metadata draws each protocol\'s endpoints under ' +
         'its own heading, and the ACME, EST, SCEP and SPIFFE tabs list none',
         misfiled.map(function (row) { return row.route; }).join(', '));
    // THE ACME, EST AND SCEP TABS' SECTIONS ARE SUB-TABS (2026-10-12): one
    // per section, the first shown, and no section heading left above them.
    const familySubTabs = {
      'cert-tab-acme': ['ca', 'profiles', 'eab', 'accounts', 'certificates',
                        'host-names', 'mode', 'settings'],
      'cert-tab-est': ['ca', 'profiles', 'credentials', 'issue',
                       'host-names', 'certificates', 'settings'],
      'cert-tab-scep': ['ca', 'profiles', 'challenges', 'host-names',
                        'certificates', 'exceptions', 'settings']
    };
    const missingSubTabs = [];
    Object.keys(familySubTabs).forEach(function (tab) {
      const family = tab.replace('cert-tab-', '');
      const html = certTabs[tab] ? certTabs[tab][1] : '';
      familySubTabs[tab].forEach(function (one, n) {
        const id = 'cert-' + family + '-' + one;
        if (!new RegExp('<div class="subpanel' + (n === 0 ? ' first' : '') +
                        '" id="' + id + '">').test(html) ||
            html.indexOf('href="#' + id + '"') < 0) {
          missingSubTabs.push(id);
        }
      });
      // The settings block draws its own heading, as on every page.
      const settingsAt = html.indexOf('id="cert-' + family + '-settings"');
      if (/<h2\b/.test(settingsAt < 0 ? html : html.slice(0, settingsAt))) {
        missingSubTabs.push(tab + ' still has a section <h2>');
      }
    });
    note(missingSubTabs.length === 0,
         'D-Cert-subtabs. the ACME, EST and SCEP tabs draw each section as a ' +
         'sub-tab', missingSubTabs.join(', '));

    // EVERY PROTOCOLS PAGE AS TABS, METADATA FIRST (2026-10-12): each page
    // `WebPages.PROTOCOL_TABS` names is drawn as tabs whose first is
    // Metadata, and every tab it draws is one the table lists (the
    // stylesheet's ids come from that table). A page this process cannot
    // answer here (the truststore, with no TLS module loaded) is skipped.
    const protocolProblems = [];
    const protocolDrawn = [];
    const protocolPaths = Object.keys(WebPages.PROTOCOL_TABS);
    for (let i = 0; i < protocolPaths.length; i++) {
      const path = protocolPaths[i];
      const row = WebPages.pageFor(path);
      if (!row) {
        protocolProblems.push(path + ' is no console page');
        continue;
      }
      const pview = await viewOf(row, {}).catch(function () {
        return null;
      });
      if (!pview) {
        continue;
      }
      const html = WebPages.render(path, pview, WebKit.context({}, true));
      const slug = path.replace(/^\/admin\//, '').replace(/[^a-z0-9]+/gi,
                                                            '-');
      const bar = /<nav class="tabbar"[^>]*>([\s\S]*?)<\/nav>/.exec(html);
      const ids = bar ? (bar[1].match(/href="#([^"]+)"/g) || [])
        .map(function (h) { return h.slice(7, -1); }) : [];
      // A page that drew no marked section this time is drawn as it was
      // (`protocolTabs()`), with no tab bar to check.
      if (ids.length && ids[0] !== slug + '-tab-metadata') {
        protocolProblems.push(path + ' does not open on Metadata: ' +
                              ids.join(' '));
      }
      ids.slice(1).forEach(function (id) {
        const name = id.replace(slug + '-tab-', '');
        if (WebPages.PROTOCOL_TABS[path].indexOf(name) < 0) {
          protocolProblems.push(path + ' draws a tab its row does not ' +
                                'list: ' + name);
        }
      });
      if (ids.length && pview.protocolEndpoints &&
          pview.protocolEndpoints.length) {
        const meta = new RegExp('<section class="tabpanel first" id="' +
          slug + '-tab-metadata">([\\s\\S]*?)<\\/section>').exec(html);
        if (!meta || meta[1].indexOf('data-copy="' +
            WebKit.esc(pview.protocolEndpoints[0].url) + '"') < 0) {
          protocolProblems.push(path + '\'s endpoints are not on Metadata');
        }
      }
      protocolDrawn.push(path);
    }
    // Every page under Protocols is tabbed: by this table, or by a page of
    // its own drawn as tabs before it.
    const tabbedOtherwise = ['/admin/oauth2', '/admin/saml2', '/admin/vc',
      '/admin/xacml', '/admin/scim', '/admin/ssf', '/admin/kerberos',
      '/admin/cert-issuance',
      // A hidden NAV row (7f9db637): its address answers, and what it draws
      // is a tab of /admin/oauth2 — the page a reader is sent to.
      '/admin/token-lifetimes'];
    // The Protocols pages are the endpoint table's pages and its
    // exemptions (`tests/protocol_endpoints.js` holds that they are).
    protocolEndpoints.pages().concat(Object.keys(protocolEndpoints.exempt()))
      .forEach(function (path) {
        if (tabbedOtherwise.indexOf(path) < 0 &&
            !WebPages.PROTOCOL_TABS[path]) {
          protocolProblems.push(path + ' is under Protocols and not tabbed');
        }
      });
    note(protocolProblems.length === 0 && protocolDrawn.length >= 14,
         'D-Protocol-tabs. every Protocols and Directory page in the table is ' +
         'drawn as ' +
         'tabs, Metadata first, its endpoints there, and draws only tabs ' +
         'the table lists', protocolProblems.join('; ') + ' (drew ' +
         protocolDrawn.length + ')');
    // EACH TAB'S NAMES ARE ITS OWN: three families page `certificatesPage`
    // and the three SPIFFE lists search `q`, so on one page each carries
    // its prefix — in its links, its pager's anchor and its filter form.
    const estLinks = WebPages.certTabLinks(
      '<a href="/admin/est?per=5&amp;certificatesPage=2#list-' +
      'certificatesPage">2</a><div class="pagenav" id="list-' +
      'certificatesPage"></div><a href="/admin/est?format=json">JSON</a>',
      'est');
    const entryLinks = WebPages.certTabLinks(
      '<a href="/admin/spiffe/entries?entry=x">x</a>' +
      '<form method="get" action="/admin/spiffe/entries"><label for="q">' +
      '</label><input id="q" name="q"><select name="per"></select></form>' +
      '<form method="post" action="/admin/spiffe/entries"></form>',
      'spiffeEntries');
    note(estLinks.indexOf('href="/admin/cert-issuance?per=5&amp;' +
           'estCertificatesPage=2#list-estCertificatesPage"') >= 0 &&
         estLinks.indexOf('id="list-estCertificatesPage"') >= 0 &&
         estLinks.indexOf('href="/admin-api/est"') >= 0 &&
         entryLinks.indexOf('href="/admin/cert-issuance?entry=x#' +
           'cert-spiffe-entries"') >= 0 &&
         entryLinks.indexOf('action="/admin/cert-issuance#' +
           'cert-spiffe-entries"') >= 0 &&
         entryLinks.indexOf('name="entriesQ"') >= 0 &&
         entryLinks.indexOf('id="entries-q"') >= 0 &&
         entryLinks.indexOf('for="entries-q"') >= 0 &&
         entryLinks.indexOf('name="per"') >= 0 &&
         entryLinks.indexOf('method="post" action="/admin/spiffe/entries"') >=
           0,
         'D-Cert-names. a tab\'s links, pager and filter form carry its own ' +
         'names, a document link is its operation, and a POST form posts ' +
         'where its operation mirrors it', estLinks + ' ' + entryLinks);
    const certAsked = WebPages.composeRequests(certPage, {
      per: '5', estCertificatesPage: '2', scepCredentialsPage: '3',
      entriesQ: 'web', agent: 'a1'
    });
    const certAskedOf = function (member) {
      return (certAsked.filter(function (one) {
        return one.member === member;
      })[0] || {}).params || null;
    };
    note(JSON.stringify(certAskedOf('est')) ===
           JSON.stringify({ per: '5', certificatesPage: '2' }) &&
         JSON.stringify(certAskedOf('scep')) ===
           JSON.stringify({ per: '5', credentialsPage: '3' }) &&
         JSON.stringify(certAskedOf('acme')) === JSON.stringify({ per: '5' }) &&
         JSON.stringify(certAskedOf('spiffeEntries')) ===
           JSON.stringify({ per: '5', q: 'web' }) &&
         JSON.stringify(certAskedOf('spiffeAgents')) ===
           JSON.stringify({ per: '5', agent: 'a1' }),
         'D-Cert-compose. each tab\'s operation is asked with its own names',
         JSON.stringify(certAsked));

    const report = mode.report();
    const here = WebPages.render('/admin/mode',
                                 JSON.parse(JSON.stringify(report)));
    const missing = report.requirements.filter(function (row) {
      return here.indexOf('id="requirement-' + WebKit.esc(row.id) + '"') < 0;
    }).concat(report.developmentOnlySettings.filter(function (row) {
      return here.indexOf('id="setting-' + WebKit.esc(row.key) + '"') < 0;
    }));
    // The page is tabs since 2026-10-12, its tiles on Metadata.
    note(missing.length === 0 && here.indexOf('<div class="tiles">') >= 0 &&
         report.requirements.length > 10,
         'D2. and it carries every requirement and every development-only ' +
         'setting of the report', missing.length + ' missing of ' +
         (report.requirements.length +
          report.developmentOnlySettings.length));
    // WHAT IT DELIBERATELY DOES NOT DO IS DRAWN IN DEVELOPMENT MODE ONLY
    // (#753): almost every entry is about what development mode does not
    // check. The answer carries `testDouble`
    // (`mode.describesItselfAsTestDouble()`), and the bundle draws from it.
    const dashConfig = require(ROOT_DIR + '/common/config');
    const dashPage = WebPages.pageFor('/admin');
    const dashDrawn = {};
    for (const wanted of ['development', 'product']) {
      dashConfig.setOverride('global.mode', wanted);
      try {
        const dashView = await viewOf(dashPage, {});
        const dashCtx = WebKit.context({}, true);
        dashDrawn[wanted] = {
          testDouble: dashView.testDouble,
          verifiesCredentials: 'verifiesCredentials' in dashView,
          here: WebPages.render('/admin', dashView, dashCtx),
          bundled: StsConsole
            ? StsConsole.render('/admin', dashView, dashCtx) : null
        };
      } finally {
        dashConfig.clearOverride('global.mode');
      }
    }
    const notHeading = 'What it deliberately does not do';
    const dashOk = function (one, drawn) {
      return !!one && (one.here.indexOf(notHeading) >= 0) === drawn &&
        one.here === one.bundled && !one.verifiesCredentials;
    };
    note(dashOk(dashDrawn.development, true) &&
         dashDrawn.development.testDouble === true &&
         dashDrawn.development.here.indexOf('admin.openWhenEmpty') >= 0 &&
         dashDrawn.development.here.indexOf('script-src') < 0,
         'D-notdo-dev. in development mode /admin draws what it ' +
         'deliberately does not do, the bundle the same',
         JSON.stringify({ testDouble: (dashDrawn.development || {})
                          .testDouble }));
    // The entries #753 retired are gone from every catalog, overlays too.
    const dashLocales = pathC.join(ROOT_DIR, 'common', 'locales',
                                   'consoleDashboard');
    const retired = [];
    fsC.readdirSync(dashLocales).forEach(function (name) {
      const keys = Object.keys(JSON.parse(fsC.readFileSync(
        pathC.join(dashLocales, name), 'utf8')));
      ['not.passwordProduct', 'not.scriptA', 'not.scriptB', 'link.picture']
        .forEach(function (key) {
          if (keys.indexOf(key) >= 0) {
            retired.push(name + ' ' + key);
          }
        });
    });
    note(retired.length === 0,
         'D-notdo-keys. no catalog keeps an entry #753 retired',
         retired.join(', '));
    note(dashOk(dashDrawn.product, false) &&
         dashDrawn.product.testDouble === false,
         'D-notdo-product. in product mode /admin draws none of it',
         JSON.stringify({ testDouble: (dashDrawn.product || {})
                          .testDouble }));
    // *Reading it from a test* names the API, in both modes (#753): every
    // `/admin/*` path answers the console's one document, so the examples
    // are `/admin-api` operations, and the API is gated.
    const testNotes = [dashDrawn.development, dashDrawn.product]
      .filter(function (one) {
        return !!one && typeof one.here === 'string';
      });
    note(testNotes.length === 2 && testNotes.every(function (one) {
      return one.here.indexOf('/admin-api/metrics') >= 0 &&
        one.here.indexOf('/admin-api/tokens/revoke') >= 0 &&
        one.here.indexOf('?format=json') < 0 &&
        one.here.indexOf('not gated') < 0 &&
        one.here.indexOf('admin:read') >= 0;
    }), 'D-dash-test. /admin\'s notes for a test name /admin-api ' +
        'operations and their scopes, and no ?format=json', '');
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
      // A handle, not a request_uri: the store keeps none (#614).
      request_uri_digest: 'Q2dS8m6k1nVv3zJ0bYQm9vX0kq3w8yQ7Zr0aLx5tP2E',
      request_uri_shown: 'sha256:43676752f26e…',
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
         heldPage.indexOf('value="delete-pushed-request"') > 0 &&
         heldPage.indexOf('name="request_uri_digest" value="Q2dS8m6k1nVv3' +
                          'zJ0bYQm9vX0kq3w8yQ7Zr0aLx5tP2E"') > 0 &&
         heldPage.indexOf('sha256:43676752f26e…') > 0,
         'D4. the render context is the query and a boolean and nothing ' +
         'else, and a page that takes it draws from it — a Withdraw on ' +
         'the OAuth activity page carries back the list parameters of the ' +
         'query it was drawn with and no other', backField);

    // --- E. the table is true ------------------------------------------------
    const consolePages = admin.consoleJson().pages;
    // Either kind (#454): a page is drawn from a management operation or,
    // where only the console wants its shape, from one of its own.
    const operations = adminApi.operationSummaries('all').map(function (one) {
      return one.method + ' ' + one.path;
    });
    // A page of the console, or a page drawn under one of its tabs
    // (`/admin/keys/history` under Key pairs).
    const consolePage = function (path) {
      const oauthChildren = [
        '/admin/authorization-servers', '/admin/token-lifetimes',
        '/admin/claims', '/admin/userinfo-claims'
      ];
      const samlChildren = [
        '/admin/saml11', '/admin/saml-assertions',
        '/admin/saml-attributes'
      ];
      return consolePages.indexOf(path) >= 0 ||
        (consolePages.indexOf('/admin/oauth2') >= 0 &&
         oauthChildren.indexOf(path) >= 0) ||
        (consolePages.indexOf('/admin/saml2') >= 0 &&
         samlChildren.indexOf(path) >= 0) ||
        consolePages.some(function (one) {
          return path.indexOf(one + '/') === 0;
        });
    };
    const untrue = WebPages.PAGES.filter(function (page) {
      return !consolePage(page.path) ||
             operations.indexOf('GET ' + page.operation) < 0 ||
             Object.keys(page.compose || {}).some(function (member) {
               return operations.indexOf(
                 'GET ' + page.compose[member]) < 0;
             }) ||
             typeof page.render !== 'function' || !page.title;
    }).map(function (page) { return page.path; });
    note(WebPages.PAGES.length >= 1 && untrue.length === 0,
         'E. every converted page is a page of the console and names an ' +
         '/admin-api operation that exists', untrue.join(', ') + ' ' +
         operations.length + ' operation(s)');
    const oauthChildren = [
      '/admin/authorization-servers', '/admin/token-lifetimes',
      '/admin/claims', '/admin/userinfo-claims'
    ];
    note(consolePages.indexOf('/admin/oauth2') >= 0 &&
         oauthChildren.every(function (page) {
           return consolePages.indexOf(page) < 0;
         }),
         'E-OAuth. the sidebar has one OAuth 2.0 / OIDC entry, not its ' +
         'four former leaves', consolePages.filter(function (page) {
           return page === '/admin/oauth2' ||
             oauthChildren.indexOf(page) >= 0;
         }).join(', '));
    const vcChildren = [
      '/admin/oid4vci', '/admin/vc-status', '/admin/oid4vp',
      '/admin/vc-verifier-config'
    ];
    note(consolePages.indexOf('/admin/vc') >= 0 &&
         vcChildren.every(function (page) {
           return consolePages.indexOf(page) < 0 &&
                  WebPages.pageFor(page) === null;
         }),
         'E-VC. the sidebar has one Verifiable Credentials destination, not ' +
         'its former leaves',
         consolePages.filter(function (page) {
           return page === '/admin/vc' || vcChildren.indexOf(page) >= 0;
         }).join(', '));
    // AND ITS MONITORING TWIN (#752), filed under Monitoring, shown to a
    // realm administrator as the tab was (a realm's page, not the
    // service's), and reached from the tab's old addresses.
    const sectionHolding = function (path) {
      const holds = function (items) {
        return (items || []).some(function (item) {
          return item.path === path || holds(item.items);
        });
      };
      const found = admin.shellJson(null, null, null).sections.filter(
        function (section) {
          return holds(section.items);
        })[0];
      return found ? found.title : '';
    };
    const scope = require(ROOT_DIR + '/admin-ui/admin_scope');
    const realmState = { authority: 'realm', realm: 'any' };
    note(consolePages.indexOf('/admin/vc/monitor') >= 0 &&
         sectionHolding('/admin/vc/monitor') === 'Monitoring' &&
         sectionHolding('/admin/vc') === 'Protocols' &&
         scope.pageVisible(realmState, '/admin/vc/monitor') &&
         scope.pageVisible(realmState, '/admin/vc') &&
         WebPages.movedTo('/admin/vc', '#vc-tab-status') ===
           '/admin/vc/monitor' &&
         WebPages.movedTo('/admin/vc-status', '') === '/admin/vc/monitor' &&
         WebPages.movedTo('/admin/vc', '#vc-tab-claims') === null &&
         WebPages.movedTo('/admin/vc', '') === null,
         'E-VC-monitor. Monitoring → Verifiable Credentials is under ' +
         'Monitoring, a realm\'s page, and where the Credential status ' +
         'tab\'s old addresses go',
         sectionHolding('/admin/vc/monitor'));
    const xacmlChildren = [
      '/admin/xacml/policies', '/admin/xacml/editor',
      '/admin/xacml/peps', '/admin/xacml/decide'
    ];
    note(consolePages.indexOf('/admin/xacml') >= 0 &&
         xacmlChildren.every(function (page) {
           return consolePages.indexOf(page) < 0 &&
                  WebPages.pageFor(page) === null;
         }) &&
         consolePages.indexOf('/admin/xacml/monitor') >= 0,
         'E-XACML. the sidebar has one XACML destination and keeps its ' +
         'monitor separate',
         consolePages.filter(function (page) {
           return page === '/admin/xacml' ||
             page.indexOf('/admin/xacml/') === 0;
         }).join(', '));
    const kerberosChildren = [
      '/admin/kerberos/claims', '/admin/kerberos/principals'
    ];
    note(consolePages.indexOf('/admin/kerberos') >= 0 &&
         kerberosChildren.every(function (page) {
           return consolePages.indexOf(page) < 0 &&
                  WebPages.pageFor(page) === null;
         }),
         'E-Kerberos. the sidebar has one Kerberos destination, not its ' +
         'former leaves',
         consolePages.filter(function (page) {
           return page === '/admin/kerberos' ||
             kerberosChildren.indexOf(page) >= 0;
         }).join(', '));
    const certChildren = [
      '/admin/acme', '/admin/est', '/admin/scep', '/admin/spiffe',
      '/admin/spiffe/entries', '/admin/spiffe/agents', '/admin/spiffe/brokers'
    ];
    note(consolePages.indexOf('/admin/cert-issuance') >= 0 &&
         certChildren.every(function (page) {
           return consolePages.indexOf(page) < 0 &&
                  WebPages.pageFor(page) === null;
         }) &&
         ['/admin/acme/monitor', '/admin/est/monitor', '/admin/scep/monitor']
           .every(function (page) {
             return consolePages.indexOf(page) >= 0;
           }),
         'E-Cert. the sidebar has one Cert issuance destination, not its ' +
         'seven former pages, and keeps the three monitors',
         consolePages.filter(function (page) {
           return page === '/admin/cert-issuance' ||
             certChildren.indexOf(page) >= 0;
         }).join(', '));
    const samlChildren = [
      '/admin/saml11', '/admin/saml-assertions', '/admin/saml-attributes'
    ];
    note(consolePages.indexOf('/admin/saml2') >= 0 &&
         samlChildren.every(function (page) {
           return consolePages.indexOf(page) < 0 &&
                  WebPages.pageFor(page) === null;
         }),
         'E-SAML. the console has one SAML destination, not its former leaves',
         consolePages.filter(function (page) {
           return page === '/admin/saml2' ||
             samlChildren.indexOf(page) >= 0;
         }).join(', '));

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
