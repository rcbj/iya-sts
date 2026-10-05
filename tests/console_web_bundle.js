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
//      process's own module draws — and `VIEWS` below must name a view for
//      each, so a page cannot be converted without joining this check.
//      `/admin/mode` is also held to carrying every requirement and setting
//      of the report.
//   E. THE TABLE IS TRUE. Every converted page is a page of the console, and
//      names a management API operation that exists.
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
    const workerPools = require(ROOT_DIR + '/admin-ui/worker_pools_admin');
    const nodeHealth = require(ROOT_DIR + '/admin-ui/node_health_admin');
    // THE VIEW OF EVERY CONVERTED PAGE, as its management API operation
    // answers it. A page added to `web_pages.ts` owes a row here: D0 fails
    // otherwise.
    const VIEWS = {
      '/admin/mode': function () {
        return Promise.resolve(mode.report());
      },
      '/admin/node-health': function () {
        return nodeHealth.nodeHealthView({});
      },
      '/admin/worker-pools': function () {
        return workerPools.workerPoolsView({});
      }
    };
    const dir = pathC.join(ROOT_DIR, 'admin-ui');

    // --- A. the sources ---------------------------------------------------
    const sources = fsC.readdirSync(dir).filter(function (name) {
      return /^web_.*\.ts$/.test(name);
    });
    note(sources.length >= 3 && sources.indexOf('web_kit.ts') >= 0 &&
         sources.indexOf('web_pages.ts') >= 0,
         'A1. the web_ sources are in the tree this test reads',
         sources.join(', '));
    const foreign = [];
    const nodeNames = [];
    sources.forEach(function (name) {
      const text = fsC.readFileSync(pathC.join(dir, name), 'utf8');
      const code = text.split('\n').filter(function (line) {
        return !/^\s*(\/\/|\*|\/\*)/.test(line);
      }).join('\n');
      const requires = /require\(\s*['"]([^'"]+)['"]\s*\)/g;
      let found = requires.exec(code);
      while (found) {
        if (!/^\.\/web_[a-z0-9_]+$/.test(found[1])) {
          foreign.push(name + ' requires ' + found[1]);
        }
        found = requires.exec(code);
      }
      // As identifiers: `global.mode`, the setting, is prose in a page.
      [/\bprocess\./, /\bBuffer\./, /\b__dirname\b/, /\b__filename\b/,
       /\bglobalThis\b/].forEach(function (one) {
        if (one.test(code)) {
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
    const unviewed = WebPages.PAGES.filter(function (page) {
      return typeof VIEWS[page.path] !== 'function';
    }).map(function (page) { return page.path; });
    note(unviewed.length === 0,
         'D0. this test has a view for every converted page',
         unviewed.join(', '));
    const differing = [];
    for (let i = 0; i < WebPages.PAGES.length; i++) {
      const page = WebPages.PAGES[i];
      if (typeof VIEWS[page.path] !== 'function') {
        continue;
      }
      const view = JSON.parse(JSON.stringify(await VIEWS[page.path]()));
      const mine = WebPages.render(page.path, view);
      const theirs = StsConsole ? StsConsole.render(page.path, view) : null;
      if (typeof mine !== 'string' || mine.length < 100 || mine !== theirs) {
        differing.push(page.path + ' (' + String(mine).length + ' against ' +
                       String(theirs).length + ')');
      }
    }
    note(differing.length === 0,
         'D1. every converted page drawn by the bundle is, to the byte, ' +
         'what this process draws from the same view (' +
         WebPages.PAGES.length + ' page(s))', differing.join(', '));
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

    // --- E. the table is true ------------------------------------------------
    const consolePages = admin.consoleJson().pages;
    const operations = adminApi.operationSummaries().map(function (one) {
      return one.method + ' ' + one.path;
    });
    const untrue = WebPages.PAGES.filter(function (page) {
      return consolePages.indexOf(page.path) < 0 ||
             operations.indexOf('GET ' + page.operation) < 0 ||
             typeof page.render !== 'function' || !page.title;
    }).map(function (page) { return page.path; });
    note(WebPages.PAGES.length >= 1 && untrue.length === 0,
         'E. every converted page is a page of the console and names a ' +
         'management API operation that exists', untrue.join(', ') + ' ' +
         operations.length + ' operation(s)');

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
