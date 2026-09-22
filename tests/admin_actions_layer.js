'use strict';
//
// File: admin_actions_layer.js
//
// ===========================================================================
// THE LAYER THE CONSOLE AND THE MANAGEMENT API SHARE, AND THE FOUR WAYS IT
// STOPS BEING ONE.
//
// Until 2026-09-12 every decision both admin surfaces make lived in
// `admin-ui/admin.ts`, and `mgmt-api/admin_api.ts` reached them by requiring
// the console module and calling its functions. Rule 7 was satisfied — a page
// and its operation could not disagree, because they were the same call — and
// the price was that the surface a machine drives sat downstream of the
// surface a person reads.
//
// The thirty-one actions moved to `admin-core/admin_actions.ts`. **It was a
// MOVE and not a rewrite**, which was affordable for one reason: not one of
// those functions had ever touched `req`, `res` or markup. They took a parsed
// body and an actor and returned a result object. The work was in finding
// what travelled with them, not in changing any of them.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE PINS, AND WHY EACH CLAIM EARNS ITS PLACE.
//
//   1. **The layer registers no route.** It is required by TWO modules, so a
//      route in it would be registered twice — once from the console and once
//      from the management API — and rule 1 means the second registration is
//      a handler that can never win. This is the claim that would fail first
//      if somebody moved a page in here.
//   2. **The layer draws no HTML and reads no request.** An action that
//      reached for `req` would work from one door and throw from the other,
//      which is the exact defect the move exists to make impossible.
//   3. **The management API does not reach its decisions through the
//      console.** This is the whole point of the change, and it is the claim
//      that would rot most quietly: adding one `admin.somethingAction()` call
//      back would restore the old direction for one operation and nothing
//      would fail.
//   4. **The forwarded collaborators are written in exactly one place
//      each.** The console still owns those slots — every filler in the tree
//      and every rule 3e sentence in CLAUDE.md names it — and forwards what it
//      was handed. One statement with two destinations is one answer; a second
//      writer would make it two, and the two would drift apart silently.
//
// WHY IN PROCESS. Every claim is a comparison between FILES, which is
// `teardown_bounds.js`'s shape and `admin_api_token_wiring.js`'s before it. The
// one thing this cannot check is whether the actions still WORK, and nothing
// here pretends to: that is `tests/vendored/sts_admin_api_operations.js`
// driving every operation and `sts_admin_console.js` driving the pages.
// **Both of those matter more than this file** — the first run of the moved
// layer failed in one of them with `numberWord is not defined`, on the single
// refusal path that used a helper the move had not carried across.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const { isSourceFile } = require('./tools/source_file');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'admin_actions_layer',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
// The layer is two files and the line between them is what each one DOES:
// `admin_actions.js` changes state, `admin_views.js` answers a question. Both
// are held to the same three refusals below, because the reason for each is
// about being required by two surfaces rather than about writing or reading.
const LAYERS = ['admin-core/admin_actions.ts', 'admin-core/admin_views.ts'];
const CONSOLE_MODULE = 'admin-ui/admin.ts';
const API_MODULE = 'mgmt-api/admin_api.ts';

// What the console forwards into each half. Named here rather than derived,
// because the point of the check is that the list does not quietly shrink.
//
// `xacmlPages` is in BOTH lists and that is not a mistake: the actions
// dispatch on it and the views draw from it, so one statement in the console's
// setter now has three destinations — its own variable and one in each half.
// Still one writer, which is the only property that matters.
//
// `truststore` (2026-09-12) is in both for the same reason: the actions add and
// remove through it and the view lists through it. It is the one collaborator
// here that `common/protocol_stack.ts` rather than its owning module hands to
// the console, which changes nothing this file checks — the forward and the
// single writer are the console's and the layer's either way.
const FORWARDED = {
  'admin-core/admin_actions.ts': ['logoutReader', 'directoryWriter',
    'groupWriter',
    'signalsReporter', 'caepReporter', 'riscReporter', 'xacmlPages',
    'truststore'],
  'admin-core/admin_views.ts': ['cryptoReporter', 'xacmlPages',
    'directoryPages',
    'scimReader', 'rolePreviewer', 'configSettingsJson', 'truststore']
};

function read(rel) {
  log.debug("Entering read().");
  log.debug("Leaving read().");
  return fs.readFileSync(path.join(ROOT, rel), 'utf8');
}

// Comments and string literals removed. This repository's refusal messages are
// long and full of words that are also identifiers — `page`, `note`, `mode` —
// so a check that reads them reports noise and buries the one real finding.
function codeOf(src) {
  log.debug("Entering codeOf().");
  let out = '';
  let i = 0;
  let quote = null;
  let lineComment = false;
  let blockComment = false;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (lineComment) {
      if (c === '\n') { lineComment = false; out += c; }
      i += 1;
      continue;
    }
    if (blockComment) {
      if (c === '*' && d === '/') { blockComment = false; i += 2; continue; }
      i += 1;
      continue;
    }
    if (quote) {
      if (c === '\\') { i += 2; continue; }
      if (c === quote) { quote = null; }
      i += 1;
      continue;
    }
    if (c === '/' && d === '/') { lineComment = true; i += 2; continue; }
    if (c === '/' && d === '*') { blockComment = true; i += 2; continue; }
    if (c === '"' || c === "'" ||
        c === '`') { quote = c; out += ' '; i += 1; continue; }
    out += c;
    i += 1;
  }
  log.debug("Leaving codeOf().");
  return out;
}

// ---------------------------------------------------------------------------
// (1) AND (2): WHAT MAY NOT BE IN THE LAYER.
// ---------------------------------------------------------------------------
function checkTheLayerIsALibrary(t) {
  log.debug("Entering checkTheLayerIsALibrary().");
  t.log.info('=== the layer registers nothing and renders nothing ===');
  LAYERS.forEach(function (layer) { checkOneLayerIsALibrary(t, layer); });
  log.debug("Leaving checkTheLayerIsALibrary().");
}

function checkOneLayerIsALibrary(t, layer) {
  log.debug("Entering checkOneLayerIsALibrary().");
  const code = codeOf(read(layer));

  t.check(!/\bapp\s*\.\s*(get|post|put|patch|delete|use|all)\s*\(/.test(code),
          layer + ' registers no route',
          'two modules require it, so a route here would be registered twice ' +
          'and rule 1 means the second one can never win — which is a ' +
          'handler that looks present and is unreachable');

  // NEITHER HALF MAY TOUCH `res`. A layer that wrote the response would be
  // deciding the status code and the content type for two surfaces that
  // legitimately answer differently — a 303 back to a page, or JSON.
  t.check(!/(?:^|[^.\w$])res(?![\w$])/.test(code),
          layer + ' never touches res',
          'the console answers a form with a 303 and the management API ' +
          'answers JSON; a layer that wrote the response would have to know ' +
          'which of the two it was serving');

  // AND THE REQUEST RULE IS NOT THE SAME FOR THE TWO HALVES, which is worth
  // stating rather than smoothing over. An ACTION is handed a parsed body and
  // an actor and must never see the request at all. A VIEW is parameterised by
  // the QUERY STRING — which page, which filter, which user — and reads
  // `req.query` to get it, exactly as it did on the console. Anything else off
  // the request (headers, cookies, the body, a session) is the console's.
  const reads = (code.match(/(?:^|[^.\w$])req\.[a-zA-Z]+/g) || [])
    .map(function (r) { return r.trim(); });
  const illegal = reads.filter(function (r) { return !/req\.query$/.test(r); });
  if (/admin_actions/.test(layer)) {
    t.check(reads.length === 0,
            'and it never touches req either — an action takes a parsed body',
            'an action that read the request would work from the console and ' +
            'throw from the management API, which is the very defect this ' +
            'separation exists to make impossible: found ' +
            (reads.join(', ') || 'none'));
  } else {
    t.check(illegal.length === 0,
            'and it reads only req.query — a view is parameterised by the ' +
              'query string and by nothing else',
            'which page, which filter, which user is a question both ' +
            'surfaces ask the same way; a header, a cookie or a body is the ' +
            'console\'s and would not mean the same thing arriving at the ' +
            'API: found ' +
            (illegal.join(', ') || 'none'));
  }

  t.check(!/<(div|table|form|span|p|a|h[1-6])[\s>]/i.test(code),
          'and it builds no HTML',
          'the console renders and this decides; markup here is the first ' +
          'step back to a layer only one of the two surfaces can use');
  log.debug("Leaving checkOneLayerIsALibrary().");
}

// ---------------------------------------------------------------------------
// AND THE REQUIRE BETWEEN THE TWO HALVES GOES ONE WAY.
//
// The views read tables that live with the actions — a page draws the buttons
// its action dispatches on — so `admin_views.js` requires `admin_actions.js`.
// The reverse must never appear: an action consulting a view is an action that
// depends on how something is going to be displayed.
// ---------------------------------------------------------------------------
function checkTheHalvesDependOneWay(t) {
  log.debug("Entering checkTheHalvesDependOneWay().");
  t.log.info('=== the two halves depend one way ===');
  t.check(/require\('\.\/admin_actions'\)/.test(read(
      'admin-core/admin_views.ts')),
          'admin_views.ts requires admin_actions.ts for the shared tables',
          'one table with two readers is what stops a page offering a ' +
          'control its action does not have');
  t.check(!/require\([^)]*admin_views/.test(read(
      'admin-core/admin_actions.ts')),
          'and admin_actions.ts does not require admin_views.ts',
          'an action that consulted a view would depend on how its result is ' +
          'going to be displayed, which is the coupling this whole directory ' +
          'exists to remove');
  log.debug("Leaving checkTheHalvesDependOneWay().");
}

// ---------------------------------------------------------------------------
// (3) THE DIRECTION OF THE DEPENDENCY, WHICH IS THE WHOLE POINT.
// ---------------------------------------------------------------------------
function checkTheApiDoesNotGoThroughTheConsole(t) {
  log.debug("Entering checkTheApiDoesNotGoThroughTheConsole().");
  t.log.info('=== the management API reaches its decisions directly ===');
  const api = codeOf(read(API_MODULE));

  t.check(/require\('\.\.\/admin-core\/admin_actions'\)/.test(read(API_MODULE)),
          'mgmt-api/admin_api.ts requires the action layer',
          'without this the operations would be calling the console module ' +
          'for their decisions, which is the arrangement the move replaced');

  // The one action-shaped thing still legitimately on the console module is
  // respondToAction(), which is TRANSPORT: it turns a result into a 303 back
  // to the page or into JSON, and belongs to the surface that has a page.
  const throughConsole = (api.match(/\badmin\.[A-Za-z0-9_$]*Action\s*\(/g) ||
                          [])
    .filter(function (call) { return !/respondToAction/.test(call); });
  t.check(throughConsole.length === 0,
          'and it calls no action on the console module',
          'one `admin.xAction()` added back would restore the old direction ' +
          'for that operation and nothing at all would fail — it is the ' +
          'quietest way this change could rot: found ' +
          (throughConsole.join(', ') || 'none'));

  // And the console must not have re-exported them, which would publish a
  // second route to the same function.
  const consoleSrc = read(CONSOLE_MODULE);
  // Since #50 the console builds its exports as `consoleExports` and hands
  // that to `export =`. Not found is a failure, not an empty list.
  const exportsAt = consoleSrc.search(
    /\n(?:module\.exports|export|const consoleExports) = \{/);
  t.check(exportsAt >= 0, 'the console\'s exports object is found');
  const exported = consoleSrc.slice(exportsAt);
  const reExported = (exported.match(/^\s{2}([A-Za-z0-9_$]+Action):/gm) || [])
    .map(function (l) { return l.trim().replace(':', ''); })
    .filter(function (n) {
      return n !== 'respondToAction' && n !== 'respondToApplicationAction';
    });
  t.check(reExported.length === 0,
          'and the console does not re-export them either',
          'the actions are aliased into that file\'s scope so its own ' +
          'several hundred call sites are unchanged; re-exporting them as ' +
          'well would publish a SECOND way to reach the same function, and ' +
          'the second way is the one that goes stale: found ' +
          (reExported.join(', ') || 'none'));
  log.debug("Leaving checkTheApiDoesNotGoThroughTheConsole().");
}

// ---------------------------------------------------------------------------
// (4) THE FORWARDS (`FORWARDED` above). One statement, one writer.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AND THE FOUR THAT STAY. This is the finish line, written down.
//
// The management API calls exactly these on the console module and nothing
// else. Three of them are the console describing ITSELF — which pages it has,
// where each settings group is edited — and the fourth reads the request. A
// layer beneath the console could not answer the first three, and the fourth
// is transport.
//
// **PURITY WAS NOT THE TEST; OWNERSHIP WAS.** All four are perfectly pure
// functions that could have moved and should not have. A fifth name appearing
// here is either something that belongs in the layer, or a decision somebody
// should have to write down next to this list.
// ---------------------------------------------------------------------------
const MAY_STAY_ON_THE_CONSOLE = ['consoleJson', 'configJson',
  'protocolSettingsJsonFor', 'listField'];

function checkOnlyTheConsolesOwnKnowledgeIsLeft(t) {
  log.debug("Entering checkOnlyTheConsolesOwnKnowledgeIsLeft().");
  t.log.info('=== what the management API still asks the console ===');
  const api = codeOf(read(API_MODULE));
  const called = [...new Set((api.match(/\badmin\.([A-Za-z0-9_$]+)\s*\(/g) ||
                              [])
    .map(function (c) { return c.slice(6).replace(/\s*\($/, ''); }))].sort();
  const unexpected = called.filter(function (n) {
    return MAY_STAY_ON_THE_CONSOLE.indexOf(n) < 0;
  });
  t.check(unexpected.length === 0,
          'it calls only the console\'s own knowledge (' + called.join(', ') +
          ')',
          'everything else it needs comes from admin-core/. A name here that ' +
          'is not one of the four is the API reading through the console ' +
          'again, which is the coupling this directory exists to remove: ' +
          'found ' + (unexpected.join(', ') || 'none'));

  // And the four are still REACHED, so the list does not rot into a licence.
  const missing = MAY_STAY_ON_THE_CONSOLE.filter(function (n) {
    return called.indexOf(n) < 0;
  });
  t.check(missing.length === 0,
          'and every one of the four is still called',
          'a name left on this list that nothing calls any more is a ' +
          'permission nobody needs, and the next reader will take it as ' +
          'evidence that reading through the console is fine: ' +
          (missing.join(', ') || 'none'));
  log.debug("Leaving checkOnlyTheConsolesOwnKnowledgeIsLeft().");
}

function checkTheForwardsCannotDrift(t) {
  log.debug("Entering checkTheForwardsCannotDrift().");
  t.log.info('=== every forwarded collaborator has one writer ===');
  LAYERS.forEach(function (layer) {
    FORWARDED[layer].forEach(function (name) {
      checkOneForward(t, layer, name);
    });
  });
  log.debug("Leaving checkTheForwardsCannotDrift().");
}

function checkOneForward(t, layer, name) {
  log.debug("Entering checkOneForward().");
  const consoleSrc = read(CONSOLE_MODULE);
  const layerCode = codeOf(read(layer));
  {
    const setter = 'set' + name.charAt(0).toUpperCase() + name.slice(1);

    // Which half is being forwarded into decides the name the console calls
    // it by. Hardcoding `adminActions` here reported four missing forwards
    // against a console that had all of them.
    const holder = /admin_actions/.test(layer) ? 'adminActions' : 'adminViews';
    t.check(new RegExp(holder + '\\.' + setter + '\\(').test(consoleSrc),
            CONSOLE_MODULE + ' forwards ' + name + ' to ' + holder,
            'the slot stays on the console because every filler in the tree ' +
            'and every rule 3e sentence in CLAUDE.md names that module — so ' +
            'the console pushes, and a forward that went missing would leave ' +
            'the actions believing a whole subsystem was absent');

    // A method of the layer's class since #50, a function before it.
    t.check(new RegExp('(?:function |^\\s+)' + setter + '\\(', 'm')
              .test(layerCode),
            'and the layer takes it through ' + setter + '()',
            'a collaborator the layer cannot be given is one the actions ' +
            'that need it can never use');

    // The layer must not acquire a second writer for it. One assignment, from
    // the setter the console calls, is what makes two caches one answer.
    //
    // The DECLARATION is not a write in that sense and is excluded by name:
    // `let logoutReader = null;` is how the binding comes into existence, and
    // counting it made this check demand zero real writers — which it then
    // reported as a failure against a layer that was correct. The first
    // version of this file did exactly that, seven times.
    const writes = (layerCode.match(new RegExp('(?:^|[^.\\w$])' + name +
                                               '\\s*=(?!=)', 'g')) || [])
      .length - (new RegExp('let ' + name + '\\s*=').test(layerCode) ? 1 : 0);
    t.check(writes === 1,
            'and nothing else in the layer assigns ' + name + ' (' + writes +
              ' writer besides the declaration)',
            'the console\'s setter is the single writer; a second one would ' +
            'make the console\'s copy and this one two answers rather than ' +
            'two caches, and they would drift apart with nothing failing');
  }
  log.debug("Leaving checkOneForward().");
}

// ---------------------------------------------------------------------------
// AND THE LOAD-ORDER CONSTRAINT THE DIRECTORY EXISTS TO STATE.
// ---------------------------------------------------------------------------
function checkNothingRequiresItEarly(t) {
  log.debug("Entering checkNothingRequiresItEarly().");
  t.log.info('=== nothing above position 18 requires the layer ===');
  // The layer requires oauth2, saml2, saml11 and federation, every one of
  // which registers routes. That is free from the console (18) and the
  // management API (19), where all of them are already loaded and every
  // require is a cache hit. From anything earlier it would pull the
  // authorization server and both SAML profiles in ahead of themselves, and
  // rule 1 says the require order IS the route order.
  // NAMED ONE BY ONE, so that a new requirer is a decision somebody made
  // rather than a directory that quietly grew. Every file here sits at 18 or
  // later in the require order: the console, the page it draws for the
  // management API's explorer, and the management API itself.
  const allowed = ['admin-ui/admin.ts', 'admin-ui/api_explorer.ts',
                   'mgmt-api/admin_api.ts', 'ldap/ldap_server.js',
                   // GNAP's view/action layer (2026-09-12), for `adminViews`'
                   // paging only. It is loaded at 23d, from
                   // `gnap/gnap_admin.ts` and lazily from the management API,
                   // so the require is a cache hit — the same position
                   // ldap_server.js argues.
                   'gnap/gnap_console.ts',
                   // Certificate enrollment's three view/action layers
                   // (2026-09-13), loaded at 23e-g from each family's
                   // `_admin.js` and lazily from the management API.
                   'acme/acme_console.ts', 'est/est_console.ts',
                   'scep/scep_console.ts',
                   // The OAuth 2.0 / OIDC monitoring page's view/action
                   // layer (2026-09-13), for `adminViews`' paging and the
                   // console actor only. Loaded at 18f from
                   // `oauth2_monitor_admin.ts` and lazily from the management
                   // API, so the require is a cache hit and moves no route.
                   'oauth-oidc/oauth2_monitor_console.ts',
                   // The PKI page (2026-09-13), for `adminViews`' paging
                   // only — its Applications and People tables. It is
                   // required at 18a, immediately after the console, so the
                   // require is a cache hit and moves no route.
                   'admin-ui/pki_admin.ts',
                   // The caches page (#74, 2026-09-17), for `adminViews`'
                   // paging only — one cache's entries. Required at 18g,
                   // after the console, so the require is a cache hit and
                   // moves no route.
                   'admin-ui/caches_admin.ts',
                   // The credential status page (#38's follow-ups), for
                   // `adminViews`' paging only — the list of issued
                   // credentials. Required at 18h, after the console, so the
                   // require is a cache hit and moves no route.
                   'admin-ui/vc_status_admin.ts',
                   // The scheduler page (#49, 2026-09-22), for `adminViews`'
                   // paging and the gate state only — the recent runs, and
                   // who is asking. Required at 18i, after the console, so
                   // the require is a cache hit and moves no route.
                   'admin-ui/scheduler_admin.ts',
                   // The composition root (#50, R2), which builds every
                   // converted module's instance — these two layers
                   // included — after the require step that loaded them,
                   // so its requires are cache hits and move no route.
                   'common/protocol_stack.ts',
                   'tests/admin_actions_layer.js'];
  const offenders = [];
  function walk(dir) {
    log.debug("Entering walk().");
    const entries = fs.readdirSync(path.join(ROOT, dir),
                                   { withFileTypes: true });
    const names = entries.map(function (e) { return e.name; });
    entries.forEach(function (entry) {
      const rel = dir ? dir + '/' + entry.name : entry.name;
      if (entry.isDirectory()) {
        // `.claude` holds agent worktrees: a second checkout of this
        // repository, whose files are not this one's (2026-09-16).
        if (['node_modules', '.git', '.claude', 'node-ldapjs',
             'tests'].indexOf(entry.name) >= 0) { return; }
        walk(rel);
        return;
      }
      // Source only: a `.ts`, or a `.js` that is not its compiled twin (#50).
      if (!isSourceFile(entry.name, names)) { return; }
      if (allowed.indexOf(rel) >= 0) { return; }
      if (/admin-core\//.test(rel)) { return; }
      const src = read(rel);
      if (/require\([^)]*admin-core\/admin_(actions|views)/.test(
          src)) { offenders.push(rel); }
    });
    log.debug("Leaving walk().");
  }
  walk('');
  t.check(offenders.length === 0,
          'only the console and the management API require it',
          'this layer pulls in four route-registering modules, which is free ' +
          'at 18 and 19 where they are already loaded and costs a reordered ' +
          'router anywhere earlier: found ' + (offenders.join(', ') || 'none'));
  log.debug("Leaving checkNothingRequiresItEarly().");
}

// ---------------------------------------------------------------------------
// EVERY NAME THE LAYER USES RESOLVES TO SOMETHING IT HAS.
//
// **THIS IS THE CHECK THE MOVE NEEDED AND DID NOT HAVE**, and it is worth
// stating what it cost to learn that. Five defects of one kind got through,
// each found by a different HTTP job, each a `ReferenceError` on one code
// path: `numberWord`, `signJwt`, `baseUrlOf`, `stsKeysFor` and `sessions`.
//
// All five came from the same place. `admin-ui/admin.ts` pulls fourteen names
// into scope through DESTRUCTURED requires — `const { log, xmlEscape,
// baseUrlOf, … } = require('../common/helpers')` and one more from `authn` —
// and both of those are spread over comment-interleaved lines. A function that
// used one read perfectly well in the file it came from and threw in the file
// it moved to, on whichever branch happened to reach it.
//
// A moved function that is never called on the path a test drives keeps its
// unresolved name for as long as nobody calls it. So this is static: it asks
// whether the name is in scope, not whether anything reached it.
// ---------------------------------------------------------------------------
function checkEveryNameResolves(t) {
  log.debug("Entering checkEveryNameResolves().");
  t.log.info('=== every name each half uses is in scope there ===');
  const adminSrc = read(CONSOLE_MODULE);

  // What admin.js has in scope: its own top-level declarations, plus every
  // name it destructures out of a require.
  const inAdmin = new Set();
  adminSrc.split('\n').forEach(function (l) {
    let m = /^(?:async )?function ([A-Za-z0-9_$]+)\(/.exec(l);
    if (m) { inAdmin.add(m[1]); return; }
    // Since #50 the console is a TypeScript class: its requires are
    // `import x = require(...)` and its functions are methods of the class.
    m = /^(?:const|let|var|import) ([A-Za-z0-9_$]+)/.exec(l);
    if (m) { inAdmin.add(m[1]); return; }
    m = /^  (?:async )?([A-Za-z0-9_$]+)\(/.exec(l);
    if (m) { inAdmin.add(m[1]); }
  });
  // `const { … } = require('…')`, or since #50 `const { … } = helpers;` on
  // the line after `import helpers = require('…')`.
  const destructure =
    /const \{([\s\S]*?)\} = (?:require\('([^']+)'\)|[A-Za-z0-9_$]+;)/g;
  let d;
  while ((d = destructure.exec(adminSrc)) !== null) {
    d[1].replace(/\/\/[^\n]*/g, '').split(',').forEach(function (n) {
      if (n.trim()) { inAdmin.add(n.trim()); }
    });
  }

  LAYERS.forEach(function (layer) {
    const src = read(layer);
    const code = codeOf(src);
    // PER FUNCTION, which is the only version of this that works.
    //
    // The first attempt collected every declaration in the file and treated a
    // name as resolved if ANY function declared it. That is wrong in exactly
    // the case this check exists for: `sessions` is a parameter name somewhere
    // in this file, so a missing `sessions` import — one of the five real
    // defects — came back clean. Mutation testing caught it; three of four
    // dropped imports were reported and the fourth was not.
    //
    // So: module scope, plus the locals of the ONE function the use is in.
    const moduleScope = new Set();
    src.split('\n').forEach(function (l) {
      let m = /^(?:async )?function ([A-Za-z0-9_$]+)\(/.exec(l);
      if (m) { moduleScope.add(m[1]); return; }
      // Since #50 the layer is a TypeScript module: its requires are
      // `import x = require(...)` and it declares a class and its types.
      m = /^(?:const|let|var|import|class|interface|type) ([A-Za-z0-9_$]+)/
        .exec(l);
      if (m) { moduleScope.add(m[1]); return; }
      // A method's own name is on its header, and it is reached as `this.`.
      m = /^  (?:private |public |static )*(?:async )?([A-Za-z0-9_$]+)\(/
        .exec(l);
      if (m) { moduleScope.add(m[1]); }
    });
    const own = /const \{([\s\S]*?)\} = require\('([^']+)'\)/g;
    let o;
    while ((o = own.exec(src)) !== null) {
      o[1].replace(/\/\/[^\n]*/g, '').split(',').forEach(function (n) {
        if (n.trim()) { moduleScope.add(n.trim()); }
      });
    }
    // Each top-level function body, with the names it binds for itself —
    // and, since #50, each method of the layer's class, whose parameters
    // are not written after `function`, so they are read off its header.
    const srcLines = src.split('\n');
    const scopes = [];
    const METHOD = /^  (?:private |public |static )*(?:async )?[A-Za-z0-9_$]+\(/;
    for (let i = 0; i < srcLines.length; i += 1) {
      const isFunction = /^(?:async )?function [A-Za-z0-9_$]+\(/.test(
        srcLines[i]);
      const isMethod = METHOD.test(srcLines[i]);
      if (!isFunction && !isMethod) { continue; }
      const closing = isFunction ? '}' : '  }';
      let j = i;
      while (j < srcLines.length && srcLines[j] !== closing) { j += 1; }
      const body = codeOf(srcLines.slice(i, j + 1).join('\n'));
      const bound = new Set();
      if (isMethod) {
        const header = /^\s*[^(]*\(([^)]*)\)/.exec(body);
        (header ? header[1].split(',') : []).forEach(function (a) {
          const name = a.trim().replace(/[?]?\s*(?::.*|=.*)?$/, '');
          if (name) { bound.add(name); }
        });
      }
      (body.match(/(?:const|let|var)\s+([A-Za-z0-9_$]+)/g) || [])
        .forEach(function (d) { bound.add(d.split(/\s+/)[1]); });
      (body.match(/(?:const|let|var)\s*\{([^}]*)\}/g) || []).forEach(
          function (d) {
        d.replace(/(?:const|let|var)\s*\{|\}/g, '')
         .split(',')
         .forEach(function (n) {
          if (n.trim()) { bound.add(n.trim().split(':').pop().trim()); }
        });
      });
      (body.match(/function\s*[A-Za-z0-9_$]*\s*\(([^)]*)\)/g) || []).forEach(
          function (sig) {
        sig.replace(/function\s*[A-Za-z0-9_$]*\s*\(|\)/g, '')
           .split(',')
           .forEach(function (a) {
          if (a.trim()) { bound.add(a.trim()); }
        });
      });
      scopes.push({ body: body, bound: bound });
    }
    const unresolved = [];
    inAdmin.forEach(function (n) {
      if (moduleScope.has(n)) { return; }
      // An object KEY is not a reference: `{ mode: action }` names no `mode`.
      const use = new RegExp('(?:^|[^.\\w$])' + n + '(?![\\w$]|\\s*:)');
      const loose = scopes.some(function (scope) {
        return !scope.bound.has(n) && use.test(scope.body);
      });
      if (loose) { unresolved.push(n); }
    });
    t.check(unresolved.length === 0,
            layer + ' uses nothing it does not have in scope',
            'a name that resolved in admin.js and does not here is a ' +
            'ReferenceError waiting for the one branch that reaches it — ' +
            'which is how five of these shipped past `npm test` and were ' +
            'caught one at a time by jobs driving the running service: ' +
            (unresolved.join(', ') || 'none'));
  });
  log.debug("Leaving checkEveryNameResolves().");
}

// ---------------------------------------------------------------------------
// AND NOTHING ANYWHERE REACHES A MOVED FUNCTION THROUGH THE CONSOLE MODULE.
//
// The management API was repointed deliberately; `admin-ui/api_explorer.ts`
// was not, and it called `admin.gateStateFor()` — which stopped existing the
// moment the console stopped re-exporting it. Nothing failed at load: it threw
// a TypeError when somebody opened the page, which is how it was found.
// ---------------------------------------------------------------------------
function checkNobodyReachesThroughTheConsole(t) {
  log.debug("Entering checkNobodyReachesThroughTheConsole().");
  t.log.info('=== nothing reaches a moved function through admin.* ===');
  const moved = new Set();
  LAYERS.forEach(function (layer) {
    // By the extensionless path: the layer is TypeScript since #50, and
    // what node loads is the `.js` compiled beside it.
    const layerExports = require(path.join(ROOT, layer.replace(/\.ts$/, '')));
    Object.keys(layerExports).forEach(function (n) {
      if (!/^set/.test(n)) { moved.add(n); }
    });
  });
  const offenders = [];
  function walk(dir) {
    log.debug("Entering walk().");
    const entries = fs.readdirSync(path.join(ROOT, dir),
                                   { withFileTypes: true });
    const names = entries.map(function (e) { return e.name; });
    entries.forEach(function (entry) {
      const rel = dir ? dir + '/' + entry.name : entry.name;
      if (entry.isDirectory()) {
        // `.claude`: see the first walk above.
        if (['node_modules', '.git', '.claude', 'node-ldapjs'].indexOf(
            entry.name) >= 0) { return; }
        walk(rel);
        return;
      }
      if (!isSourceFile(entry.name, names) || /^admin-core\//.test(rel)) {
        return;
      }
      read(rel).split('\n').forEach(function (l, i) {
        if (/^\s*(\/\/|\*)/.test(l)) { return; }
        (l.match(/\badmin\.([A-Za-z0-9_$]+)\s*\(/g) || []).forEach(
            function (call) {
          const n = call.slice(6).replace(/\s*\($/, '');
          if (moved.has(n)) {
            offenders.push(rel + ':' + (i + 1) + ' admin.' + n);
          }
        });
      });
    });
    log.debug("Leaving walk().");
  }
  walk('');
  t.check(offenders.length === 0,
          'every caller reaches the layer directly',
          'the console does not re-export what moved, so a call left ' +
          'pointing at it is a TypeError the next time somebody opens that ' +
          'page — it loads fine and fails on ' +
          'use: ' + (offenders.join(', ') || 'none'));
  log.debug("Leaving checkNobodyReachesThroughTheConsole().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheLayerIsALibrary(t);
  checkEveryNameResolves(t);
  checkNobodyReachesThroughTheConsole(t);
  checkTheHalvesDependOneWay(t);
  checkTheApiDoesNotGoThroughTheConsole(t);
  checkOnlyTheConsolesOwnKnowledgeIsLeft(t);
  checkTheForwardsCannotDrift(t);
  checkNothingRequiresItEarly(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_actions_layer',
  describe: 'that the decisions both admin surfaces make live in a layer ' +
            'neither of them owns, and that the management API no longer ' +
            'reaches them through the console',
  run: run
};
