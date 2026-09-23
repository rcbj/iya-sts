// @ts-check
'use strict';
//
// File: compiled_tree.js
//
// ---------------------------------------------------------------------------
// IS THIS TREE COMPILED? (#50, 2026-09-16)
//
// Part of this service is TypeScript, and rcbj's rule is that it is compiled
// only inside an image build — never on the host (issue #50). A checkout
// therefore holds `x.ts` with no `x.js` beside it, and `node server.js` or
// `npm test` run there would die at the first `require` of that module with
// "Cannot find module", which names the module and not the reason.
//
// `refuseUncompiledTree()` is called FIRST by `server.js` and `tests/run.js`
// and says the reason instead: which sources are uncompiled, and that the
// service and its in-process suite run in containers
// (`./docker-npm-test.sh`, `./run-tests.sh`). Inside an image built by
// `build-typescript.sh` every `.ts` has its `.js` (or, in the service image,
// no `.ts` is left), and this answers nothing.
//
// **WHERE IT LOOKS** is where `tsconfig.build.json` compiles: `.ts` files one
// level down, in the service's own directories, and at the package root
// (`sts_metadata.ts`, #50), declarations aside.
//
// **NO LOGGER, AND THEREFORE NO Entering/Leaving LINES**, for
// `config_file.js`'s reason: this runs before anything that could make one,
// and must not require anything of this service. What it has to say goes to
// stderr and the process exits.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// Top-level directories that are not the service's own sources — the
// exclusions `build-typescript.sh` and `tsconfig.build.json` use.
const NOT_SOURCES = ['node_modules', 'tests', 'node-ldapjs', 'xacml-pep',
                     'docs', 'deploy', 'types', '.git', '.claude',
                     '.github'];

// The `.ts` sources in one listing with no `.js` of the same name beside
// them, each prefixed with `prefix` (the directory, or '' for the root).
function twinless(names, prefix, out) {
  names.forEach(function (name) {
    if (!/\.ts$/.test(name) || /\.d\.ts$/.test(name)) {
      return;
    }
    const twin = name.slice(0, -3) + '.js';
    if (names.indexOf(twin) < 0) {
      out.push(prefix + name);
    }
  });
}

// Every `x.ts` at the root of `root` and every `dir/x.ts` under it with no
// `.js` beside it, as paths relative to `root`.
function uncompiledSources(root) {
  const base = root || ROOT;
  const out = [];
  let dirs = [];
  try {
    dirs = fs.readdirSync(base, { withFileTypes: true });
  } catch (e) {
    // An unreadable root is not this check's question; the require that
    // follows will say what is wrong with it.
    return { found: out, problem: String((e && e.message) || e) };
  }
  dirs.forEach(function (dir) {
    if (!dir.isDirectory() || NOT_SOURCES.indexOf(dir.name) >= 0) {
      return;
    }
    let names = [];
    try {
      names = fs.readdirSync(path.join(base, dir.name));
    } catch (e) {
      // A directory that cannot be listed holds nothing this check can
      // report; recorded on the answer rather than swallowed.
      out.push(dir.name + '/ (unreadable: ' + ((e && e.message) || e) + ')');
      return;
    }
    twinless(names, dir.name + '/', out);
  });
  // The package root's own sources, compiled in place like the rest.
  twinless(dirs.filter(function (entry) {
    return entry.isFile();
  }).map(function (entry) {
    return entry.name;
  }), '', out);
  return { found: out.sort(), problem: '' };
}

// Exits the process, with the reason, when the tree is not compiled. `what`
// names the caller for the message: 'node server.js', 'npm test'.
function refuseUncompiledTree(what) {
  const answer = uncompiledSources(ROOT);
  if (!answer.found.length) {
    return;
  }
  console.error(
    '[STS-CORE-0093] ' + (what || 'this process') + ' cannot run from this ' +
    'tree: ' + answer.found.length + ' TypeScript source(s) have no compiled ' +
    '.js beside them (' + answer.found.slice(0, 5).join(', ') +
    (answer.found.length > 5 ? ', ...' : '') + '). TypeScript here is ' +
    'compiled only inside an image build (issue #50), so the service and its ' +
    'in-process suite run in containers: ./docker-npm-test.sh for npm test, ' +
    './run-tests.sh for the whole suite. On the host, ' +
    '`tests/node_modules/.bin/tsc -p tsconfig.json` checks the types and ' +
    'writes nothing.');
  process.exit(1);
}

module.exports = {
  NOT_SOURCES: NOT_SOURCES,
  uncompiledSources: uncompiledSources,
  refuseUncompiledTree: refuseUncompiledTree
};
