// @ts-check
'use strict';
//
// File: source_file.js
//
// ---------------------------------------------------------------------------
// IS THIS FILE SOURCE? — for the tests that read the service's own code as
// text (#50, 2026-09-16).
//
// Part of the service is TypeScript. On a checkout a converted module is
// `x.ts` alone; in the tests image it is `x.ts` AND the `x.js` that
// `build-typescript.sh` compiled beside it. A test that reads source — for
// error codes, for a require it forbids, for a call it counts — must read
// `x.ts` in both places and must not read the compiled `x.js` as a second
// copy of the same module. So a file is source when it is:
//
//   * a `.ts` that is not a declaration (`.d.ts`), or
//   * a `.js` with no `.ts` of the same name beside it.
//
// `siblings` is the directory's file names (one `readdirSync` the caller has
// already made), so this adds no filesystem call per file.
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({ name: 'source_file',
  level: process.env.LOG_LEVEL || 'info' });

// Called once per directory entry while a test walks the tree, so no
// Entering/Leaving pair — the hot-path exception, stated as it requires.
function isSourceFile(name, siblings) {
  if (/\.d\.ts$/.test(name)) {
    return false;
  }
  if (/\.ts$/.test(name)) {
    return true;
  }
  if (!/\.js$/.test(name)) {
    return false;
  }
  const twin = name.slice(0, -3) + '.ts';
  return (siblings || []).indexOf(twin) < 0;
}

// The same question for a whole listing, for the callers that filter one.
function sourceFilesIn(names) {
  log.debug("Entering sourceFilesIn().");
  const list = names || [];
  log.debug("Leaving sourceFilesIn().");
  return list.filter(function (name) {
    return isSourceFile(name, list);
  });
}

module.exports = { isSourceFile: isSourceFile, sourceFilesIn: sourceFilesIn };
