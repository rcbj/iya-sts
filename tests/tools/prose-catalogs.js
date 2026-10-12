#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/prose-catalogs.js
//
// ===========================================================================
// KEEPS THE PROSE CATALOGS IN STEP WITH THE SOURCE (#543, 2026-10-12).
//
//   node tests/tools/prose-catalogs.js --print=<ns>
//   node tests/tools/prose-catalogs.js --write
//   node tests/tools/prose-catalogs.js --untranslated=<ns> --tag=<tag>
//   node tests/tools/prose-catalogs.js --merge=<ns> --tag=<tag> --from=<file>
//   node tests/tools/prose-catalogs.js --report
//
// `common/server_prose.ts` keeps the English of the prose the server writes
// into a console view IN THE SOURCE (rcbj's answer 3 on #543), and
// `common/prose_locales/<ns>/en.json` is what this writes from it:
//
//   --print         the namespace's en.json on standard output
//   --write         every namespace's en.json, in place
//   --untranslated  key → English for every message the catalog lacks or
//                   translated from an older English: what a translator is
//                   handed
//   --merge         a translator's key → text file into the catalog, each
//                   entry recording the hash of the English it translates —
//                   computed HERE from the source, never taken from the file,
//                   so a translation cannot claim an English it was not made
//                   from
//   --report        every catalog's coverage of every namespace
//
// `--print` AND `--write` READ THE SOURCE, which is TypeScript compiled only
// inside an image (#50), so they run in the tests image, and `--print`
// writes to standard output so its answer reaches the host:
//
//   docker run --rm iya-sts-npm-test:local \
//     node tests/tools/prose-catalogs.js --print=settings \
//     > common/prose_locales/settings/en.json
//
// The other three read the catalog files and run on the host.
//
// Its `log` is console-backed and bunyan-shaped, the arrangement the root
// CLAUDE.md names for a tool outside the service.
// ===========================================================================
const fs = require('fs');
const path = require('path');

const log = {
  debug: function (message) {
    if (process.env.LOG_LEVEL === 'debug') {
      console.error(message);
    }
  },
  info: function (message) {
    console.error(message);
  }
};

// THE ANSWER IS THE ONLY THING ON STANDARD OUTPUT. The service's logger
// writes there, and `config.js` logs while it loads, before any level is
// read; so every write the modules make goes to standard error, and the
// tool writes its answer through the real stdout.
const answer = process.stdout.write.bind(process.stdout);
process.stdout.write = process.stderr.write.bind(process.stderr);

const ROOT = path.join(__dirname, '..', '..');
const DIRECTORY = path.join(ROOT, 'common', 'prose_locales');

/**
 * Reads `--name=value` arguments.
 *
 * @returns name → value
 */
function argsOf() {
  log.debug("Entering argsOf().");
  const out = {};
  process.argv.slice(2).forEach(function (arg) {
    const m = /^--([a-z-]+)(?:=(.*))?$/.exec(arg);
    if (m) {
      out[m[1]] = m[2] === undefined ? true : m[2];
    }
  });
  log.debug("Leaving argsOf().");
  return out;
}

/**
 * Serialises a catalog the way every catalog file is written: two-space
 * JSON with a final newline.
 *
 * @param body - the catalog
 * @returns the file's text
 */
function serialise(body) {
  log.debug("Entering serialise().");
  log.debug("Leaving serialise().");
  return JSON.stringify(body, null, 2) + '\n';
}

// -------------------------------------------------------------------------
// THE CATALOG FILES, READ AS FILES. `--untranslated`, `--merge` and
// `--report` need no TypeScript: they read `en.json`, which
// tests/server_prose_catalogs.js holds to the source, so they run on the
// host as well — and `--merge` has to, to write where the repository is.
// The hash is `common/server_prose.ts`'s `hashOf()`: the first sixteen hex
// digits of the English's SHA-256. It is taken with node's own `crypto`
// here, not `common/crypto.js`, which requires TypeScript modules and so
// cannot load on the host; `tests/server_prose_catalogs.js` compares every
// catalog against the service's own `hashOf()`, so the two cannot drift
// unnoticed.
// -------------------------------------------------------------------------
/**
 * Hashes an English message the way `ServerProse.hashOf()` does.
 *
 * @param english - the English text
 * @returns sixteen hex digits
 */
function hashOf(english) {
  log.debug("Entering hashOf().");
  log.debug("Leaving hashOf().");
  return require('crypto').createHash('sha256')
    .update(String(english), 'utf8').digest('hex').slice(0, 16);
}

/**
 * Reads a catalog file, or answers an empty object when there is none.
 *
 * @param ns - the namespace
 * @param tag - the catalog (`en` for the English)
 * @returns the file's object
 */
function readCatalog(ns, tag) {
  log.debug("Entering readCatalog(). " + ns + '/' + tag);
  const file = path.join(DIRECTORY, ns, tag + '.json');
  const out = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8'))
                                  : {};
  log.debug("Leaving readCatalog().");
  return out;
}

/**
 * Says what one catalog owes: the English keys it lacks, the ones it
 * translated from an older English, and the keys the English no longer has.
 *
 * @param ns - the namespace
 * @param tag - the catalog
 * @returns `{ english, entries, current, missing, stale, orphans }`
 */
function owed(ns, tag) {
  log.debug("Entering owed(). " + ns + '/' + tag);
  const english = readCatalog(ns, 'en');
  const entries = readCatalog(ns, tag);
  const out = { english: english, entries: entries, current: 0,
                missing: [], stale: [], orphans: [] };
  Object.keys(english).forEach(function (key) {
    if (!entries[key]) {
      out.missing.push(key);
    } else if (entries[key].en === hashOf(english[key])) {
      out.current++;
    } else {
      out.stale.push(key);
    }
  });
  Object.keys(entries).forEach(function (key) {
    if (!(key in english)) {
      out.orphans.push(key);
    }
  });
  log.debug("Leaving owed().");
  return out;
}

/**
 * Merges a translator's file into one catalog, in the English's key order,
 * dropping any key the English no longer has.
 *
 * @param ns - the namespace
 * @param tag - the catalog
 * @param from - the file: key → translated text
 * @returns the number of entries merged
 */
function merge(ns, tag, from) {
  log.debug("Entering merge(). " + ns + '/' + tag);
  const state = owed(ns, tag);
  const given = JSON.parse(fs.readFileSync(from, 'utf8'));
  const held = state.entries;
  let merged = 0;
  Object.keys(given).forEach(function (key) {
    if (!(key in state.english)) {
      throw new Error('the file names ' + key + ', which ' + ns +
                      '/en.json does not hold');
    }
    if (typeof given[key] !== 'string' || !given[key]) {
      throw new Error('the translation of ' + key + ' is not a string');
    }
    held[key] = { en: hashOf(state.english[key]), text: given[key] };
    merged++;
  });
  const out = {};
  Object.keys(state.english).forEach(function (key) {
    if (held[key]) {
      out[key] = held[key];
    }
  });
  fs.mkdirSync(path.join(DIRECTORY, ns), { recursive: true });
  fs.writeFileSync(path.join(DIRECTORY, ns, tag + '.json'), serialise(out));
  log.debug("Leaving merge(). " + merged);
  return merged;
}

/**
 * Runs the tool.
 *
 * @returns nothing
 */
function main() {
  log.debug("Entering main().");
  const args = argsOf();
  if (args.print) {
    answer(serialise(require('../../common/server_prose')
      .extract(args.print)));
  } else if (args.write) {
    const prose = require('../../common/server_prose');
    prose.namespaces().forEach(function (ns) {
      fs.mkdirSync(path.join(DIRECTORY, ns), { recursive: true });
      fs.writeFileSync(path.join(DIRECTORY, ns, 'en.json'),
                       serialise(prose.extract(ns)));
      log.info('wrote common/prose_locales/' + ns + '/en.json');
    });
  } else if (args.untranslated) {
    const state = owed(args.untranslated, args.tag);
    const out = {};
    state.missing.concat(state.stale).forEach(function (key) {
      out[key] = state.english[key];
    });
    answer(serialise(out));
  } else if (args.merge) {
    const merged = merge(args.merge, args.tag, args.from);
    log.info('merged ' + merged + ' translation(s) into ' + args.merge +
             '/' + args.tag + '.json');
  } else if (args.report) {
    const index = JSON.parse(fs.readFileSync(path.join(ROOT, 'common',
      'locales', 'catalogs.json'), 'utf8'));
    fs.readdirSync(DIRECTORY).sort().forEach(function (ns) {
      index.catalogs.forEach(function (c) {
        if (c.tag === 'en') {
          return;
        }
        const state = owed(ns, c.tag);
        answer(ns + '/' + c.tag + ': ' + state.current + '/' +
               Object.keys(state.english).length + ' current, ' +
               state.stale.length + ' stale, ' + state.missing.length +
               ' missing, ' + state.orphans.length + ' orphaned\n');
      });
    });
  } else {
    log.info('usage: see the header of tests/tools/prose-catalogs.js');
    process.exitCode = 2;
  }
  log.debug("Leaving main().");
}

main();
