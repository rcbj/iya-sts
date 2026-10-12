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
// THE MODULE IS TYPESCRIPT, compiled only inside an image (#50), so this
// runs in the tests image. `--print` and `--untranslated` write to standard
// output so their answer reaches the host:
//
//   docker run --rm iya-sts-npm-test:local \
//     node tests/tools/prose-catalogs.js --print=settings \
//     > common/prose_locales/settings/en.json
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

/**
 * Merges a translator's file into one catalog, in the English's key order.
 *
 * @param prose - `common/server_prose`
 * @param ns - the namespace
 * @param tag - the catalog
 * @param from - the file: key → translated text
 * @returns the number of entries merged
 */
function merge(prose, ns, tag, from) {
  log.debug("Entering merge(). " + ns + '/' + tag);
  const english = prose.extract(ns);
  const given = JSON.parse(fs.readFileSync(from, 'utf8'));
  const held = prose.entriesOf(ns, tag);
  let merged = 0;
  Object.keys(given).forEach(function (key) {
    if (!(key in english)) {
      throw new Error('the file names ' + key + ', which ' + ns +
                      '/en.json does not hold');
    }
    if (typeof given[key] !== 'string' || !given[key]) {
      throw new Error('the translation of ' + key + ' is not a string');
    }
    held[key] = { en: prose.hashOf(english[key]), text: given[key] };
    merged++;
  });
  const out = {};
  Object.keys(english).forEach(function (key) {
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
  const prose = require('../../common/server_prose');
  if (args.print) {
    answer(serialise(prose.extract(args.print)));
  } else if (args.write) {
    prose.namespaces().forEach(function (ns) {
      fs.mkdirSync(path.join(DIRECTORY, ns), { recursive: true });
      fs.writeFileSync(path.join(DIRECTORY, ns, 'en.json'),
                       serialise(prose.extract(ns)));
      log.info('wrote common/prose_locales/' + ns + '/en.json');
    });
  } else if (args.untranslated) {
    const coverage = prose.coverage(args.untranslated, args.tag);
    const english = prose.extract(args.untranslated);
    const out = {};
    coverage.missing.concat(coverage.stale).forEach(function (key) {
      out[key] = english[key];
    });
    answer(serialise(out));
  } else if (args.merge) {
    const merged = merge(prose, args.merge, args.tag, args.from);
    log.info('merged ' + merged + ' translation(s) into ' + args.merge +
             '/' + args.tag + '.json');
  } else if (args.report) {
    const tags = require('../../common/i18n').catalogs().map(function (c) {
      return c.tag;
    }).filter(function (tag) {
      return tag !== prose.SOURCE;
    });
    prose.namespaces().forEach(function (ns) {
      tags.forEach(function (tag) {
        const c = prose.coverage(ns, tag);
        answer(ns + '/' + tag + ': ' + c.current + '/' +
                             c.total + ' current, ' + c.stale.length +
                             ' stale, ' + c.missing.length + ' missing, ' +
                             c.orphans.length + ' orphaned\n');
      });
    });
  } else {
    log.info('usage: see the header of tests/tools/prose-catalogs.js');
    process.exitCode = 2;
  }
  log.debug("Leaving main().");
}

main();
