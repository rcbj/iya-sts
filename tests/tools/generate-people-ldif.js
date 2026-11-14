#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/generate-people-ldif.js
//
// ===========================================================================
// SYNTHETIC PEOPLE AS LDIF, FOR THE BULK IMPORT (#629).
//
//   node tests/tools/generate-people-ldif.js --count=1000000 \
//        [--stamp=26cb84b3] [--start=1] [--base=dc=example,dc=com] \
//        [--out=people.ldif]
//
// The shape the LDAP loader (`load-users.js`, the 10M load) adds over LDAPS,
// so the two doors' people are the same people: `uid=load-<stamp>-<n>` under
// `ou=users,<base>`, the four inetOrgPerson classes, and `cn`, `sn`,
// `givenName`, `displayName`, `mail` (`<uid>@load.example`) and `uid`.
// Numbered from `--start`, so a 40M load is made as chunk files that do not
// overlap (`--start=1 --count=5000000`, `--start=5000001 …`) — each one a
// file `persistence/bulk_import.js` can import, re-run or resume alone.
//
// STREAMED, with backpressure: memory stays flat whatever `--count` is. Every
// value is plain ASCII under 76 columns, so no line needs base64 or folding
// (RFC 2849 section 2). Nothing here touches a store or the network.
// ===========================================================================

const fs = require('fs');
const crypto = require('crypto');

const log = require('bunyan').createLogger({
  name: 'generate-people-ldif',
  level: process.env.LOG_LEVEL || 'info' });

const USAGE = 'Usage: node tests/tools/generate-people-ldif.js --count=<n> ' +
  '[--stamp=<hex>] [--start=<n>] [--base=<dn>] [--out=<file>]';

/**
 * The arguments, or null when they are wrong.
 *
 * @param argv - the arguments after the script
 * @returns `{ count, stamp, start, base, out }` or null
 */
function optionsOf(argv) {
  log.debug("Entering optionsOf().");
  const out = { count: '', stamp: crypto.randomBytes(4).toString('hex'),
                start: '1', base: 'dc=example,dc=com', out: '' };
  for (const arg of argv) {
    const m = /^--(count|stamp|start|base|out)=(.*)$/.exec(arg);
    if (!m) {
      log.debug("Leaving optionsOf(). Unknown argument.");
      return null;
    }
    out[m[1]] = m[2];
  }
  const count = Number(out.count);
  const start = Number(out.start);
  if (!Number.isInteger(count) || count < 0 || !Number.isInteger(start) ||
      start < 0 || !/^[A-Za-z0-9-]+$/.test(out.stamp) ||
      !/^dc=[^,]+(,dc=[^,]+)*$/i.test(out.base)) {
    log.debug("Leaving optionsOf(). A value.");
    return null;
  }
  log.debug("Leaving optionsOf().");
  return { count: count, stamp: out.stamp, start: start, base: out.base,
           out: out.out };
}

/**
 * One person's record, as the loader adds them. A HOT PATH (once a person,
 * forty million times), so no Entering/Leaving pair.
 *
 * @param stamp - the run's stamp
 * @param n - the person's number
 * @param base - the realm's base DN
 * @returns the record's text, with its trailing blank line
 */
function recordOf(stamp, n, base) {
  const uid = 'load-' + stamp + '-' + n;
  return 'dn: uid=' + uid + ',ou=users,' + base + '\n' +
    'objectClass: top\nobjectClass: person\n' +
    'objectClass: organizationalPerson\nobjectClass: inetOrgPerson\n' +
    'uid: ' + uid + '\n' +
    'cn: Load User ' + n + '\n' +
    'sn: User ' + n + '\n' +
    'givenName: Load\n' +
    'displayName: Load User ' + n + '\n' +
    'mail: ' + uid + '@load.example\n\n';
}

/**
 * Writes the people to a stream, waiting for it to drain.
 *
 * @param options - `optionsOf()`'s answer
 * @param sink - a writable stream
 * @returns a promise of the number written
 */
async function generate(options, sink) {
  log.debug("Entering generate().");
  sink.write('version: 1\n\n');
  const end = options.start + options.count;
  let chunk = '';
  for (let n = options.start; n < end; n++) {
    chunk += recordOf(options.stamp, n, options.base);
    if (chunk.length >= 1 << 16) {
      if (!sink.write(chunk)) {
        await new Promise(function (resolve) {
          sink.once('drain', resolve);
        });
      }
      chunk = '';
    }
  }
  if (chunk) {
    sink.write(chunk);
  }
  log.debug("Leaving generate().");
  return options.count;
}

/**
 * Runs the command line.
 *
 * @param argv - the arguments after the script
 * @returns a promise of the exit code
 */
async function main(argv) {
  log.debug("Entering main().");
  const options = optionsOf(argv);
  if (!options) {
    process.stderr.write(USAGE + '\n');
    log.debug("Leaving main(). Usage.");
    return 2;
  }
  const sink = options.out ? fs.createWriteStream(options.out)
    : process.stdout;
  const written = await generate(options, sink);
  if (options.out) {
    await new Promise(function (resolve, reject) {
      sink.end(resolve);
      sink.on('error', reject);
    });
  }
  process.stderr.write('generate-people-ldif: ' + written + ' people, ' +
                       'load-' + options.stamp + '-' + options.start +
                       ' to load-' + options.stamp + '-' +
                       (options.start + options.count - 1) + '\n');
  log.debug("Leaving main().");
  return 0;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(function (code) {
    process.exitCode = code;
  }, function (e) {
    process.stderr.write('generate-people-ldif: ' +
                         ((e && e.stack) || e) + '\n');
    process.exitCode = 1;
  });
}

module.exports = {
  optionsOf: optionsOf,
  recordOf: recordOf,
  generate: generate,
  main: main
};
