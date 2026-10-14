// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: no_full_directory_walk_in_jobs.js
//
// ===========================================================================
// NO SCHEDULER JOB WALKS EVERY PERSON OR EVERY DEVICE — OR IT SAYS WHY (#615).
//
// A scheduler job runs on the serving front process (`cluster/CLAUDE.md`,
// *The scheduler*), and since #320 that process holds the directory as a
// window onto the store: a walk of `ou=users` or `ou=devices` there is the
// whole container paged through the SYNCHRONOUS bridge on the thread that
// holds every socket. On 8081 the Android attestation recheck did that at
// about 191,000 people and every listener stopped for minutes. rcbj's fifth
// point on #615: audit every job, fix what can be fixed, and hold the rest
// with a test that fails when a job's code path reaches a full walk, with
// an explicit, argued exemption list.
//
// HOW IT READS THE CODE. Every `register({ … run: … })` in the service's own
// source (the files `tests/no_periodic_timers.js` reads, with its reader:
// comments and strings blanked, statements matched by their brackets) is a
// job; its `run` is followed, by NAME, into every function or method the
// tree defines under that name, to `DEPTH` calls deep. A name defined in
// more than `MAX_DEFINITIONS` files, or one of the ordinary names in `STOP`,
// is not followed: it is a collection's method or a word every module uses,
// and following it would make every job reach everything. The reach is
// therefore an approximation in both directions — said here rather than
// discovered — and what it holds is the thing that bit: a job whose path
// names one of the walks below.
//
// THE WALKS (`SINKS`): the calls that list every person or device of a
// realm, or every directory row of the store — `persons()`, `personNames()`,
// `allPersons()`, `personRows()`, `eachEntryInRealm()`,
// `listDeviceEntries()`, `attributeSourcePeople()` (the refresh's old
// page), `walkDirectory()` and `countDirectory()` (the store's), and
// `entriesUnder()` of `usersDn()` or `devicesDn()`. A holder query
// (`eachHolderOfAny()`, `holdersAsync()`, `withAttribute()`) is not one.
//
// EVERY HIT IS ON `EXEMPT` WITH ITS REASON, keyed `<job>|<walk>`, or the test
// fails; and an exemption whose hit has gone fails too — THE LIST ONLY
// SHRINKS, as `no_periodic_timers.js`'s does.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const reader = require('./no_periodic_timers');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({
  name: 'no_full_directory_walk_in_jobs',
  level: process.env.LOG_LEVEL || 'info' });

// How many calls deep a job's run is followed.
const DEPTH = 8;
// A name defined in more files than this is not followed (see the header).
const MAX_DEFINITIONS = 3;
// Names never followed: ordinary words, collection methods and the
// scheduler's own vocabulary.
const STOP = ['get', 'set', 'has', 'delete', 'list', 'run', 'map', 'forEach',
  'filter', 'push', 'value', 'values', 'keys', 'entries', 'find', 'some',
  'every', 'slice', 'concat', 'join', 'split', 'sort', 'reduce', 'then',
  'catch', 'resolve', 'reject', 'require', 'String', 'Number', 'Boolean',
  'Array', 'Object', 'JSON', 'Date', 'Math', 'Promise', 'Error', 'Map',
  'Set', 'log', 'debug', 'info', 'warn', 'error', 'record', 'register',
  'start', 'stop', 'write', 'read', 'open', 'close', 'query', 'call',
  'apply', 'bind', 'emit', 'send', 'now', 'nowMs', 'stillOwner', 'job',
  'tag', 'mark', 'codeOf', 'store', 'deps', 'self', 'this', 'super',
  'instance', 'install', 'forward', 'current', 'currentId', 'run'];

// The walks — see the header. `people` is the attribute-source directory
// hook's name for `attributeSourcePeople()`, which a job reaches through
// the hook and never by the function's own name.
const SINKS = ['persons', 'personNames', 'allPersons', 'personRows',
  'eachEntryInRealm', 'listDeviceEntries', 'attributeSourcePeople',
  'people', 'walkDirectory', 'countDirectory'];

// ---------------------------------------------------------------------------
// NOT FOLLOWED, AND WHY: functions whose walk is ONLY their in-memory
// branch. In a windowed process — the one #615 is about — each asks the
// store an indexed question first (`windowedFind()`, the window's holders)
// and returns; without a window the directory is a Map in this process and
// the walk reads memory, never the store. Following them would report every
// job that looks one person up as a walk of everybody.
// ---------------------------------------------------------------------------
const BARRIERS = {
  eachHolderOfAny: 'the holders, asked of the store in a windowed process ' +
    '(`withAttribute()`); a walk of the in-memory Map otherwise',
  holdersAsync: 'the holders, asked asynchronously (#615)',
  holders: 'the window\'s or a register\'s holders',
  existingUserEntry: '`byName` asked of the store in a windowed process; ' +
    'the in-memory username index otherwise',
  usernameIndexNow: 'the in-memory username index, which a windowed ' +
    'process never builds (existingUserEntry() asks the store first)',
  peopleByMail: '`byMail` asked of the store in a windowed process; a walk ' +
    'of the in-memory Map otherwise',
  peopleByFederationLink: 'an indexed `windowedFind()` in a windowed ' +
    'process; a walk of the in-memory Map otherwise'
};
const CONTAINER_WALK = /\bentriesUnder\s*\(\s*(usersDn|devicesDn)\s*\(\s*\)/;

// ---------------------------------------------------------------------------
// THE EXEMPTIONS, each argued. `fallback` is a walk the job reaches only on
// a path its primary one replaced — a directory that offers no holder query
// or page (a test's stub, an older `ldap_server.js`) — and `inherent` a
// walk the job's purpose needs, with what it would take to remove it.
// ---------------------------------------------------------------------------
const EXEMPT = {
  'devices.android-status-recheck|persons': { fallback:
    'credentials.androidAttestedCredentials(), the walk #615 replaced, ' +
    'reached only where the directory offers no holdersAsync(); the job ' +
    'reads the holders of stsAndroidAttestedCredential ' +
    '(tests/devices_android_recheck.js counts it: persons() never)' },
  'attribute-sources.refresh|people': { fallback:
    'the directory\'s people() — every person listed and sorted for one ' +
    'page — reached only where the directory offers no peoplePage(); the ' +
    'job asks peoplePage(), one page() statement after a key cursor ' +
    '(#615\'s audit)' },
  'scim-client.reconcile|allPersons': { inherent:
    'a reconciliation compares every person in a client\'s scope with what ' +
    'the service provider holds, to find who must be deprovisioned, so it ' +
    'reads everybody by design. What would remove the walk from the front ' +
    'process: paging it after a key cursor across runs (as ' +
    'attribute-sources.refresh now does) with a yield between pages, and ' +
    'for scopeMode=groups starting from the groups\' members. Recorded on ' +
    '#615 rather than changed there: the reconcile\'s deprovisioning rule ' +
    'needs the whole desired set at once, and splitting it is a design ' +
    'change of the SCIM client (#552)' }
};

// ---------------------------------------------------------------------------
// WALKS THE NAME-FOLLOWING CANNOT SEE, audited by hand on #615 and recorded
// here so the record cannot outlive its jobs (each id must still be
// registered). They reach the walk through an object handed over at run
// time — the keystore's sealed store, implemented by the store's driver —
// which no name leads to.
// ---------------------------------------------------------------------------
const INDIRECT = {
  'keys.data-key-reencrypt': 'store.reseal() -> the postgres driver\'s ' +
    'resealSealed() -> walkDirectory(): every sts_ldap_entries row of every ' +
    'realm, opened to find the blobs sealed under the retiring data key. ' +
    'Asynchronous and paged on the driver\'s maintenance pool, so it does ' +
    'not hold the event loop; it reads every row because a sealed blob ' +
    'names its key only inside. Removing it needs the data-key ids in an ' +
    'indexed column, which a holder query cannot stand in for',
  'keys.data-key-count': 'store.countAll() -> countAllSealed() -> ' +
    'countDirectory() -> walkDirectory(), for the reason above'
};

// The job ids a file's `register({ … })` objects carry, with their `run`'s
// text (blanked) and where each is.
function jobsIn(rel, src, s) {
  log.debug('Entering jobsIn(). ' + rel);
  const out = [];
  const re = /\bregister\s*\(\s*\{/g;
  let m;
  while ((m = re.exec(s))) {
    const open = s.indexOf('{', m.index);
    const close = reader.matching(s, open, '{', '}');
    const body = s.slice(open, close + 1);
    const runAt = body.search(/\brun\s*:/);
    if (runAt < 0 || !/\bid\s*:/.test(body)) {
      continue;
    }
    const idAt = body.search(/\bid\s*:/);
    const raw = src.slice(open + idAt, open + idAt + 200)
      .replace(/^id\s*:\s*/, '');
    let id = '';
    const literal = /^(['"])([^'"]+)\1/.exec(raw);
    if (literal) {
      id = literal[2];
    } else {
      const name = /^([A-Za-z_$][\w$.]*)/.exec(raw);
      const bare = name ? name[1].split('.').pop() : '';
      const declared = bare ? new RegExp('\\b' + bare.replace(/\$/g, '\\$') +
        '\\s*=\\s*([\'"])([^\'"]+)\\1').exec(src) : null;
      id = declared ? declared[2] : rel + ':' + bare;
    }
    out.push({ id: id, file: rel,
               line: src.slice(0, m.index).split('\n').length,
               text: body.slice(runAt) });
  }
  log.debug('Leaving jobsIn(). ' + out.length + '.');
  return out;
}

// Every name called in a text.
function callsIn(text) {
  log.debug('Entering callsIn().');
  const out = new Set();
  const re = /\b([A-Za-z_$][\w$]*)\s*\(/g;
  let m;
  while ((m = re.exec(text))) {
    out.add(m[1]);
  }
  log.debug('Leaving callsIn().');
  return Array.from(out);
}

// The walks a text names.
function sinksIn(text) {
  log.debug('Entering sinksIn().');
  const out = SINKS.filter(function (name) {
    return new RegExp('\\b' + name + '\\s*\\(').test(text);
  });
  const container = CONTAINER_WALK.exec(text);
  if (container) {
    out.push('entriesUnder(' + container[1] + '())');
  }
  log.debug('Leaving sinksIn().');
  return out;
}

// Every walk a job reaches, as `{ sink, via }`, the first path found.
function reachOf(job, index, files) {
  log.debug('Entering reachOf(). ' + job.id);
  const found = new Map();
  const seen = new Set();
  const queue = [{ text: job.text, file: job.file, via: [job.id], depth: 0 }];
  while (queue.length) {
    const at = queue.shift();
    sinksIn(at.text).forEach(function (sink) {
      if (!found.has(sink)) {
        found.set(sink, at.via.concat([sink]));
      }
    });
    if (at.depth >= DEPTH) {
      continue;
    }
    callsIn(at.text).forEach(function (name) {
      if (STOP.indexOf(name) >= 0 || name.length < 4 ||
          SINKS.indexOf(name) >= 0 || BARRIERS[name]) {
        return;
      }
      const defs = index.get(name) || [];
      const inFiles = new Set(defs.map(function (d) {
        return d.file;
      }));
      if (!defs.length || inFiles.size > MAX_DEFINITIONS) {
        return;
      }
      defs.forEach(function (d) {
        const key = d.file + '|' + d.start;
        if (seen.has(key)) {
          return;
        }
        seen.add(key);
        queue.push({ text: files.get(d.file).slice(d.start, d.end + 1),
                     file: d.file,
                     via: at.via.concat([d.file + ':' + name]),
                     depth: at.depth + 1 });
      });
    });
  }
  log.debug('Leaving reachOf(). ' + found.size + '.');
  return Array.from(found.entries()).map(function (pair) {
    return { sink: pair[0], via: pair[1] };
  });
}

// The whole audit: every job, and every walk each reaches.
function audit() {
  log.debug('Entering audit().');
  const rels = reader.walk(ROOT, []);
  const files = new Map();
  const index = new Map();
  const jobs = [];
  rels.forEach(function (rel) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const s = reader.blank(src);
    files.set(rel, s);
    reader.functionsOf(s).forEach(function (f) {
      if (!index.has(f.name)) {
        index.set(f.name, []);
      }
      index.get(f.name).push({ file: rel, start: f.start, end: f.end });
    });
    jobsIn(rel, src, s).forEach(function (job) {
      jobs.push(job);
    });
  });
  const hits = [];
  jobs.forEach(function (job) {
    reachOf(job, index, files).forEach(function (hit) {
      hits.push({ key: job.id + '|' + hit.sink, job: job, sink: hit.sink,
                  via: hit.via });
    });
  });
  log.debug('Leaving audit(). ' + jobs.length + ' job(s), ' + hits.length +
            ' walk(s).');
  return { jobs: jobs, hits: hits };
}

function run(t) {
  log.debug('Entering run().');
  const result = audit();
  t.check(result.jobs.length >= 40,
          'the scheduler jobs were found to read (' + result.jobs.length +
          ')', result.jobs.map(function (job) {
            return job.id;
          }).join(', '));
  t.check(result.jobs.some(function (job) {
    return job.id === 'devices.android-status-recheck';
  }), 'the Android attestation recheck is among them');
  const unlisted = result.hits.filter(function (hit) {
    return !EXEMPT[hit.key];
  });
  t.check(unlisted.length === 0,
          'no scheduler job reaches a walk of every person, every device or ' +
          'every directory row unless it is a recorded, argued exemption — ' +
          'read the holders (eachHolderOfAny(), holdersAsync()) or a page ' +
          'after a cursor instead (#615)',
          unlisted.map(function (hit) {
            return hit.key + ' via ' + hit.via.join(' -> ');
          }).join('\n'));
  const keys = result.hits.map(function (hit) {
    return hit.key;
  });
  const gone = Object.keys(EXEMPT).filter(function (key) {
    return keys.indexOf(key) < 0;
  });
  t.check(gone.length === 0,
          'every exemption still has its walk: THE LIST ONLY SHRINKS — ' +
          'remove the entry of a job that stopped walking', gone.join('; '));
  const ids = result.jobs.map(function (job) {
    return job.id;
  });
  const lost = Object.keys(INDIRECT).filter(function (id) {
    return ids.indexOf(id) < 0;
  });
  t.check(lost.length === 0,
          'every hand-audited indirect walk names a job still registered',
          lost.join('; '));
  t.check(Object.keys(EXEMPT).every(function (key) {
    const row = EXEMPT[key];
    return !!(row.fallback || row.inherent) &&
      !(row.fallback && row.inherent);
  }), 'each exemption is either a fallback or inherent, and says why');
  // The detector itself, on shapes.
  const shapes = [
    ['x.register({ id: \'a.b\', run: function () { return walkIt(); } });\n' +
     'function walkIt() { return dir.persons(); }', 'persons'],
    ['x.register({ id: \'a.c\', run: function () { ' +
     'return entriesUnder(usersDn()); } });', 'entriesUnder(usersDn())'],
    ['x.register({ id: \'a.d\', run: function () { ' +
     'return eachHolderOfAny([\'x\'], f); } });', null]
  ];
  shapes.forEach(function (shape) {
    const s = reader.blank(shape[0]);
    const index = new Map();
    reader.functionsOf(s).forEach(function (f) {
      index.set(f.name, [{ file: 'x.js', start: f.start, end: f.end }]);
    });
    const files = new Map([['x.js', s]]);
    const job = jobsIn('x.js', shape[0], s)[0];
    const got = job ? reachOf(job, index, files).map(function (hit) {
      return hit.sink;
    }) : [];
    t.check(shape[1] ? got.indexOf(shape[1]) >= 0 : got.length === 0,
            'the detector ' + (shape[1] ? 'finds ' + shape[1] + ' in ' +
              (job && job.id) : 'passes a holder query'),
            JSON.stringify(got));
  });
  log.debug('Leaving run().');
}

module.exports = {
  name: 'no_full_directory_walk_in_jobs',
  describe: 'no scheduler job walks every person, every device or every ' +
            'directory row unless it is a recorded, argued exemption (#615)',
  run: run,
  audit: audit
};
