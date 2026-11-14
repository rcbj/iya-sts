// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: no_full_directory_walk_in_requests.js
//
// ===========================================================================
// NO REQUEST HANDLER WALKS EVERY PERSON OR EVERY DEVICE SYNCHRONOUSLY — OR
// IT SAYS WHY (#616).
//
// `tests/no_full_directory_walk_in_jobs.js` (#615) asks this of the
// scheduler's jobs; this asks it of the REQUESTS. Since #320 a process
// holding a postgres store keeps its people and devices as a window onto it,
// so a walk of `ou=users` or `ou=devices` in a request is the whole
// container paged through the SYNCHRONOUS bridge on that process's event
// loop. On 8081, at about 200,000 people, `GET /admin-api/ldap/directory`
// held a request worker for 38–45 s to draw one row, an LDAP search for
// every group for 28.5 s, and `/admin-api/users` for 3 s; every request
// dispatched to that worker waited behind each. rcbj's direction on #616:
// minimise full scans, and read what must be read ASYNCHRONOUSLY.
//
// HOW IT READS THE CODE (the job test's reader, and its approximations):
//
//   * THE ROOTS are the request handlers the source registers: every
//     `handler: function` of a management-API operation table, every
//     `<app|router|api>.<get|post|put|patch|delete|all>(` route, every
//     `server.<search|bind|add|modify|del|compare|modifyDN>(` LDAP
//     operation, every SCIM resource's `egress`, `ingress` and `degress`,
//     and the views a slot hands to a router (`VIEW_ROOTS`),
//     which no name leads to.
//   * Every function or method the tree defines under a name a root calls
//     is followed, to `DEPTH` calls deep, under the job test's rules: its
//     `STOP` words, its `MAX_DEFINITIONS`, and its `BARRIERS` (functions
//     whose walk is only their in-memory branch, which in a windowed process
//     ask the store an indexed question) — plus `REQUEST_BARRIERS` below,
//     #616's.
//   * A DIRECTORY HOOK CALLED BY ITS NAME — `this.store('<hook>', …)`,
//     `credentials.deviceStore('<hook>', …)` — is followed as a call to that
//     name, and a hook that is a walk is a hit (#636: both of its bugs were
//     reached this way, the device register's walk under a person's page and
//     a token request, and neither was seen). `common/devices.ts`' every
//     device, `this.all()`, is a walk keyed by the function that asks.
//   * A HIT is a reached function that NAMES one of the walks (`SINKS`: the
//     job test's, and `personDns()`, `residentsPage()`, the window's
//     synchronous `walk()`, and `entriesUnder()` of `usersDn()` or
//     `devicesDn()`), keyed `<file>|<function>|<walk>` by the innermost named
//     function the call is in.
//
// EVERY HIT IS ON `EXEMPT` WITH ITS REASON or the test fails, and an
// exemption whose hit has gone fails too — THE LIST ONLY SHRINKS. Each
// exemption is one of:
//
//   * `memory` — the walk is the function's in-memory branch; a windowed
//     process takes another path first (named);
//   * `fallback` — reached only where the directory lacks the question that
//     replaced it (a test's stub, an older filler);
//   * `bounded` — not every person: a cap the reader can see;
//   * `notRequest` — reached by the name-following, but run at start-up, by
//     the scheduler or only in development mode, which the reason says;
//   * `owed` — a request path that still walks in a windowed process, with
//     what it would take to stop. These are #616's audit's remainder,
//     recorded rather than hidden, and the reason to keep this list short.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const reader = require('./no_periodic_timers');
const jobs = require('./no_full_directory_walk_in_jobs');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({
  name: 'no_full_directory_walk_in_requests',
  level: process.env.LOG_LEVEL || 'info' });

// How many calls deep a handler is followed.
const DEPTH = 8;

// The walks: the job test's, and the ones a request reaches that a job
// does not.
const SINKS = jobs.SINKS.concat(['personDns', 'residentsPage',
  'buildDeviceIndex']);
const WINDOW_WALK = /\bdirectoryWindow\s*\.\s*walk\s*\(/;

// #636: `common/devices.ts`' `all()` is every device entry, copied — in a
// windowed process `ou=devices` paged through the synchronous bridge, whose
// `page()` under that container costs the realm's keys past the last device
// (the whole directory). Its callers are keyed one by one, so a new caller
// is a new hit. And `buildDeviceIndex()` is the device index's walk, which
// a windowed process no longer reaches (`windowedDeviceEntries()`).
const DEVICE_REGISTER_FILE = 'common/devices.ts';
const DEVICE_REGISTER_WALK = /\bthis\s*\.\s*all\s*\(\s*\)/;

// #636: A DIRECTORY HOOK CALLED BY ITS NAME AS A STRING —
// `this.store('listDeviceEntries')`, `credentials.deviceStore('…', [...])` —
// is followed as a call to that name. The name is a string, which the
// reader blanks, so it is read from the source; both bugs #636 found were
// reached this way and neither was seen here.
const HOOK_CALL = /\b(?:store|deviceStore)\s*\(\s*'([A-Za-z_$][\w$]*)'/g;
const CONTAINER_WALK = /\bentriesUnder\s*\(\s*(usersDn|devicesDn)\s*\(\s*\)/;

// #616's barriers: functions whose walk is only their in-memory branch, a
// windowed process asking the store first (asynchronously where it reads
// more than a handful of rows).
const REQUEST_BARRIERS = {
  ldapDirectoryView: 'windowedDirectoryView() in a windowed process: the ' +
    'store\'s counts and one page, asked asynchronously (#616)',
  personNamesUpTo: 'keysUnder() in a windowed process: limit + 1 keys, no ' +
    'entry read (#616)',
  personNamesUpToAsync: 'keysUnderAsync(), asynchronously (#616)',
  personsHolding: 'eachHolderOfAny(): the holders (#616)',
  windowedSearchCandidates: 'walkAsync() / classesUnderAsync(): the store ' +
    'paged asynchronously, the paging stopped at the size or time limit ' +
    '(#616)'
};

// The views a slot hands to a router, which no name leads to: the nine
// `/admin/ldap/*` pages (`admin.setDirectoryPages()`), answered by
// `GET /admin-api/ldap/*` through `adminViews.directoryPageJson()`.
const VIEW_ROOTS = ['ldapServiceView', 'ldapDirectoryView',
  'ldapApplicationsView', 'ldapFederationsView', 'ldapSpiffeView',
  'ldapRolesView', 'ldapPoliciesView', 'ldapPepsView', 'ldapDevicesView'];

// ---------------------------------------------------------------------------
// THE EXEMPTIONS, each argued (see the header for the four kinds).
// ---------------------------------------------------------------------------
const EXEMPT = {
  'ldap/ldap_server.js|ldapDirectoryView|eachEntryInRealm': { memory:
    'the whole directory\'s page, held in memory; a windowed process ' +
    'returns windowedDirectoryView() first — the store\'s counts and one ' +
    'page, asynchronously (#616)' },
  'ldap/ldap_server.js|delegateCandidates|personRows': { memory:
    '/portal/delegate\'s uid search (2026-10-20) over the realm\'s people ' +
    'held in memory; a windowed process asks the store one indexed ' +
    'statement first (`uidContains`, the trigram index) for an ' +
    'over-fetch of 51 rows, asynchronously' },
  'ldap/ldap_server.js|certificateHolders|eachEntryInRealm': { memory:
    'the stored-certificate index (#1061) built over every entry held in ' +
    'memory, and only when its clock moved (a write to a holder, or an ' +
    'unnamed write); a windowed process walks directoryWindow.eachResident() ' +
    'instead — the resident containers, never ou=users or ou=devices, whose ' +
    'holders the store\'s usercertificatesha256 index answers through ' +
    'windowedFind(\'byAttribute\')' },
  'ldap/ldap_server.js|peopleMissing|eachEntryInRealm': { memory:
    'the attribute policy\'s count of people lacking a required ' +
    'attribute (#396, /admin-api/policies?missing=count), held in memory; ' +
    'a windowed process answers `missing: null` before the walk, and the ' +
    'LDAP filter that finds those people is given either way' },
  'ldap/ldap_server.js|entriesUnder|directoryWindow.walk': { bounded:
    'entriesUnder() of a RESIDENT container (applications, roles, ' +
    'policies…) — walk() pages nothing for a base that reaches no windowed ' +
    'container. Its ou=users and ou=devices callers are caught by name ' +
    '(entriesUnder(usersDn()) / entriesUnder(devicesDn())).' },
  'common/credentials.ts|secondFactorPopulation|persons': { fallback:
    'persons() is the list where the directory offers no personNamesUpTo() ' +
    'hook; ldap_server.js offers it, and /admin-api/users and /admin-api/mfa ' +
    'ask personNamesUpToAsync() first (#616)' },
  'admin-ui/admin_rbac.ts|candidates|allPersons': { fallback:
    'reached only where the directory offers no personDns(); see the next ' +
    'entry for personDns() itself' },
  'admin-ui/admin_rbac.ts|candidates|personDns': { memory:
    'the role screen\'s in-memory candidates; a windowed process returns ' +
    'before personDns() and /admin/rbac asks candidatePageAsync() (#359)' },
  'admin-ui/cells_admin.ts|answerPeople|residentsPage': { memory:
    'the cells page\'s in-memory keyset; a windowed process asks ' +
    'residentsPageAsync() — one rdnPage of ou=users (#359)' },
  'scim/scim.ts|declareResources|allPersons': { owed:
    'GET /scim/v2/Users with a filter other than userName eq (asked of the ' +
    'name index since #616) builds a resource for every person and filters ' +
    'them, as SCIM\'s filter language is wider than the store\'s indexes. ' +
    'What would stop it: more filters mapped onto indexed questions (emails ' +
    'eq onto byMail, externalId), and the rest paged asynchronously with ' +
    'startIndex/count pushed down (#616\'s audit)' },
  'common/devices.ts|ownedEntries|devices.all': { fallback:
    'reached only where the directory offers no deviceEntriesOwnedBy() ' +
    'hook (an in-process test\'s stand-in); ldap_server.js offers it, and ' +
    'in a windowed process it is one byAttribute on owner under ' +
    'ou=devices (#636)' },
  'ldap/ldap_server.js|deviceEntriesOwnedBy|entriesUnder(devicesDn())': {
    memory: 'the container\'s kept listing in memory; a windowed process ' +
    'asks windowedDeviceEntries() first — one byAttribute on owner under ' +
    'ou=devices — and pages nothing (#636)' },
  'ldap/ldap_server.js|ldapDevicesView|listDeviceEntries': { memory:
    'the device page held in memory; a windowed process returns ' +
    'windowedDevicesView() first — one count and one containerPage (#359)' }
};

// The handler registrations a file makes: the text of each one's arguments
// (a route's, an LDAP operation's) or body (an operation table's
// `handler`).
function rootsIn(rel, s) {
  log.debug('Entering rootsIn(). ' + rel);
  const out = [];
  const patterns = [
    /\bhandler\s*:\s*(?:async\s+)?function\b[^{]*\{/g,
    /\b(?:app|router|api|this\.app)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(/g,
    /\bserver\s*\.\s*(?:search|bind|add|modify|del|compare|modifyDN)\s*\(/g,
    // SCIM's resources (SCIMMY's handlers for a read, a write, a delete).
    /\.\s*(?:egress|ingress|degress)\s*\(/g
  ];
  patterns.forEach(function (re) {
    let m;
    while ((m = re.exec(s))) {
      const last = m[0].slice(-1);
      const open = m.index + m[0].length - 1;
      const close = reader.matching(s, open, last, last === '{' ? '}' : ')');
      if (close < 0) {
        continue;
      }
      out.push({ file: rel, line: s.slice(0, m.index).split('\n').length,
                 start: open, text: s.slice(open, close + 1) });
    }
  });
  log.debug('Leaving rootsIn(). ' + out.length + '.');
  return out;
}

// The walks a text names directly. `rel` is the file it is in, for the
// walks only one file's text can name.
function sinksIn(text, rel) {
  log.debug('Entering sinksIn().');
  const out = SINKS.filter(function (name) {
    return new RegExp('\\b' + name + '\\s*\\(').test(text);
  });
  if (rel === DEVICE_REGISTER_FILE && DEVICE_REGISTER_WALK.test(text)) {
    out.push('devices.all');
  }
  if (WINDOW_WALK.test(text)) {
    out.push('directoryWindow.walk');
  }
  const container = CONTAINER_WALK.exec(text);
  if (container) {
    out.push('entriesUnder(' + container[1] + '())');
  }
  log.debug('Leaving sinksIn().');
  return out;
}

// Whether a name is followed.
// Hot path (once per call named in every reached function): no
// Entering/Leaving pair, the exception the code style allows.
function followed(name) {
  return jobs.STOP.indexOf(name) < 0 && name.length >= 4 &&
    SINKS.indexOf(name) < 0 && !jobs.BARRIERS[name] &&
    !REQUEST_BARRIERS[name];
}

// Every definition the roots reach, `file|start` -> `{ def, via }`.
function reached(roots, index, files, raws) {
  log.debug('Entering reached().');
  const out = new Map();
  const queue = roots.map(function (root) {
    return { text: root.text, via: [root.file + ':' + root.line], depth: 0,
             raw: raws && root.start !== undefined
               ? raws.get(root.file).slice(root.start, root.start +
                                           root.text.length)
               : '' };
  });
  while (queue.length) {
    const at = queue.shift();
    if (at.depth >= DEPTH) {
      continue;
    }
    const names = jobs.callsIn(at.text).concat(hookCallsIn(at.raw));
    names.forEach(function (name) {
      if (!followed(name)) {
        return;
      }
      const defs = index.get(name) || [];
      const inFiles = new Set(defs.map(function (d) {
        return d.file;
      }));
      if (!defs.length || inFiles.size > jobs.MAX_DEFINITIONS) {
        return;
      }
      defs.forEach(function (d) {
        const key = d.file + '|' + d.start;
        if (out.has(key)) {
          return;
        }
        const via = at.via.concat([d.file + ':' + name]);
        out.set(key, { def: d, via: via });
        queue.push({ text: files.get(d.file).slice(d.start, d.end + 1),
                     raw: raws ? raws.get(d.file).slice(d.start, d.end + 1)
                       : '',
                     via: via, depth: at.depth + 1 });
      });
    });
  }
  log.debug('Leaving reached(). ' + out.size + '.');
  return out;
}

// The directory hooks a source text calls by name (`HOOK_CALL`).
function hookCallsIn(raw) {
  log.debug('Entering hookCallsIn().');
  const out = [];
  const g = new RegExp(HOOK_CALL.source, 'g');
  let m;
  while ((m = g.exec(String(raw || '')))) {
    if (out.indexOf(m[1]) < 0 && m[1] !== 'hasHook') {
      out.push(m[1]);
    }
  }
  log.debug('Leaving hookCallsIn().');
  return out;
}

// The innermost named definition of a file containing a position.
// Hot path (once per walk found): no Entering/Leaving pair, the exception
// the code style allows.
function innermost(defs, at) {
  let best = null;
  defs.forEach(function (d) {
    if (d.start <= at && at <= d.end &&
        (!best || d.end - d.start < best.end - best.start)) {
      best = d;
    }
  });
  return best;
}

// The whole audit: the roots, what they reach, and every walk a reached
// function names, keyed by the innermost named function the call is in.
function audit() {
  log.debug('Entering audit().');
  const sources = new Map();
  reader.walk(ROOT, []).forEach(function (rel) {
    sources.set(rel, fs.readFileSync(path.join(ROOT, rel), 'utf8'));
  });
  log.debug('Leaving audit().');
  return auditSources(sources);
}

// The audit of one text, for the detector's own checks.
function auditText(rel, src) {
  log.debug('Entering auditText().');
  log.debug('Leaving auditText().');
  return auditSources(new Map([[rel, src]])).hits;
}

// The audit of a set of sources, `rel` -> text.
function auditSources(sources) {
  log.debug('Entering auditSources().');
  const files = new Map();
  const index = new Map();
  const byFile = new Map();
  const roots = [];
  sources.forEach(function (src, rel) {
    const s = reader.blank(src);
    files.set(rel, s);
    const defs = reader.functionsOf(s).map(function (f) {
      return { name: f.name, file: rel, start: f.start, end: f.end };
    });
    byFile.set(rel, defs);
    defs.forEach(function (d) {
      if (!index.has(d.name)) {
        index.set(d.name, []);
      }
      index.get(d.name).push(d);
    });
    rootsIn(rel, s).forEach(function (root) {
      roots.push(root);
    });
  });
  VIEW_ROOTS.forEach(function (name) {
    (index.get(name) || []).forEach(function (d) {
      roots.push({ file: d.file, line: name,
                   text: files.get(d.file).slice(d.start, d.end + 1) });
    });
  });
  const reach = reached(roots, index, files, sources);
  // The roots' own text is reached too: a handler that names a walk.
  const hits = new Map();
  const note = function (rel, at, sink, via) {
    const d = innermost(byFile.get(rel), at);
    const key = rel + '|' + (d ? d.name : '(handler)') + '|' + sink;
    if (!hits.has(key)) {
      hits.set(key, { key: key, via: via });
    }
  };
  const scan = function (rel, from, to, via) {
    const text = files.get(rel).slice(from, to + 1);
    sinksIn(text, rel).forEach(function (sink) {
      const re = sink === 'directoryWindow.walk' ? WINDOW_WALK
        : sink === 'devices.all' ? DEVICE_REGISTER_WALK
          : /^entriesUnder/.test(sink) ? CONTAINER_WALK
            : new RegExp('\\b' + sink + '\\s*\\(');
      const g = new RegExp(re.source, 'g');
      let m;
      while ((m = g.exec(text))) {
        const d = innermost(byFile.get(rel), from + m.index);
        // Only a call inside the reached definition itself, or inside one
        // of its own anonymous callbacks — a nested NAMED function is
        // judged when it is reached.
        if (d && d.start > from && !reach.has(rel + '|' + d.start)) {
          continue;
        }
        note(rel, from + m.index, sink, via);
      }
    });
    // A walk called as a hook by its name (#636): `store('<walk>')`.
    const raw = sources.get(rel).slice(from, to + 1);
    const g = new RegExp(HOOK_CALL.source, 'g');
    let m;
    while ((m = g.exec(raw))) {
      if (SINKS.indexOf(m[1]) < 0) {
        continue;
      }
      const d = innermost(byFile.get(rel), from + m.index);
      if (d && d.start > from && !reach.has(rel + '|' + d.start)) {
        continue;
      }
      note(rel, from + m.index, m[1], via);
    }
  };
  reach.forEach(function (one) {
    scan(one.def.file, one.def.start, one.def.end, one.via);
  });
  roots.forEach(function (root) {
    const s = files.get(root.file);
    const at = s.indexOf(root.text);
    if (at >= 0) {
      scan(root.file, at, at + root.text.length - 1, [root.file + ':' +
                                                      root.line]);
    }
  });
  log.debug('Leaving auditSources(). ' + roots.length + ' root(s), ' +
            hits.size + ' walk(s).');
  return { roots: roots, hits: Array.from(hits.values()) };
}

function run(t) {
  log.debug('Entering run().');
  const result = audit();
  t.check(result.roots.length >= 500,
          'the request handlers were found to read (' + result.roots.length +
          ')');
  const unlisted = result.hits.filter(function (hit) {
    return !EXEMPT[hit.key];
  });
  t.check(unlisted.length === 0,
          'no request handler reaches a synchronous walk of every person or ' +
          'every device unless it is a recorded, argued exemption — ask an ' +
          'index, the holders, a count or a page after a cursor, and read ' +
          'anything larger asynchronously (#616)',
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
          'remove the entry of a path that stopped walking', gone.join('; '));
  t.check(Object.keys(EXEMPT).every(function (key) {
    const row = EXEMPT[key];
    const kinds = ['memory', 'fallback', 'bounded', 'notRequest', 'owed']
      .filter(function (kind) {
        return !!row[kind];
      });
    return kinds.length === 1;
  }), 'each exemption is exactly one of memory, fallback, bounded, ' +
      'notRequest or owed, and says why');
  // THE DETECTOR ITSELF, on shapes: a handler that reaches a walk through a
  // helper, one that reaches it through a barrier (not a hit), and an LDAP
  // operation naming the window's synchronous walk.
  const shapes = [
    ['app.get(\'/a\', function (req, res) { res.json(listThem()); });\n' +
     'function listThem() { return dir.allPersons(); }',
     'x.js|listThem|allPersons'],
    ['app.get(\'/b\', function (req, res) { res.json(peopleByMail(m)); });\n' +
     'function peopleByMail(m) { return eachEntryInRealm(f); }', null],
    ['server.search(\'\', function (req, res, next) {\n' +
     '  for (const p of directoryWindow.walk(r, b)) { res.send(p); }\n});',
     'x.js|(handler)|directoryWindow.walk'],
    // #636: a hook called by its name, and a device register's every
    // device, each found under the function that asks.
    ['app.get(\'/c\', function (req, res) { res.json(mine(u)); });\n' +
     'function mine(u) { return this.store(\'listDeviceEntries\'); }',
     'x.js|mine|listDeviceEntries'],
    ['app.get(\'/d\', function (req, res) { res.json(viaHook(u)); });\n' +
     'function viaHook(u) { return x.store(\'hooked\', u); }\n' +
     'function hooked(u) { return allPersons(); }',
     'x.js|hooked|allPersons']
  ];
  shapes.forEach(function (shape) {
    const got = auditText('x.js', shape[0]).map(function (hit) {
      return hit.key;
    });
    t.check(shape[1] ? got.indexOf(shape[1]) >= 0 : got.length === 0,
            'the detector ' + (shape[1] ? 'finds ' + shape[1]
              : 'passes a walk behind a barrier'), JSON.stringify(got));
  });
  log.debug('Leaving run().');
}

module.exports = {
  name: 'no_full_directory_walk_in_requests',
  describe: 'no request handler walks every person or every device ' +
            'synchronously unless it is a recorded, argued exemption (#616)',
  run: run,
  audit: audit
};

if (require.main === module) {
  audit().hits.forEach(function (hit) {
    console.log(hit.key + '\n    via ' + hit.via.join(' -> '));
  });
}
