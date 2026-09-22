'use strict';
//
// File: no_periodic_timers.js
//
// ===========================================================================
// ANYTHING PERIODIC IS A SCHEDULER JOB — THE DIRECTIVE, ENFORCED (#49,
// 2026-09-22; the plan's T4).
//
// rcbj, 2026-09-21: anything this service does periodically in the
// background is a job on `cluster/scheduler.ts`, and no module starts a
// repeating timer of its own. This test reads the service's own source —
// every `.js` and `.ts` outside the vendored copies, the tests, the embedded
// debugger's build output, the remote PEP (a second container) and the
// Terraform — and finds every REPEATING timer:
//
//   * every `setInterval(`;
//   * every `setTimeout(` inside a named function whose call names that
//     function, or which calls itself anywhere in its body — the
//     `setTimeout` chain, however its callback is spelled (an arrow `again`
//     that calls `this.scheduleSweep()` is the same chain).
//
// Each one found must be on ALLOWED below, keyed by file, function and kind,
// with either the scheduler job it BECOMES (an exception until it moves) or
// the reason it is PERMANENT (the heartbeat and the origin-claim renewal the
// scheduler's own leadership stands on, a retry within one operation, a
// debounce, a start-up timeout the recursion rule catches by accident). A new
// repeating timer fails with a pointer to the directive, and an entry whose
// timer has gone fails too — THE LIST ONLY EVER SHRINKS.
//
// It READS STATEMENTS, NOT LINES (root CLAUDE.md, 80 columns): comments and
// string contents are blanked first, the call's argument list is taken by
// matching its parentheses, and a function's body by matching its braces, so
// a call broken across four lines is one call.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'no_periodic_timers',
  level: process.env.LOG_LEVEL || 'info' });

// What is not the service's own source.
const SKIP = new RegExp('(^|/)(node_modules|tests|coverage|debugger/embedded|' +
                        'common/vendored|node-ldapjs|deploy|xacml-pep|docs|' +
                        '\\.claude|types)(/|$)');

// The scheduler itself is the one place a repeating timer belongs.
const THE_SCHEDULER = 'cluster/scheduler.ts';

// ---------------------------------------------------------------------------
// THE RECORDED EXCEPTIONS. `becomes` is the scheduler job a timer turns into
// when it moves (#49's P5); `permanent` is why it stays a timer.
// ---------------------------------------------------------------------------
const ALLOWED = {
  'cluster/cluster.js|scheduleHeartbeat|timeout': { permanent:
    'the cluster heartbeat: the scheduler\'s own leadership is a lease this ' +
    'renews, so it cannot run on the scheduler' },
  'cluster/cluster.js|attempt|timeout': { permanent:
    'an active-passive standby asking for the service lease before it has ' +
    'restored or bound anything — before any scheduler exists' },
  'persistence/persistence.js|adoptStableOrigin|interval': { permanent:
    'the origin-claim renewal, which the directive names beside the ' +
    'heartbeat' },
  'persistence/persistence_postgres.js|connect|timeout': { permanent:
    'a reconnect retry within one attempt to reach the database' },
  'ldap/ldap_cluster_connections.ts|noteLocalChange|timeout': { permanent:
    'a debounce: one publish for a burst of connection changes' },
  'common/request_worker.ts|start|timeout': { permanent:
    'not periodic: a one-shot start-up timeout, caught by the recursion rule ' +
    'because start() is also a method name it calls' },
  'debugger/debugger_api_process.ts|fork|timeout': { permanent:
    'not periodic: the api child\'s start-up timeout; its restart is a ' +
    'retry with back-off within supervising one child' },
  'cluster/cluster.js|scheduleCacheReport|timeout': { becomes:
    'a per-process job on the front process: the cache snapshot on the ' +
    'membership row (P5)' },
  'ldap/ldap_cluster_connections.ts|armMaintenance|interval': { becomes:
    'a per-process job: the LDAP connection mirror\'s maintenance (P5)' },
  'oauth-oidc/backchannel_logout.ts|scheduleSweep|timeout': { becomes:
    'a cluster job: the back-channel logout delivery sweep (P5)' },
  'persistence/persistence_replication.js|schedule|timeout': { becomes:
    'a per-process job: this process\'s change-log pull (P5)' },
  'persistence/persistence_replication.js|schedulePurge|timeout': { becomes:
    'a cluster job: the change-log trim, ops.change-log-purge (P5)' },
  'saml/sp_metadata.ts|tick|timeout': { becomes:
    'a cluster job: the SAML service-provider metadata refresher (P5)' },
  'ssf/ssf.ts|scheduleSweep|timeout': { becomes:
    'a cluster job: the Shared Signals dead-letter and delivery sweep (P5)' }
};

function walk(dir, out) {
  log.debug('Entering walk().');
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (entry) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(ROOT, full).split(path.sep).join('/');
    if (SKIP.test(rel)) {
      return;
    }
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (/\.(js|ts)$/.test(entry.name) &&
               !/\.d\.ts$/.test(entry.name) &&
               // In an image a `.ts` has its compiled `.js` beside it; the
               // source is the `.ts`, and one timer is one finding.
               !(/\.js$/.test(entry.name) &&
                 fs.existsSync(full.replace(/\.js$/, '.ts')))) {
      out.push(rel);
    }
  });
  log.debug('Leaving walk().');
  return out;
}

// Comments and string contents blanked, same length, so offsets still match.
function blank(src) {
  log.debug('Entering blank().');
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < n && src[i] !== '\n') {
        out += ' ';
        i++;
      }
      continue;
    }
    if (c === '/' && d === '*') {
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  ';
      i += 2;
      continue;
    }
    if (c === '"' || c === '\'' || c === '`') {
      out += c;
      i++;
      while (i < n && src[i] !== c) {
        if (src[i] === '\\') {
          out += '  ';
          i += 2;
          continue;
        }
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += c;
      i++;
      continue;
    }
    out += c;
    i++;
  }
  log.debug('Leaving blank().');
  return out;
}

function matching(s, i, open, close) {
  log.debug('Entering matching().');
  let depth = 0;
  for (let j = i; j < s.length; j++) {
    if (s[j] === open) {
      depth++;
    } else if (s[j] === close) {
      depth--;
      if (depth === 0) {
        log.debug('Leaving matching().');
        return j;
      }
    }
  }
  log.debug('Leaving matching(). Unbalanced.');
  return s.length;
}

const NOT_NAMES = ['if', 'for', 'while', 'switch', 'catch', 'function',
                   'return', 'constructor'];

// Every named function and method, with its body's span.
function functionsOf(s) {
  log.debug('Entering functionsOf().');
  const out = [];
  const re = new RegExp(
    '(?:function\\s+([A-Za-z_$][\\w$]*)\\s*\\(|' +
    '(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:async\\s+)?' +
    'function\\s*\\(|' +
    '^\\s*(?:(?:private|public|static|async|protected)\\s+)*' +
    '([A-Za-z_$][\\w$]*)\\s*\\([^)]*\\)\\s*(?::\\s*[^{;]+)?\\{)', 'gm');
  let m;
  while ((m = re.exec(s))) {
    const name = m[1] || m[2] || m[3];
    if (NOT_NAMES.indexOf(name) >= 0) {
      continue;
    }
    const body = s.indexOf('{', m.index + m[0].length - 1);
    if (body < 0) {
      continue;
    }
    out.push({ name: name, start: body, end: matching(s, body, '{', '}') });
  }
  log.debug('Leaving functionsOf(). ' + out.length + '.');
  return out;
}

function nameRe(name, suffix) {
  log.debug('Entering nameRe().');
  log.debug('Leaving nameRe().');
  return new RegExp('\\b' + name.replace(/\$/g, '\\$') + '\\b' +
                    (suffix || ''));
}

// Every repeating timer in one file: `{ key, line, kind, fn }`.
function repeatingTimersIn(rel, src) {
  log.debug('Entering repeatingTimersIn(). ' + rel);
  const s = blank(src);
  const fns = functionsOf(s);
  const found = [];
  const re = /\bset(Interval|Timeout)\s*\(/g;
  let m;
  while ((m = re.exec(s))) {
    const kind = m[1] === 'Interval' ? 'interval' : 'timeout';
    const open = s.indexOf('(', m.index);
    const call = s.slice(open, matching(s, open, '(', ')') + 1);
    const enclosing = fns.filter(function (f) {
      return f.start < m.index && f.end > m.index;
    }).sort(function (a, b) {
      return (a.end - a.start) - (b.end - b.start);
    });
    const line = src.slice(0, m.index).split('\n').length;
    let fn = null;
    if (kind === 'interval') {
      fn = enclosing[0] ? enclosing[0].name : '(module)';
    } else {
      const byCall = enclosing.filter(function (f) {
        return nameRe(f.name).test(call);
      })[0];
      const byRecursion = enclosing.filter(function (f) {
        return nameRe(f.name, '\\s*\\(').test(s.slice(f.start + 1, f.end));
      })[0];
      const hit = byCall || byRecursion;
      fn = hit ? hit.name : null;
    }
    if (fn) {
      found.push({ key: rel + '|' + fn + '|' + kind, line: line, kind: kind,
                   fn: fn });
    }
  }
  log.debug('Leaving repeatingTimersIn(). ' + found.length + '.');
  return found;
}

function run(t) {
  log.debug('Entering run().');
  const files = walk(ROOT, []);
  t.check(files.length > 200,
          'the service\'s own source was found to read', String(files.length));
  const found = [];
  files.forEach(function (rel) {
    if (rel === THE_SCHEDULER) {
      return;
    }
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    repeatingTimersIn(rel, src).forEach(function (one) {
      found.push(Object.assign({ file: rel }, one));
    });
  });
  const unlisted = found.filter(function (one) {
    return !ALLOWED[one.key];
  });
  t.check(unlisted.length === 0,
          'every repeating timer in the service is a recorded exception — a ' +
          'new one is a scheduler job instead (root CLAUDE.md, *Anything ' +
          'periodic is a scheduler job*; register it with ' +
          'cluster/scheduler.ts)',
          unlisted.map(function (one) {
            return one.file + ':' + one.line + ' ' + one.kind + ' in ' +
                   one.fn + '()';
          }).join('; '));
  const keys = found.map(function (one) { return one.key; });
  const gone = Object.keys(ALLOWED).filter(function (key) {
    return keys.indexOf(key) < 0;
  });
  t.check(gone.length === 0,
          'every recorded exception still exists: THE LIST ONLY SHRINKS — ' +
          'remove the entry of a timer that moved onto the scheduler',
          gone.join('; '));
  t.check(Object.keys(ALLOWED).every(function (key) {
    const row = ALLOWED[key];
    return !!(row.permanent || row.becomes) && !(row.permanent && row.becomes);
  }), 'each exception says either the job it becomes or why it is permanent');
  // THE TWO THAT MOVED IN P1 ARE NOT ON THE LIST, AND NOT IN THE SOURCE.
  ['authn/authn.ts', 'common/pki_revocation.js'].forEach(function (rel) {
    const src = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    t.check(!/\bsetInterval\s*\(/.test(blank(src)),
            rel + ' starts no interval: its periodic work is a scheduler job');
  });
  // THE DETECTOR ITSELF: it must see the shapes it claims to.
  const shapes = [
    ['function a() { setInterval(f, 1); }', 'x.js|a|interval'],
    ['function tick() {\n  setTimeout(\n    tick,\n    5);\n}',
     'x.js|tick|timeout'],
    ['class C {\n  scheduleSweep(): void {\n    const again = () => {\n' +
     '      this.scheduleSweep();\n    };\n    setTimeout(() => ' +
     '{ again(); }, 5);\n  }\n}', 'x.js|scheduleSweep|timeout'],
    ['function once() { setTimeout(done, 5); } // setInterval(x)', null]
  ];
  shapes.forEach(function (shape) {
    const got = repeatingTimersIn('x.js', shape[0]).map(function (one) {
      return one.key;
    });
    t.check(shape[1] ? got.indexOf(shape[1]) >= 0 : got.length === 0,
            'the detector ' + (shape[1] ? 'finds ' + shape[1]
              : 'ignores a one-shot timeout and a timer in a comment'),
            JSON.stringify(got));
  });
  log.debug('Leaving run(). ' + found.length + ' repeating timer(s).');
}

module.exports = {
  name: 'no_periodic_timers',
  describe: 'the directive enforced: every repeating timer outside ' +
            'cluster/scheduler.ts is a recorded exception, and the list only ' +
            'shrinks',
  run: run
};
