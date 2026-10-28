// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_activities.js
//
// ===========================================================================
// STARTED POST-LOGIN ACTIVITIES (#1111, #1123), AND THE PROGRESS THEY LEAVE
// IN /report (#1110).
//
// rcbj: an administrator starts a post-login activity, optionally narrowed
// to groups chosen by search (their union, #1123), from the console and
// /admin-api; a cluster
// scheduler job mails each person still due with reminders every N days up
// to a maximum per person; pause, resume and end; the mail sends the person
// to sign in and carries no credential; the per-person progress is a
// /report source.
//
//   A. IN PROCESS, over doubles and a clock this file moves
//      (`PostLoginActivities` built with its own dependencies): a start's
//      refusals (0490, 0492), the acts and their refusals (0491); a run
//      reading a slice after a key cursor, mailing only the people due, the
//      cursor moving and starting over at the end of the people; the
//      interval and the maximum holding a person back; a refusal by the
//      channel counted (0494); no transport mailing nobody and moving
//      nothing (0495); a paused one mailing nobody; one audit row per
//      started activity per run; `offIn()`; and #1123's groups — a list
//      resolved to DNs, a missing group refused by name (0530), too many
//      refused (0490), the same set in another order refused (0492), the
//      union walked with one cursor and a member of two groups mailed once,
//      and the chooser's slice (twenty, paged, the offset clamped, the
//      chosen left out, the `groups` parameter one name a line).
//   B. IN A CHILD PROCESS with the whole stack on an ephemeral port: the
//      job registered with the scheduler; GET and POST
//      /admin-api/post-login-activities (a start, a second refused, a bad
//      value refused, pause, resume, end, an act on an ended one refused);
//      a run of the job's body through the REAL mail channel (development's
//      capture transport) and the real progress store, `dueFor()` replaced
//      by a list of who is due — the captured message goes to the address on
//      the entry, its one link is the portal's path with no query, and it
//      carries no token; a started activity over two groups of the REAL
//      directory mails each member once (one person in both); the API's
//      group chooser over twenty-five real groups (a page of twenty, the
//      next page, a stale offset clamped, the chosen left out) and its
//      `groups` list refused for a missing group (0530); and over
//      /report-api the `postLoginProgress` source and its presets, the
//      mailed people with their mail counts.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'post_login_activities',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DAY = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// A. In process.
// ---------------------------------------------------------------------------
function doubles(people, groupMembers, otherMembers, groupNames) {
  log.debug("Entering doubles().");
  const PostLogin = require('../common/post_login').PostLogin;
  const helpers = require('../common/helpers');
  const clock = { now: Date.parse('2026-10-01T00:00:00.000Z') };
  const due = {};
  const progress = new Map();
  const real = new PostLogin({ log: helpers.log, credentials: {},
    passkeyPolicy: {}, postLoginPolicy: {}, webauthnPolicy: {},
    progress: progress, now: function () {
      return clock.now;
    } });
  const sent = [];
  const audits = [];
  const mailState = { available: true, refuse: {} };
  const sorted = people.slice().sort();
  const directory = {
    passkeyScanAsync: function (ask) {
      const after = String(ask.after || '');
      const rest = sorted.filter(function (n) {
        return 'uid=' + n > after;
      });
      const slice = rest.slice(0, ask.readLimit);
      slice.forEach(function (n) {
        ask.accept({ id: n, dn: 'uid=' + n, values: [] });
      });
      return Promise.resolve({
        next: slice.length ? 'uid=' + slice[slice.length - 1] : after,
        read: slice.length, done: rest.length <= ask.readLimit });
    },
    // The ldap_server.js shape over two groups, `staff` and `ops`: a list
    // of names, the UNION of their members in key order after a cursor.
    groupMembersAfterAsync: function (names, after, limit) {
      directory.asked.push([].concat(names));
      const union = new Set();
      const groups = [].concat(names).map(function (g) {
        const dn = /^cn=/.test(g) ? g : 'cn=' + g;
        const held = groupsHeld[dn];
        (held || []).forEach(function (n) {
          union.add(n);
        });
        return { asked: g, dn: dn, found: !!held };
      });
      const any = groups.some(function (g) {
        return g.found;
      });
      if (!any) {
        return Promise.resolve({ found: false, dn: groups[0].dn,
          groups: groups, rows: [], next: after, done: true });
      }
      const rest = Array.from(union).sort().filter(function (n) {
        return 'uid=' + n > String(after || '');
      });
      const slice = rest.slice(0, limit);
      return Promise.resolve({ found: true, dn: groups[0].dn,
        groups: groups,
        rows: slice.map(function (n) {
          return { id: n, dn: 'uid=' + n };
        }),
        next: slice.length ? 'uid=' + slice[slice.length - 1] : after,
        done: rest.length <= limit });
    },
    groupsNamed: function (names) {
      return [].concat(names).map(function (g) {
        const dn = /^cn=/.test(g) ? g : 'cn=' + g;
        return { asked: g, dn: dn, cn: dn.slice(3),
                 found: !!groupsHeld[dn] };
      });
    },
    // The chooser's page over `groupNames`, by ldap_server.js's rule.
    groupChoices: function (wanted, from, limit, exclude) {
      const left = (exclude || []).map(function (dn) {
        return dn.toLowerCase();
      });
      const matched = groupNames.filter(function (cn) {
        return left.indexOf('cn=' + cn) < 0 &&
               cn.indexOf(String(wanted || '').toLowerCase()) >= 0;
      }).sort();
      let at = parseInt(String(from || ''), 10);
      if (!isFinite(at) || at < 0 || at >= matched.length) {
        at = 0;
      }
      return { total: groupNames.length, matched: matched.length, from: at,
               rows: matched.slice(at, at + limit).map(function (cn) {
                 return { dn: 'cn=' + cn, cn: cn };
               }) };
    },
    asked: []
  };
  const groupsHeld = { 'cn=staff': groupMembers || [],
                       'cn=ops': otherMembers || [] };
  (groupNames || []).forEach(function (cn) {
    if (!groupsHeld['cn=' + cn]) {
      groupsHeld['cn=' + cn] = [];
    }
  });
  groupNames = groupNames || ['ops', 'staff'];
  const postLogin = {
    dueFor: function (u) {
      return due[u] ? Object.assign({ activity: 'pqc-passkey-migration',
        role: 'primary', reason: 'classical', required: false,
        enforceable: true, method: 'upgrade', fallback: 'none',
        snoozeDays: 7, graceDays: 30, invitedAt: 0, deadline: 0,
        profile: 'default' }, due[u]) : null;
    },
    stateOf: function (u, a) {
      return real.stateOf(u, a);
    },
    noteMailed: function (u, d, c) {
      return real.noteMailed(u, d, c);
    }
  };
  const Activities = require('../common/post_login_activities')
    .PostLoginActivities;
  let ids = 0;
  const activities = new Activities({
    log: helpers.log, errorCodes: require('../common/error_codes'),
    audit: { audit: function (row) {
      audits.push(row);
    } },
    realms: { currentId: function () {
      return 'default';
    } },
    started: new Map(), runs: new Map(),
    directory: function () {
      return directory;
    },
    postLogin: function () {
      return postLogin;
    },
    mailUses: function () {
      return { postLoginReminder: function (u, facts) {
        if (mailState.refuse[u]) {
          return { ok: true, queued: [], refused: [{ code: 'STS-MAIL-0011' }],
                   duplicates: [] };
        }
        sent.push({ to: u, facts: facts });
        return { ok: true, queued: [{ id: 'm' + sent.length }], refused: [],
                 duplicates: [] };
      } };
    },
    mail: function () {
      return { available: function () {
        return mailState.available;
      } };
    },
    scheduler: function () {
      return { job: function () {
        return null;
      }, register: function () {
        return true;
      } };
    },
    randomId: function () {
      ids += 1;
      return 'id' + ids;
    },
    now: function () {
      return clock.now;
    }
  });
  log.debug("Leaving doubles().");
  return { activities: activities, clock: clock, due: due, sent: sent,
           audits: audits, mailState: mailState, real: real,
           directory: directory };
}

async function inProcess(t) {
  log.debug("Entering inProcess().");
  const d = doubles(['ann', 'ben', 'cat', 'dan', 'eli'], ['ben', 'dan'],
                    ['dan', 'eli']);
  const c = d.activities;
  const ctx = { actor: 'admin', via: 'test' };

  // Refusals of a start.
  let r = await c.act({ action: 'start', activity: 'nope' }, ctx);
  t.equal(r.ok === false && r.errorCode, 'STS-AUTHN-0490',
    'an unknown activity is refused');
  r = await c.act({ action: 'start', intervalDays: 0 }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0490', 'an interval of 0 is refused');
  r = await c.act({ action: 'start', maxMails: 21 }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0490', 'a maximum past 20 is refused');
  r = await c.act({ action: 'start', perRun: 1.5 }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0490', 'a fraction is refused');
  r = await c.act({ action: 'start', groups: ['staff', 'nobody-here'] },
                  ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0530', 'an unknown group is refused');
  t.check(r.errors && r.errors.length === 1 &&
          /nobody-here/.test(r.errors[0]), 'by name, and only it',
          JSON.stringify(r));
  const many = [];
  for (let i = 0; i <= 50; i++) {
    many.push('g' + i);
  }
  r = await c.act({ action: 'start', groups: many }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0490', 'more than fifty groups refused');
  r = await c.act({ action: 'frobnicate', id: 'x' }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0491', 'an unknown action is refused');

  // A start, and the second one refused.
  r = await c.act({ action: 'start', activity: 'pqc-passkey-migration',
                    intervalDays: 7, maxMails: 2, perRun: 2 }, ctx);
  t.equal(r.ok, true, 'an activity starts', JSON.stringify(r));
  const id = r.started && r.started.id;
  t.equal(r.started && r.started.state, 'running', 'running');
  t.equal(d.audits.length && d.audits[d.audits.length - 1].action,
    'admin.post-login-activity.change', 'the start is audited');
  r = await c.act({ action: 'start' }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0492',
    'a second for the same people is refused');
  t.equal(c.offIn('default'), '', 'the job is on with one running');

  // Run 1: two people read, of whom ben is due.
  d.due.ben = {};
  d.due.dan = {};
  d.due.eli = {};
  const before = d.audits.length;
  let out = await c.runAsync({});
  let one = (out.started || [])[0] || {};
  t.equal(one.read, 2, 'a run reads one slice (perRun)');
  t.equal(one.mailed, 1, 'and mails only the person due');
  t.equal(one.notDue, 1, 'the other is not due');
  t.equal(d.sent.map(function (s) {
    return s.to;
  }).join(','), 'ben', 'ben was mailed');
  t.equal(d.audits.length - before, 1, 'one audit row for the run');
  t.equal(d.audits[d.audits.length - 1].action,
    'authn.post-login.activity-run', 'the run row');
  t.check(!JSON.stringify(d.sent[0].facts).match(/token|code|secret/i),
    'the reminder is asked with no credential', JSON.stringify(d.sent[0]));
  const benRow = d.real.stateOf('ben');
  t.equal(benRow.mails, 1, 'ben\'s progress row counts the mail');
  t.equal(benRow.mailedBy, id, 'and names the started activity');
  t.equal(benRow.invitedAt, 0, 'and a mail is not an invitation');

  // Run 2 and 3: the rest, then the pass ends.
  out = await c.runAsync({});
  one = out.started[0];
  t.equal(one.mailed, 1, 'run two mails dan');
  out = await c.runAsync({});
  one = out.started[0];
  t.equal(one.mailed, 1, 'run three mails eli');
  t.equal(one.passEnded, true, 'and the pass ends at the last person');
  t.equal(c.view().started[0].run.passes, 1, 'one pass is counted');
  t.equal(c.view().started[0].run.cursor, '',
    'the cursor starts over');

  // The next pass, inside the interval: everybody held back.
  out = await c.runAsync({});
  one = out.started[0];
  t.equal(one.mailed, 0, 'inside the interval nobody is mailed again');
  t.equal(one.heldBack, 1, 'ben is held back');

  // Past the interval: mailed again, up to the maximum of two.
  d.clock.now += 8 * DAY;
  await c.runAsync({});
  await c.runAsync({});
  await c.runAsync({});
  t.equal(d.real.stateOf('ben').mails, 2, 'a reminder after the interval');
  d.clock.now += 8 * DAY;
  await c.runAsync({});
  out = await c.runAsync({});
  t.equal(d.real.stateOf('ben').mails, 2,
    'never past the maximum (' + JSON.stringify(out.started[0]) + ')');

  // A refusal by the channel is counted, and audited with 0494.
  d.clock.now += 30 * DAY;
  const r2 = await c.act({ action: 'end', id: id }, ctx);
  t.equal(r2.ok && r2.started.state, 'ended', 'end ends it');
  r = await c.act({ action: 'pause', id: id }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0491', 'an ended one cannot pause');
  r = await c.act({ action: 'start', maxMails: 5, perRun: 10 }, ctx);
  const id2 = r.started && r.started.id;
  t.check(r.ok && id2 && id2 !== id, 'a new one once the first ended');
  d.mailState.refuse.dan = true;
  out = await c.runAsync({});
  one = out.started[0];
  t.equal(one.refused, 1, 'a refusal by the channel is counted');
  t.equal(d.audits[d.audits.length - 1].errorCode, 'STS-AUTHN-0494',
    'and the run row carries 0494');
  t.equal(d.real.stateOf('ben').mails, 1,
    'a new started activity counts its own mails');

  // Pause: nobody mailed; no transport: nobody mailed and nothing moved.
  r = c.move('pause', id2, ctx);
  t.equal(r.ok && r.started.state, 'paused', 'pause pauses');
  t.check(c.offIn('default') !== '', 'the job is off with none running');
  out = await c.runAsync({});
  t.equal(out.summary, 'No post-login activity is running in this realm.',
    'a paused one mails nobody');
  r = c.move('resume', id2, ctx);
  t.equal(r.ok && r.started.state, 'running', 'resume resumes');
  r = c.move('resume', id2, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0491', 'a running one cannot resume');
  d.mailState.available = false;
  const sentBefore = d.sent.length;
  out = await c.runAsync({});
  t.equal(out.errorCode, 'STS-AUTHN-0495', 'no transport is 0495');
  t.equal(d.sent.length, sentBefore, 'and nobody is mailed');
  d.mailState.available = true;
  c.move('end', id2, ctx);

  // Groups (#1123): one group walks its members only.
  r = await c.act({ action: 'start', groups: ['staff'], perRun: 10 }, ctx);
  t.equal(r.ok && r.started.groups.join(';'), 'cn=staff',
    'a started activity keeps its group\'s DN');
  const gid = r.started && r.started.id;
  d.clock.now += 30 * DAY;
  d.sent.length = 0;
  d.mailState.refuse = {};
  await c.runAsync({});
  t.equal(d.sent.map(function (s) {
    return s.to;
  }).sort().join(','), 'ben,dan',
    'only the group\'s due members are mailed (eli is not one)');
  c.move('end', gid, ctx);

  // Two groups: their UNION, dan (in both) read and mailed once.
  r = await c.act({ action: 'start', groups: 'staff\ncn=ops', perRun: 2 },
                  ctx);
  t.equal(r.ok && r.started.groups.join(';'), 'cn=staff;cn=ops',
    'a list given one name a line is resolved to DNs, in order');
  const uid = r.started && r.started.id;
  r = await c.act({ action: 'start', groups: ['ops', 'staff'] }, ctx);
  t.equal(r.errorCode, 'STS-AUTHN-0492',
    'the same groups in another order are the same people');
  r = await c.act({ action: 'start', groups: ['ops'] }, ctx);
  t.check(r.ok, 'another set of groups is other people', JSON.stringify(r));
  c.move('end', r.started.id, ctx);
  d.clock.now += 30 * DAY;
  d.sent.length = 0;
  d.directory.asked.length = 0;
  out = await c.runAsync({});
  t.equal(out.started[0].read, 2, 'a slice of the union (perRun 2)');
  out = await c.runAsync({});
  t.equal(out.started[0].passEnded, true, 'the union ends a pass');
  t.equal(d.sent.map(function (s) {
    return s.to;
  }).sort().join(','), 'ben,dan,eli',
    'each member of either group mailed once; dan, in both, once');
  t.equal(JSON.stringify(d.directory.asked[0]), '["cn=staff","cn=ops"]',
    'one walk asks both groups together');
  t.equal(c.view().started.filter(function (one) {
    return one.id === uid;
  })[0].run.read, 3, 'three people read in the pass, not four');
  c.move('end', uid, ctx);
  log.debug("Leaving inProcess().");
}

// The chooser's slice, from the page's query (#1123), over twenty-five
// groups: `chooserPane()`'s twenty, the next page, a stale offset clamped,
// the chosen left out and resolved.
async function chooser(t) {
  log.debug("Entering chooser().");
  const names = [];
  for (let i = 0; i < 25; i++) {
    names.push('team-' + (i < 10 ? '0' : '') + i);
  }
  const d = doubles(['ann'], [], [], names.concat(['ops', 'staff']));
  const c = d.activities;
  let g = c.view({}).groupChooser;
  t.equal(g.pane.matched, 27, 'every group matches no search');
  t.equal(g.pane.shown.length, 20, 'twenty to a page');
  g = c.view({ groupq: 'team' }).groupChooser;
  t.equal(g.pane.matched, 25, 'the search narrows');
  t.equal(g.search, 'team', 'and is echoed');
  g = c.view({ groupq: 'team', groupfrom: '20' }).groupChooser;
  t.equal(g.pane.from === 20 && g.pane.shown.length, 5,
    'the next page holds the last five');
  g = c.view({ groupq: 'team', groupfrom: '400' }).groupChooser;
  t.equal(g.pane.from, 0, 'a stale offset is clamped to the first page');
  g = c.view({ groupq: 'team', groups: 'team-03\ncn=team-07\nnope' })
    .groupChooser;
  t.equal(g.pane.matched, 23, 'the chosen are left out of the results');
  t.equal(g.chosen.map(function (one) {
    return one.dn + ':' + one.found;
  }).join(','), 'cn=team-03:true,cn=team-07:true,cn=nope:false',
    'the list is resolved, a missing group marked');
  t.equal(require('../common/post_login_activities')
    .groupNamesOf(['a\r\n b', '', 'c']).join('|'), 'a|b|c',
    'groupNamesOf splits lines and drops empties');
  log.debug("Leaving chooser().");
}

// ---------------------------------------------------------------------------
// B. In a child process. Runs there, stringified, so it uses nothing from
// this file's scope and — code in a `node -e` child — is exempt from the
// Entering/Leaving rule (root CLAUDE.md, *Code style*).
// ---------------------------------------------------------------------------
function childMain() {
  const ROOT_DIR = process.env.PLA_ROOT;
  const OUT = process.env.PLA_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        headers.authorization = 'Bearer ' + token;
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }
  const brief = function (r) {
    return r.status + ' ' + (r.text || '').slice(0, 300);
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const applications = require(ROOT_DIR + '/common/applications');
    const scheduler = require(ROOT_DIR + '/cluster/scheduler');
    const mail = require(ROOT_DIR + '/common/mail');
    const postLogin = require(ROOT_DIR + '/common/post_login');
    const activities = require(ROOT_DIR + '/common/post_login_activities');
    const stamp = String(process.pid);
    const A = 'pla-a-' + stamp;
    const B = 'pla-b-' + stamp;
    const C = 'pla-c-' + stamp;
    const ADMIN = 'pla-admin-' + stamp;
    const GROUP = 'pla-group-' + stamp;
    const OTHER = 'pla-other-' + stamp;
    const TEAM = 'pla-team-' + stamp + '-';
    const CLIENT = 'pla-client-' + stamp;
    const BASE_REALM = realms.DEFAULT_REALM;
    const inDefault = function (fn) {
      return realms.run(BASE_REALM, fn);
    };

    note(!!scheduler.job('post-login.activity-mail'),
         'B1. the job post-login.activity-mail is registered');
    [A, B, C].forEach(function (n) {
      ldap.createUser(n, { invent: false,
        attributes: { mail: n + '@example.test' } });
    });
    ldap.createUser(ADMIN, { invent: false });
    ldap.createGroup(GROUP, { actor: 'test' });
    ldap.addGroupMember(GROUP, B, { actor: 'test' });
    // #1123: a second group sharing B with GROUP, and C of its own.
    ldap.createGroup(OTHER, { actor: 'test' });
    ldap.addGroupMember(OTHER, B, { actor: 'test' });
    ldap.addGroupMember(OTHER, C, { actor: 'test' });
    // Twenty-five groups for the chooser's pages.
    for (let i = 0; i < 25; i++) {
      ldap.createGroup(TEAM + (i < 10 ? '0' : '') + i, { actor: 'test' });
    }
    ldap.addGroupMember('report-admins', ADMIN, { actor: 'test' });
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthTokenEndpointAuthMethod: ['client_secret_basic'],
                oauthAllowedScope: ['openid', 'report:use',
                                    'report:admin'] } });

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const admin = await inDefault(function () {
      return oauth2.accessTokenAsync(base, {
        audience: base + '/admin-api', scope: 'admin:read admin:write',
        client_id: 'sts-management-api', sub: 'sts-management-api' });
    });
    const reporter = await oauth2.accessTokenAsync(base, {
      audience: base + '/report-api', client_id: CLIENT, username: ADMIN,
      sub: String(helpers.subjectForName(ADMIN) || ''),
      scope: 'report:admin' });

    // --- the API -----------------------------------------------------------
    let r = await call(port, 'GET', '/admin-api/post-login-activities', admin);
    note(r.status === 200 && r.json && Array.isArray(r.json.started) &&
         r.json.job === 'post-login.activity-mail' &&
         r.json.activities.indexOf('pqc-passkey-migration') >= 0,
         'B2. GET /admin-api/post-login-activities answers the view',
         brief(r));
    r = await call(port, 'POST', '/admin-api/post-login-activities/start',
                   admin, { activity: 'pqc-passkey-migration',
                            intervalDays: 0 });
    note(r.status === 400, 'B3. an interval of 0 is refused 400', brief(r));
    r = await call(port, 'POST', '/admin-api/post-login-activities/start',
                   admin, { activity: 'pqc-passkey-migration',
                            intervalDays: 3, maxMails: 2, perRun: 500 });
    const id = r.json && r.json.started && r.json.started.id;
    note(r.status === 200 && !!id && r.json.started.state === 'running',
         'B4. a post-login activity starts over the API', brief(r));
    r = await call(port, 'POST', '/admin-api/post-login-activities/start',
                   admin, { activity: 'pqc-passkey-migration' });
    note(r.status === 400, 'B5. a second for the same people is refused',
         brief(r));
    r = await call(port, 'POST', '/admin-api/post-login-activities/pause',
                   admin, { id: id });
    note(r.status === 200 && r.json.started.state === 'paused',
         'B6. pause', brief(r));
    r = await call(port, 'POST', '/admin-api/post-login-activities/resume',
                   admin, { id: id });
    note(r.status === 200 && r.json.started.state === 'running',
         'B7. resume', brief(r));

    // --- the group chooser over the API (#1123) ---------------------------
    const pane = async function (query) {
      const got = await call(port, 'GET', '/admin-api/post-login-activities' +
                             query, admin);
      return got.json && got.json.groupChooser;
    };
    let g = await pane('?groupq=' + encodeURIComponent(TEAM));
    note(g && g.pane.matched === 25 && g.pane.shown.length === 20 &&
         g.pane.from === 0, 'B7a. the search matches 25, twenty shown',
         JSON.stringify(g && g.pane && { m: g.pane.matched,
                                         n: g.pane.shown.length }));
    g = await pane('?groupq=' + encodeURIComponent(TEAM) + '&groupfrom=20');
    note(g && g.pane.from === 20 && g.pane.shown.length === 5,
         'B7b. the next page holds the last five');
    g = await pane('?groupq=' + encodeURIComponent(TEAM) + '&groupfrom=900');
    note(g && g.pane.from === 0, 'B7c. a stale offset is clamped');
    g = await pane('?groupq=' + encodeURIComponent(TEAM) + '&groups=' +
                   encodeURIComponent(TEAM + '00\n' + TEAM + '01'));
    note(g && g.pane.matched === 23 && g.chosen.length === 2 &&
         g.chosen.every(function (one) {
           return one.found && /^cn=/i.test(one.dn);
         }), 'B7d. the chosen are resolved and left out of the results',
         JSON.stringify(g && g.chosen));

    // --- the job's body, through the real channel and store --------------
    const dueNow = {};
    dueNow[A] = true;
    dueNow[B] = true;
    const realDue = postLogin.dueFor;
    postLogin.dueFor = function (u) {
      return dueNow[u] ? { activity: 'pqc-passkey-migration', role: 'primary',
        reason: 'classical', required: false, enforceable: true,
        method: 'upgrade', fallback: 'none', snoozeDays: 7, graceDays: 30,
        invitedAt: 0, deadline: 0, profile: 'default' } : null;
    };
    try {
      const ran = await inDefault(function () {
        return activities.runAsync({ runId: 'test' });
      });
      note(ran && Array.isArray(ran.started) &&
           ran.started[0].mailed === 2,
           'B8. a run mails the two people due', JSON.stringify(ran));
      const rows = inDefault(function () {
        return mail.list({ q: 'post-login-reminder' });
      });
      const toA = rows.filter(function (m) {
        return m.username === A;
      })[0];
      const toC = rows.filter(function (m) {
        return m.username === C;
      })[0];
      note(!!toA && toA.to === A + '@example.test' && !toC,
           'B9. to the address on the entry, and not to somebody not due',
           JSON.stringify(rows.map(function (m) {
             return m.username + ' ' + m.to;
           })));
      // The process that queued it attempts it at once, asynchronously:
      // the captured body is there once the attempt has finished.
      let body = null;
      for (let i = 0; toA && i < 40; i++) {
        body = inDefault(function () {
          return mail.message(toA.id);
        });
        if (body && body.state === 'captured') {
          break;
        }
        await new Promise(function (r) { setTimeout(r, 50); });
      }
      const links = body ? String(body.text || '')
        .match(/https?:\/\/[^\s]+/g) || [] : [];
      note(links.length === 1 && /\/portal$/.test(links[0]),
           'B10. its one link is the portal\'s path, with no query',
           JSON.stringify(links));
      note(!!body && !/token|code=|secret/i.test(String(body.html || '') +
                                                String(body.text || '')),
           'B11. and it carries no credential');
      const row = inDefault(function () {
        return postLogin.stateOf(A);
      });
      note(row.mails === 1 && row.mailedBy === id && !row.invitedAt,
           'B12. the progress row records the mail, not an invitation',
           JSON.stringify(row));
      // Two groups (#1123): end the realm's, start one over both.
      await call(port, 'POST', '/admin-api/post-login-activities/end', admin,
                 { id: id });
      r = await call(port, 'POST', '/admin-api/post-login-activities/end',
                     admin, { id: id });
      note(r.status === 400, 'B13. an ended one cannot end again',
           brief(r));
      r = await call(port, 'POST', '/admin-api/post-login-activities/start',
                     admin, { groups: [GROUP, 'pla-none-' + stamp],
                              intervalDays: 1 });
      note(r.status === 400 && r.json &&
           r.json.errorCode === 'STS-AUTHN-0530' &&
           /pla-none-/.test(JSON.stringify(r.json.errors)),
           'B14a. a group this realm does not have is refused (0530)',
           brief(r));
      r = await call(port, 'POST', '/admin-api/post-login-activities/start',
                     admin, { groups: [GROUP, OTHER], intervalDays: 1 });
      const gid = r.json && r.json.started && r.json.started.id;
      note(r.status === 200 && !!gid &&
           r.json.started.groups.length === 2,
           'B14. a post-login activity over two groups starts', brief(r));
      const before = inDefault(function () {
        return mail.list({ q: 'post-login-reminder' }).length;
      });
      // A and B are inside the interval of the first one; forget their
      // rows so only the groups' walk decides. C is due now too: B is in
      // both groups, C in one, A in neither.
      inDefault(function () {
        [A, B].forEach(function (n) {
          postLogin.forget(n);
        });
      });
      dueNow[C] = true;
      const ranG = await inDefault(function () {
        return activities.runAsync({ runId: 'test-group' });
      });
      const after = inDefault(function () {
        return mail.list({ q: 'post-login-reminder' });
      });
      note(ranG.started[0].mailed === 2 && ranG.started[0].read === 2 &&
           after.length === before + 2 && after.filter(function (m) {
             return m.username === B;
           }).length === 2 && after.filter(function (m) {
             return m.username === C;
           }).length === 1 && after.filter(function (m) {
             return m.username === A;
           }).length === 1,
           'B15. the union of two groups, B (in both) mailed once, A not',
           JSON.stringify(ranG));
    } finally {
      postLogin.dueFor = realDue;
    }

    // --- the report -------------------------------------------------------
    r = await call(port, 'GET', '/report-api/catalog/postLoginProgress',
                   reporter);
    note(r.status === 200 && r.json && r.json.source &&
         (r.json.source.presets || []).length === 3,
         'B16. /report-api publishes the source and its three presets',
         brief(r));
    r = await call(port, 'POST', '/report-api/queries', reporter, {
      source: 'postLoginProgress',
      select: ['username', 'mailedBy', 'mails', 'progress'],
      where: { op: 'eq', field: 'username', value: B },
      limit: 10, format: 'json', mode: 'sync' });
    const got = r.json && Array.isArray(r.json.rows) ? r.json.rows : [];
    note(r.status === 200 && got.length === 1 && got[0].mails === 1 &&
         got[0].progress === 'mailed',
         'B17. the report reads the started activity\'s mail on the ' +
         'person\'s row',
         brief(r));
    const preset = r.status === 200 ? await call(port, 'POST',
      '/report-api/queries', reporter,
      Object.assign({}, (await call(port, 'GET',
        '/report-api/catalog/postLoginProgress', reporter))
        .json.source.presets[0].document, { mode: 'sync' })) : null;
    note(!!preset && preset.status === 200 &&
         Array.isArray(preset.json && preset.json.rows),
         'B18. the progress-by-activity preset runs over the API',
         preset ? brief(preset) : 'not run');

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function overHttp(t) {
  log.debug("Entering overHttp().");
  const out = path.join(os.tmpdir(), 'pla-' + process.pid + '-' +
                        Date.now() + '.json');
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
                                  PLA_ROOT: ROOT, PLA_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in overHttp(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in overHttp(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving overHttp().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving overHttp().");
}

async function run(t) {
  log.debug("Entering run().");
  await inProcess(t);
  await chooser(t);
  await overHttp(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'post_login_activities',
  describe: 'started post-login activities (#1111, #1123): the start, the ' +
            'groups, their union and the chooser, the acts, the ' +
            'job\'s slices, interval and maximum, the real channel\'s ' +
            'message with one sign-in link and no credential, the API, and ' +
            'the progress it leaves in /report (#1110)',
  run: run
};
