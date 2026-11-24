// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_started_kinds.js
//
// ===========================================================================
// STARTED ACTIVITIES, THEIR MAIL AND THEIR REPORT, PER ACTIVITY (#2009 P4,
// design X6).
//
// Until P4 an administrator could start the passkey migration alone, its
// reminder said "register a post-quantum passkey" whatever was due, and the
// report's activity filter was a copy of a one-value list. In process:
//
//   A. The table: every activity startable, each with its own reminder
//      template (the passkey migration's keeps `post-login-reminder`), each
//      template a built-in notification; `switchedOnIn()` reads each
//      activity's own policy switch; and the table is a leaf that requires
//      nothing of this service.
//   B. Started activities over doubles, for `pqc-mail-encryption` and
//      `piv-reissue` each: a start for a group, a run asking `dueFor()` FOR
//      THAT ACTIVITY and mailing its people with the activity on the
//      reminder's facts, a pause mailing nobody, a resume, an end; a second
//      for the same activity and group refused (0492) while the other
//      activities start beside it; and the regression: a start naming no
//      activity is the passkey migration and its reminder is asked as
//      before.
//   C. The mail use: `postLoginReminder()` sends each activity's own
//      template, the passkey migration's (and a reminder naming none) the
//      template it always sent, the link and dedup key unchanged.
//   D. The templates: each new one passes the rules a realm's wording is
//      held to, says what its activity asks, and reads its regional
//      overlays (es-ES, fr-CA, zh-Hant-HK) where they differ.
//   E. The report: the activity field enumerates the table, a filter on
//      each activity validates, the per-activity presets validate, the
//      first preset is unchanged; a row's fallback deadline is its
//      activity's own `graceDays` (`timingOf()`), and the passkey row's is
//      what it was.
//   F. The console page: each activity named in the reader's words, with
//      its id beside it on the list and what it asks under the chooser.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'post_login_started_kinds',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DAY = 24 * 60 * 60 * 1000;
const PASSKEY = 'pqc-passkey-migration';
const MAIL = 'pqc-mail-encryption';
const PIV = 'piv-reissue';

// ---------------------------------------------------------------------------
// A. The table.
// ---------------------------------------------------------------------------
function tableChecks(t) {
  log.debug("Entering tableChecks().");
  const Kinds = require('../common/post_login_kinds');
  const MailTemplates = require('../common/mail_templates');
  t.equal(Kinds.startableIds().join(','), [PASSKEY, MAIL, PIV].join(','),
    'A. every activity may be started, in the table\'s order');
  t.equal(Kinds.templateOf(PASSKEY), 'post-login-reminder',
    'the passkey migration keeps the reminder template it always had');
  t.equal(Kinds.templateOf(MAIL), 'post-login-reminder-mail-encryption',
    'the mail-encryption migration has its own');
  t.equal(Kinds.templateOf(PIV), 'post-login-reminder-piv-reissue',
    'and so has the PIV re-issue');
  t.equal(Kinds.templateOf(''), 'post-login-reminder',
    'a reminder naming no activity is the passkey migration\'s');
  Kinds.templates().forEach(function (id) {
    const spec = MailTemplates.builtIn(id);
    t.check(!!spec && spec.category === 'notification' &&
            spec.links.join(',') === 'signin',
      id + ' is a built-in notification with one link, signin');
  });
  t.check(Kinds.switchedOnIn(PASSKEY, { enabled: true }) &&
          !Kinds.switchedOnIn(MAIL, { enabled: true }) &&
          Kinds.switchedOnIn(MAIL, { mailEnabled: true }) &&
          Kinds.switchedOnIn(PIV, { pivEnabled: true }) &&
          !Kinds.switchedOnIn(PIV, { mailEnabled: true }) &&
          !Kinds.switchedOnIn('nope', { enabled: true }),
    'switchedOnIn() reads each activity\'s own switch');
  const source = fs.readFileSync(path.join(ROOT, 'common',
    'post_login_kinds.ts'), 'utf8');
  const requires = (source.match(/require\('[^']+'\)/g) || []);
  t.equal(requires.join(','), "require('bunyan')",
    'the table requires nothing of this service (the report reads it)');
  log.debug("Leaving tableChecks().");
}

// ---------------------------------------------------------------------------
// B. Started activities over doubles.
// ---------------------------------------------------------------------------
function doubles() {
  log.debug("Entering doubles().");
  const PostLogin = require('../common/post_login').PostLogin;
  const helpers = require('../common/helpers');
  const clock = { now: Date.parse('2026-11-23T00:00:00.000Z') };
  const real = new PostLogin({ log: helpers.log, credentials: {},
    passkeyPolicy: {}, postLoginPolicy: {}, webauthnPolicy: {},
    progress: new Map(), now: function () {
      return clock.now;
    } });
  // Who is due, per activity.
  const due = {};
  due[PASSKEY] = {};
  due[MAIL] = {};
  due[PIV] = {};
  const asked = [];
  const sent = [];
  const members = { 'cn=staff': ['ann', 'ben'], 'cn=ops': ['cat'] };
  const directory = {
    groupsNamed: function (names) {
      return [].concat(names).map(function (g) {
        const dn = /^cn=/.test(g) ? g : 'cn=' + g;
        return { asked: g, dn: dn, cn: dn.slice(3), found: !!members[dn] };
      });
    },
    groupMembersAfterAsync: function (names, after) {
      const union = new Set();
      const groups = [].concat(names).map(function (dn) {
        (members[dn] || []).forEach(function (n) {
          union.add(n);
        });
        return { asked: dn, dn: dn, found: !!members[dn] };
      });
      const rows = Array.from(union).sort().filter(function (n) {
        return 'uid=' + n > String(after || '');
      });
      return Promise.resolve({ found: true, groups: groups,
        rows: rows.map(function (n) {
          return { id: n, dn: 'uid=' + n };
        }),
        next: rows.length ? 'uid=' + rows[rows.length - 1] : after,
        done: true });
    },
    passkeyScanAsync: function () {
      return Promise.resolve({ next: '', done: true });
    }
  };
  const postLogin = {
    dueFor: function (u, application, activity) {
      asked.push(activity);
      return due[activity] && due[activity][u]
        ? { activity: activity, reason: 'classical', required: false,
            enforceable: true, method: '', fallback: 'none', snoozeDays: 7,
            graceDays: 30, invitedAt: 0, deadline: 0, profile: 'default' }
        : null;
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
  let n = 0;
  const activities = new Activities({
    log: helpers.log, errorCodes: require('../common/error_codes'),
    audit: { audit: function () {
      return true;
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
        sent.push({ to: u, facts: facts });
        return { ok: true, queued: [{ id: 'm' + sent.length }], refused: [],
                 duplicates: [] };
      } };
    },
    mail: function () {
      return { available: function () {
        return true;
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
      n += 1;
      return 'k' + n;
    },
    now: function () {
      return clock.now;
    }
  });
  log.debug("Leaving doubles().");
  return { activities: activities, due: due, sent: sent, asked: asked,
           clock: clock, real: real };
}

async function startedChecks(t) {
  log.debug("Entering startedChecks().");
  const errorCodes = require('../common/error_codes');
  const ctx = { actor: 'admin', via: 'test' };
  for (const activity of [MAIL, PIV]) {
    const d = doubles();
    const c = d.activities;
    d.due[activity].ann = true;
    d.due[activity].ben = true;
    // Due the passkey migration too: it must not be what this one mails.
    d.due[PASSKEY].ann = true;
    let r = await c.act({ action: 'start', activity: activity,
                          groups: ['staff'], intervalDays: 7, maxMails: 2,
                          perRun: 100 }, ctx);
    t.check(r.ok === true && r.started.activity === activity &&
            r.started.groups.join(',') === 'cn=staff',
      'B. ' + activity + ' starts for a group', JSON.stringify(r));
    const id = r.started && r.started.id;
    r = await c.act({ action: 'start', activity: activity,
                      groups: ['cn=staff'] }, ctx);
    t.equal(errorCodes.codeOf(r), 'STS-AUTHN-0492',
      'a second for the same activity and group is refused');
    r = await c.act({ action: 'start', activity: PASSKEY,
                      groups: ['staff'] }, ctx);
    t.equal(r.ok, true,
      'the passkey migration starts beside it for the same group');
    const passkeyId = r.started && r.started.id;
    c.move('pause', passkeyId, ctx);
    let out = await c.runAsync({});
    const mine = (out.started || []).filter(function (one) {
      return one.started === id;
    })[0] || {};
    t.equal(mine.mailed, 2, 'a run mails the two members due it');
    t.check(d.asked.length > 0 && d.asked.every(function (a) {
      return a === activity;
    }), 'and asks dueFor() for THIS activity only',
      JSON.stringify(d.asked));
    t.check(d.sent.length === 2 && d.sent.every(function (s) {
      return s.facts.activity === activity && s.facts.started === id;
    }), 'each reminder is asked with the activity, for its own message',
      JSON.stringify(d.sent));
    t.equal(d.real.stateOf('ann', activity).mailedBy, id,
      'the progress row under the activity names the started activity');
    t.equal(d.real.stateOf('ann', PASSKEY).mails || 0, 0,
      'and the passkey migration\'s row is untouched');
    t.equal(c.move('pause', id, ctx).ok, true, 'it pauses');
    d.clock.now += 8 * DAY;
    const before = d.sent.length;
    out = await c.runAsync({});
    t.equal(d.sent.length, before, 'paused, it mails nobody');
    t.equal(c.move('resume', id, ctx).started.state, 'running',
      'it resumes');
    t.equal(c.move('end', id, ctx).started.state, 'ended', 'it ends');
    t.equal(errorCodes.codeOf(c.move('pause', id, ctx)), 'STS-AUTHN-0491',
      'an ended one does not pause');
    t.check(c.runningOf(activity).length === 0 &&
            c.list().some(function (one) {
              return one.id === id && one.activity === activity;
            }), 'ended, it asks nobody at sign-in and is still listed');
  }
  // THE REGRESSION: a start naming no activity, and its reminder.
  const d = doubles();
  d.due[PASSKEY].cat = true;
  const r = await d.activities.act({ action: 'start', groups: ['ops'] },
                                   { actor: 'admin', via: 'test' });
  t.equal(r.ok && r.started.activity, PASSKEY,
    'a start naming no activity is still the passkey migration');
  await d.activities.runAsync({});
  t.check(d.sent.length === 1 && d.sent[0].to === 'cat' &&
          d.sent[0].facts.activity === PASSKEY,
    'and its reminder is asked as the passkey migration\'s',
    JSON.stringify(d.sent));
  t.equal(d.activities.view().activities.join(','),
    [PASSKEY, MAIL, PIV].join(','), 'the view offers all three');
  log.debug("Leaving startedChecks().");
}

// ---------------------------------------------------------------------------
// C. The mail use.
// ---------------------------------------------------------------------------
function mailUseChecks(t) {
  log.debug("Entering mailUseChecks().");
  const MailUses = require('../common/mail_uses').MailUses;
  const sent = [];
  const deps = Object.assign(MailUses.defaultDeps(), {
    mail: {
      available: function () {
        return true;
      },
      send: function (message) {
        sent.push(message);
        return { ok: true, queued: [{ id: 'x' }], refused: [],
                 duplicates: [] };
      }
    }
  });
  const uses = new MailUses(deps);
  [[PASSKEY, 'post-login-reminder'],
   [MAIL, 'post-login-reminder-mail-encryption'],
   [PIV, 'post-login-reminder-piv-reissue'],
   [undefined, 'post-login-reminder']].forEach(function (pair) {
    sent.length = 0;
    const answer = uses.postLoginReminder('ann', { started: 'pla-1',
      activity: pair[0], mails: 1, actor: 'admin' });
    const m = sent[0] || {};
    t.check(answer.ok === true && m.template === pair[1] &&
            m.username === 'ann' && m.links && m.links.signin === '/portal' &&
            m.dedupKey === 'post-login-reminder:pla-1:ann:1',
      'C. ' + (pair[0] || 'no activity') + ' is mailed ' + pair[1] +
      ', its link and dedup key as before', JSON.stringify(m));
  });
  log.debug("Leaving mailUseChecks().");
}

// ---------------------------------------------------------------------------
// D. The templates.
// ---------------------------------------------------------------------------
function templateChecks(t) {
  log.debug("Entering templateChecks().");
  const MailTemplates = require('../common/mail_templates');
  const words = { 'post-login-reminder-mail-encryption': /ML-KEM/,
                  'post-login-reminder-piv-reissue': /PIV/ };
  Object.keys(words).forEach(function (id) {
    const spec = MailTemplates.builtIn(id);
    t.equal(MailTemplates.problem(spec, spec), '',
      'D. ' + id + ' passes the rules a realm\'s wording is held to');
    const rendered = MailTemplates.render(spec, { service: 'Iya',
      username: 'ann', signin: 'https://sts.example/portal' });
    t.check(words[id].test(rendered.text) &&
            /https:\/\/sts\.example\/portal/.test(rendered.text) &&
            /href="https:\/\/sts\.example\/portal"/.test(rendered.html),
      'it says what its activity asks, and links to the portal');
    // Read from each FILE: a bare `es` reads the Spain overlay first
    // (`chainFor()`), so asking the walk for `es` would answer es-ES.
    const files = MailTemplates.localeFiles();
    ['es', 'fr', 'de', 'sv', 'fil', 'zh-Hans', 'zh-Hant', 'ar', 'hi']
      .forEach(function (tag) {
        const parts = files[tag] && files[tag].templates &&
                      files[tag].templates[id];
        t.check(!!parts && MailTemplates.problem(spec, parts) === '',
          id + ' in ' + tag);
      });
    [['es-ES', 'es'], ['fr-CA', 'fr'], ['zh-Hant-HK', 'zh-Hant']]
      .forEach(function (pair) {
        const overlay = MailTemplates.builtInFor(id, pair[0]);
        const base = files[pair[1]].templates[id];
        t.check(!!overlay && overlay.lang === pair[0] &&
                overlay.parts.text !== base.text &&
                MailTemplates.problem(spec, overlay.parts) === '',
          id + ' reads its ' + pair[0] + ' overlay, which differs from ' +
          pair[1]);
      });
  });
  log.debug("Leaving templateChecks().");
}

// ---------------------------------------------------------------------------
// E. The report.
// ---------------------------------------------------------------------------
function reportChecks(t) {
  log.debug("Entering reportChecks().");
  const Catalog = require('../report/catalog');
  const Limits = require('../report/limits');
  const Query = require('../report/query');
  const Kinds = require('../common/post_login_kinds');
  const catalog = new Catalog();
  const limits = Limits.fixed({ syncMaxRows: 1000, asyncMaxRows: 5000,
                                pdfMaxRows: 100 });
  const ask = function (document) {
    return new Query({ catalog: catalog, limits: limits }).validate(document);
  };
  t.equal(JSON.stringify(catalog.field('postLoginProgress',
    'activity').values), JSON.stringify(Kinds.ids()),
    'E. the activity field enumerates the activities\' own table');
  [PASSKEY, MAIL, PIV].forEach(function (activity) {
    const asked = ask({ source: 'postLoginProgress',
      select: ['username', 'activity', 'progress'],
      where: { op: 'eq', field: 'activity', value: activity },
      limit: 100, format: 'json', mode: 'auto' });
    t.equal(asked.ok, true, 'a filter on ' + activity + ' validates',
            asked.description);
  });
  const first = catalog.preset('postLoginProgress', 'progress-by-activity');
  t.equal(first.document.where.value, PASSKEY,
    'the first preset is the passkey migration\'s, as it was');
  [['progress-mail-encryption', MAIL], ['progress-piv-reissue', PIV]]
    .forEach(function (pair) {
      const preset = catalog.preset('postLoginProgress', pair[0]);
      t.check(!!preset && preset.document.where.value === pair[1] &&
              ask(preset.document).ok === true,
        'the ' + pair[0] + ' preset filters on ' + pair[1] + ' and ' +
        'validates');
    });
  // The fallback deadline is the activity's own.
  const PostLogin = require('../common/post_login').PostLogin;
  const helpers = require('../common/helpers');
  const real = new PostLogin({ log: helpers.log, credentials: {},
    passkeyPolicy: {}, postLoginPolicy: {}, webauthnPolicy: {},
    progress: new Map(), now: function () {
      return Date.now();
    } });
  const rules = { graceDays: 30, snoozeDays: 7, mailGraceDays: 9,
                  mailSnoozeDays: 2, pivGraceDays: 40, pivSnoozeDays: 5 };
  t.equal(real.timingOf(PASSKEY, rules).graceDays, 30,
    'timingOf(): the passkey migration\'s allotted time is graceDays');
  t.equal(real.timingOf(MAIL, rules).graceDays, 9,
    'the mail-encryption migration\'s is mailGraceDays');
  t.equal(real.timingOf(PIV, rules).graceDays, 40,
    'the PIV re-issue\'s is pivGraceDays');
  t.equal(real.timingOf('nope', rules).graceDays, 0,
    'and an activity not asked here has none');
  const sources = require('../report/sources');
  const seen = [];
  const invited = Date.parse('2026-11-01T00:00:00.000Z');
  const row = sources.postLoginRow({ username: 'ann', activity: MAIL,
    row: { invitedAt: invited } }, real, function (username, activity) {
    seen.push(username + '|' + activity);
    return { name: 'default', graceDays: 9 };
  });
  t.check(seen.join(',') === 'ann|' + MAIL &&
          row.deadline === new Date(invited + 9 * DAY).toISOString() &&
          row.activity === MAIL,
    'a row with no stamp asks the profile for its own activity, and its ' +
    'deadline is that activity\'s', JSON.stringify({ seen: seen, row: row }));
  log.debug("Leaving reportChecks().");
}

// ---------------------------------------------------------------------------
// F. The console page.
// ---------------------------------------------------------------------------
function translator(chain) {
  log.debug("Entering translator().");
  const messages = require('../common/web_messages');
  const catalogs = {};
  chain.forEach(function (tag) {
    const flat = {};
    const own = JSON.parse(fs.readFileSync(path.join(ROOT, 'common',
      'locales', 'consolePostLoginActivities', tag + '.json'), 'utf8'));
    Object.keys(own).forEach(function (key) {
      flat['consolePostLoginActivities.' + key] = own[key];
    });
    catalogs[tag] = flat;
  });
  log.debug("Leaving translator().");
  return messages.WebTranslator.fromData({ catalogs: catalogs,
    negotiated: { locale: chain[0], chain: chain, catalog: chain[0],
                  direction: 'ltr', matched: true } });
}

function pageChecks(t) {
  log.debug("Entering pageChecks().");
  const Page = require('../admin-ui/web_post_login_activities');
  const view = {
    activities: [PASSKEY, MAIL, PIV], mailAvailable: true, everyMinutes: 10,
    limits: { intervalDays: { min: 1, max: 365, dflt: 7 },
              maxMails: { min: 1, max: 20, dflt: 3 },
              perRun: { min: 1, max: 20000, dflt: 1000 },
              groups: { max: 50 } },
    groupChooser: { chosen: [], pane: { total: 0, matched: 0, from: 0,
                                         shown: [] } },
    started: [{ id: 'pla-1', activity: PIV, groups: [], state: 'running',
                intervalDays: 7, maxMails: 3, perRun: 1000, run: {} }]
  };
  [['en', /PIV certificate re-issue/, /Post-quantum mail encryption/],
   ['fr', /Réémission du certificat PIV/,
    /Chiffrement des e-mails post-quantique/]].forEach(function (one) {
    const html = Page.render(view, { t: translator([one[0], 'en']),
                                     query: {}, write: true });
    t.check(one[1].test(html) && one[2].test(html) &&
            /<code>piv-reissue<\/code>/.test(html) &&
            /<option value="pqc-mail-encryption">/.test(html) &&
            !/consolePostLoginActivities\./.test(html),
      'F. in ' + one[0] + ' each activity is named in the reader\'s ' +
      'words, its id beside it on the list, no key left untranslated');
  });
  log.debug("Leaving pageChecks().");
}

module.exports = {
  name: 'post_login_started_kinds',
  describe: 'started post-login activities, their reminders and their ' +
            'report, per activity (#2009 P4)',
  run: async function (t) {
    log.debug("Entering run().");
    tableChecks(t);
    await startedChecks(t);
    mailUseChecks(t);
    templateChecks(t);
    reportChecks(t);
    pageChecks(t);
    log.debug("Leaving run().");
  }
};
