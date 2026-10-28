// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: ssf_announcements.js
//
// ===========================================================================
// AN ANNOUNCEMENT TO EVERYBODY SIGNED IN (#1086), in process.
//
//   A. THE STREAMS: the console's, the portal's and reports' own receiver
//      streams ask for this service's `announcement` event, and one seeded
//      before it existed is made to ask at the next seeding.
//   B. THE REFUSALS of `ssf.broadcastAnnouncement()`: no message, one too
//      long, no application, an application this service does not have.
//   C. THE SENDING: only the chosen applications' streams get the SET.
//   D. THE RECEIVER: a verified announcement naming the surface is kept and
//      answered to a tab after its first ask; one for another surface, a
//      tampered one, and one past `ssf.announcementKeepS` are not.
//   E. THE PAGE: Server configuration → Broadcast Announcement's form, and
//      the every-realm choice only where the view allows it.
//   F. THE BANNER (`common/web_announcements.ts`) over a small fake DOM: the
//      first answer draws nothing, a new one draws once, as text, with an ×
//      that closes it, and it closes itself after ten seconds.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_announcements',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in a child, with the whole stack loaded, and writes its findings.
function childMain() {
  const ROOT = process.env.SA_ROOT;
  const OUT = process.env.SA_OUT;
  const fs = require('fs');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const sleep = function (ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const receivers = require(ROOT + '/ssf/ssf_receivers');
    const events = require(ROOT + '/ssf/ssf_events');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const ssf = require(ROOT + '/ssf/ssf');
    const uri = events.ANNOUNCEMENT;

    // --- A. the streams -----------------------------------------------------
    receivers.seedStreams();
    const ids = ['admin-console', 'user-portal', 'report'];
    const asks = ids.map(function (id) {
      const record = receivers.streamFor(id);
      return !!record && record.events_requested.indexOf(uri) >= 0 &&
             record.events_delivered.indexOf(uri) >= 0;
    });
    note(asks.every(Boolean), 'A1. each of the three receiver streams asks ' +
         'for the announcement event and is agreed it', JSON.stringify(asks));
    const old = receivers.streamFor('report');
    old.events_requested = old.events_requested.filter(function (one) {
      return one !== uri;
    });
    old.events_delivered = old.events_delivered.filter(function (one) {
      return one !== uri;
    });
    receivers.seedStreams();
    const again = receivers.streamFor('report');
    note(again.events_requested.indexOf(uri) >= 0 &&
         again.events_delivered.indexOf(uri) >= 0,
         'A2. a stream seeded before the event existed asks for it at the ' +
         'next seeding');

    // --- B. the refusals ----------------------------------------------------
    const empty = await ssf.broadcastAnnouncement({ message: '  ',
      surfaces: ['admin-console'] });
    config.setOverride('ssf.announcementMaxChars', 20);
    const long = await ssf.broadcastAnnouncement({ message: 'x'.repeat(21),
      surfaces: ['admin-console'] });
    config.clearOverride('ssf.announcementMaxChars');
    const none = await ssf.broadcastAnnouncement({ message: 'Hello',
      surfaces: [] });
    const unknown = await ssf.broadcastAnnouncement({ message: 'Hello',
      surfaces: ['admin-console', 'kiosk'] });
    note(!empty.ok && /needs a message/.test(empty.errors[0]) &&
         !long.ok && /21 characters/.test(long.errors[0]) &&
         !none.ok && /at least one application/.test(none.errors[0]) &&
         !unknown.ok && /kiosk/.test(unknown.errors[0]) &&
         [empty, long, none, unknown].every(function (r) {
           return r.code === 'STS-SSF-0153' && r.sent === 0;
         }),
         'B1. no message, a message too long, no application and an ' +
         'unknown one are refused (STS-SSF-0153) and send nothing',
         JSON.stringify([empty.errors, long.errors, none.errors,
                         unknown.errors]));

    // --- C. the sending -----------------------------------------------------
    const queued = function (id) {
      return streams.queueOf(receivers.streamFor(id))
        .filter(function (one) {
          const claims = one && (one.claims || one.set || {});
          const evs = claims.events || {};
          return !!evs[uri] || JSON.stringify(one).indexOf(uri) >= 0;
        }).length;
    };
    const before = ids.map(queued);
    const sent = await ssf.broadcastAnnouncement({
      message: 'Maintenance at 18:00 UTC.',
      surfaces: ['admin-console', 'user-portal'], by: 'a test' });
    const after = ids.map(queued);
    note(sent.ok && sent.sent === 2 && sent.streams === 2 &&
         sent.realms.length === 1 && /went to 2 of 2/.test(sent.message) &&
         after[0] === before[0] + 1 && after[1] === before[1] + 1 &&
         after[2] === before[2],
         'C1. the announcement is queued on the console\'s and the ' +
         'portal\'s streams, and not on reports\', which was not chosen',
         JSON.stringify({ sent: sent, before: before, after: after }));

    // --- D. the receiver ----------------------------------------------------
    const record = receivers.streamFor('admin-console');
    const announce = function (surfaces, message, tamper) {
      const claims = events.buildSet({ uri: uri, issuer: record.iss,
        audience: 'sts-admin-console',
        payload: events.EVENT_BY_URI[uri].generate({ realm: 'default',
          message: message, surfaces: surfaces }) });
      let token = events.signSetSync(claims);
      if (tamper) {
        token = token.slice(0, -4) + (token.slice(-4) === 'AAAA' ? 'BBBB'
                                                                  : 'AAAA');
      }
      return receivers.acceptPolled('admin-console', token);
    };
    const first = receivers.announcementsFor('admin-console', 0);
    note(first.now > 0 && first.announcements.length === 0 &&
         first.everyMs === Number(config.value('ssf.announcementPollMs')),
         'D1. a tab\'s first ask is answered `now` and no announcement',
         JSON.stringify(first));
    await sleep(5);
    announce(['admin-console', 'user-portal'], 'Back in five minutes.');
    announce(['user-portal'], 'For the portal only.');
    announce(['admin-console'], 'Tampered with.', true);
    const second = receivers.announcementsFor('admin-console', first.now);
    const texts = second.announcements.map(function (a) {
      return a.message;
    });
    note(texts.length === 1 && texts[0] === 'Back in five minutes.',
         'D2. a verified announcement naming the console is answered after ' +
         'the first ask; one naming only the portal, and a tampered one, ' +
         'are not', JSON.stringify(texts));
    const portalAsk = receivers.announcementsFor('user-portal', first.now);
    note(portalAsk.announcements.length === 0,
         'D3. what the console\'s receiver took in is not the portal\'s',
         JSON.stringify(portalAsk.announcements));
    const realNow = Date.now;
    try {
      Date.now = function () {
        return realNow() + (Number(config.value('ssf.announcementKeepS')) +
                            1) * 1000;
      };
      const late = receivers.announcementsFor('admin-console', first.now);
      Date.now = realNow;
      const after2 = receivers.announcementsFor('admin-console', first.now);
      note(late.announcements.length === 0 &&
           after2.announcements.length === 0,
           'D4. past ssf.announcementKeepS it is not answered, and the read ' +
           'that found it so deleted it', JSON.stringify(after2));
    } finally {
      Date.now = realNow;
    }

    // --- E. the page --------------------------------------------------------
    const BroadcastPage = require(ROOT + '/admin-ui/web_broadcast');
    const WebKit = require(ROOT + '/admin-ui/web_kit');
    const view = { realm: 'default', ready: true, everyRealm: true,
      realmCount: 3, maxChars: 500, pollMs: 5000,
      surfaces: receivers.SURFACES.map(function (s) {
        return { id: s.id, label: s.label };
      }) };
    const page = BroadcastPage.render(view, WebKit.context({}, true));
    const realmPage = BroadcastPage.render(Object.assign({}, view,
      { everyRealm: false }), WebKit.context({}, true));
    note(/action="\/admin\/broadcast"/.test(page) &&
         /name="action" value="send"/.test(page) &&
         (page.match(/name="surfaces"[^>]*checked/g) || []).length === 3 &&
         /name="everyRealm" value="true"/.test(page) &&
         !/name="everyRealm"/.test(realmPage) &&
         /maxlength="500"/.test(page),
         'E1. the page posts send to /admin/broadcast with three ticked ' +
         'applications, and offers every realm only where the view allows',
         page.slice(0, 600));

    // --- F. the banner ------------------------------------------------------
    const WebAnnouncements = require(ROOT + '/common/web_announcements');
    const timers = [];
    const fakeElement = function (tag) {
      const el = { tagName: tag, children: [], style: {}, attrs: {},
        listeners: {}, parentNode: null, textContent: '', id: '',
        className: '',
        appendChild: function (child) {
          child.parentNode = this;
          this.children.push(child);
          return child;
        },
        removeChild: function (child) {
          this.children = this.children.filter(function (c) {
            return c !== child;
          });
          child.parentNode = null;
        },
        setAttribute: function (k, v) {
          this.attrs[k] = String(v);
        },
        addEventListener: function (type, fn) {
          this.listeners[type] = fn;
        } };
      return el;
    };
    const body = fakeElement('body');
    const doc = { body: body, hidden: false,
      createElement: fakeElement,
      getElementById: function (id) {
        const walk = function (el) {
          if (el.id === id) {
            return el;
          }
          for (const c of el.children) {
            const hit = walk(c);
            if (hit) {
              return hit;
            }
          }
          return null;
        };
        return walk(body);
      } };
    const win = { setTimeout: function (fn, ms) {
        timers.push({ fn: fn, ms: ms, live: true });
        return timers.length - 1;
      },
      clearTimeout: function (id) {
        if (timers[id]) {
          timers[id].live = false;
        }
      } };
    const banner = new WebAnnouncements({ document: doc, window: win },
      { ask: function () {
          return Promise.resolve(null);
        }, heading: 'Announcement', closeLabel: 'Close' });
    const none1 = banner.take({ now: 1000, everyMs: 5000,
      announcements: [{ id: 'a', message: 'old' }] });
    const drawn = banner.take({ now: 2000, everyMs: 5000,
      announcements: [{ id: 'b', message: '<b>Hello</b>' }] });
    const twice = banner.take({ now: 3000, everyMs: 5000,
      announcements: [{ id: 'b', message: '<b>Hello</b>' }] });
    const box = doc.getElementById(WebAnnouncements.CONTAINER_ID);
    const shown = box ? box.children : [];
    const textOf = function (el) {
      return el.textContent + el.children.map(textOf).join('');
    };
    note(none1.length === 0 && drawn.length === 1 && twice.length === 0 &&
         shown.length === 1 && textOf(shown[0]).indexOf('<b>Hello</b>') >= 0 &&
         shown[0].attrs.role === 'status',
         'F1. the first answer draws nothing, a new announcement is drawn ' +
         'once, as text, in a status banner', JSON.stringify(
           { none1: none1, drawn: drawn, twice: twice, n: shown.length }));
    const closeTimer = timers.filter(function (one) {
      return one.live && one.ms === WebAnnouncements.CLOSE_AFTER_MS;
    });
    const closeButton = shown[0] && shown[0].children[1];
    closeButton.listeners.click();
    note(closeTimer.length === 1 && box.children.length === 0,
         'F2. it is armed to close after ten seconds, and the × closes it ' +
         'at once', JSON.stringify(timers.map(function (one) {
           return one.ms;
         })));
    banner.take({ now: 4000, everyMs: 5000,
      announcements: [{ id: 'c', message: 'Second.' }] });
    const timed = timers[timers.length - 1];
    timed.fn();
    note(box.children.length === 0 && timed.ms === 10000,
         'F3. left alone, it closes itself after ten seconds');

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ssf-announcements-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', SA_ROOT: ROOT, SA_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_announcements',
  describe: 'an administrator\'s announcement to everybody signed in ' +
            '(#1086): the three receiver streams ask for it, the sender\'s ' +
            'refusals, only the chosen streams get it, a verified one kept ' +
            'and answered to a tab after its first ask (and nothing else ' +
            'is), the broadcast page, and the banner drawn once, as text, ' +
            'closed by its × or after ten seconds',
  run: run
};
