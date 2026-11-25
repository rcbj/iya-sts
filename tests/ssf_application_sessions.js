// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_application_sessions.js
//
// ===========================================================================
// AN APPLICATION'S STREAM CARRIES EVENTS ONLY ABOUT PEOPLE WITH AN ACTIVE
// SESSION ON THAT APPLICATION (#2234, 2026-11-25).
//
// `ssf/application_sessions.ts` argues the rule; this holds it through the
// real `ssf_streams.ts`'s `streamCoversSubject()`, with the scope registered
// as `ssf.ts` registers it and the sessions, registry, RISC register and GNAP
// store given as plain objects:
//
//   1. Two applications and two people, each signed in to one: each
//      application's stream covers its own person and not the other — by
//      `iss_sub`, by a complex session subject, by `email` through RISC.
//   2. Each of the four relying-party lists counts (OIDC, SAML 2.0, SAML
//      1.1, WS-Federation), an expired session and an arrival session do
//      not, and a GNAP client counts a live grant the person approved to it.
//   3. THE ENDING EVENT: a session that ends is kept (`noteEnded()`), so its
//      session-revoked reaches the application whose session it was — and
//      not the other — and so does an event about the person within the
//      grace, even once their entry is gone; past the grace neither does.
//      A GNAP session-revoked naming a finalized grant of the application's
//      reaches it.
//   4. What it has no opinion on: an event with no subject; an event about
//      the application itself (#2028's `pep-policies-changed` shape, an
//      application's own credential change) or a device with no person; a
//      person's stream (#336); this service's own receivers; a GNAP
//      resource server's stream; a stream no application owns.
//   5. `ssf.applicationStreamScope: all` restores the old behaviour, and a
//      session store that cannot be read withholds the event (fails closed).
//
// In a CHILD PROCESS: it registers a subject scope on `ssf_streams.ts`, which
// is module-level state no other file in this run could have back.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_application_sessions',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.SSF_APPSESS_CHILD_OUT;
  const ROOT = process.env.SSF_APPSESS_CHILD_ROOT;
  try {
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    config.setOverride('ssf.enabled', 'true');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const subjects = require(ROOT + '/ssf/ssf_subjects');
    const mod = require(ROOT + '/ssf/application_sessions');

    const people = {
      alice: 'urn:uuid:00000000-0000-4000-8000-0000000a11ce',
      bob: 'urn:uuid:00000000-0000-4000-8000-000000000b0b',
      carol: 'urn:uuid:00000000-0000-4000-8000-0000000ca201',
      dave: 'urn:uuid:00000000-0000-4000-8000-00000000da7e'
    };
    const nameFor = function (sub) {
      return Object.keys(people).find(function (k) {
        return people[k] === sub;
      }) || '';
    };
    let clock = 1000000;
    const HOUR = 3600 * 1000;
    // THE SESSIONS: alice is signed in to the OIDC application, bob to the
    // SAML 2.0 service provider.
    const sessions = {
      's-alice': { id: 's-alice', user: { username: 'alice' },
        subjectId: people.alice, expires: clock + HOUR,
        oidcClients: { 'oidc-a': { first: 1 } } },
      's-bob': { id: 's-bob', user: { username: 'bob' },
        subjectId: people.bob, expires: clock + HOUR,
        saml2ServiceProviders: { 'urn:sp:b': { at: 1 } } }
    };
    let unread = false;
    const authn = {
      sessionsHeldUnder: function (username, subjectId) {
        if (unread) {
          return null;
        }
        return Object.keys(sessions).map(function (k) {
          return sessions[k];
        }).filter(function (s) {
          return s.user.username === username || s.subjectId === subjectId;
        });
      },
      sessionById: function (id) {
        return sessions[id] || null;
      }
    };
    const apps = {
      'oidc-a': { identifier: 'oidc-a', names: ['oidc-a'],
                  kinds: ['oidc-relying-party'] },
      'app-b': { identifier: 'app-b', names: ['urn:sp:b'],
                 kinds: ['saml2-service-provider'] },
      'gnap-c': { identifier: 'gnap-c', names: ['gnap-c'],
                  kinds: ['gnap-client'] },
      'rs-d': { identifier: 'rs-d', names: ['rs-d'],
                kinds: ['gnap-resource-server'] }
    };
    const grants = {
      g1: { id: 'g1', client: { identifier: 'gnap-c' },
            ro: { username: 'carol' }, live: true }
    };
    let setting = 'active-sessions';
    const endedStore = (function () {
      const map = new Map();
      map.lookup = function (key) {
        const out = [];
        map.forEach(function (row, id) {
          if (mod.ApplicationSessions.personKeysOf(row).indexOf(key) >= 0) {
            out.push(id);
          }
        });
        return out;
      };
      return map;
    })();
    const scopeOf = new mod.ApplicationSessions(Object.assign(
      mod.ApplicationSessions.defaultDeps(), {
        config: { value: function (key) {
          return key === 'ssf.applicationStreamScope' ? setting
                                                      : config.value(key);
        } },
        ended: endedStore,
        now: function () { return clock; },
        nameForSubject: nameFor,
        subjectForName: function (name) { return people[name] || ''; },
        loadAuthn: function () { return authn; },
        loadApplications: function () {
          return { ssfAllowedEventsFor: function (p) {
            return apps[p] || null;
          } };
        },
        loadRisc: function () {
          return { accountIdOf: function (s) {
            const map = { 'alice@example.test': 'alice',
                          'bob@example.test': 'bob' };
            return (s && map[s.email]) || '';
          } };
        },
        loadDirectory: function () {
          return { personByMail: function () { return ''; } };
        },
        loadGnapStore: function () {
          return {
            grantsApprovedTo: function (identifier, username) {
              return Object.keys(grants).map(function (k) {
                return grants[k];
              }).filter(function (g) {
                return g.client.identifier === identifier &&
                       g.ro.username === username;
              });
            },
            getGrant: function (id) { return grants[id] || null; },
            tokenByJti: function () { return null; }
          };
        },
        loadGnapRevocation: function () {
          return { isLive: function (g) { return !!g.live; } };
        }
      }));
    // Registered as `ssf.ts`'s installHooks() registers it.
    streams.setSubjectScope('application-sessions', function (record, s) {
      return scopeOf.scope(record, s);
    });

    const issSub = function (sub) {
      return { format: 'iss_sub', iss: 'https://sts.test', sub: sub };
    };
    const ofSession = function (sub, sid) {
      return { format: 'complex', user: issSub(sub),
               session: { format: 'opaque', id: sid } };
    };
    const stream = function (createdBy, extra) {
      return Object.assign({ stream_id: 'st-' + createdBy,
                             createdBy: createdBy, subjects: [] },
                           extra || {});
    };
    const covers = function (record, subject) {
      return streams.streamCoversSubject(record, subject);
    };
    const realm = realms.create({ id: 'ssf-app-sessions', name: 'a' }).realm;

    realms.run(realm, function () {
      const A = stream('oidc-a');
      const B = stream('app-b');
      const C = stream('gnap-c');

      // --- 1. each application hears about its own person --------------------
      note(covers(A, issSub(people.alice)) === true &&
           covers(A, issSub(people.bob)) === false,
           'the OIDC application\'s stream covers alice, signed in to it, ' +
           'and not bob');
      note(covers(B, issSub(people.bob)) === true &&
           covers(B, issSub(people.alice)) === false,
           'the SAML service provider\'s stream covers bob, signed in to ' +
           'it, and not alice');
      note(covers(A, ofSession(people.alice, 's-alice')) === true &&
           covers(B, ofSession(people.alice, 's-alice')) === false,
           'a CAEP session subject reaches only the application the ' +
           'session signed in to');
      note(covers(A, { format: 'email', email: 'alice@example.test' }) ===
           true && covers(B, { format: 'email',
                               email: 'alice@example.test' }) === false,
           'an email subject is judged through the RISC account');
      note(covers(A, issSub('urn:uuid:00000000-0000-4000-8000-00000000dead'))
           === false,
           'a person nobody here knows has no session here either');

      // --- 2. every relying-party list, and what is not live ---------------
      note(scopeOf.partiesOf({
        oidcClients: { c1: {} }, saml2ServiceProviders: { 'urn:sp:2': {} },
        saml11RelyingParties: { r11: { providerId: 'urn:p11' } },
        wsfedRealms: { 'urn:realm:w': 'https://w' } }).sort().join(',') ===
           'c1,r11,urn:p11,urn:realm:w,urn:sp:2',
           'the four relying-party lists of a session are its parties');
      sessions['s-old'] = { id: 's-old', user: { username: 'dave' },
        subjectId: people.dave, expires: clock - 1,
        oidcClients: { 'oidc-a': {} } };
      note(covers(A, issSub(people.dave)) === false,
           'an expired session is not active');
      delete sessions['s-old'];
      sessions['s-arrival'] = { id: 's-arrival', user: { username: 'dave' },
        subjectId: people.dave, chosen: false, expires: clock + HOUR,
        oidcClients: { 'oidc-a': {} } };
      note(covers(A, ofSession(people.dave, 's-arrival')) === false,
           'an arrival session nobody chose is not active');
      delete sessions['s-arrival'];
      note(covers(C, issSub(people.carol)) === true &&
           covers(C, issSub(people.alice)) === false,
           'a GNAP client\'s stream covers a person with a live grant ' +
           'approved to it, and nobody else');
      grants.g1.live = false;
      note(covers(C, issSub(people.carol)) === false,
           'a finalized grant is not an active session');
      note(covers(C, ofSession(people.carol, 'gnap-grant:g1')) === true &&
           covers(A, ofSession(people.carol, 'gnap-grant:g1')) === false,
           'GNAP\'s session-revoked naming the application\'s own grant ' +
           'reaches it, and no other application');

      // --- 3. the event that ends a session ---------------------------------
      const gone = sessions['s-alice'];
      scopeOf.noteEnded(gone);
      delete sessions['s-alice'];
      note(covers(A, ofSession(people.alice, 's-alice')) === true &&
           covers(B, ofSession(people.alice, 's-alice')) === false,
           'the session-revoked of an ended session reaches the application ' +
           'whose session it was, and not the other');
      note(covers(A, issSub(people.alice)) === true,
           'an event about the person within the grace still reaches it ' +
           '(a RISC event sent after the sessions it ended)');
      delete people.alice;
      note(covers(A, issSub('urn:uuid:00000000-0000-4000-8000-0000000a11ce'))
           === true,
           'and still does once the person\'s entry is gone (account-purged)');
      people.alice = 'urn:uuid:00000000-0000-4000-8000-0000000a11ce';
      clock += mod.ENDED_GRACE_MS + 1;
      note(covers(A, issSub(people.alice)) === false &&
           covers(A, ofSession(people.alice, 's-alice')) === false,
           'past the grace an application the person left hears nothing ' +
           'more about them');
      note(endedStore.size === 0, 'an expired record is deleted at the read');
      // A global sign-out notes the session before its families take the
      // SAML and WS-Federation parties off it (logout.ts's terminate()); the
      // session observer notes it again, emptied, as it ends.
      const twice = { id: 's-twice', user: { username: 'dave' },
        subjectId: people.dave, saml2ServiceProviders: { 'urn:sp:b': {} } };
      scopeOf.noteEnded(twice);
      twice.saml2ServiceProviders = {};
      scopeOf.noteEnded(twice);
      note(covers(B, ofSession(people.dave, 's-twice')) === true,
           'a session noted twice keeps every party either note saw');
      endedStore.delete('s-twice');
      scopeOf.noteEnded({ id: 's-none', user: { username: 'bob' } });
      note(endedStore.size === 0,
           'a session that signed in to nobody keeps no record');

      // --- 4. what it has no opinion on -------------------------------------
      note(covers(A, undefined) === true,
           'an event with no subject (verification, stream-updated) still ' +
           'reaches an application\'s stream');
      const appSubject = { format: 'complex',
        application: { format: 'opaque', id: 'oidc-a' } };
      note(scopeOf.scope(A, appSubject) === undefined &&
           covers(A, appSubject) === true,
           'an event about the application itself — pep-policies-changed\'s ' +
           'subject (#2028), its own credential change — reaches its stream ' +
           'with nobody signed in');
      // A RECEIVER THAT NAMES ITS PEOPLE still hears about itself: the
      // libraries add the person at sign-in and, since #2234, the
      // application's own opaque id, which names no person (so the scope has
      // no opinion and Add Subject accepts it).
      const named = stream('oidc-a', { subjects: [
        { key: subjects.subjectKey(issSub(people.bob)),
          subject: issSub(people.bob) }] });
      const otherApp = { format: 'complex',
        application: { format: 'opaque', id: 'app-b' } };
      note(covers(named, appSubject) === true &&
           covers(named, otherApp) === false,
           'with people on its list and NOT the application, an event about ' +
           'the stream\'s own application still reaches it, and another ' +
           'application\'s does not');
      const ownId = { format: 'opaque', id: 'oidc-a' };
      note(scopeOf.scope(named, ownId) === undefined,
           'Add Subject of the application\'s own opaque id is not refused ' +
           'by the scope');
      named.subjects.push({ key: subjects.subjectKey(ownId), subject: ownId });
      note(covers(named, appSubject) === true &&
           covers(named, ownId) === true,
           'and with it added, the application\'s events still reach it');
      note(covers(A, { format: 'complex',
                       device: { format: 'opaque', id: 'd1' } }) === true &&
           covers(A, { format: 'opaque', id: 'whatever' }) === true,
           'a device-only or bare opaque subject names no person and is not ' +
           'scoped');
      const personal = stream(people.bob,
        { ownerPerson: { sub: people.bob, client: 'oidc-a',
                         username: 'bob' } });
      note(scopeOf.scope(personal, issSub(people.bob)) === undefined,
           'a person\'s own stream (#336) is left to its own rule');
      note(covers(personal, appSubject) === false,
           'a person\'s stream is not sent an event about an application');
      note(scopeOf.scope(stream('internal', { internalSurface: 'console' }),
                         issSub(people.bob)) === undefined,
           'this service\'s own receivers are not scoped');
      note(scopeOf.scope(stream('rs-d'), issSub(people.bob)) === undefined,
           'a GNAP resource server\'s stream is left to #432\'s rule');
      note(scopeOf.scope(stream('receiver-under-test'),
                         issSub(people.bob)) === undefined,
           'a stream no application owns (a made-up Basic name) is ' +
           'unchanged');
      note(scopeOf.scope(stream(people.bob), issSub(people.alice)) ===
           undefined,
           'a stream from before #336 owned by a person\'s subject is not ' +
           'an application\'s');

      // --- 5. the setting, and failing closed -------------------------------
      setting = 'all';
      note(covers(A, issSub(people.bob)) === true &&
           scopeOf.scope(A, issSub(people.bob)) === undefined,
           'ssf.applicationStreamScope all restores the old behaviour');
      const onlyBob = stream('oidc-a', { subjects: [
        { key: subjects.subjectKey(issSub(people.bob)),
          subject: issSub(people.bob) }] });
      note(covers(onlyBob, { format: 'complex', user: issSub(people.alice),
                             application: { format: 'opaque',
                                            id: 'oidc-a' } }) === false,
           'a PERSON\'s session on the application is judged as the ' +
           'person, not as the application (with all, by the list)');
      setting = 'active-sessions';
      // The sessions are asked once per person per turn of the event loop;
      // the next turn asks again.
      const tick = function () {
        return new Promise(function (r) { setImmediate(r); });
      };
      note(covers(B, issSub(people.bob)) === true,
           'bob is signed in to B (asked this turn)');
      unread = true;
      return tick().then(function () {
        note(scopeOf.scope(B, issSub(people.bob)) === false,
             'a session store that cannot be read withholds the event ' +
             '(asked again on the next turn)');
        unread = false;
        sessions['s-bob-a'] = { id: 's-bob-a', user: { username: 'bob' },
          subjectId: people.bob, expires: clock + HOUR,
          oidcClients: { 'oidc-a': {} } };
        return tick();
      }).then(function () {
        note(covers(A, issSub(people.bob)) === true,
             'a sign-in to A since the last event is seen at the next one');
      });
    });
  } catch (e) {
    note(false, 'the child ran to the end', (e && e.stack) || String(e));
  }
  // The last checks run on later turns (the per-turn memo is emptied).
  setTimeout(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
  }, 200);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-appsess-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_APPSESS_CHILD_OUT: out, SSF_APPSESS_CHILD_ROOT: root,
    LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_application_sessions',
  describe: 'an application\'s Shared Signals stream carries events only ' +
            'about people with an active session on that application, the ' +
            'event that ends a session still reaches it, and subject-less, ' +
            'application and person streams are unchanged (#2234)',
  run: run
};
