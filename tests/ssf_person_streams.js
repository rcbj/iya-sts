// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: ssf_person_streams.js
//
// ===========================================================================
// A STREAM A PERSON OWNS CARRIES EVENTS ONLY ABOUT THAT PERSON (#336,
// 2026-09-28).
//
// Found from a relying party's side: a demo receiver signed a person in with
// the authorization code grant, created its stream with that person's access
// token (`ssf:read ssf:write`), and under `default_subjects: ALL` was sent
// every other person's session-established, credential-change and
// risk-level-change. `ssf_streams.ts`'s "A PERSON'S STREAM IS ABOUT THAT
// PERSON" argues the rule; this asserts it:
//
//   1. `ssf_auth.ts` says what KIND of party authenticated: a token issued
//      FOR a person is `person` with its `sub` and client, a client's own
//      token (bare or `urn:sts:client:`) is `client`.
//   2. A stream created with a person's credential records them, and covers
//      a subject only when it names them — by `iss_sub`, by a complex
//      subject's `user`, by `email` through the RISC account, by an alias —
//      even when its subject list names somebody else.
//   3. A pairwise owner is matched FORWARDS through their client; an
//      ephemeral one through the mapping back at creation.
//   4. A Basic name is a person only when the directory holds it.
//   5. A client's stream, a GNAP application's and this service's own are
//      untouched, and so is everything with `ssf.personStreamsSelfOnly` off.
//   6. A stream from before the change whose `createdBy` is a person's
//      `urn:uuid:` subject is narrowed too.
//
// In a CHILD PROCESS: it installs a subject resolver and setting overrides,
// neither of which another file in this run could have back.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_person_streams',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.SSF_PERSON_CHILD_OUT;
  const ROOT = process.env.SSF_PERSON_CHILD_ROOT;
  try {
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const helpers = require(ROOT + '/common/helpers');
    config.setOverride('ssf.enabled', 'true');
    const people = {
      alice: 'urn:uuid:00000000-0000-4000-8000-0000000a11ce',
      bob: 'urn:uuid:00000000-0000-4000-8000-000000000b0b'
    };
    helpers.setSubjectResolver({
      subjectFor: function (name) { return people[name] || ''; },
      nameFor: function (sub) {
        return Object.keys(people).find(function (k) {
          return people[k] === sub;
        }) || '';
      }
    });
    const streamsModule = require(ROOT + '/ssf/ssf_streams');
    const SsfStreams = streamsModule.SsfStreams;
    const streams = new SsfStreams(Object.assign(SsfStreams.defaultDeps(), {
      loadApplications: function () {
        return {
          ssfAllowedEventsFor: function () { return null; },
          clientConfigOf: function (client) {
            return { subject_type: client === 'pairwise-rp'
              ? 'pairwise' : client === 'ephemeral-rp' ? 'ephemeral'
                : 'public' };
          }
        };
      },
      loadPairwise: function () {
        return {
          subjectFor: function (client, sub) {
            return 'pw:' + client + ':' + sub;
          },
          localFor: function (sub) {
            return sub === 'eph-1' ? people.alice : '';
          }
        };
      },
      loadRisc: function () {
        const accounts = { 'alice@example.test': 'alice',
                           'bob@example.test': 'bob' };
        return {
          accountIdOf: function (subject) {
            return (subject && accounts[subject.email]) || '';
          }
        };
      }
    }));
    const realm = realms.create({ id: 'ssf-person-streams', name: 'p' })
      .realm;
    const issSub = function (sub) {
      return { format: 'iss_sub', iss: 'https://sts.test', sub: sub };
    };
    const session = function (sub) {
      return { format: 'complex', user: issSub(sub),
               session: { format: 'opaque', id: 'sid-1' } };
    };

    realms.run(realm, function () {
      const make = function (principal, owner, extra) {
        const made = streams.createStream(
          { delivery: { method: streamsModule.DELIVERY_POLL } },
          Object.assign({ issuer: 'https://sts.test', principal: principal,
                          owner: owner,
                          audience: 'https://receiver.test/' + principal },
                        extra || {}));
        if (!made.ok) {
          throw new Error('createStream refused: ' +
                          JSON.stringify(made.errors));
        }
        return made.stream;
      };
      const covers = function (record, subject) {
        return streams.streamCoversSubject(record, subject);
      };

      // --- 2. a public-sub person's stream ---------------------------------
      const mine = make(people.alice,
                        { kind: 'person', sub: people.alice, client: 'rp' });
      note(mine.ownerPerson && mine.ownerPerson.username === 'alice',
           'a stream created with a person\'s token records them as its owner',
           JSON.stringify(mine.ownerPerson));
      note(covers(mine, issSub(people.alice)) === true,
           'a person\'s stream covers an iss_sub naming them');
      note(covers(mine, issSub(people.bob)) === false,
           'a person\'s stream does NOT cover another person, under ALL');
      note(covers(mine, session(people.alice)) === true &&
           covers(mine, session(people.bob)) === false,
           'a complex session subject is judged by its user member');
      note(covers(mine, { format: 'complex',
                          device: { format: 'opaque', id: 'd1' } }) === false,
           'a complex subject naming no user names nobody on it');
      note(covers(mine, { format: 'email', email: 'alice@example.test' }) ===
           true && covers(mine, { format: 'email',
                                  email: 'bob@example.test' }) === false,
           'an email subject is matched through the RISC account');
      note(covers(mine, { format: 'aliases', identifiers: [
        { format: 'email', email: 'bob@example.test' },
        issSub(people.alice)] }) === true,
           'an aliases subject covers when any alias names the owner');
      note(covers(mine, undefined) === true,
           'an event with no subject (SSF\'s own) still reaches the stream');
      const added = streams.addSubject(mine.stream_id, issSub(people.bob),
                                       true, {});
      note(added.ok && covers(streams.getStream(mine.stream_id),
                              issSub(people.bob)) === false,
           'naming somebody else on the list does not widen a person\'s ' +
           'stream (in-process; the route refuses it outright)');

      // --- 3. pairwise and ephemeral owners ---------------------------------
      const pw = make('pw:pairwise-rp:' + people.alice,
        { kind: 'person', sub: 'pw:pairwise-rp:' + people.alice,
          client: 'pairwise-rp' });
      note(covers(pw, issSub(people.alice)) === true &&
           covers(pw, issSub(people.bob)) === false,
           'a pairwise owner is matched forwards through their client');
      note(covers(pw, { format: 'email', email: 'alice@example.test' }) ===
           false,
           'an owner known only by a pairwise sub is named only by iss_sub');
      const eph = make('eph-1',
        { kind: 'person', sub: 'eph-1', client: 'ephemeral-rp' });
      note(eph.ownerPerson && eph.ownerPerson.username === 'alice' &&
           covers(eph, issSub(people.alice)) === true &&
           covers(eph, issSub(people.bob)) === false,
           'an ephemeral owner is mapped back to the person at creation',
           JSON.stringify(eph.ownerPerson));

      // --- 4. Basic ----------------------------------------------------------
      const basicPerson = make('bob', { kind: 'basic', name: 'bob' });
      note(covers(basicPerson, issSub(people.bob)) === true &&
           covers(basicPerson, issSub(people.alice)) === false,
           'a Basic name the directory holds owns a person\'s stream');
      const basicTool = make('receiver-under-test',
                             { kind: 'basic', name: 'receiver-under-test' });
      note(!basicTool.ownerPerson &&
           covers(basicTool, issSub(people.alice)) === true,
           'a Basic name that is nobody keeps the old behaviour');

      // --- 5. what is untouched ----------------------------------------------
      const client = make('rp', { kind: 'client', client: 'rp' });
      note(!client.ownerPerson &&
           streams.ownerPersonCovers(client, issSub(people.bob)) ===
           undefined && covers(client, issSub(people.bob)) === true,
           'a client\'s own stream is not narrowed');
      const gnap = make('gnap-instance-1', { kind: 'gnap' });
      note(!gnap.ownerPerson && covers(gnap, issSub(people.bob)) === true,
           'a GNAP application\'s stream is left to its own scope');
      const internal = make(people.alice,
        { kind: 'person', sub: people.alice, client: 'rp' },
        { internalSurface: 'console' });
      note(!internal.ownerPerson &&
           covers(internal, issSub(people.bob)) === true,
           'this service\'s own receivers are never a person\'s');
      config.setOverride('ssf.personStreamsSelfOnly', 'false');
      try {
        note(covers(mine, issSub(people.bob)) === true,
             'ssf.personStreamsSelfOnly off restores the old behaviour');
      } finally {
        config.clearOverride('ssf.personStreamsSelfOnly');
      }

      // --- 6. a stream from before -------------------------------------------
      const legacy = make(people.alice, null);
      note(!legacy.ownerPerson &&
           covers(legacy, issSub(people.bob)) === false &&
           covers(legacy, issSub(people.alice)) === true,
           'a stream from before whose createdBy is a person\'s subject is ' +
           'narrowed to them');
    });

    // --- 1. what kind of party authenticated ---------------------------------
    const authModule = require(ROOT + '/ssf/ssf_auth');
    const decide = function (claims) {
      const auth = new authModule.SsfAuth(Object.assign(
        authModule.SsfAuth.defaultDeps(), {
          dpop: { presentedAccessToken: function () {
            return { verified: true, scheme: 'bearer', claims: claims };
          } },
          scopePolicy: { declares: function () { return true; } }
        }));
      return auth.authenticate({ headers: { authorization: 'Bearer t' } },
                               'write');
    };
    const scope = 'ssf:read ssf:write';
    const person = decide({ typ: 'Bearer', sub: people.alice,
                            client_id: 'rp', scope: scope });
    note(person.ok && person.owner && person.owner.kind === 'person' &&
         person.owner.sub === people.alice && person.owner.client === 'rp',
         'a token issued for a person is a person\'s, with its sub and client',
         JSON.stringify(person.owner || person));
    const bare = decide({ typ: 'Bearer', sub: 'rp', client_id: 'rp',
                          scope: scope });
    const prefixed = decide({ typ: 'Bearer', sub: 'urn:sts:client:rp',
                              client_id: 'rp', scope: scope });
    note(bare.ok && bare.owner.kind === 'client' && prefixed.ok &&
         prefixed.owner.kind === 'client',
         'a client\'s own token is a client\'s, in both spellings of its sub',
         JSON.stringify([bare.owner, prefixed.owner]));
  } catch (e) {
    note(false, 'the child ran to the end', (e && e.stack) || String(e));
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-person-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_PERSON_CHILD_OUT: out, SSF_PERSON_CHILD_ROOT: root,
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
  name: 'ssf_person_streams',
  describe: 'a Shared Signals stream created with a person\'s own credential ' +
            'carries events only about that person, and a client\'s, a GNAP ' +
            'application\'s and this service\'s own streams are unchanged',
  run: run
};
