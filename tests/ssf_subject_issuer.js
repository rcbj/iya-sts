// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/ssf_subject_issuer.js
//
// AN EVENT AN ADMINISTRATOR RAISES NAMES THE PERSON UNDER THE ISSUER THE
// RECEIVER DISCOVERED (#154). A receiver matches an `iss_sub` pair against
// the issuer it discovered — the stream's `iss`, the SET's — and the doors
// that raise an event with no request in hand (/admin-api's set-password,
// disable and enable) named the person under this process's own address,
// which behind a published port is an address no receiver discovered:
// `https://127.0.0.1:8081` inside SETs whose `iss` was
// `https://127.0.0.1:38081`.
//
// In a CHILD PROCESS (it loads the whole stack): two poll streams created
// under a PUBLISHED issuer that is not the process's own — one about
// everybody, and one that ADDED the person under the published issuer,
// which was not even sent the event before, the stream's subject key being
// the issuer and the subject together. Then the three doors, through the
// same function /admin-api calls (`usersAction()`), and every SET on both
// streams is held to: the subject's `iss` (top-level or a complex
// subject's member) is the SET's `iss`. A partner's subject is left alone,
// which is the control that the rewrite is not "every iss becomes ours".

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_subject_issuer',
  level: process.env.LOG_LEVEL || 'info' });

function child() {
  const ROOT = process.env.SSI_ROOT;
  const OUT = process.env.SSI_OUT;
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const claimsOf = function (token) {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url')
                            .toString('utf8'));
  };
  const issuersIn = function (subject) {
    const out = [];
    const one = function (s) {
      if (s && s.format === 'iss_sub') {
        out.push(s.iss);
      }
    };
    one(subject);
    if (subject && subject.format === 'complex') {
      Object.keys(subject).forEach(function (k) {
        one(subject[k]);
      });
    }
    return out;
  };
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  (async function () {
    const config = require(ROOT + '/common/config');
    config.setOverride('ssf.enabled', 'true');
    config.setOverride('ssf.pushDelivery', 'false');
    require(ROOT + '/common/protocol_stack');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const events = require(ROOT + '/ssf/ssf_events');
    const ssf = require(ROOT + '/ssf/ssf');
    const ldapServer = require(ROOT + '/ldap/ldap_server');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const PUBLISHED = 'https://127.0.0.1:38081';
    ldapServer.createUser('ssi-alice', {});
    const helpers = require(ROOT + '/common/helpers');
    const aliceSub = String(helpers.subjectForName('ssi-alice') || '');
    note(aliceSub, 'precondition: the person has a subject', aliceSub);
    const wanted = [events.CAEP_PREFIX + 'credential-change',
                    events.RISC_PREFIX + 'account-disabled',
                    events.RISC_PREFIX + 'account-enabled'];
    const everybody = streams.createStream({ delivery: {
      method: streams.DELIVERY_POLL }, events_requested: wanted },
      { issuer: PUBLISHED, principal: 'ssi-receiver-a' }).stream;
    const named = streams.createStream({ delivery: {
      method: streams.DELIVERY_POLL }, events_requested: wanted },
      { issuer: PUBLISHED, principal: 'ssi-receiver-b' }).stream;
    const added = streams.addSubject(named.stream_id,
      { format: 'iss_sub', iss: PUBLISHED, sub: aliceSub });
    note(everybody && named && (!added || added.ok !== false),
         'precondition: two poll streams under the published issuer, one ' +
         'naming the person under it', JSON.stringify(added || null));
    note(everybody.iss === PUBLISHED,
         'precondition: the stream\'s iss is the published issuer',
         everybody.iss);

    // The three doors, as /admin-api calls them.
    const ctx = { actor: 'ssi-admin', via: 'admin-api' };
    const set = actions.usersAction({ action: 'set-password',
      user: 'ssi-alice', generate: true }, ctx);
    const off = actions.usersAction({ action: 'disable', user: 'ssi-alice' },
                                    ctx);
    const on = actions.usersAction({ action: 'enable', user: 'ssi-alice' },
                                   ctx);
    note(set && set.ok !== false && off && off.ok !== false && on &&
         on.ok !== false, 'precondition: set-password, disable and enable ' +
         'were accepted', JSON.stringify([set, off, on]).slice(0, 400));

    // A partner's subject, raised by hand: its issuer is left alone.
    await ssf.transmit(everybody, { uri: events.RISC_PREFIX +
      'account-enabled', payload: {},
      subject: { format: 'iss_sub', iss: 'https://partner.example',
                 sub: 'p-1' } });

    const collect = async function (record) {
      let sets = [];
      for (let i = 0; i < 40; i++) {
        const queued = streams.queueOf(streams.getStream(record.stream_id));
        sets = queued.map(function (one) {
          return one.claims || claimsOf(one.token);
        });
        const types = sets.map(function (c) {
          return Object.keys(c.events || {})[0];
        });
        if (wanted.every(function (u) { return types.indexOf(u) >= 0; })) {
          break;
        }
        await sleep(100);
      }
      return sets;
    };
    const check = function (label, sets, partnerExpected) {
      wanted.forEach(function (uri) {
        const mine = sets.filter(function (c) {
          return (c.events || {})[uri] &&
            issuersIn(c.sub_id).indexOf('https://partner.example') < 0;
        });
        const name = uri.split('/').pop();
        note(mine.length > 0, label + ': a ' + name + ' about the person ' +
             'was delivered', JSON.stringify(sets.map(function (c) {
               return Object.keys(c.events || {})[0];
             })));
        mine.forEach(function (c) {
          const named = issuersIn(c.sub_id);
          note(named.length > 0 && named.every(function (iss) {
            return iss === c.iss;
          }), label + ': ' + name + ' names the person under the SET\'s ' +
              'own iss (' + c.iss + ')', JSON.stringify(c.sub_id));
        });
      });
      if (partnerExpected) {
        const partner = sets.filter(function (c) {
          return issuersIn(c.sub_id).indexOf('https://partner.example') >= 0;
        });
        note(partner.length === 1, label + ': a partner\'s subject keeps ' +
             'its partner\'s issuer — the control', partner.length);
      }
    };
    check('A. the stream about everybody', await collect(everybody), true);
    check('B. the stream that ADDED the person under the published issuer',
          await collect(named), false);
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssi-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { SSI_OUT: out, SSI_ROOT: root,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
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
  if (!findings) {
    log.debug("Leaving run(). The child wrote no report.");
    throw new Error('the child process wrote no report (status ' +
                    result.status + '): ' +
                    String(result.stderr || '').slice(-2000));
  }
  findings.forEach(function (f) {
    t.check(f.ok, f.what, f.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_subject_issuer',
  describe: 'an event an administrator raises names the person under the ' +
            'issuer the receiver discovered (#154)',
  run: run
};
