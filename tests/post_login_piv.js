// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_piv.js
//
// ===========================================================================
// THE PIV CERTIFICATE RE-ISSUE AS A POST-LOGIN ACTIVITY (#2009 P3).
//
// In process, over the REAL `PostLogin` asking the REAL activity
// (`common/post_login_piv.ts`), with the REAL post-quantum classifier
// (`common/pqc_support.ts`) reading REAL certificates — one signed with
// RSA, one with ML-DSA — and doubles for the enrolment core (a person's
// certificate records, `est.allowedProfiles`, `findEnrolled()` and
// `revokeEnrolled()`), the PKI (the EST Issuing CA's key), the PIV
// enrolment form and the clock.
//
//   A. The table: `piv-reissue` is a row, exposed `forgery`, loads whole,
//      and is startable since P4 (#2009), with its own reminder.
//   B. Due: a classically-signed certificate under a post-quantum EST CA
//      (`classical-issuer`); one expiring within `pivRenewDays`
//      (`expiring`); the trigger rows narrowing which.
//   C. Not due: an ML-DSA-signed certificate; a classical EST CA; no PIV
//      certificate; a revoked or expired one; a profile left out of
//      `est.allowedProfiles`; a slot `pivSlots` leaves out; `rekey`; the
//      block off (and the passkey switch does not turn it on).
//   D. Skipped, then due again after `pivSnoozeDays`; required past
//      `pivGraceDays` from the first invitation, when Skip is refused.
//   E. The act: a slot the step does not ask for (STS-AUTHN-0620); a
//      profile no longer enrolled (STS-AUTHN-0621); a refusal of the form
//      handed back; an enrolment recording what it replaces, with an
//      audit row, and revoking NOTHING at issue.
//   F. D5: the old certificate revoked `superseded` at the new one's first
//      use, only the person's own, and the row gone; another person's use
//      revoking nothing; a failed revocation keeping the row for the next
//      use; an old certificate already revoked counting as done.
//   G. The policy: the `list` row's parse, a save that leaves the block out
//      keeping what was stored, and the rules saying the block where on.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'post_login_piv',
  level: process.env.LOG_LEVEL || 'info' });

const DAY = 24 * 60 * 60 * 1000;
const PIV = 'piv-reissue';
const PQC = 'pqc-passkey-migration';

// A store with the realm map's shape the module uses.
function storeDouble() {
  log.debug("Entering storeDouble().");
  const m = new Map();
  log.debug("Leaving storeDouble().");
  return {
    map: m,
    get: function (k) {
      return m.get(k);
    },
    set: function (k, v) {
      m.set(k, v);
    },
    delete: function (k) {
      return m.delete(k);
    },
    clear: function () {
      m.clear();
    }
  };
}

function world(pems) {
  log.debug("Entering world().");
  const helpers = require('../common/helpers');
  const errorCodes = require('../common/error_codes');
  const PostLoginPiv = require('../common/post_login_piv').PostLoginPiv;
  const PostLogin = require('../common/post_login').PostLogin;
  const pqc = require('../common/pqc_support');
  const clock = { now: Date.parse('2026-11-23T00:00:00.000Z') };
  const records = new Map();
  const revoked = [];
  const audits = [];
  const enrolled = [];
  const state = { allowed: ['piv-auth', 'piv-sign', 'piv-key-management',
                            'piv-card-auth'],
                  caKeyAlg: 'ml-dsa-65', revokeFails: false, serial: 100,
                  revokeCalls: 0 };
  const enrollment = {
    enrolledOf: function (entry) {
      return (records.get(entry.id) || []).slice().sort(function (a, b) {
        return String(b.issuedAt).localeCompare(String(a.issuedAt));
      });
    },
    allowedProfiles: function () {
      return state.allowed.slice();
    },
    findEnrolled: function (serial) {
      for (const [id, list] of records) {
        const r = list.filter(function (one) {
          return one.serialHex === serial;
        })[0];
        if (r) {
          return { entry: { kind: 'person', id: id }, record: r };
        }
      }
      return null;
    },
    revokeEnrolled: async function (serial, reason, by, opts) {
      state.revokeCalls += 1;
      if (state.revokeFails) {
        return errorCodes.mark({ ok: false, why: 'the CA refused' },
                               'STS-ENROLL-0072');
      }
      const found = enrollment.findEnrolled(serial);
      if (!found || (opts && opts.entry && opts.entry.id !== found.entry.id)) {
        return { ok: false, why: 'not that entry\'s' };
      }
      found.record.revoked = true;
      revoked.push({ serial: serial, reason: reason, by: by });
      return { ok: true };
    }
  };
  const add = function (who, rec) {
    const list = records.get(who) || [];
    list.push(Object.assign({ revoked: false,
      issuedAt: new Date(clock.now - DAY).toISOString() }, rec));
    records.set(who, list);
  };
  const piv = new PostLoginPiv(Object.assign(PostLoginPiv.defaultDeps(), {
    store: storeDouble(),
    audit: { audit: function (row) {
      audits.push(row);
    } },
    currentRealm: function () {
      return 'default';
    },
    enrollment: function () {
      return enrollment;
    },
    pki: function () {
      return { describeIssuer: function () {
        return { keyAlg: state.caKeyAlg };
      } };
    },
    pqc: function () {
      return pqc;
    },
    enrolment: function () {
      return { enrol: async function (spec) {
        enrolled.push(spec);
        if (String(spec.csr) === 'bad') {
          return errorCodes.mark({ ok: false, errors: ['refused'] },
                                 'STS-PIV-0009');
        }
        state.serial += 1;
        const serialHex = state.serial.toString(16);
        add(spec.username, { serialHex: serialHex, profile: spec.profile,
          notAfter: new Date(clock.now + 365 * DAY).toISOString(),
          issuedAt: new Date(clock.now).toISOString(),
          certificatePem: pems.pq });
        return { ok: true, serialHex: serialHex, profile: spec.profile,
                 certificatePem: pems.pq, chainPem: ['chain'] };
      } };
    },
    now: function () {
      return clock.now;
    } }));
  const kind = { id: PIV, exposure: 'forgery',
    enabledIn: piv.enabledIn.bind(piv), turnedOn: piv.turnedOn.bind(piv),
    timing: piv.timing.bind(piv), due: piv.due.bind(piv) };
  const profile = { name: 'default', enabled: false, activity: PQC,
    snoozeDays: 7, graceDays: 0, noPasskey: 'leave', method: 'automatic',
    attestation: 'any', noPasskeyFallback: 'none', pivEnabled: true,
    pivSnoozeDays: 3, pivGraceDays: 10, pivSlots: '9a,9c,9d,9e',
    pivTrigger: 'both', pivRenewDays: 30, pivTarget: 'reissue' };
  const policy = { DEFAULT_PROFILE: 'default',
    anyEnabled: function (isOn) {
      return isOn(profile);
    },
    personGroups: function () {
      return [];
    },
    forPerson: function () {
      return profile;
    } };
  const postLogin = new PostLogin({ log: helpers.log,
    credentials: { keysOf: function () {
      return [];
    } },
    passkeyPolicy: { select: function () {
      return null;
    } },
    postLoginPolicy: policy, webauthnPolicy: {}, progress: new Map(),
    now: function () {
      return clock.now;
    },
    kinds: function () {
      return [kind];
    } });
  log.debug("Leaving world().");
  return { clock: clock, piv: piv, postLogin: postLogin, profile: profile,
           state: state, add: add, records: records, revoked: revoked,
           audits: audits, enrolled: enrolled, errorCodes: errorCodes };
}

function slotsOf(w, name) {
  log.debug("Entering slotsOf().");
  const due = w.postLogin.dueFor(name);
  log.debug("Leaving slotsOf().");
  return due && due.activity === PIV ? due.slots.map(function (one) {
    return one.slot + ':' + one.reason;
  }).join(',') : '';
}

async function run(t) {
  log.debug("Entering run().");
  const Kinds = require('../common/post_login_kinds');
  const realPiv = require('../common/post_login_piv');
  const stsCrypto = require('../common/crypto');
  const pqc = require('../common/pqc_support');
  const pems = {
    classical: stsCrypto.selfSignedRsaCertificate({ commonName: 'piv-rsa',
                                                    bits: 2048 }).certPem,
    pq: stsCrypto.selfSignedMlDsaCertificate({ algorithm: 'ml-dsa-44',
                                               commonName: 'piv-pq' }).certPem
  };

  // A. The table.
  const row = Kinds.rowOf(PIV);
  t.check(!!row && row.exposure === 'forgery' &&
          row.module === './post_login_piv',
    'A. piv-reissue is a row of the table, exposed forgery');
  t.equal(Kinds.problemWith(row, realPiv.kind), '',
    'and its module answers as a whole activity');
  t.check(Kinds.ids().indexOf(PIV) >= 0 &&
          Kinds.startableIds().indexOf(PIV) >= 0 &&
          Kinds.templateOf(PIV) === 'post-login-reminder-piv-reissue',
    'it is asked at a sign-in, and since P4 startable with its own reminder');
  t.check(!pqc.ofSignature(pems.classical) &&
          ['pq', 'composite'].indexOf((pqc.ofSignature(pems.pq) || {}).kind)
            >= 0,
    'the classifier tells an RSA-signed certificate from an ML-DSA-signed ' +
    'one by its signature');

  // B. Due.
  const w = world(pems);
  const far = new Date(w.clock.now + 200 * DAY).toISOString();
  const soon = new Date(w.clock.now + 10 * DAY).toISOString();
  w.add('ana', { serialHex: 'a1', profile: 'piv-auth', notAfter: far,
                 certificatePem: pems.classical });
  w.add('ana', { serialHex: 'b1', profile: 'piv-sign', notAfter: soon,
                 certificatePem: pems.pq });
  t.equal(slotsOf(w, 'ana'), '9a:classical-issuer,9c:expiring',
    'B. a classically-signed certificate under a post-quantum EST CA and ' +
    'one expiring within pivRenewDays are each due');
  const ana = w.postLogin.dueFor('ana') || {};
  t.check(ana.reason === 'classical-issuer' && ana.method === 'reissue' &&
          ana.snoozeDays === 3 && ana.graceDays === 10 &&
          ana.slots[0].serialHex === 'a1',
    'the due carries its reason, the certificate it replaces and the ' +
    'block\'s own Skip and allotted time');
  w.profile.pivTrigger = 'expiring';
  t.equal(slotsOf(w, 'ana'), '9c:expiring',
    'trigger expiring: only the expiring certificate');
  w.profile.pivTrigger = 'classical-issuer';
  t.equal(slotsOf(w, 'ana'), '9a:classical-issuer',
    'trigger classical-issuer: only the classically-signed one');
  w.profile.pivTrigger = 'both';

  // C. Not due.
  w.add('ben', { serialHex: '1a', profile: 'piv-auth', notAfter: far,
                 certificatePem: pems.pq });
  t.equal(slotsOf(w, 'ben'), '',
    'C. an ML-DSA-signed certificate far from expiry: not due');
  t.equal(slotsOf(w, 'cy'), '', 'no PIV certificate: not due');
  w.add('dee', { serialHex: '2a', profile: 'piv-auth', notAfter: far,
                 certificatePem: pems.classical, revoked: true });
  w.add('dee', { serialHex: '2b', profile: 'piv-sign',
                 notAfter: new Date(w.clock.now - DAY).toISOString(),
                 certificatePem: pems.classical });
  t.equal(slotsOf(w, 'dee'), '', 'a revoked or expired one: not due');
  w.state.caKeyAlg = 'rsa-3072';
  t.equal(slotsOf(w, 'ana'), '9c:expiring',
    'a classical EST Issuing CA: the classically-signed one is not due ' +
    '(a re-issue would be no better)');
  w.state.caKeyAlg = 'ml-dsa-65';
  w.state.allowed = ['piv-sign'];
  t.equal(slotsOf(w, 'ana'), '9c:expiring',
    'a profile left out of est.allowedProfiles is never asked');
  w.state.allowed = ['piv-auth', 'piv-sign', 'piv-key-management',
                     'piv-card-auth'];
  w.profile.pivSlots = '9c';
  t.equal(slotsOf(w, 'ana'), '9c:expiring',
    'a slot pivSlots leaves out is not looked at');
  w.profile.pivSlots = '9a,9c,9d,9e';
  w.profile.pivTarget = 'rekey';
  t.equal(slotsOf(w, 'ana'), '', 'rekey asks nobody');
  w.profile.pivTarget = 'reissue';
  w.profile.pivEnabled = false;
  w.profile.enabled = true;
  t.equal(slotsOf(w, 'ana'), '',
    'the block off: not due, and the passkey switch does not turn it on');
  w.profile.pivEnabled = true;
  w.profile.enabled = false;

  // D. Skip and the allotted time.
  const due = w.postLogin.dueFor('ana');
  t.check(due && due.required === false, 'D. first asked: not required');
  w.postLogin.noteAsked('ana', due);
  const skipped = w.postLogin.noteSkipped('ana', due);
  t.check(skipped && skipped.ok === true && !w.postLogin.dueFor('ana'),
    'a skip puts it off');
  w.clock.now += 3 * DAY + 1000;
  t.check(!!w.postLogin.dueFor('ana'), 'due again after pivSnoozeDays');
  w.clock.now += 8 * DAY;
  const late = w.postLogin.dueFor('ana') || {};
  t.check(late.required === true &&
          w.postLogin.noteSkipped('ana', late).ok === false,
    'past pivGraceDays from the first invitation it is required and Skip ' +
    'is refused');

  // E. The act.
  const d = w.postLogin.dueFor('ana');
  const notAsked = await w.piv.enrol('ana', d, { slot: '9d', csr: 'x' });
  t.equal(w.errorCodes.codeOf(notAsked), 'STS-AUTHN-0620',
    'E. a slot the step does not ask for is refused');
  w.state.allowed = ['piv-sign'];
  const gone = await w.piv.enrol('ana', d, { slot: '9a', csr: 'x' });
  t.equal(w.errorCodes.codeOf(gone), 'STS-AUTHN-0621',
    'a profile the realm no longer enrols is refused');
  w.state.allowed = ['piv-auth', 'piv-sign', 'piv-key-management',
                     'piv-card-auth'];
  const refused = await w.piv.enrol('ana', d, { slot: '9a', csr: 'bad' });
  t.equal(w.errorCodes.codeOf(refused), 'STS-PIV-0009',
    'the form\'s own refusal is handed back');
  const issued = await w.piv.enrol('ana', d, { slot: '9a', csr: 'ok',
    slotPem: 's', attestationPem: 'f' });
  const spec = w.enrolled[w.enrolled.length - 1] || {};
  t.check(issued.ok && issued.slot === '9a' &&
          /ykman piv certificates import 9a/.test(issued.command) &&
          spec.username === 'ana' && spec.actor === 'ana' &&
          spec.admin === false && spec.profile === 'piv-auth' &&
          spec.slotPem === 's' && spec.attestationPem === 'f',
    'an enrolment goes through the PIV form as the person, for the slot\'s ' +
    'profile, and answers the certificate and the import command');
  const recorded = w.piv.supersedeOf(issued.serialHex) || {};
  t.check(recorded.username === 'ana' &&
          (recorded.replaces || []).join() === 'a1' &&
          w.audits.some(function (a) {
            return a.action === 'piv.reissued';
          }),
    'it records under the new serial what it replaces, with an audit row');
  t.equal(w.revoked.length, 0, 'and revokes nothing at issue (D5)');

  // F. D5: revoked at first use.
  const other = await w.piv.certificateUsed('ben', issued.serialHex);
  t.check(other === 0 && w.revoked.length === 0 &&
          w.state.revokeCalls === 0 &&
          !!w.piv.supersedeOf(issued.serialHex),
    'F. another person\'s use of the serial revokes nothing, and asks the ' +
    'certificate authority nothing');
  t.equal(await w.piv.certificateUsed('ana', 'ff'), 0,
    'a certificate no re-issue recorded revokes nothing');
  w.state.revokeFails = true;
  t.check(await w.piv.certificateUsed('ana', issued.serialHex) === 0 &&
          !!w.piv.supersedeOf(issued.serialHex),
    'a failed revocation keeps the row, for the next sign-in');
  w.state.revokeFails = false;
  const upper = '00' + issued.serialHex.toUpperCase();
  t.equal(await w.piv.certificateUsed('ana', upper), 1,
    'its first use (in the socket\'s spelling) revokes the old certificate');
  t.check(w.revoked.length === 1 && w.revoked[0].serial === 'a1' &&
          w.revoked[0].reason === 'superseded' &&
          !w.piv.supersedeOf(issued.serialHex) &&
          w.audits.some(function (a) {
            return a.action === 'piv.superseded';
          }),
    'superseded, the row gone, an audit row');
  t.equal(await w.piv.certificateUsed('ana', issued.serialHex), 0,
    'a second use revokes nothing more');
  const again = await w.piv.enrol('ana', { slots: [{ slot: '9c',
    profile: 'piv-sign', serialHex: 'b1', notAfter: soon,
    reason: 'expiring' }] }, { slot: '9c', csr: 'ok' });
  w.records.get('ana').filter(function (r) {
    return r.serialHex === 'b1';
  })[0].revoked = true;
  t.check(await w.piv.certificateUsed('ana', again.serialHex) === 0 &&
          !w.piv.supersedeOf(again.serialHex),
    'an old certificate already revoked counts as done, and the row goes');

  // G. The policy.
  await checkPolicy(t);
  log.debug("Leaving run().");
}

async function checkPolicy(t) {
  log.debug("Entering checkPolicy().");
  const PostLoginPolicy = require('../common/post_login_policy')
    .PostLoginPolicy;
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const stored = new Map();
  const policy = new PostLoginPolicy({ log: helpers.log, realms: realms,
                                       errorCodes: errorCodes });
  policy.setDirectory({
    allPostLoginPolicies: function () {
      return Array.from(stored.entries()).map(function (e) {
        return { name: e[0], dn: 'cn=' + e[0], attributes: e[1] };
      });
    },
    writePostLoginPolicy: function (name, attributes) {
      stored.set(name, attributes);
      return true;
    },
    deletePostLoginPolicy: function (name) {
      return stored.delete(name);
    }
  });
  const base = { enabled: true, activity: PQC, snoozeDays: 7,
    graceDays: 0, noPasskey: 'leave', method: 'automatic',
    attestation: 'any', noPasskeyFallback: 'none' };
  const first = policy.save('default', base);
  t.check(first.ok && first.profile.pivEnabled === false &&
          first.profile.pivSlots === '9a,9c,9d,9e' &&
          first.profile.pivTrigger === 'both' &&
          first.profile.pivRenewDays === 30,
    'G. a save that names no PIV field is accepted, and reads the block as ' +
    'off with its defaults');
  const on = policy.save('default', Object.assign({}, base,
    { pivEnabled: true, pivSlots: '9C, 9a', pivTrigger: 'expiring' }));
  t.check(on.ok && on.profile.pivEnabled === true &&
          on.profile.pivSlots === '9a,9c',
    'the slots list takes either case and either separator, and is kept ' +
    'in the slots\' own order');
  const kept = policy.save('default', base);
  t.check(kept.ok && kept.profile.pivEnabled === true &&
          kept.profile.pivSlots === '9a,9c' &&
          kept.profile.pivTrigger === 'expiring',
    'a later save that leaves the block out keeps what was stored');
  const bad = policy.save('default', Object.assign({}, base,
    { pivSlots: '9a,9f' }));
  const none = policy.save('default', Object.assign({}, base,
    { pivSlots: '' }));
  t.check(errorCodes.codeOf(bad) === 'STS-AUTHN-0471' &&
          errorCodes.codeOf(none) === 'STS-AUTHN-0471',
    'a slot that is not one, or none at all, is refused as any field is');
  t.check(policy.describe(kept.profile).some(function (s) {
    return /PIV slot certificate \(9a,9c\)/.test(s);
  }) && !policy.describe(first.profile).some(function (s) {
    return /PIV/.test(s);
  }),
    'the rules say the block where it is on, and nothing of it where off');
  log.debug("Leaving checkPolicy().");
}

module.exports = {
  name: 'post_login_piv',
  describe: 'the post-login PIV re-issue (#2009 P3): who is due it, Skip ' +
    'and the allotted time, the step\'s act through the PIV form, D5\'s ' +
    'revocation at first use, and the policy block optional on a save',
  run: run
};
