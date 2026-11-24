// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_mail.js
//
// ===========================================================================
// THE MAIL-ENCRYPTION MIGRATION AS A POST-LOGIN ACTIVITY (#2009 P2).
//
// In process, over the REAL `PostLogin` asking the REAL mail activity
// (`common/post_login_mail.ts`), and the REAL `OpenPgpKeys` for rcbj's D3,
// each over doubles: a directory of people, the OpenPGP reader (no
// OpenPGP tool can make an RFC 9980 key in a test, so what the reader says
// a key is, is the double's), the claims and a clock.
//
//   A. The table: `pqc-mail-encryption` is a row, exposed `decrypt-later`,
//      loads whole, and is asked before the passkey migration; it is not
//      startable until P4.
//   B. Due: a classical OpenPGP key, a classical S/MIME certificate, no
//      encryption under `invite` and `require` (and not under `leave`).
//   C. Not due: a post-quantum OpenPGP key or an ML-KEM certificate; no
//      address; the profile's block off (and the passkey `enabled` on does
//      not turn it on); nothing the realm can take; `mailPrefer` narrowing
//      what is offered, the person's own kind first.
//   D. Skipped, then due again after `mailSnoozeDays`; required past
//      `mailGraceDays` from the first invitation, when Skip is refused;
//      `none` under `invite` never required.
//   E. Done: the progress row records it, and the person is due nothing
//      once their key is post-quantum.
//   F. The step's acts: a kind the step does not offer (STS-AUTHN-0601); a
//      classical S/MIME certificate (STS-AUTHN-0600) writing nothing; a
//      classical OpenPGP key refused before its proof (STS-OPENPGP-0033).
//   G. D3: a post-quantum key registered keeps the classical one in the
//      second slot for `mailKeepClassical` days; the Web Key Directory
//      answers both while it is kept and only the new one after; mail goes
//      to the new key; the job removes the kept key once its time has
//      passed (and not before), with an audit row; 0 days keeps nothing.
//   H. The policy: a save that leaves the block out keeps what was stored
//      and is not refused; a profile saved before reads it as off.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'post_login_mail',
  level: process.env.LOG_LEVEL || 'info' });

const DAY = 24 * 60 * 60 * 1000;
const MAIL = 'pqc-mail-encryption';
const PQC = 'pqc-passkey-migration';
const DOMAIN = 'mail2009.example.org';

// THE DIRECTORY: people by name, their attributes as the store holds them.
function directory() {
  log.debug("Entering directory().");
  const people = new Map();
  const out = {
    people: people,
    add: function (name, attrs) {
      people.set(name, { dn: 'uid=' + name + ',ou=users,dc=example',
        uuid: '00000000-0000-4000-8000-' +
          String(1e12 + people.size).slice(1),
        attrs: Object.assign({ mail: [name + '@' + DOMAIN] }, attrs || {}) });
    },
    locate: function (name) {
      const p = people.get(String(name));
      return p ? { dn: p.dn, username: name, attributes: Object.assign({},
        p.attrs), smime: [].concat(p.attrs['userSMIMECertificate;binary'] ||
        []) } : null;
    },
    write: function (dn, name, values) {
      for (const [, p] of people) {
        if (p.dn === dn) {
          if (values.length) {
            p.attrs[name] = values.slice();
          } else {
            delete p.attrs[name];
          }
          return true;
        }
      }
      return false;
    },
    personByMail: function () {
      return '';
    }
  };
  log.debug("Leaving directory().");
  return out;
}

// An OpenPGP key as the double's reader describes it: classical (an RSA
// encryption key) or post-quantum (ML-KEM-768+X25519).
function keyOf(name, pq, n) {
  log.debug("Entering keyOf().");
  log.debug("Leaving keyOf().");
  return {
    armored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n' + name + '-' + n +
      '\n-----END PGP PUBLIC KEY BLOCK-----',
    fingerprint: (pq ? 'aa' : 'bb') + String(n).padStart(38, '0'),
    pq: pq
  };
}

function cryptoDouble(real, keysByArmor) {
  log.debug("Entering cryptoDouble().");
  const out = Object.assign({}, real, {
    openpgpReadKey: async function (armored) {
      const k = keysByArmor.get(String(armored));
      if (!k) {
        return { ok: false, error: 'not a key' };
      }
      return { ok: true, armored: k.armored, key: k,
        description: { fingerprint: k.fingerprint, version: 6,
          primary: { algorithm: k.pq ? 'ML-DSA-65+Ed25519' : 'ed25519' },
          signing: { algorithm: k.pq ? 'ML-DSA-65+Ed25519' : 'ed25519' },
          encryption: k.pq ? { algorithm: 'ML-KEM-768+X25519' }
                           : { algorithm: 'rsaEncrypt', bits: 3072 },
          users: [{ valid: true, email: k.armored.split('\n')[1]
            .split('-')[0] + '@' + DOMAIN, text: 'x' }],
          created: '2026-11-01T00:00:00.000Z', expiresAt: '' } };
    },
    openpgpVerifyChallenge: async function () {
      return { ok: true };
    },
    openpgpBinaryKey: async function (armored) {
      return Buffer.from(String(armored));
    },
    smimeRecipientCertificate: function (values) {
      let v = String([].concat(values || [])[0] || '');
      // A value the door wrote is its DER in base64: the double's DER is
      // the text it was handed.
      if (v && !/:/.test(v)) {
        v = Buffer.from(v, 'base64').toString();
      }
      if (!v) {
        return { ok: false, error: 'the entry has no userSMIMECertificate' };
      }
      const pq = /^MLKEM/.test(v);
      return { ok: true, postQuantum: pq,
        keyAlgorithm: pq ? 'ML-KEM-768' : 'RSA', der: Buffer.from(v),
        emails: [v.split(':')[1]], serial: '01', subject: 'x' };
    },
    smimeKemAvailable: function () {
      return true;
    }
  });
  log.debug("Leaving cryptoDouble().");
  return out;
}

function world() {
  log.debug("Entering world().");
  const realCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');
  const OpenPgpKeys = require('../common/openpgp_keys').OpenPgpKeys;
  const PostLoginMail = require('../common/post_login_mail').PostLoginMail;
  const PostLogin = require('../common/post_login').PostLogin;
  const errorCodes = require('../common/error_codes');
  const clock = { now: Date.parse('2026-11-23T00:00:00.000Z') };
  const dir = directory();
  const keysByArmor = new Map();
  const audits = [];
  const settings = { 'openpgp.algorithms': [], 'openpgp.minRsaBits': 3072,
    'openpgp.pqcOnly': false, 'openpgp.pqcAlongsideClassical': false,
    'openpgp.signatureSkewS': 300, 'openpgp.challengeLifetimeS': 600,
    'openpgp.wkd': true, 'openpgp.wkdDomains': [DOMAIN] };
  const config = { value: function (k) {
    return settings[k];
  } };
  const crypto = cryptoDouble(realCrypto, keysByArmor);
  const fakeHelpers = Object.assign({}, helpers, {
    subjectForName: function (name) {
      const p = dir.people.get(String(name));
      return p ? 'urn:uuid:' + p.uuid : '';
    },
    nameForSubject: function (sub) {
      for (const [name, p] of dir.people) {
        if ('urn:uuid:' + p.uuid === sub) {
          return name;
        }
      }
      return '';
    }
  });
  const keys = new OpenPgpKeys(Object.assign(OpenPgpKeys.defaultDeps(), {
    helpers: fakeHelpers, config: config, crypto: crypto,
    audit: { audit: function (row) {
      audits.push(row);
    } },
    claims: { claim: async function () {
      return { ok: true };
    } },
    now: function () {
      return clock.now;
    },
    directory: function () {
      return dir;
    } }));
  const mail = new PostLoginMail(Object.assign(PostLoginMail.defaultDeps(), {
    config: config, crypto: crypto, openpgp: keys,
    scheduler: function () {
      return null;
    },
    now: function () {
      return clock.now;
    } }));
  const kind = { id: MAIL, exposure: 'decrypt-later',
    enabledIn: mail.enabledIn.bind(mail), turnedOn: mail.turnedOn.bind(mail),
    timing: mail.timing.bind(mail), due: mail.due.bind(mail) };
  const profile = { name: 'default', enabled: false, activity: PQC,
    snoozeDays: 7, graceDays: 0, noPasskey: 'leave', method: 'automatic',
    attestation: 'any', noPasskeyFallback: 'none', mailEnabled: true,
    mailSnoozeDays: 3, mailGraceDays: 10, mailNoKey: 'leave',
    mailPrefer: 'either', mailKeepClassical: 90 };
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
  const progress = new Map();
  const postLogin = new PostLogin({ log: helpers.log,
    credentials: { keysOf: function () {
      return [];
    } },
    passkeyPolicy: { select: function () {
      return null;
    } },
    postLoginPolicy: policy, webauthnPolicy: {}, progress: progress,
    now: function () {
      return clock.now;
    },
    kinds: function () {
      return [kind];
    } });
  // A person whose mail goes to a key: the key registered by hand.
  const withKey = function (name, pq, n) {
    const k = keyOf(name, pq, n);
    keysByArmor.set(k.armored, k);
    dir.add(name, { stsOpenPgpKey: [k.armored],
      stsOpenPgpFingerprint: [k.fingerprint],
      stsOpenPgpKeyInfo: [JSON.stringify({ fingerprint: k.fingerprint,
        algorithm: pq ? 'ML-DSA-65+Ed25519' : 'ed25519',
        encryption: pq ? 'ML-KEM-768+X25519' : 'rsaEncrypt 3072',
        addresses: [name + '@' + DOMAIN], wkd: true })],
      stsMailEncryption: ['openpgp'] });
    return k;
  };
  log.debug("Leaving world().");
  return { clock: clock, dir: dir, keys: keys, mail: mail, kind: kind,
           profile: profile, postLogin: postLogin, progress: progress,
           settings: settings, keysByArmor: keysByArmor, audits: audits,
           withKey: withKey, errorCodes: errorCodes };
}

function activities(w, name) {
  log.debug("Entering activities().");
  log.debug("Leaving activities().");
  return w.postLogin.dueListFor(name).map(function (one) {
    return one.activity + ':' + one.reason;
  }).join(',');
}

async function run(t) {
  log.debug("Entering run().");
  const Kinds = require('../common/post_login_kinds');
  const realMail = require('../common/post_login_mail');

  // A. The table.
  const row = Kinds.rowOf(MAIL);
  t.check(!!row && row.exposure === 'decrypt-later' &&
          row.module === './post_login_mail',
    'A. pqc-mail-encryption is a row of the table, exposed decrypt-later');
  t.equal(Kinds.problemWith(row, realMail.kind), '',
    'and its module answers as a whole activity');
  t.check(Kinds.ids().indexOf(MAIL) >= 0 &&
          Kinds.startableIds().indexOf(MAIL) < 0,
    'it is asked at a sign-in and not yet startable (P4)');
  t.check(Kinds.exposureRank('decrypt-later') < Kinds.exposureRank('forgery'),
    'and it is asked before the passkey migration (forgery)');

  // B. Due.
  const w = world();
  w.withKey('ana', false, 1);
  w.dir.add('ben', { stsMailEncryption: ['smime'],
    'userSMIMECertificate;binary': ['RSA:ben@' + DOMAIN] });
  w.dir.add('cy', {});
  t.equal(activities(w, 'ana'), MAIL + ':openpgp-classical',
    'B. a classical OpenPGP key is due');
  t.equal(activities(w, 'ben'), MAIL + ':smime-classical',
    'a classical S/MIME certificate is due');
  t.equal(activities(w, 'cy'), '', 'no encryption under leave: not due');
  w.profile.mailNoKey = 'invite';
  const invited = w.postLogin.dueFor('cy') || {};
  t.check(invited.reason === 'none' && invited.enforceable === false,
    'no encryption under invite: due, and never enforceable');
  w.profile.mailNoKey = 'require';
  t.check((w.postLogin.dueFor('cy') || {}).enforceable === true,
    'under require: due and enforceable');
  w.profile.mailNoKey = 'leave';
  const ana = w.postLogin.dueFor('ana') || {};
  t.check(ana.offers && ana.offers.join(',') === 'openpgp,smime' &&
          ana.keepClassicalDays === 90 && ana.snoozeDays === 3 &&
          ana.graceDays === 10,
    'the due carries what is offered (the person\'s kind first), the kept ' +
    'days and the block\'s own Skip and allotted time');
  const ben = w.postLogin.dueFor('ben') || {};
  t.equal((ben.offers || []).join(','), 'smime,openpgp',
    'an S/MIME person is offered S/MIME first');

  // C. Not due.
  w.withKey('dee', true, 2);
  w.dir.add('eve', { stsMailEncryption: ['smime'],
    'userSMIMECertificate;binary': ['MLKEM:eve@' + DOMAIN] });
  t.equal(activities(w, 'dee'), '', 'C. a post-quantum OpenPGP key: not due');
  t.equal(activities(w, 'eve'), '', 'an ML-KEM certificate: not due');
  w.withKey('fay', false, 3);
  w.dir.people.get('fay').attrs.mail = [];
  t.equal(activities(w, 'fay'), '', 'no address on the entry: not due');
  w.profile.mailEnabled = false;
  w.profile.enabled = true;
  t.equal(activities(w, 'ana'), '',
    'the block off: not due, and the passkey switch does not turn it on');
  w.profile.mailEnabled = true;
  w.profile.enabled = false;
  w.profile.mailPrefer = 'smime';
  t.equal(((w.postLogin.dueFor('ana') || {}).offers || []).join(','),
    'smime', 'mailPrefer smime offers S/MIME alone');
  w.settings['openpgp.algorithms'] = ['ed25519', 'x25519'];
  w.profile.mailPrefer = 'openpgp';
  t.equal(activities(w, 'ana'), '',
    'openpgp alone, with no ML-KEM algorithm the realm takes: not due');
  w.settings['openpgp.algorithms'] = [];
  w.profile.mailPrefer = 'either';

  // D. Skipped, required.
  const due = w.postLogin.dueFor('ana');
  w.postLogin.noteAsked('ana', due);
  const skipped = w.postLogin.noteSkipped('ana', due);
  t.check(skipped.ok && activities(w, 'ana') === '',
    'D. skipped: not asked while put off');
  w.clock.now += 3 * DAY + 1000;
  t.equal(activities(w, 'ana'), MAIL + ':openpgp-classical',
    'due again once mailSnoozeDays have passed');
  w.clock.now += 8 * DAY;
  const late = w.postLogin.dueFor('ana') || {};
  t.check(late.required === true &&
          w.postLogin.noteSkipped('ana', late).ok === false,
    'past mailGraceDays from the first invitation it is required, and Skip ' +
    'is refused');
  w.profile.mailNoKey = 'invite';
  w.postLogin.noteAsked('cy', w.postLogin.dueFor('cy'));
  w.clock.now += 30 * DAY;
  t.check((w.postLogin.dueFor('cy') || {}).required === false,
    'none under invite is never required');
  w.profile.mailNoKey = 'leave';

  // F. The step's acts.
  const dueAna = w.postLogin.dueFor('ana');
  const notOffered = w.mail.registerSmime('ana', { offers: ['openpgp'] },
    { certificate: 'MLKEM:ana@' + DOMAIN });
  t.equal(w.errorCodes.codeOf(notOffered), 'STS-AUTHN-0601',
    'F. a kind the step does not offer is refused (STS-AUTHN-0601)');
  const rsaCert = w.mail.registerSmime('ana', dueAna,
    { certificate: 'RSA:ana@' + DOMAIN });
  t.check(w.errorCodes.codeOf(rsaCert) === 'STS-AUTHN-0600' &&
          !w.dir.people.get('ana').attrs['userSMIMECertificate;binary'],
    'a classical S/MIME certificate is refused (STS-AUTHN-0600) and ' +
    'nothing is written');
  const classicalNew = keyOf('ana', false, 9);
  w.keysByArmor.set(classicalNew.armored, classicalNew);
  w.mail.challenge('ana', dueAna);
  const refusedKey = await w.mail.registerOpenPgp('ana', dueAna,
    { publicKey: classicalNew.armored, signed: 'x' });
  t.check(w.errorCodes.codeOf(refusedKey) === 'STS-OPENPGP-0033' &&
          w.dir.people.get('ana').attrs.stsOpenPgpFingerprint[0] ===
            'bb' + String(1).padStart(38, '0'),
    'a classical OpenPGP key is refused before its proof ' +
    '(STS-OPENPGP-0033) and the key on the entry is unchanged');

  // G. D3: the post-quantum key, and the classical one kept.
  const old = { armored: w.dir.people.get('ana').attrs.stsOpenPgpKey[0],
                fingerprint: 'bb' + String(1).padStart(38, '0') };
  const pq = keyOf('ana', true, 10);
  w.keysByArmor.set(pq.armored, pq);
  w.mail.challenge('ana', dueAna);
  const done = await w.mail.registerOpenPgp('ana', dueAna,
    { publicKey: pq.armored, signed: 'x' });
  const attrs = w.dir.people.get('ana').attrs;
  t.check(done.ok && attrs.stsOpenPgpFingerprint[0] === pq.fingerprint &&
          (attrs.stsOpenPgpClassicalKey || [])[0] === old.armored,
    'G. a post-quantum key registered: it is the key, and the classical ' +
    'one is kept in the second slot');
  const keptInfo = JSON.parse((attrs.stsOpenPgpClassicalKeyInfo || ['{}'])[0]);
  t.check(Date.parse(keptInfo.keptUntil) === w.clock.now + 90 * DAY &&
          done.keptUntil === keptInfo.keptUntil &&
          keptInfo.fingerprint === old.fingerprint,
    'kept until mailKeepClassical (90) days from now, which the act answers');
  t.equal(w.keys.encryptionFor('ana').fingerprint, pq.fingerprint,
    'new mail goes to the post-quantum key');
  const crypto = require('../common/crypto');
  const local = 'ana';
  const both = await w.keys.lookup(DOMAIN, crypto.wkdHash(local), local);
  t.check(!!both && both.toString().indexOf(pq.armored) >= 0 &&
          both.toString().indexOf(old.armored) >= 0,
    'the Web Key Directory answers both keys while the old one is kept');
  t.equal(activities(w, 'ana'), '',
    'E. done: with a post-quantum key the person is due nothing');
  w.postLogin.noteDone('ana', dueAna);
  t.check(Number(w.postLogin.stateOf('ana', MAIL).doneAt) === w.clock.now,
    'and the progress row records it');

  const early = await w.keys.retireClassicalDueAsync();
  t.check(early.retired === 0 &&
          !!w.dir.people.get('ana').attrs.stsOpenPgpClassicalKey,
    'the job before its time removes nothing');
  w.clock.now += 90 * DAY + 1000;
  const after = await w.keys.lookup(DOMAIN, crypto.wkdHash(local), local);
  t.check(!!after && after.toString().indexOf(old.armored) < 0,
    'past its time the kept key is not published, whether or not the job ' +
    'has run');
  const ran = await w.keys.retireClassicalDueAsync();
  t.check(ran.retired === 1 &&
          !w.dir.people.get('ana').attrs.stsOpenPgpClassicalKey &&
          !w.dir.people.get('ana').attrs.stsOpenPgpClassicalKeyInfo &&
          w.audits.some(function (a) {
            return a.action === 'openpgp.classical-retired';
          }),
    'the job removes it from the entry once its time has passed, with an ' +
    'audit row');
  const again = await w.keys.retireClassicalDueAsync();
  t.equal(again.retired, 0, 'and a second run finds nothing to remove');

  w.withKey('gus', false, 20);
  w.profile.mailKeepClassical = 0;
  const gusDue = w.postLogin.dueFor('gus');
  const gusPq = keyOf('gus', true, 21);
  w.keysByArmor.set(gusPq.armored, gusPq);
  w.mail.challenge('gus', gusDue);
  await w.mail.registerOpenPgp('gus', gusDue,
    { publicKey: gusPq.armored, signed: 'x' });
  t.check(!w.dir.people.get('gus').attrs.stsOpenPgpClassicalKey,
    'mailKeepClassical 0 keeps nothing: the classical key is replaced');

  // S/MIME done.
  const benDue = w.postLogin.dueFor('ben');
  const benDone = w.mail.registerSmime('ben', benDue,
    { certificate: 'MLKEM:ben@' + DOMAIN });
  t.check(benDone.ok && activities(w, 'ben') === '',
    'an uploaded ML-KEM certificate is done: the person is due nothing');

  // H. The policy: the block is optional on a save.
  checkPolicy(t);
  log.debug("Leaving run().");
}

function checkPolicy(t) {
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
  const passkeyOnly = { enabled: true, activity: PQC, snoozeDays: 7,
    graceDays: 0, noPasskey: 'leave', method: 'automatic',
    attestation: 'any', noPasskeyFallback: 'none' };
  const first = policy.save('default', passkeyOnly);
  t.check(first.ok && first.profile.mailEnabled === false &&
          first.profile.mailKeepClassical === 90,
    'H. a save that names no mail field is accepted, and reads the block ' +
    'as off with its defaults');
  const on = policy.save('default', Object.assign({}, passkeyOnly,
    { mailEnabled: true, mailKeepClassical: 30, mailPrefer: 'openpgp' }));
  t.check(on.ok && on.profile.mailEnabled === true &&
          on.profile.mailKeepClassical === 30,
    'a save naming the block stores it');
  const again = policy.save('default', passkeyOnly);
  t.check(again.ok && again.profile.mailEnabled === true &&
          again.profile.mailKeepClassical === 30 &&
          again.profile.mailPrefer === 'openpgp',
    'a later save that leaves the block out keeps what was stored');
  const bad = policy.save('default', Object.assign({}, passkeyOnly,
    { mailKeepClassical: 99999 }));
  t.equal(errorCodes.codeOf(bad), 'STS-AUTHN-0471',
    'a value out of range in the block is refused as any field is');
  t.check(policy.describe(again.profile).some(function (s) {
    return /post-quantum \(ML-KEM\)/.test(s);
  }) && !policy.describe(first.profile).some(function (s) {
    return /ML-KEM/.test(s);
  }),
    'the rules say the block where it is on, and nothing of it where off');
  log.debug("Leaving checkPolicy().");
}

module.exports = {
  name: 'post_login_mail',
  describe: 'the post-login mail-encryption activity (#2009 P2): who is ' +
    'due it, Skip and the allotted time, the step\'s refusals, D3\'s ' +
    'classical key kept and then retired by its job, and the policy ' +
    'block optional on a save',
  run: run
};
