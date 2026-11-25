// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: credential_expiry_mail.js
//
// ===========================================================================
// A PERSON IS REMINDED BEFORE A CERTIFICATE OF THEIRS EXPIRES (#2247, ASVS
// 5.0.0 6.4.5), in process, through the real mail channel and its outbox.
//
//   A. What an entry holds: an enrolled certificate and a PIV slot
//      certificate from their records, an S/MIME and a sign-in certificate
//      from their DER, a revoked record left out, one certificate on two
//      attributes filed once.
//   B. The index: an entry written files a row per certificate under the
//      day its next reminder is due.
//   C. ONCE PER STEP, ONE MAIL PER PERSON: two certificates inside the
//      30-day step are one message naming both, with the day each expires
//      and how to renew it; a second run sends nothing; the next step (7
//      days) mails again for the one now inside it; a step passed is never
//      told (inside 1 day, the 7 is skipped).
//   D. A certificate first seen inside a step is told at the nearest; the
//      outbox is a record too (a row whose `told` was lost sends nothing).
//   E. Nothing without a transport, and nothing with the switch off.
//   F. A deleted person's rows go; the entry observer's watcher reaches the
//      index; the job is a cluster job per realm, off with a reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'credential_expiry_mail',
  level: process.env.LOG_LEVEL || 'info' });

const DAY = 24 * 60 * 60 * 1000;

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + nodeCrypto.randomBytes(3).toString('hex');
}

function withRealm(t, overrides, fn) {
  log.debug('Entering withRealm().');
  const realms = require('../common/realms');
  const id = realmId('credential-expiry');
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: overrides || {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withRealm(). Not created.');
    return Promise.resolve();
  }
  log.debug('Leaving withRealm().');
  return Promise.resolve(realms.run(made.realm, function () {
    return fn(made.realm);
  })).finally(function () {
    realms.remove(id);
  });
}

// A directory of people for the channel's slot.
function stubDirectory(people) {
  log.debug('Entering stubDirectory().');
  log.debug('Leaving stubDirectory().');
  return {
    personEntry: function (u) {
      return people[u] ? { dn: 'uid=' + u,
                           attributes: Object.assign({}, people[u]) } : null;
    },
    personByMail: function () {
      return '';
    },
    writeMailFlag: function () {
      return true;
    }
  };
}

// The real channel over a transport that keeps what it is handed, and the
// uses over it.
function channel(available) {
  log.debug('Entering channel().');
  const mailModule = require('../common/mail');
  const usesModule = require('../common/mail_uses');
  const sent = [];
  const transports = {
    build: function () {
      return Promise.resolve({
        name: 'stub',
        send: function (message) {
          sent.push(message);
          return Promise.resolve({ providerId: 'p' + sent.length });
        },
        close: function () {
          return undefined;
        }
      });
    }
  };
  const m = new mailModule.Mail(Object.assign(mailModule.Mail.defaultDeps(),
                                              { transports: transports }));
  const u = new usesModule.MailUses(Object.assign(
    usesModule.MailUses.defaultDeps(), {
      mail: {
        send: m.send.bind(m),
        available: function () {
          return available === false ? false : m.available();
        },
        queuedWithin: m.queuedWithin.bind(m)
      }
    }));
  log.debug('Leaving channel().');
  return { m: m, u: u, sent: sent };
}

// The reminder over the channel, a clock the test moves, and no directory.
function reminder(u, clock) {
  log.debug('Entering reminder().');
  const expiry = require('../common/credential_expiry');
  const C = expiry.CredentialExpiry;
  const r = new C(Object.assign(C.defaultDeps(), {
    now: function () {
      return clock.now;
    },
    mailUses: function () {
      return u;
    },
    directory: function () {
      return {
        passkeyScanAsync: function (ask) {
          return Promise.resolve({ next: String(ask.after || ''), read: 0,
                                   done: true });
        },
        usernameOfEntry: function () {
          return '';
        }
      };
    },
    tlsClients: function () {
      return { personCertificatesOf: function () {
        return [];
      } };
    }
  }));
  log.debug('Leaving reminder().');
  return r;
}

function settle() {
  log.debug('Entering settle().');
  log.debug('Leaving settle().');
  return new Promise(function (resolve) {
    setTimeout(resolve, 30);
  });
}

function reminders(m) {
  log.debug('Entering reminders().');
  log.debug('Leaving reminders().');
  return m.list().filter(function (r) {
    return r.template === 'credential-expiring';
  });
}

// A record as `cert_enrollment.ts` writes it.
function enrolled(serial, profile, subject, notAfterMs, revoked) {
  log.debug('Entering enrolled().');
  const record = { serialHex: serial, family: 'est', profile: profile,
                   subject: subject,
                   thumbprint: nodeCrypto.createHash('sha256')
                     .update(serial).digest('hex'),
                   notBefore: new Date(notAfterMs - 90 * DAY).toISOString(),
                   notAfter: new Date(notAfterMs).toISOString() };
  if (revoked) {
    record.revoked = { at: new Date().toISOString() };
  }
  log.debug('Leaving enrolled().');
  return JSON.stringify(record);
}

const SUBJECT = 'urn:uuid:11111111-2222-4333-8444-555555555555';

async function held(t) {
  log.debug('Entering held().');
  const stsCrypto = require('../common/crypto');
  const { CredentialExpiry } = require('../common/credential_expiry');
  const smime = stsCrypto.selfSignedRsaCertificate({ commonName: 'ann smime',
                                                     years: 1 });
  const now = Date.now();
  const attrs = {
    stsenrolledcertificate: [
      enrolled('0a', 'tls-client', 'CN=ann', now + 20 * DAY),
      enrolled('0b', 'piv-auth', 'CN=ann card', now + 25 * DAY),
      enrolled('0c', 'tls-client', 'CN=gone', now + 10 * DAY, true)],
    'usersmimecertificate;binary': [smime.certB64],
    'usercertificate;binary': [smime.certB64]
  };
  const list = CredentialExpiry.heldIn(attrs);
  const kinds = list.map(function (one) {
    return one.kind;
  }).sort().join(',');
  t.check(list.length === 3 && kinds === 'certificate,piv,smime',
          'A1. an enrolled and a PIV certificate from their records, an ' +
          'S/MIME one from its DER; the revoked record left out, and one ' +
          'certificate on two attributes filed once', JSON.stringify(list));
  const signIn = CredentialExpiry.heldIn({ usercertificate: [smime.certPem] });
  t.check(signIn.length === 1 && signIn[0].kind === 'signin-certificate' &&
          signIn[0].label === 'ann smime' &&
          Math.abs(signIn[0].notAfter - Date.parse(smime.notAfter)) < 1000,
          'A2. a sign-in certificate from its PEM, with its name and expiry',
          JSON.stringify(signIn));
  log.debug('Leaving held().');
  return { smime: smime, attrs: attrs, t0: now };
}

async function steps(t, fixture) {
  log.debug('Entering steps().');
  const mailModule = require('../common/mail');
  const expiry = require('../common/credential_expiry');
  const original = mailModule.directory();
  mailModule.setDirectory(stubDirectory({
    ann: { mail: ['ann@example.com'] }
  }));
  try {
    await withRealm(t, {}, async function () {
      const { m, u, sent } = channel();
      const clock = { now: fixture.t0 };
      const r = reminder(u, clock);
      const enrolledOnly = {
        stsenrolledcertificate: fixture.attrs.stsenrolledcertificate };
      await r.entryChanged({ subject: SUBJECT, username: 'ann',
                             before: {}, after: enrolledOnly });
      const rows = [];
      expiry.store.forEach(function (value, key) {
        rows.push({ key: key, value: value });
      });
      const today = new Date(fixture.t0).toISOString().slice(0, 10);
      t.check(rows.length === 2 && rows.every(function (e) {
        return e.value.next === today && e.value.username === 'ann' &&
          e.value.subject === SUBJECT;
      }),
      'B1. an entry written files a row per certificate, due today (both ' +
      'are inside the 30-day step)', JSON.stringify(rows));

      const first = await r.remindAsync();
      await settle();
      const text = String((sent[0] || {}).text || '');
      t.check(first.mailed === 1 && reminders(m).length === 1 &&
              sent.length === 1 && /CN=ann\b/.test(text) &&
              /CN=ann card/.test(text) && /PIV smart card/.test(text) &&
              /Certificates page/.test(text) &&
              /Security keys page/.test(text) &&
              text.indexOf(new Date(fixture.t0 + 20 * DAY).toISOString()
                .slice(0, 10)) >= 0 && /\/portal/.test(text),
              'C1. two certificates inside the 30-day step are ONE message ' +
              'naming both, the day each expires and how to renew it',
              text + ' ' + JSON.stringify(first));
      const second = await r.remindAsync();
      await settle();
      t.check(second.mailed === 0 && reminders(m).length === 1,
              'C2. a second run sends nothing for the same step',
              JSON.stringify(second));

      clock.now = fixture.t0 + 14 * DAY;
      const third = await r.remindAsync();
      await settle();
      const later = String((sent[1] || {}).text || '');
      t.check(third.mailed === 1 && reminders(m).length === 2 &&
              /CN=ann\b/.test(later) && !/CN=ann card/.test(later),
              'C3. the next step (7 days) mails again, for the certificate ' +
              'now inside it only', later + ' ' + JSON.stringify(third));

      clock.now = fixture.t0 + 24 * DAY;
      const fourth = await r.remindAsync();
      await settle();
      const last = String((sent[2] || {}).text || '');
      let card = null;
      expiry.store.forEach(function (value) {
        if (value.kind === 'piv') {
          card = value;
        }
      });
      t.check(fourth.mailed === 1 && /CN=ann card/.test(last) && card &&
              card.told.join(',') === '30,1' && card.next === '',
              'C4. inside one day the 7-day step is passed and never told; ' +
              'after the last step the row leaves the due index',
              JSON.stringify(card));
    });

    await withRealm(t, {}, async function () {
      const { m, u, sent } = channel();
      const notAfter = Date.parse(fixture.smime.notAfter);
      const clock = { now: notAfter - 3 * DAY };
      const r = reminder(u, clock);
      await r.entryChanged({ subject: SUBJECT, username: 'ann', before: {},
        after: { 'usersmimecertificate;binary': [fixture.smime.certB64] } });
      const answer = await r.remindAsync();
      await settle();
      let row = null;
      let key = '';
      expiry.store.forEach(function (value, k) {
        if (k.charAt(0) !== '$') {
          row = value;
          key = k;
        }
      });
      t.check(answer.mailed === 1 && row && row.told.join(',') === '7' &&
              /S\/MIME certificate/.test(String((sent[0] || {}).text)) &&
              /OpenPGP and mail encryption page/.test(
                String((sent[0] || {}).text)),
              'D1. a certificate first seen inside the 30 and 7-day steps ' +
              'is told once, at the nearest', JSON.stringify(row));
      // The row's record lost (a crash between the send and the write):
      // the outbox still holds the message, so nothing is sent again.
      expiry.store.set(key, Object.assign({}, row, { told: [],
        next: new Date(clock.now).toISOString().slice(0, 10) }));
      const again = await r.remindAsync();
      await settle();
      t.check(again.mailed === 0 && reminders(m).length === 1 &&
              expiry.store.get(key).told.join(',') === '7',
              'D2. the outbox is a record too: a row whose told step was ' +
              'lost sends nothing, and is marked again',
              JSON.stringify(again));
    });

    await withRealm(t, {}, async function () {
      const { m, u } = channel(false);
      const clock = { now: fixture.t0 };
      const r = reminder(u, clock);
      await r.entryChanged({ subject: SUBJECT, username: 'ann', before: {},
        after: { stsenrolledcertificate:
                 fixture.attrs.stsenrolledcertificate } });
      const answer = await r.remindAsync();
      t.check(answer.skipped === 'off' && m.list().length === 0 &&
              /transport/.test(r.offIn(require('../common/realms')
                .currentId()) || 'transport'),
              'E1. nothing is sent without a transport',
              JSON.stringify(answer));
    });
    await withRealm(t, { 'mail.expiryReminders': false }, async function () {
      const { m, u } = channel();
      const clock = { now: fixture.t0 };
      const r = reminder(u, clock);
      await r.entryChanged({ subject: SUBJECT, username: 'ann', before: {},
        after: { stsenrolledcertificate:
                 fixture.attrs.stsenrolledcertificate } });
      const answer = await r.remindAsync();
      const realmNow = require('../common/realms').currentId();
      t.check(answer.skipped === 'off' && m.list().length === 0 &&
              /mail\.expiryReminders/.test(r.offIn(realmNow)),
              'E2. nothing is sent with mail.expiryReminders off, and the ' +
              'job says why', JSON.stringify(answer));
      await r.entryChanged({ subject: SUBJECT, username: 'ann',
        deleted: true,
        before: { stsenrolledcertificate:
                  fixture.attrs.stsenrolledcertificate }, after: {} });
      let left = 0;
      expiry.store.forEach(function (value, k) {
        if (k.charAt(0) !== '$') {
          left += 1;
        }
      });
      t.check(left === 0, 'F1. a deleted person\'s rows go with them');
    });

    await withRealm(t, {}, async function () {
      const observer = require('../common/entry_observer');
      t.check(observer.watching().indexOf('common/credential_expiry') >= 0,
              'F2. the reminder watches the entry observer');
      observer.entryChanged({ kind: 'updated', dn: 'uid=bea', username: 'bea',
        subject: SUBJECT, realm: require('../common/realms').currentId(),
        before: {}, after: { stsenrolledcertificate: [
          enrolled('0d', 'email', 'CN=bea', Date.now() + 60 * DAY)] } });
      await settle();
      let filed = null;
      expiry.store.forEach(function (value, k) {
        if (k.charAt(0) !== '$') {
          filed = value;
        }
      });
      t.check(filed && filed.username === 'bea' && filed.kind ===
              'certificate' && filed.next !== '',
              'F3. a write the observer is told of reaches the index',
              JSON.stringify(filed));
      const registered = [];
      const { CredentialExpiry } = expiry;
      const r = new CredentialExpiry(Object.assign(
        CredentialExpiry.defaultDeps(), {
          scheduler: function () {
            return { job: function () {
              return null;
            }, register: function (spec) {
              registered.push(spec);
            } };
          }
        }));
      t.check(r.registerJobs() && registered.length === 1 &&
              registered[0].id === 'mail.credential-expiry' &&
              registered[0].kind === 'cluster' &&
              registered[0].scope === 'realm' &&
              typeof registered[0].off === 'function',
              'F4. the job is a cluster job per realm, with an off reason');
    });
  } finally {
    mailModule.setDirectory(original);
  }
  log.debug('Leaving steps().');
}

module.exports = {
  name: 'credential_expiry_mail',
  describe: 'A person is reminded before a certificate of theirs expires ' +
            '(#2247, ASVS 5.0.0 6.4.5): what an entry holds, the index, ' +
            'once per step and one mail per person, the outbox as a ' +
            'record, the off switches, the watcher and the job',
  run: async function (t) {
    log.debug('Entering run().');
    const fixture = await held(t);
    await steps(t, fixture);
    log.debug('Leaving run().');
  }
};
