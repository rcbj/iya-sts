// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: credential_change_mail.js
//
// ===========================================================================
// A CREDENTIAL ADDED OR REMOVED IS MAILED TO THE PERSON (#2163, ASVS 5.0.0
// 6.3.7), in process. Until then only a password change was.
//
//   A. Every kind the issue names is a notice line: a passkey, an
//      authenticator app, an app password, a one-time code and a YubiKey
//      OTP token, a certificate, recovery codes generated — each with what
//      changed, by whom, and nothing secret.
//   B. What is NOT mailed: the password itself (its own notice), an app
//      password signal naming no change, a change the service or a policy
//      made, a recovery code spent, a type no kind names.
//   C. ONE ACT, ONE MAIL: a batch of changes — synchronous, or across
//      awaits — sends one notice listing each line once; outside a batch
//      each change sends its own.
//   D. Off: `mail.credentialChangeNotices` false, security notices off, or
//      no transport — nothing is sent.
//   E. The list is put into words in the recipient's language (`{ list }`).
//   F. END TO END through `ssf/account_signals.ts` and the real channel,
//      captured in development: recovery codes generated, and an
//      administrator's removal of every factor as one message.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'credential_change_mail',
  level: process.env.LOG_LEVEL || 'info' });

// A recording stand-in for the mail channel: `send()` keeps each request.
function recorder(available) {
  log.debug('Entering recorder().');
  const sent = [];
  log.debug('Leaving recorder().');
  return {
    sent: sent,
    send: function (req) {
      sent.push(req);
      return { ok: true, queued: [{ id: 'm' + sent.length }], refused: [],
               duplicates: [] };
    },
    available: function () {
      return available !== false;
    }
  };
}

// A MailUses over the recorder, in the ambient realm.
function usesOver(mail) {
  log.debug('Entering usesOver().');
  const usesModule = require('../common/mail_uses');
  log.debug('Leaving usesOver().');
  return new usesModule.MailUses(Object.assign(
    usesModule.MailUses.defaultDeps(), { mail: mail }));
}

function notices(mail) {
  log.debug('Entering notices().');
  log.debug('Leaving notices().');
  return mail.sent.filter(function (r) {
    return r.template === 'credential-changed';
  });
}

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + nodeCrypto.randomBytes(3).toString('hex');
}

function withRealm(t, overrides, fn) {
  log.debug('Entering withRealm().');
  const realms = require('../common/realms');
  const id = realmId('cred-mail');
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

async function kinds(t) {
  log.debug('Entering kinds().');
  await withRealm(t, {}, async function () {
    const signals = require('../ssf/account_signals');
    const told = [
      ['passkey', { credentialType: 'fido2-platform', changeType: 'create',
                    friendlyName: 'Laptop', initiatingEntity: 'user' }],
      ['passkey', { credentialType: 'fido-u2f', changeType: 'delete' }],
      ['totp', { credentialType: signals.TOTP_CREDENTIAL_TYPE,
                 changeType: 'delete', initiatingEntity: 'admin' }],
      ['app-password', { credentialType: 'password', changeType: 'create',
                         friendlyName: 'mail client',
                         initiatingEntity: 'user' }],
      ['hotp', { credentialType: signals.HOTP_CREDENTIAL_TYPE,
                 changeType: 'create' }],
      ['yubiotp', { credentialType: signals.YUBIOTP_CREDENTIAL_TYPE,
                    changeType: 'revoke' }],
      ['certificate', { credentialType: 'x509', changeType: 'create',
                        friendlyName: 'stored certificate' }]
    ];
    told.forEach(function (one, i) {
      const mail = recorder();
      const u = usesOver(mail);
      u.fromAccountSignal('credentialChanged',
                          Object.assign({ username: 'kim' }, one[1]));
      const got = notices(mail);
      const line = got[0] && got[0].values.what.list[0];
      t.check(got.length === 1 && got[0].username === 'kim' &&
              line && line.params.kind === one[0],
              'A' + i + '. a ' + one[0] + ' change is one notice line',
              JSON.stringify(got));
    });
    const mail = recorder();
    const u = usesOver(mail);
    u.fromAccountSignal('credentialChanged', { username: 'kim',
      credentialType: 'fido2-roaming', changeType: 'create',
      friendlyName: 'Blue key', initiatingEntity: 'user' });
    const one = notices(mail)[0];
    t.check(one && one.values.what.list[0].i18n ===
              'mailValues.credentialChange.itemNamed' &&
            one.values.what.list[0].params.label === 'Blue key' &&
            one.values.what.list[0].params.change === 'added' &&
            one.values.by.params.entity === 'user' &&
            one.values.when && typeof one.values.when.date === 'number',
            'A7. the line names the kind, its label and the change; by ' +
            'you; when', JSON.stringify(one));
    const admin = recorder();
    usesOver(admin).fromAccountSignal('credentialChanged', {
      username: 'kim', credentialType: 'app', changeType: 'delete' });
    t.check(notices(admin)[0].values.by.params.entity === 'admin',
            'A8. a change no person initiated is said to be an ' +
            'administrator\'s', JSON.stringify(notices(admin)));
    const codes = recorder();
    usesOver(codes).fromAccountSignal('recoveryInformationChanged', {
      username: 'kim', changeType: 'create', initiatingEntity: 'user' });
    t.check(notices(codes).length === 1 &&
            notices(codes)[0].values.what.list[0].params.kind ===
              'recovery-codes' &&
            notices(codes)[0].values.what.list[0].params.change ===
              'generated',
            'A9. recovery codes generated are one notice line',
            JSON.stringify(codes.sent));
  });
  log.debug('Leaving kinds().');
}

async function notMailed(t) {
  log.debug('Entering notMailed().');
  await withRealm(t, {}, async function () {
    const cases = [
      ['credentialChanged', { credentialType: 'password',
                              changeType: 'update' }, 'the password itself'],
      ['credentialChanged', { credentialType: 'password',
                              friendlyName: 'mail client' },
       'an app password signal naming no change'],
      ['credentialChanged', { credentialType: 'fido2-roaming',
                              changeType: 'update',
                              initiatingEntity: 'policy' },
       'a key a policy no longer accepts'],
      ['credentialChanged', { credentialType: 'x509', changeType: 'revoke',
                              initiatingEntity: 'system' },
       'a certificate superseded by the service'],
      ['credentialChanged', {
        credentialType: 'urn:iya:sts:credential-type:kerberos-key',
        changeType: 'create' }, 'the Kerberos keys'],
      ['credentialChanged', { credentialType: 'password',
                              changeType: 'create',
                              friendlyName: 'SCEP challenge password 1',
                              via: 'SCEP' },
       'a SCEP challenge password'],
      ['recoveryInformationChanged', { initiatingEntity: 'user' },
       'a recovery code spent']
    ];
    cases.forEach(function (one, i) {
      const mail = recorder();
      usesOver(mail).fromAccountSignal(one[0],
        Object.assign({ username: 'kim' }, one[1]));
      t.check(notices(mail).length === 0,
              'B' + i + '. ' + one[2] + ' sends no credential notice',
              JSON.stringify(mail.sent));
    });
  });
  log.debug('Leaving notMailed().');
}

async function batches(t) {
  log.debug('Entering batches().');
  await withRealm(t, {}, async function () {
    const mail = recorder();
    const u = usesOver(mail);
    const answer = u.batch(function () {
      u.credentialChanged({ username: 'kim', kind: 'totp',
                            change: 'removed', by: 'admin' });
      u.credentialChanged({ username: 'kim', kind: 'passkey',
                            change: 'removed', label: 'A', by: 'admin' });
      u.credentialChanged({ username: 'kim', kind: 'passkey',
                            change: 'removed', label: 'B', by: 'admin' });
      // The same change told twice (two doors) is one line.
      u.credentialChanged({ username: 'kim', kind: 'passkey',
                            change: 'removed', label: 'B', by: 'admin' });
      u.credentialChanged({ username: 'lee', kind: 'totp',
                            change: 'removed', by: 'admin' });
      t.check(notices(mail).length === 0,
              'C1. nothing is sent while the batch runs');
      return 'done';
    });
    const got = notices(mail);
    const kim = got.filter(function (r) {
      return r.username === 'kim';
    });
    t.check(answer === 'done' && got.length === 2 && kim.length === 1 &&
            kim[0].values.what.list.length === 3,
            'C2. one notice per person for the whole act, each change ' +
            'listed once', JSON.stringify(got));
    const later = recorder();
    const v = usesOver(later);
    await v.batch(async function () {
      v.credentialChanged({ username: 'kim', kind: 'hotp',
                            change: 'removed', by: 'user' });
      await new Promise(function (resolve) {
        setTimeout(resolve, 5);
      });
      v.credentialChanged({ username: 'kim', kind: 'openpgp',
                            change: 'removed', by: 'user' });
    });
    t.check(notices(later).length === 1 &&
            notices(later)[0].values.what.list.length === 2 &&
            notices(later)[0].values.by.params.entity === 'user',
            'C3. a batch across awaits is still one notice, sent when it ' +
            'ends', JSON.stringify(later.sent));
    const loose = recorder();
    const w = usesOver(loose);
    w.credentialChanged({ username: 'kim', kind: 'smime', change: 'added',
                          by: 'user' });
    w.credentialChanged({ username: 'kim', kind: 'certificate-binding',
                          change: 'removed', by: 'admin' });
    t.check(notices(loose).length === 2,
            'C4. outside a batch each change is its own notice',
            JSON.stringify(loose.sent));
    const mixed = recorder();
    const x = usesOver(mixed);
    x.batch(function () {
      x.credentialChanged({ username: 'kim', kind: 'totp', change: 'added',
                            by: 'user' });
      x.credentialChanged({ username: 'kim', kind: 'passkey',
                            change: 'removed', by: 'admin' });
    });
    t.check(notices(mixed)[0].values.by.params.entity === 'admin',
            'C5. a batch an administrator had a hand in says so',
            JSON.stringify(mixed.sent));
  });
  log.debug('Leaving batches().');
}

async function off(t) {
  log.debug('Entering off().');
  await withRealm(t, { 'mail.credentialChangeNotices': false },
                  async function () {
    const mail = recorder();
    usesOver(mail).credentialChanged({ username: 'kim', kind: 'totp',
                                       change: 'added', by: 'user' });
    t.check(mail.sent.length === 0,
            'D1. mail.credentialChangeNotices false sends nothing');
    const pw = recorder();
    usesOver(pw).fromAccountSignal('credentialChanged', { username: 'kim',
      credentialType: 'password', changeType: 'update' });
    t.check(pw.sent.length === 1 && pw.sent[0].template === 'password-changed',
            'D2. the password-changed notice is not this setting\'s',
            JSON.stringify(pw.sent));
  });
  await withRealm(t, { 'mail.securityNotices': false }, async function () {
    const mail = recorder();
    usesOver(mail).credentialChanged({ username: 'kim', kind: 'totp',
                                       change: 'added', by: 'user' });
    t.check(mail.sent.length === 0,
            'D3. security notices off sends nothing');
  });
  await withRealm(t, {}, async function () {
    const mail = recorder(false);
    usesOver(mail).credentialChanged({ username: 'kim', kind: 'totp',
                                       change: 'added', by: 'user' });
    t.check(mail.sent.length === 0, 'D4. no transport, nothing sent');
  });
  log.debug('Leaving off().');
}

function words(t) {
  log.debug('Entering words().');
  const mailModule = require('../common/mail');
  const usesModule = require('../common/mail_uses');
  const m = new mailModule.Mail(mailModule.Mail.defaultDeps());
  const value = { list: [
    usesModule.said('credentialChange.item',
                    { kind: 'totp', change: 'removed' }),
    usesModule.said('credentialChange.itemNamed',
                    { kind: 'passkey', change: 'added', label: 'Clé <b>' })
  ] };
  const fr = m.resolveValues({ what: value }, 'fr').what;
  const en = m.resolveValues({ what: value }, 'en').what;
  t.check(/suppression/.test(fr) && /application d’authentification/
    .test(fr) && /Clé <b>/.test(fr) && fr.indexOf('mailValues') < 0,
          'E1. the list is put into words in the recipient\'s language, a ' +
          'label as given', fr);
  t.check(/authenticator app removed/.test(en) &&
          /passkey or security key “Clé <b>” added/.test(en) &&
          /\band\b/.test(en),
          'E2. in English, joined as a list', en);
  log.debug('Leaving words().');
}

// A directory of people for the real channel's slot.
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

async function endToEnd(t) {
  log.debug('Entering endToEnd().');
  const mailModule = require('../common/mail');
  const signals = require('../ssf/account_signals');
  const original = mailModule.directory();
  mailModule.setDirectory(stubDirectory({
    nia: { mail: ['nia@example.com'] }
  }));
  try {
    await withRealm(t, {}, async function () {
      signals.recoveryInformationChanged({ username: 'nia',
        changeType: 'create', initiatingEntity: 'user', via: 'portal' });
      signals.recoveryInformationChanged({ username: 'nia',
        initiatingEntity: 'user', via: 'sign-in' });
      signals.batch(function () {
        signals.credentialChanged({ username: 'nia',
          credentialType: signals.TOTP_CREDENTIAL_TYPE,
          changeType: 'delete', via: 'api' });
        signals.credentialChanged({ username: 'nia',
          credentialType: 'fido2-roaming', changeType: 'delete',
          friendlyName: 'Desk key', via: 'api' });
        signals.recoveryInformationChanged({ username: 'nia',
          changeType: 'delete', initiatingEntity: 'admin', via: 'api' });
      });
      await new Promise(function (resolve) {
        setTimeout(resolve, 30);
      });
      // The realm is this test's own, so its outbox holds only these.
      const ours = mailModule.list().filter(function (r) {
        return r.template === 'credential-changed';
      });
      const texts = ours.map(function (r) {
        const full = mailModule.message(r.id);
        return full ? String(full.text || '') : '';
      });
      t.check(ours.length === 2 &&
              texts.some(function (x) {
                return /recovery codes generated/.test(x) &&
                       /by you/.test(x);
              }) &&
              texts.some(function (x) {
                return /authenticator app removed/.test(x) &&
                       /“Desk key” removed/.test(x) &&
                       /recovery codes removed/.test(x) &&
                       /by an administrator/.test(x);
              }),
              'F1. through the account signals and the real channel: ' +
              'codes generated mailed once, a code spent not, and an ' +
              'administrator\'s removal of every factor as one message',
              JSON.stringify(texts));
    });
  } finally {
    mailModule.setDirectory(original);
  }
  log.debug('Leaving endToEnd().');
}

module.exports = {
  name: 'credential_change_mail',
  describe: 'A credential added or removed is mailed to the person (#2163, ' +
            'ASVS 5.0.0 6.3.7): every kind, what is not mailed, one mail per ' +
            'act, off switches, the list in the recipient\'s language, end ' +
            'to end',
  run: async function (t) {
    log.debug('Entering run().');
    await kinds(t);
    await notMailed(t);
    await batches(t);
    await off(t);
    words(t);
    await endToEnd(t);
    log.debug('Leaving run().');
  }
};
