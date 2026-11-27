// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sign_in_alert_mail.js
//
// ===========================================================================
// AN UNUSUAL SIGN-IN, AND A RUN OF REFUSED PASSWORDS, ARE MAILED TO THE
// PERSON (#2162, ASVS 5.0.0 6.3.5), in process.
//
//   A. The kinds: a sign-in's signals as the alert names them, a new
//      country, and `unusual` for MEDIUM or above with none of those.
//   B. The level: a low-risk success is not told at the default
//      (MEDIUM), a risky one is, a live session's re-assessment never is,
//      and `mail.signInAlertLevel` LOW tells a LOW one with a kind.
//   C. ONCE PER WINDOW PER KIND, through the real channel and its outbox:
//      a risky success mails once, a second in the window does not, a new
//      kind beside a told one mails only the new one, and a kind told
//      beside another is found by itself later. The message carries the
//      time, the place, the browser, the method and the portal's link.
//   D. N refused passwords mail once, and not before the Nth; a second
//      run in the window does not.
//   E. Nothing without a transport, and nothing with the switch off.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'sign_in_alert_mail',
  level: process.env.LOG_LEVEL || 'info' });

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + nodeCrypto.randomBytes(3).toString('hex');
}

function withRealm(t, overrides, fn) {
  log.debug('Entering withRealm().');
  const realms = require('../common/realms');
  const id = realmId('sign-in-alert');
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

// A transport factory that keeps what it is handed.
function stubTransports() {
  log.debug('Entering stubTransports().');
  const sent = [];
  log.debug('Leaving stubTransports().');
  return {
    sent: sent,
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
}

// The real channel over stub transports, and the uses over it.
function channel(available) {
  log.debug('Entering channel().');
  const mailModule = require('../common/mail');
  const usesModule = require('../common/mail_uses');
  const transports = stubTransports();
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
  return { m: m, u: u, transports: transports };
}

function settle() {
  log.debug('Entering settle().');
  log.debug('Leaving settle().');
  return new Promise(function (resolve) {
    setTimeout(resolve, 30);
  });
}

function alertsIn(m, template) {
  log.debug('Entering alertsIn().');
  log.debug('Leaving alertsIn().');
  return m.list().filter(function (r) {
    return r.template === template;
  });
}

function kinds(t) {
  log.debug('Entering kinds().');
  const { RiskEngine } = require('../risk/risk_engine');
  const of = RiskEngine.alertKindsOf;
  t.equal(of([{ signal: 'tor-exit' }, { signal: 'reputation' }], 'HIGH',
             false).join(','), 'anonymiser',
          'A1. Tor and the reputation list are one kind, an anonymiser');
  t.equal(of([{ signal: 'new-device' }, { signal: 'account-failures' }],
             'MEDIUM', true).join(','),
          'new-device,after-refusals,new-country',
          'A2. a new device, refused passwords just before, a new country');
  t.equal(of([{ signal: 'new-tls-stack' }], 'MEDIUM', false).join(','),
          'unusual', 'A3. MEDIUM with no named kind is unusual');
  t.equal(of([], 'LOW', false).length, 0,
          'A4. a LOW sign-in with nothing unusual has no kind');
  log.debug('Leaving kinds().');
}

async function levels(t) {
  log.debug('Entering levels().');
  const { RiskEngine } = require('../risk/risk_engine');
  const told = [];
  const engine = new RiskEngine(Object.assign(RiskEngine.defaultDeps(), {
    lazy: function (name) {
      if (/mail_uses$/.test(name)) {
        return { signInAlert: function (who, facts) {
          told.push({ who: who, facts: facts });
          return { ok: true };
        } };
      }
      return require(name);
    }
  }));
  const base = { id: 'a1', at: Date.now(), phase: 'user', country: 'NZ',
                 city: 'Wellington', uaFamily: 'Firefox', uaOs: 'Linux',
                 credentialKind: 'password' };
  await withRealm(t, {}, async function () {
    t.check(!engine.signedIn(Object.assign({}, base,
              { level: 'LOW', alerts: ['new-device'] }), 'ann') &&
            told.length === 0,
            'B1. a low-risk success is not told at the default level');
    t.check(engine.signedIn(Object.assign({}, base,
              { level: 'MEDIUM', alerts: ['new-device'] }), 'ann') &&
            told.length === 1 && told[0].who === 'ann' &&
            told[0].facts.kinds.join(',') === 'new-device' &&
            told[0].facts.city === 'Wellington' &&
            told[0].facts.browser === 'Firefox' &&
            told[0].facts.method === 'password',
            'B2. a risky success is told, with where, with what and how',
            JSON.stringify(told));
    t.check(!engine.signedIn(Object.assign({}, base,
              { level: 'HIGH', phase: 'session', alerts: ['anonymiser'] }),
                             'ann') && told.length === 1,
            'B3. a live session re-assessed is not a sign-in, and is not ' +
            'told');
    t.check(!engine.signedIn(Object.assign({}, base,
              { level: 'HIGH', alerts: [] }), 'ann') && told.length === 1,
            'B4. nothing unusual named, nothing told');
  });
  await withRealm(t, { 'mail.signInAlertLevel': 'LOW' }, async function () {
    t.check(engine.signedIn(Object.assign({}, base,
              { level: 'LOW', alerts: ['new-country'] }), 'ann') &&
            told.length === 2,
            'B5. mail.signInAlertLevel LOW tells a LOW sign-in with a kind');
  });
  log.debug('Leaving levels().');
}

async function once(t) {
  log.debug('Entering once().');
  const mailModule = require('../common/mail');
  const original = mailModule.directory();
  mailModule.setDirectory(stubDirectory({
    ann: { mail: ['ann@example.com'] }
  }));
  try {
    await withRealm(t, {}, async function () {
      const { m, u, transports } = channel();
      const facts = { kinds: ['new-device'], at: Date.UTC(2026, 10, 24, 9),
                      city: 'Wellington', country: 'NZ',
                      browser: 'Firefox', os: 'Linux', method: 'webauthn' };
      const first = u.signInAlert('ann', facts);
      await settle();
      const rows = alertsIn(m, 'sign-in-alert');
      // A SENT message keeps no body in the outbox; the transport has it.
      const text = String((transports.sent[0] || {}).text || '');
      t.check(first.ok && rows.length === 1 &&
              /Wellington, NZ/.test(text) && /Firefox on Linux/.test(text) &&
              /a passkey or security key/.test(text) &&
              /a device or browser not seen before/.test(text) &&
              /2026/.test(text) && /\/portal\/sign-ins/.test(text),
              'C1. a risky success mails the person: when, where, the ' +
              'browser, the method, what was unusual, the sign-ins link',
              text);
      const second = u.signInAlert('ann', facts);
      t.check(!second.ok && second.skipped === 'told in the window' &&
              alertsIn(m, 'sign-in-alert').length === 1,
              'C2. a second in the window does not', JSON.stringify(second));
      u.signInAlert('ann', Object.assign({}, facts,
        { kinds: ['new-device', 'anonymiser', 'new-country'] }));
      await settle();
      const now = alertsIn(m, 'sign-in-alert');
      const newer = now.filter(function (r) {
        return r.id !== rows[0].id;
      })[0];
      const latestText = newer ? String((transports.sent[1] || {}).text ||
                                        '') : '';
      t.check(now.length === 2 && /anonymising/.test(latestText) &&
              /a country not seen before/.test(latestText) &&
              !/a device or browser not seen before/.test(latestText),
              'C3. a new kind beside a told one mails only the new ones',
              latestText);
      const later = u.signInAlert('ann', Object.assign({}, facts,
        { kinds: ['new-country'] }));
      t.check(!later.ok && alertsIn(m, 'sign-in-alert').length === 2,
              'C4. a kind told beside another is found by itself later',
              JSON.stringify(later));
    });
    await withRealm(t, { 'mail.signInAlertWindowS': 60 },
                    async function () {
      const { m, u, transports } = channel();
      const refusals = [];
      const { RiskFailures } = require('../risk/risk_failures');
      let total = 0;
      const failures = new RiskFailures(Object.assign(
        RiskFailures.defaultDeps(), {
          store: {
            recordFailure: function () {
              total++;
              return Promise.resolve('f' + total);
            },
            listFailures: function () {
              return Promise.resolve({ total: total, rows: [] });
            }
          },
          keystore: function () {
            return { sealed: function () {
              return false;
            } };
          },
          subjectOf: function () {
            return 'urn:uuid:ann';
          },
          nameOf: function () {
            return 'ann';
          },
          asnOf: function () {
            return Promise.resolve(0);
          },
          mailAvailable: function () {
            return true;
          },
          mailUses: function () {
            return { refusedAttempts: function (who, f) {
              refusals.push(f);
              return u.refusedAttempts(who, f);
            } };
          }
        }));
      const limit = Number(require('../common/config')
        .value('security.rateLimitPerIdentity'));
      for (let i = 0; i < limit - 1; i++) {
        await failures.recordFailure('ann', 'the sign-in screen',
                                     'STS-AUTHN-0054');
      }
      t.check(refusals.length === 0,
              'D1. fewer refusals than the sign-in limit tell nobody');
      await failures.recordFailure('ann', 'the sign-in screen',
                                   'STS-AUTHN-0054');
      await failures.recordFailure('ann', 'the sign-in screen',
                                   'STS-AUTHN-0054');
      await settle();
      const told = alertsIn(m, 'sign-in-refusals');
      const sentText = transports.sent.map(function (x) {
        return String(x.text || '');
      }).join('\n');
      t.check(refusals.length === 2 && told.length === 1 &&
              new RegExp(limit + ' attempts to sign in').test(sentText),
              'D2. the limit reached mails once, and the next refusal in ' +
              'the window does not', JSON.stringify(refusals));
      await failures.recordFailure('ann', 'a replayed one-time code',
                                   'STS-AUTHN-0106');
      t.check(refusals.length === 2,
              'D3. a replayed one-time code is not a refused password');
    });
    await withRealm(t, {}, async function () {
      const { m, u } = channel(false);
      const answer = u.signInAlert('ann', { kinds: ['anonymiser'] });
      const refused = u.refusedAttempts('ann', { count: 9, minutes: 1 });
      t.check(!answer.ok && !refused.ok && m.list().length === 0,
              'E1. nothing is sent without a transport');
    });
    await withRealm(t, { 'mail.signInAlerts': false }, async function () {
      const { m, u } = channel();
      const answer = u.signInAlert('ann', { kinds: ['anonymiser'] });
      t.check(!answer.ok && m.list().length === 0,
              'E2. nothing is sent with mail.signInAlerts off');
    });
  } finally {
    mailModule.setDirectory(original);
  }
  log.debug('Leaving once().');
}

module.exports = {
  name: 'sign_in_alert_mail',
  describe: 'An unusual sign-in and a run of refused passwords are mailed ' +
            'to the person (#2162, ASVS 5.0.0 6.3.5): the kinds, the level, ' +
            'once per window per kind, the refusals, the off switches',
  run: async function (t) {
    log.debug('Entering run().');
    kinds(t);
    await levels(t);
    await once(t);
    log.debug('Leaving run().');
  }
};
