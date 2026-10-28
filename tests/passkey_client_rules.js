// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_client_rules.js
//
// ===========================================================================
// THE CLIENTS A PASSKEY REGISTRATION OFFERS NO ML-DSA (#1112):
// `common/passkey_clients.ts` and the passkey policy's `clientRules` row.
// In process, a fake User-Agent per client, read by the ceremony rows' one
// parser (`webauthn_ceremonies.clientOf()`).
//
//   A. The row: rules parsed to one canonical text, and a rule that is not
//      `<browser> on <system>` (or a range that is empty, or too many) is
//      refused at the save (STS-AUTHN-0309).
//   B. Matching: a family is compared without regard to case, a range needs
//      a major version inside it, `*` is any.
//   C. Configured: a registration armed at `/portal/keys` from a matching
//      client offers no ML-DSA and carries the rule; another client's
//      offers ML-DSA first; the ceremony row's `offered` says what the
//      rule did after a `|`.
//   D. Never where a classical passkey is not allowed: webauthn.pqcOnly,
//      registrationMode pq-only, postQuantumRequired
//      registration-and-sign-in, and — at the sign-in step only —
//      postQuantumRequired sign-in. The offer is unchanged and the rule is
//      recorded as not applied, with why.
//   E. Learned: off by default (nothing counted). On, N different people's
//      NotSupportedError registrations that asked for ML-DSA learn the
//      client (one person counts once); NotAllowedError, a registration
//      that asked for no ML-DSA and an unreadable client count nothing; the
//      learned client's next registration offers no ML-DSA; switched off,
//      it is listed and not applied; a success that asked for ML-DSA
//      removes it.
//   F. The register on the console's view and the API's: paged by
//      `clientsPage`/`clientsPer`, learned first; one cleared, an unlisted
//      one refused (STS-AUTHN-0477), all cleared.
//   G. The sweep job is registered, removes an entry whose failures aged
//      out of the window, and keeps a learned one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const audit = require('../common/audit');
const config = require('../common/config');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const passkeyPolicy = require('../common/passkey_policy');
const passkeyClients = require('../common/passkey_clients');
const ceremonies = require('../authn/webauthn_ceremonies');
const adminViews = require('../admin-core/admin_views');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({
  name: 'passkey_client_rules', level: process.env.LOG_LEVEL || 'info' });

// ONE FAKE USER-AGENT PER CLIENT.
const FIREFOX_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:144.0) ' +
  'Gecko/20100101 Firefox/144.0';
const FIREFOX_LINUX_OLD = 'Mozilla/5.0 (X11; Linux x86_64; rv:139.0) ' +
  'Gecko/20100101 Firefox/139.0';
const CHROME_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.54 ' +
  'Safari/537.36';
const CHROME_ANDROID = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile ' +
  'Safari/537.36';

// The COSE identifiers of ML-DSA (RFC 9964).
const ML_DSA = [-48, -49, -50];

const SETTINGS = ['webauthn.clientLearning', 'webauthn.clientLearningFailures',
                  'webauthn.clientLearningWindowHours', 'webauthn.pqcOnly'];

function reqFor(userAgent) {
  log.debug('Entering reqFor().');
  log.debug('Leaving reqFor().');
  return { headers: { 'user-agent': userAgent }, socket: {} };
}

function asks(offered) {
  log.debug('Entering asks().');
  log.debug('Leaving asks().');
  return (offered || []).some(function (id) {
    return ML_DSA.indexOf(Number(id)) >= 0;
  });
}

function someone(prefix) {
  log.debug('Entering someone().');
  const who = prefix + '-' + crypto.randomBytes(3).toString('hex');
  ldap.createUser(who, { invent: false });
  log.debug('Leaving someone().');
  return who;
}

// The profile with every row at its default and `fields` over them.
function saveProfile(fields) {
  log.debug('Entering saveProfile().');
  log.debug('Leaving saveProfile().');
  return passkeyPolicy.save('default', Object.assign({},
    passkeyPolicy.DEFAULTS, fields));
}

// Arms a `/portal/keys` registration from a client, as the page's request
// would: the request is ambient, as it is behind the account API.
function begin(userAgent, who) {
  log.debug('Entering begin().');
  const req = reqFor(userAgent);
  const out = audit.withSource({ req: req }, function () {
    const begun = credentials.beginKeyEnrolment(who, { role: 'mfa' });
    return { begun: begun,
             held: credentials.pendingKeyEnrolmentFor(who) || {} };
  });
  log.debug('Leaving begin().');
  return out;
}

// A registration the browser refused, through the ceremony row's funnel.
function failed(userAgent, who, error, offered) {
  log.debug('Entering failed().');
  ceremonies.record({
    ceremony: 'registration', door: 'portal', username: who,
    role: 'mfa', lane: 'classical', outcome: 'refused',
    errorCode: 'STS-AUTHN-0022', offered: offered || [-50, -49, -48, -7],
    posted: { error: error }, req: reqFor(userAgent) });
  log.debug('Leaving failed().');
}

function rowFor(client) {
  log.debug('Entering rowFor().');
  log.debug('Leaving rowFor().');
  return (passkeyClients.view({ clientsPer: '200' }).rows || [])
    .filter(function (one) {
      return one.client === client;
    })[0] || null;
}

function parsing(t) {
  log.debug('Entering parsing().');
  const good = passkeyPolicy.parseClientRules(
    'firefox 140- on  Linux;  * on Android 13 ;Chrome 130-141 on macOS; ' +
    'Safari -18 on *');
  t.check(!good.problem && good.text === 'firefox 140- on Linux; ' +
          '* on Android 13; Chrome 130-141 on macOS; Safari -18 on *',
          'A1. client rules are read to one canonical text',
          JSON.stringify(good));
  const bad = ['Firefox', 'Chrome 141-130 on macOS', '<b> on Linux',
               'Chrome on'];
  const refused = bad.filter(function (one) {
    return !!passkeyPolicy.parseClientRules(one).problem;
  });
  const many = passkeyPolicy.parseClientRules(new Array(22).join(
    'Chrome on Linux;'));
  t.check(refused.length === bad.length && !!many.problem,
          'A2. a rule that is not `<browser> on <system>`, an empty range ' +
          'and more than twenty rules are refused',
          JSON.stringify(refused));
  const saved = saveProfile({ clientRules: 'Firefox' });
  t.check(!saved.ok && require('../common/error_codes').codeOf(saved) ===
          'STS-AUTHN-0309',
          'A3. the save refuses an unreadable row (STS-AUTHN-0309)',
          JSON.stringify(saved.errors));
  log.debug('Leaving parsing().');
}

function matching(t) {
  log.debug('Entering matching().');
  const rules = { clientRules: 'Firefox 140- on linux; Chrome 130-141 on ' +
                  'macOS; * on Android 15' };
  const of = function (ua) {
    return passkeyPolicy.clientRuleFor(ceremonies.clientOf(ua), rules);
  };
  t.check(of(FIREFOX_LINUX) === 'Firefox 140- on linux' &&
          of(FIREFOX_LINUX_OLD) === '' &&
          of(CHROME_MAC) === 'Chrome 130-141 on macOS' &&
          of(CHROME_ANDROID) === '' &&
          passkeyPolicy.clientRuleFor(ceremonies.clientOf(CHROME_ANDROID),
            { clientRules: '* on Android' }) === '* on Android',
          'B. a family matches without regard to case, a range needs the ' +
          'major version inside it, `*` is any',
          JSON.stringify([ceremonies.clientOf(FIREFOX_LINUX),
                          ceremonies.clientOf(CHROME_ANDROID)]));
  log.debug('Leaving matching().');
}

async function configured(t) {
  log.debug('Entering configured().');
  const saved = saveProfile({ clientRules: 'Firefox on Linux' });
  const who = someone('pcr-cfg');
  const firefox = begin(FIREFOX_LINUX, who);
  t.check(saved.ok && firefox.begun.ok &&
          firefox.held.classicalOnly === true &&
          !asks(firefox.held.offered) &&
          firefox.held.clientRule && firefox.held.clientRule.narrowed &&
          firefox.held.clientRule.record === 'configured: Firefox on Linux',
          'C1. a registration from a configured client offers no ML-DSA, ' +
          'and carries the rule', JSON.stringify(firefox.held));
  const answer = await credentials.confirmKeyEnrolment(who,
    firefox.begun.enrolmentId, { error: 'NotAllowedError' },
    { origin: 'https://localhost:8081', rpId: 'localhost' });
  const rows = audit.list().filter(function (row) {
    return row.action === 'webauthn.ceremony' && row.actor === who;
  });
  const offered = String(((rows[0] || {}).detail || {}).offered || '');
  t.check(!answer.ok && rows.length === 1 &&
          /^[^|]+\|configured: Firefox on Linux$/.test(offered) &&
          offered.indexOf('ML-DSA') < 0,
          'C2. the ceremony row\'s `offered` is what was offered, then what ' +
          'the rule did', offered);
  const other = someone('pcr-cfg2');
  const chrome = begin(CHROME_MAC, other);
  t.check(chrome.begun.ok && chrome.held.classicalOnly === false &&
          asks(chrome.held.offered) && !chrome.held.clientRule,
          'C3. another client is offered ML-DSA as before',
          JSON.stringify(chrome.held));
  log.debug('Leaving configured().');
}

function notApplied(t) {
  log.debug('Entering notApplied().');
  saveProfile({ clientRules: 'Firefox on Linux' });
  const cases = [];
  config.setOverride('webauthn.pqcOnly', true);
  try {
    const one = begin(FIREFOX_LINUX, someone('pcr-pqc')).held;
    cases.push(['webauthn.pqcOnly', one]);
  } finally {
    config.clearOverride('webauthn.pqcOnly');
  }
  saveProfile({ clientRules: 'Firefox on Linux', registrationMode: 'pq-only' });
  cases.push(['registrationMode pq-only',
              begin(FIREFOX_LINUX, someone('pcr-mode')).held]);
  saveProfile({ clientRules: 'Firefox on Linux',
                postQuantumRequired: 'registration-and-sign-in' });
  cases.push(['postQuantumRequired registration-and-sign-in',
              begin(FIREFOX_LINUX, someone('pcr-req')).held]);
  const bad = cases.filter(function (c) {
    const held = c[1];
    return !(held.classicalOnly === false && asks(held.offered) &&
             held.clientRule && held.clientRule.narrowed === false &&
             held.clientRule.record === 'not applied (' + c[0] + '): ' +
               'configured: Firefox on Linux');
  });
  t.check(cases.length === 3 && bad.length === 0,
          'D1. where a classical passkey is not allowed the offer is ' +
          'unchanged and the rule recorded as not applied, with why',
          JSON.stringify(bad));
  saveProfile({ clientRules: 'Firefox on Linux',
                postQuantumRequired: 'sign-in' });
  const req = reqFor(FIREFOX_LINUX);
  const atStep = passkeyClients.offerFor({ at: 'sign-in', req: req });
  const atPortal = passkeyClients.offerFor({ req: req });
  t.check(!atStep.narrowed &&
          atStep.notApplied === 'postQuantumRequired sign-in' &&
          atPortal.narrowed === true && atPortal.by === 'configured',
          'D2. under postQuantumRequired sign-in the passkey step is not ' +
          'narrowed (its key would not sign the person in) and the portal ' +
          'is', JSON.stringify([atStep, atPortal]));
  passkeyPolicy.reset('default');
  log.debug('Leaving notApplied().');
}

function learned(t) {
  log.debug('Entering learned().');
  passkeyPolicy.reset('default');
  passkeyClients.act('clear-passkey-clients', {});
  const client = ceremonies.clientOf(CHROME_ANDROID);
  const first = someone('pcr-l1');
  failed(CHROME_ANDROID, first, 'NotSupportedError');
  t.check(rowFor(client) === null,
          'E1. off by default: a failure is not counted', client);
  config.setOverride('webauthn.clientLearning', true);
  config.setOverride('webauthn.clientLearningFailures', 2);
  try {
    failed(CHROME_ANDROID, first, 'NotSupportedError');
    failed(CHROME_ANDROID, first, 'NotSupportedError');
    failed(CHROME_ANDROID, someone('pcr-l2'), 'NotAllowedError');
    failed(CHROME_ANDROID, someone('pcr-l3'), 'NotSupportedError', [-7, -257]);
    failed('', someone('pcr-l4'), 'NotSupportedError');
    const counting = rowFor(client);
    t.check(counting && counting.failures === 1 && !counting.learned &&
            rowFor('') === null,
            'E2. one person counts once; NotAllowedError, an offer with no ' +
            'ML-DSA and a client with no User-Agent count nothing',
            JSON.stringify(counting));
    const second = someone('pcr-l5');
    failed(CHROME_ANDROID, second, 'NotSupportedError');
    const row = rowFor(client);
    const learntRows = audit.list().filter(function (one) {
      return one.action === 'webauthn.client.learned' &&
             one.target === client;
    });
    t.check(row && row.learned && row.learnedFailures === 2 &&
            learntRows.length === 1,
            'E3. a second person\'s failure learns the client, with one ' +
            'audit row', JSON.stringify(row));
    const next = begin(CHROME_ANDROID, someone('pcr-l6')).held;
    t.check(next.classicalOnly === true && !asks(next.offered) &&
            next.clientRule && next.clientRule.record === 'learned: ' +
              client,
            'E4. the learned client\'s next registration offers no ML-DSA',
            JSON.stringify(next));
    config.setOverride('webauthn.clientLearning', false);
    const off = begin(CHROME_ANDROID, someone('pcr-l7')).held;
    t.check(asks(off.offered) && !off.clientRule && !!rowFor(client),
            'E5. switched off, the entry is kept and not applied',
            JSON.stringify(off));
    config.setOverride('webauthn.clientLearning', true);
    ceremonies.record({
      ceremony: 'registration', door: 'portal', username: second,
      role: 'mfa', lane: 'classical', outcome: 'success',
      offered: [-50, -49, -48, -7], algorithm: 'ES256', posted: {},
      req: reqFor(CHROME_ANDROID) });
    t.check(rowFor(client) === null,
            'E6. a registration from the client that asked for ML-DSA and ' +
            'succeeded removes the entry', client);
  } finally {
    config.clearOverride('webauthn.clientLearning');
    config.clearOverride('webauthn.clientLearningFailures');
  }
  log.debug('Leaving learned().');
}

function register(t) {
  log.debug('Entering register().');
  passkeyClients.act('clear-passkey-clients', {});
  config.setOverride('webauthn.clientLearning', true);
  config.setOverride('webauthn.clientLearningFailures', 1);
  try {
    const who = someone('pcr-reg');
    for (let major = 100; major < 130; major++) {
      failed(CHROME_ANDROID.replace('Chrome/140', 'Chrome/' + major), who,
             'NotSupportedError');
    }
    const view = adminViews.policiesView({ clientsPage: '2',
                                           clientsPer: '10' });
    const clients = view.passkey && view.passkey.clients;
    t.check(clients && clients.paging.total === 30 &&
            clients.paging.pages === 3 && clients.paging.page === 2 &&
            clients.rows.length === 10 && clients.learning === true &&
            clients.rows.every(function (one) {
              return one.learned;
            }),
            'F1. the policies view carries the register, paged by ' +
            'clientsPage and clientsPer',
            JSON.stringify(clients && clients.paging));
    const target = clients.rows[0].client;
    const refused = adminActions.policiesAction(
      { action: 'clear-passkey-client', client: 'Nobody 1 on Nothing 2' },
      { via: 'api', actor: 'tester' });
    const cleared = adminActions.policiesAction(
      { action: 'clear-passkey-client', client: target },
      { via: 'api', actor: 'tester' });
    t.check(!refused.ok && require('../common/error_codes').codeOf(refused) ===
              'STS-AUTHN-0477' &&
            cleared.ok && cleared.removed === 1 && rowFor(target) === null,
            'F2. one learned client is cleared; an unlisted one is refused ' +
            '(STS-AUTHN-0477)', JSON.stringify([refused, cleared]));
    const all = adminActions.policiesAction(
      { action: 'clear-passkey-clients' }, { via: 'api', actor: 'tester' });
    t.check(all.ok && all.removed === 29 &&
            passkeyClients.view({}).paging.total === 0,
            'F3. every learned client is cleared at once',
            JSON.stringify(all));
  } finally {
    config.clearOverride('webauthn.clientLearning');
    config.clearOverride('webauthn.clientLearningFailures');
  }
  log.debug('Leaving register().');
}

function sweeping(t) {
  log.debug('Entering sweeping().');
  const scheduler = require('../cluster/scheduler');
  t.check(!!scheduler.job(passkeyClients.SWEEP_JOB),
          'G1. the sweep is a scheduler job', passkeyClients.SWEEP_JOB);
  passkeyClients.act('clear-passkey-clients', {});
  let now = Date.now();
  const deps = Object.assign(
    passkeyClients.PasskeyClients.defaultDeps(), {
      now: function () {
        return now;
      } });
  const clock = new passkeyClients.PasskeyClients(deps);
  config.setOverride('webauthn.clientLearning', true);
  config.setOverride('webauthn.clientLearningFailures', 1);
  config.setOverride('webauthn.clientLearningWindowHours', 1);
  try {
    const learnt = clock.observe({ ceremony: 'registration',
      outcome: 'refused', clientError: 'NotSupportedError',
      offered: ['ML-DSA-65'], client: 'Firefox 144 on Linux',
      username: 'pcr-sweep-a' });
    config.setOverride('webauthn.clientLearningFailures', 5);
    const counted = clock.observe({ ceremony: 'registration',
      outcome: 'refused', clientError: 'NotSupportedError',
      offered: ['ML-DSA-65'], client: 'Safari 18 on iOS 18',
      username: 'pcr-sweep-b' });
    now += 2 * 60 * 60 * 1000;
    const swept = clock.sweep();
    t.check(learnt === 'learned' && counted === 'counted' &&
            swept.removed === 1 && !!rowFor('Firefox 144 on Linux') &&
            rowFor('Safari 18 on iOS 18') === null,
            'G2. the sweep removes an entry whose failures aged out and ' +
            'keeps a learned one', JSON.stringify(swept));
  } finally {
    SETTINGS.forEach(function (key) {
      config.clearOverride(key);
    });
    passkeyClients.act('clear-passkey-clients', {});
  }
  log.debug('Leaving sweeping().');
}

module.exports = {
  name: 'passkey_client_rules',
  describe: 'the clients a passkey registration offers no ML-DSA: the ' +
            'configured clientRules row and the learned register (#1112)',
  run: async function (t) {
    log.debug('Entering run().');
    try {
      parsing(t);
      matching(t);
      await configured(t);
      notApplied(t);
      learned(t);
      register(t);
      sweeping(t);
    } finally {
      SETTINGS.forEach(function (key) {
        config.clearOverride(key);
      });
      passkeyPolicy.reset('default');
      passkeyClients.act('clear-passkey-clients', {});
    }
    log.debug('Leaving run().');
  }
};
