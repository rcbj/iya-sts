'use strict';
//
// File: risk_engine.js
//
// ===========================================================================
// ASSESSING A SIGN-IN (#62 P2, 2026-09-23), in process, on the memory store.
//
// `risk/risk_engine.ts` is what every sign-in is handed to. What this holds:
//
//   A. The device a User-Agent names (`bowser`) and whether it is an
//      automated client (`isbot`), and that an empty header is answered
//      rather than thrown on.
//   B. A first sign-in is recorded UNSCORED, and moves the history on; and
//      with `risk.minimumHistory` at its default (5) so is the SECOND — too
//      little history to score, and no new-tls-stack either — while an
//      evidence signal (an automated client) still counts. The sections
//      after it score from the second sign-in (the setting at 1), because
//      the model and the novelty signals are what they are about.
//   C. The same person again, from the same network and device, scores LOW —
//      the model against the history the first sign-in left.
//   D. The evaluators: an address on a Tor list, an automated client, a TLS
//      stack never seen, and recent refused passwords are each a signal with
//      its factor, and together they take a sign-in to HIGH.
//   E. What is kept: no address in the clear anywhere in an assessment, the
//      session's context replaced, the person's standing kept with its
//      previous level.
//   F. `assess()` never rejects, and a person nobody named is not assessed.
//   G. An operator's factor (`risk.signalFactors`, calibration) is the one a
//      sign-in is scored with, and an entry naming no signal is ignored.
//
// Every address is a documentation one (RFC 5737), every list synthetic.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const audit = require('../common/audit');
const riskStore = require('../risk/risk_store');
const riskDatasets = require('../risk/risk_datasets');
const riskFailures = require('../risk/risk_failures');
const riskEngine = require('../risk/risk_engine');

const log = require('bunyan').createLogger({ name: 'risk_engine',
  level: process.env.LOG_LEVEL || 'info' });

const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
const SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) ' +
  'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 ' +
  'Safari/604.1';
const REALM = 'default';
const ALICE = 'urn:uuid:00000000-0000-4000-8000-00000000a11c';

// One sign-in's input, as `authn/authn.ts` builds it.
function signIn(address, userAgent, extra) {
  log.debug("Entering signIn().");
  const e = extra || {};
  log.debug("Leaving signIn().");
  return riskEngine.assess({
    realm: REALM, subject: e.subject || ALICE,
    sessionId: e.sessionId ||
      'session-' + require('crypto').randomBytes(8).toString('hex'),
    door: 'the sign-in screen', clientId: 'a-client',
    context: { address: address, uaFingerprint: 'fp-' + userAgent.length,
               ja4: e.ja4 || '', credential: { kind: 'password' } },
    userAgent: userAgent });
}

async function run(t) {
  log.debug("Entering run().");
  riskStore.reset();
  riskDatasets.forget();

  // --- A. the device --------------------------------------------------------
  const chrome = riskEngine.deviceOf(CHROME);
  const iphone = riskEngine.deviceOf(SAFARI);
  const curl = riskEngine.deviceOf('curl/8.5.0');
  const none = riskEngine.deviceOf('');
  t.check(chrome.browser === 'Chrome 140' && chrome.os === 'Windows 10' &&
          chrome.device === 'desktop' && !chrome.bot,
          'A1. a desktop Chrome is Chrome 140 on Windows 10, a desktop, not ' +
          'automated', JSON.stringify(chrome));
  t.check(iphone.device === 'mobile' && /^Safari 18/.test(iphone.browser) &&
          /^iOS/.test(iphone.os),
          'A2. an iPhone\'s Safari is a mobile', JSON.stringify(iphone));
  t.check(curl.bot === true && none.present === false && none.bot === false,
          'A3. curl is an automated client, and an empty User-Agent is ' +
          'answered rather than thrown on', JSON.stringify([curl, none]));

  // --- B. a first sign-in ---------------------------------------------------
  const first = await signIn('192.0.2.10', CHROME);
  t.check(first && first.level === 'UNSCORED' &&
          first.signals[0].score === null && first.decision === 'observe',
          'B1. a first sign-in is recorded UNSCORED, and decides nothing',
          JSON.stringify(first && first.signals));

  // --- B, continued. too little history (risk.minimumHistory, 5) -----------
  const second = await signIn('192.0.2.10', CHROME);
  t.check(second && second.level === 'UNSCORED' &&
          second.signals[0].score === null &&
          /risk\.minimumHistory/.test(String(second.signals[0].why)),
          'B2. with risk.minimumHistory at its default (5), a SECOND ' +
          'sign-in is UNSCORED too — one earlier sign-in is too little ' +
          'history to score, and nothing asks for more',
          JSON.stringify(second && second.signals));
  const thinBot = await signIn('192.0.2.10', 'python-requests/2.32',
                               { ja4: 't13i111111_111111111111_111111111111' });
  t.check(thinBot && thinBot.signals.some(function (s) {
    return s.signal === 'automated-client';
  }) && !thinBot.signals.some(function (s) {
    return s.signal === 'new-tls-stack' || s.signal === 'new-device';
  }),
          'B3. and on so little history the NOVELTY signals wait too, while ' +
          'an EVIDENCE signal (an automated client) still counts',
          JSON.stringify(thinBot && thinBot.signals));
  config.setOverride('risk.minimumHistory', 1);

  // --- C. the same person again ---------------------------------------------
  const again = await signIn('192.0.2.10', CHROME);
  t.check(again && again.level === 'LOW' && again.score < 1,
          'C1. the same person from the same network and device scores LOW',
          again && again.score);

  // --- D. the evaluators ----------------------------------------------------
  config.setOverride('risk.datasetShrinkLimitPercent', 100);
  await require('../risk/risk_terms').accept({ provider: 'tor-project',
    acceptedBy: 'a test', via: 'upload' });
  await riskDatasets.importVersion({ dataset: 'iplist.tor-exit',
    format: 'ip-list', content: '203.0.113.66\n', version: 'tor-test',
    source: 'upload' });
  const tor = await signIn('203.0.113.66', CHROME);
  t.check(tor && tor.signals.some(function (s) {
    return s.signal === 'tor-exit' && s.factor === 5;
  }) && tor.ipLists.indexOf('tor-exit') >= 0,
          'D1. an address on the Tor list is a tor-exit signal (×5)',
          JSON.stringify(tor && tor.signals));
  const bot = await signIn('192.0.2.10', 'python-requests/2.32',
                           { ja4: 't13i000000_000000000000_000000000000' });
  t.check(bot && bot.signals.some(function (s) {
    return s.signal === 'automated-client';
  }) && bot.signals.some(function (s) {
    return s.signal === 'new-tls-stack';
  }),
          'D2. an automated client, over a TLS stack this person never used, ' +
          'is two signals', JSON.stringify(bot && bot.signals));
  for (let i = 0; i < 5; i++) {
    await audit.withSource({ address: '198.51.100.20' }, function () {
      return riskFailures.recordFailure('alice-typed', 'the sign-in screen',
                                        'STS-AUTHN-0054');
    });
  }
  // The failures above name nobody (no directory here), so the account
  // signal is proved on the person's own subject through the store.
  for (let i = 0; i < 5; i++) {
    await riskStore.recordFailure({ realm: REALM, at: Date.now(),
      door: 'an LDAP simple bind', subject: ALICE, nameHmac: '',
      addressSealed: '', addressPrefix: '198.51.100.0/24', asn: 0,
      errorCode: 'STS-AUTHN-0054' }, false);
  }
  const hot = await signIn('203.0.113.66', 'curl/8.5.0');
  t.check(hot && hot.level === 'HIGH' && hot.signals.some(function (s) {
    return s.signal === 'account-failures';
  }),
          'D3. a Tor exit, an automated client and five refused passwords ' +
          'for the person in the last hour take a sign-in to HIGH',
          hot && (hot.level + ' ' + hot.score + ' ' +
                  JSON.stringify(hot.signals.map(function (s) {
                    return s.signal;
                  }))));

  // --- E. what is kept ------------------------------------------------------
  const view = await riskEngine.view(REALM, {});
  const text = JSON.stringify(view);
  t.check(view.assessments.total === 7 &&
          text.indexOf('192.0.2.10') < 0 && text.indexOf('203.0.113.66') < 0,
          'E1. every assessment is listed, and no address is in any of them ' +
          'in the clear — the network prefix only', view.assessments.total);
  const standing = view.subjects.filter(function (p) {
    return p.subject === ALICE;
  })[0] || {};
  t.check(standing.level === 'HIGH' && !!standing.previousLevel &&
          standing.lastAssessment === hot.id,
          'E2. the person\'s standing is the latest assessment\'s, with the ' +
          'level it came from',
          JSON.stringify(standing));
  const session = await signIn('192.0.2.10', CHROME,
                               { sessionId: 'session-kept' });
  const kept = riskStore.sessionContextOf(REALM, 'session-kept');
  t.check(kept && kept.addressPrefix === '192.0.2.0/24' &&
          kept.level === session.level,
          'E3. the session\'s context is kept for continuous evaluation',
          JSON.stringify(kept));

  // --- F. never rejects -----------------------------------------------------
  const nobody = await riskEngine.assess({ realm: REALM, subject: '' });
  let rejected = false;
  const odd = await riskEngine.assess({ realm: REALM, subject: ALICE,
    context: null, userAgent: null }).catch(function () {
      rejected = true;
    });
  t.check(nobody === null && !rejected && odd && odd.level,
          'F1. a sign-in naming nobody is not assessed, and one with no ' +
          'context is assessed rather than rejected', JSON.stringify(odd &&
                                                        odd.level));
  // --- G. an operator's factor ----------------------------------------------
  // An operator's factor (calibration, #62): risk.signalFactors changes
  // the factor a sign-in is scored with, and an entry naming no signal is
  // ignored rather than breaking the rest.
  config.setOverride('risk.signalFactors', 'tor-exit=8,no-such-signal=3');
  let tuned = null;
  try {
    tuned = await signIn('203.0.113.66', CHROME);
  } finally {
    config.clearOverride('risk.signalFactors');
  }
  const factors = riskEngine.factors();
  t.check(tuned && tuned.signals.some(function (s) {
    return s.signal === 'tor-exit' && s.factor === 8;
  }) && factors.factors['tor-exit'] === 5,
          'G1. risk.signalFactors scores tor-exit at ×8, and cleared it is ' +
          '×5 again', JSON.stringify(tuned && tuned.signals));

  config.setOverride('risk.datasetShrinkLimitPercent', 50);
  config.clearOverride('risk.minimumHistory');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_engine',
  describe: 'assessing a sign-in (#62 P2): the device a User-Agent names, a ' +
            'first sign-in unscored, the same person LOW, the evaluators ' +
            'taking a sign-in to HIGH, no address kept in the clear, the ' +
            'person\'s standing and the session\'s context kept, and never ' +
            'a rejection',
  run: run
};
