// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   H. One shared network at the default threshold (#499), with datasets.
//   I. The same with NO datasets (#502): every address unmapped, as on a
//      container bridge. Repeated sign-ins stay LOW; a new address with no
//      ASN and no country is new, and the record says which levels were
//      unknown.
//   J. The device feature is `device-id`, not the model's `device` (#506):
//      the history's own feature names are none of the model's levels, a
//      fingerprint and a device type are counted apart, neither makes the
//      other "seen", and the model's factors are the same with fingerprints
//      as without them.
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
               ja4: e.ja4 || '', device: e.device || '',
               credential: { kind: 'password' } },
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
  // THE MODEL ROW EXPLAINS THE WHOLE SCORE (#499): the two features and the
  // user term multiply to the model's score, the counts the user term is
  // made of beside them — on the record, so on the API's assessment too —
  // and Monitoring → Risk draws all three.
  const row = (again && again.signals[0]) || {};
  const f = row.factors || {};
  const t3 = row.terms || {};
  t.check(typeof f.user === 'number' &&
          Math.abs(f.ip * f.ua * f.user - row.score) <= 1e-12 * row.score &&
          t3.users === 1 && t3.userSignIns > 0 &&
          t3.signIns === t3.userSignIns &&
          Math.abs(f.user - (1 / t3.users) / (t3.userSignIns / t3.signIns)) <
            1e-12,
          'C2. the model row carries ip, ua and the user term, which ' +
          'multiply to its score, and the counts the user term is made of',
          JSON.stringify(row));
  const recorded = (await riskEngine.view(REALM, { subject: ALICE, days: 1 }))
    .assessments.rows.filter(function (a) {
      return again && a.id === again.id;
    })[0] || {};
  let drawn = '';
  try {
    const RiskPage = require('../admin-ui/web_risk');
    drawn = RiskPage.assessmentsHtml({ query: {}, write: false },
      JSON.parse(JSON.stringify({
        assessments: { rows: [recorded], total: 1 }, subjects: [],
        assessmentsPaging: { page: 1, pages: 1, perPage: 50, firstRow: 1,
                             lastRow: 1, total: 1,
                             param: 'assessmentsPage', noun: 'assessments' },
        subjectsPaging: { page: 1, pages: 1, perPage: 25, firstRow: 0,
                          lastRow: 0, total: 0, param: 'subjectsPage',
                          noun: 'people' } })));
  } catch (e) {
    drawn = 'threw: ' + (e && e.message);
  }
  const rf = (recorded.signals && recorded.signals[0] &&
              recorded.signals[0].factors) || {};
  t.check(typeof rf.user === 'number' &&
          drawn.indexOf('model: ip ×') >= 0 &&
          drawn.indexOf('user ×' + Number(rf.user).toPrecision(3)) >= 0 &&
          drawn.indexOf((recorded.signals[0].terms || {}).signIns +
                        ' sign-ins') >= 0,
          'C3. the recorded assessment (what GET /admin-api/risk answers) ' +
          'keeps the user term, and Monitoring → Risk draws the model\'s ' +
          'three factors from it',
          drawn.slice(drawn.indexOf('<tbody>'), drawn.indexOf('<tbody>') +
                      600));

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
  await sharedNetwork(t);
  await unmappedNetwork(t);
  await deviceFeature(t);
  log.debug("Leaving run().");
}

// ---------------------------------------------------------------------------
// H. ONE SHARED NETWORK, AT THE DEFAULT THRESHOLD (#499). Every person behind
// one address with one browser — a NAT, a VPN, a container bridge, a test
// stack — and one of them signing in far more than the rest. With
// risk.minimumHistory at its default, a person whose earlier sign-ins are all
// from that same context is scored, and the score is mostly the model's
// user term (above 1: they sign in less than the average). At the default
// MEDIUM line (risk.mediumScorePercent 300, Freeman et al.'s θ calibrated —
// rcbj's decision on #499) that is LOW; at the old line of 1 it was MEDIUM,
// which is what refused the WS-Trust chain jobs on a long-lived service. A
// genuinely new address, or a new browser, still raises the score past it.
// ---------------------------------------------------------------------------
async function sharedNetwork(t) {
  log.debug("Entering sharedNetwork().");
  riskStore.reset();
  riskDatasets.forget();
  // Two networks in two countries, so a new address can be in a new one.
  // Without the datasets every address has no network and no country, which
  // the model counts as unseen since #502 — section I, below.
  await require('../risk/risk_terms').accept({ provider: 'dbip-lite',
    acceptedBy: 'a test', via: 'upload' });
  const networks = await riskDatasets.importVersion({ dataset: 'asn',
    format: 'dbip-asn-csv', version: 'h-asn', source: 'upload',
    content: '192.0.2.0,192.0.2.255,64496,Example Networks\n' +
             '198.18.8.0,198.18.8.255,64497,Documentation Carrier' });
  const places = await riskDatasets.importVersion({ dataset: 'geo.city',
    format: 'dbip-city-csv', version: 'h-city', source: 'upload',
    content: '192.0.2.0,192.0.2.255,OC,AU,Queensland,Example City,' +
             '-27.4748,153.017\n198.18.8.0,198.18.8.255,EU,DE,Berlin,' +
             'Berlin,52.52,13.405' });
  const SHARED = '192.0.2.50';
  const HEAVY = 'urn:uuid:00000000-0000-4000-8000-0000000000aa';
  const people = ['b1', 'b2', 'b3'].map(function (n) {
    return 'urn:uuid:00000000-0000-4000-8000-0000000000' + n;
  });
  const minimum = Number(config.value('risk.minimumHistory'));
  for (let i = 0; i < 30; i++) {
    await signIn(SHARED, CHROME, { subject: HEAVY });
  }
  let last = null;
  for (const person of people) {
    for (let i = 0; i <= minimum; i++) {
      last = await signIn(SHARED, CHROME, { subject: person });
    }
  }
  const model = (last && last.signals[0]) || {};
  const f = model.factors || {};
  t.check(Number(config.value('risk.mediumScorePercent')) === 300 &&
          last && last.level === 'LOW' && typeof model.score === 'number' &&
          model.score > 1 && last.score < 3 && f.user > 1 &&
          f.ip <= 1 && f.ua <= 1 && model.knownContext === true,
          'H1. a person with risk.minimumHistory (' + minimum + ') identical ' +
          'sign-ins on a shared network is LOW at the default MEDIUM line ' +
          '(3): the score is above 1 only by the user term, which says they ' +
          'sign in less than average and nothing about this context',
          JSON.stringify({ level: last && last.level, score: last &&
                           last.score, factors: f }));
  const person = people[people.length - 1];
  const newAddress = await signIn('198.18.8.10', CHROME,
                                  { subject: person });
  const newBrowser = await signIn(SHARED, 'Mozilla/5.0 (X11; Linux x86_64; ' +
    'rv:142.0) Gecko/20100101 Firefox/142.0', { subject: person });
  t.check(networks && networks.ok && places && places.ok &&
          newAddress && newBrowser &&
          newAddress.score > last.score * 2 &&
          newBrowser.score > last.score * 2 &&
          newAddress.level !== 'LOW' && newBrowser.level !== 'LOW' &&
          JSON.stringify(newAddress.signals[0].unknown) === '[]' &&
          JSON.stringify(model.unknown) === '[]',
          'H2. a genuinely new address (on a new network), or a new ' +
          'browser, still raises the ' +
          'same person\'s score past the MEDIUM line',
          JSON.stringify({ networks: networks.ok, places: places.ok,
                           known: last && last.score,
                           address: newAddress && newAddress.score,
                           browser: newBrowser && newBrowser.score }));
  log.debug("Leaving sharedNetwork().");
}

// ---------------------------------------------------------------------------
// I. NO DATASETS, ONE BRIDGE (#502). H again with nothing loaded: every
// address — a private one on a container bridge, as every suite job is —
// has no ASN and no country. Until #502 that empty network and country were
// values everybody shared, so a new address read as a new address on a
// known network and moved the score from 2.01 to 2.06. Now the two levels
// are unseen on both sides (Freeman et al. section II-C, Eq. (9)), so the
// person's repeated sign-ins from the bridge are still LOW (their address
// counts at the address level) and a new unmapped address is new.
// ---------------------------------------------------------------------------
async function unmappedNetwork(t) {
  log.debug("Entering unmappedNetwork().");
  riskStore.reset();
  riskDatasets.forget();
  const BRIDGE = '172.29.0.1';
  const HEAVY = 'urn:uuid:00000000-0000-4000-8000-0000000000ca';
  const people = ['c1', 'c2', 'c3'].map(function (n) {
    return 'urn:uuid:00000000-0000-4000-8000-0000000000' + n;
  });
  const minimum = Number(config.value('risk.minimumHistory'));
  for (let i = 0; i < 30; i++) {
    await signIn(BRIDGE, CHROME, { subject: HEAVY });
  }
  let last = null;
  for (const person of people) {
    for (let i = 0; i <= minimum; i++) {
      last = await signIn(BRIDGE, CHROME, { subject: person });
    }
  }
  const model = (last && last.signals[0]) || {};
  const f = model.factors || {};
  t.check(last && last.level === 'LOW' && last.score < 3 &&
          f.ip <= 1 && f.ua <= 1 && model.knownContext === true &&
          JSON.stringify(model.unknown) === '["asn","country"]',
          'I1. with no datasets, a person\'s repeated sign-ins from one ' +
          'bridge address stay LOW at the default MEDIUM line (H1\'s case, ' +
          'unmapped), a known context, with asn and country recorded unknown',
          JSON.stringify({ level: last && last.level, score: last &&
                           last.score, model: model }));
  const person = people[people.length - 1];
  const fresh = await signIn('172.29.0.9', CHROME, { subject: person });
  const freshModel = (fresh && fresh.signals[0]) || {};
  t.check(fresh && freshModel.factors && freshModel.factors.ip === 4 &&
          fresh.score > last.score * 3 && fresh.level !== 'LOW' &&
          freshModel.knownContext === false &&
          JSON.stringify(freshModel.unknown) === '["asn","country"]',
          'I2. a new address with no ASN and no country raises the score ' +
          'past the MEDIUM line: ip ×4, where the shared empty network gave ' +
          '~1 (2.01 → 2.06 on #499)',
          JSON.stringify({ known: last && last.score, fresh: fresh &&
                           fresh.score, factors: freshModel.factors }));
  const empties = await riskStore.featureCounts(REALM, '*',
    [{ feature: 'asn', value: '' }, { feature: 'country', value: '' }],
    false);
  const mine = await riskStore.featureCounts(REALM, person,
    [{ feature: 'asn', value: '' }, { feature: 'country', value: '' }],
    false);
  // Nor as a network or country an address was seen in: no ASN or country
  // was ever known here, so the combination rows the smoothing counts are
  // empty.
  const combos = [];
  for (const level of ['ip>asn', 'ip>country']) {
    combos.push(await riskStore.distinctValues(REALM, '*', level, '', false));
  }
  t.check(empties.length === 0 && mine.length === 0 &&
          combos[0] === 0 && combos[1] === 0,
          'I3. and a missing network or country is never counted as a ' +
          'value, for the population or the person, nor as a network or ' +
          'country an address was seen in',
          JSON.stringify({ population: empties, person: mine,
                           combinations: combos }));
  // `risk.listsMatchSpecialPurpose` sets the LISTS aside for a private
  // address (#226); it does not make the model treat one as familiar.
  config.setOverride('risk.listsMatchSpecialPurpose', false);
  let aside = null;
  try {
    aside = await signIn('10.0.0.7', CHROME, { subject: person });
  } finally {
    config.clearOverride('risk.listsMatchSpecialPurpose');
  }
  t.check(aside && aside.signals[0].factors &&
          aside.signals[0].factors.ip === 4 && aside.level !== 'LOW',
          'I4. with risk.listsMatchSpecialPurpose off, a new private address ' +
          'is still new to the model: the setting is about lists',
          JSON.stringify(aside && aside.signals[0]));
  let drawn = '';
  try {
    const RiskPage = require('../admin-ui/web_risk');
    drawn = RiskPage.modelCell(freshModel) + ' | ' +
      RiskPage.modelCell({ signal: 'model', score: null,
                           unknown: ['asn', 'country'] });
  } catch (e) {
    drawn = 'threw: ' + (e && e.message);
  }
  t.check(/model: ip ×4\.00 .* · unknown: asn, country \|/.test(drawn) &&
          /\| model: unknown: asn, country$/.test(drawn),
          'I5. Monitoring → Risk draws the unknown levels beside the ' +
          'factors, and on an unscored sign-in too', drawn);
  log.debug("Leaving unmappedNetwork().");
}

// ---------------------------------------------------------------------------
// J. THE DEVICE FEATURE HAS A NAME OF ITS OWN (#506). Until #506 the browser
// fingerprint / registered device was counted under `device`, the name of
// the model's device-type level (desktop, mobile), so the two shared one
// history per person. The fingerprints below are chosen to COLLIDE with the
// device types — a fingerprint reading `desktop`, then `mobile` — which is
// what shows a shared key: a fingerprint would count as a device type, and a
// device type would make a fingerprint "seen" (no `new-device`). The last
// check runs the same sign-ins twice, with and without fingerprints, and
// asks for the same model factors every time.
// ---------------------------------------------------------------------------
async function deviceFeature(t) {
  log.debug("Entering deviceFeature().");
  const levels = [];
  require('../risk/risk_model').FEATURES.forEach(function (f) {
    f.levels.forEach(function (l) {
      levels.push(l[0]);
    });
  });
  const own = riskEngine.HISTORY_FEATURES || [];
  t.check(riskEngine.DEVICE_ID_FEATURE === 'device-id' &&
          own.indexOf('device-id') >= 0 && levels.indexOf('device') >= 0 &&
          !own.some(function (name) {
            return levels.indexOf(name) >= 0 || name === 'user' ||
              name === '_total' || name.indexOf('>') >= 0;
          }),
          'J1. the history\'s own features (' + own.join(', ') + ') are ' +
          'none of the model\'s levels (' + levels.join(', ') + '), whose ' +
          'device type keeps the paper\'s name',
          JSON.stringify({ own: own, levels: levels }));

  const PERSON = 'urn:uuid:00000000-0000-4000-8000-0000000000d1';
  const ADDRESS = '192.0.2.77';
  // The sequence: enough history from one desktop browser with one
  // fingerprint, then a phone whose fingerprint reads `desktop`, a phone
  // whose fingerprint reads `mobile`, the desktop with that one, and the
  // phone with none.
  const steps = [];
  for (let i = 0; i < 6; i++) {
    steps.push({ ua: CHROME, device: 'fp-a' });
  }
  steps.push({ ua: CHROME, device: 'fp-a' });
  steps.push({ ua: SAFARI, device: 'desktop' });
  steps.push({ ua: SAFARI, device: 'mobile' });
  steps.push({ ua: CHROME, device: 'mobile' });
  steps.push({ ua: SAFARI, device: '' });
  const play = async function (fingerprints) {
    log.debug("Entering play(). " + fingerprints);
    riskStore.reset();
    riskDatasets.forget();
    const out = [];
    for (const s of steps) {
      out.push(await signIn(ADDRESS, s.ua, { subject: PERSON,
        device: fingerprints ? s.device : '' }));
    }
    log.debug("Leaving play().");
    return out;
  };
  const newDevice = function (a) {
    return !!a && a.signals.some(function (s) {
      return s.signal === 'new-device';
    });
  };
  const count = async function (feature, value) {
    log.debug("Entering count(). " + feature);
    const rows = await riskStore.featureCounts(REALM, PERSON,
      [{ feature: feature, value: value }], false);
    log.debug("Leaving count().");
    return rows.length ? rows[0].count : 0;
  };
  const withPrints = await play(true);
  const counted = {
    'device-id fp-a': await count('device-id', 'fp-a'),
    'device fp-a': await count('device', 'fp-a'),
    'device desktop': await count('device', 'desktop'),
    'device mobile': await count('device', 'mobile'),
    'device-id desktop': await count('device-id', 'desktop'),
    'device-id mobile': await count('device-id', 'mobile')
  };
  t.check(counted['device-id fp-a'] === 7 && counted['device fp-a'] === 0 &&
          counted['device desktop'] === 8 && counted['device mobile'] === 3 &&
          counted['device-id desktop'] === 1 &&
          counted['device-id mobile'] === 2,
          'J2. a fingerprint is counted under device-id and a device type ' +
          'under device, each once per sign-in, neither in the other\'s ' +
          'history', JSON.stringify(counted));
  t.check(!newDevice(withPrints[6]) && newDevice(withPrints[7]) &&
          newDevice(withPrints[8]),
          'J3. a fingerprint already seen is not new-device; one reading ' +
          '"desktop" or "mobile" is, although this person has signed in ' +
          'from a desktop (and, by then, a mobile) — the device type does ' +
          'not make a fingerprint seen',
          JSON.stringify(withPrints.slice(6, 9).map(function (a) {
            return a && a.signals.map(function (s) {
              return s.signal;
            });
          })));
  const factorsOf = function (list) {
    return JSON.stringify(list.map(function (a) {
      return a && a.signals[0].factors;
    }));
  };
  const without = await play(false);
  const scored = without.filter(function (a) {
    return a && a.signals[0].factors;
  }).length;
  t.check(scored >= 5 && factorsOf(withPrints) === factorsOf(without),
          'J4. and the model\'s factors are the same, sign-in by sign-in, ' +
          'with those fingerprints as without any: a fingerprint does not ' +
          'move the device-type level (' + scored + ' scored)',
          factorsOf(withPrints) + ' vs ' + factorsOf(without));
  log.debug("Leaving deviceFeature().");
}

module.exports = {
  name: 'risk_engine',
  describe: 'assessing a sign-in (#62 P2): the device a User-Agent names, a ' +
            'first sign-in unscored, the same person LOW, the evaluators ' +
            'taking a sign-in to HIGH, no address kept in the clear, the ' +
            'person\'s standing and the session\'s context kept, never ' +
            'a rejection, and the device feature apart from the device ' +
            'type (#506)',
  run: run
};
