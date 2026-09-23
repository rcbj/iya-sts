'use strict';
//
// File: risk_model.js
//
// ===========================================================================
// THE FREEMAN ET AL. PORT, HELD TO THE NOTEBOOK IT WAS PORTED FROM (#62 P2,
// 2026-09-23).
//
// `risk/risk_model.ts` is a port of `das-group/rba-algorithm`'s
// `freeman_rba_score()`. The notebook's own test compares against scores
// computed from das-group's RBA dataset, and that dataset is THIRD-PARTY
// DATA this repository does not carry (the licence review on #62). So the
// check is made the other way round: the notebook's code cells were run,
// unchanged, on the SYNTHETIC history below — eight invented users,
// documentation-range addresses (RFC 5737), documentation ASNs (RFC 5398)
// and invented user agents, seeded (Python's random.Random(62)) — scoring
// every sign-in against the history before it, exactly as its
// `login_test_single()` does. EXPECTED is what the notebook answered, and
// every one must be reproduced here to a relative error of 1e-9.
//
// A score the port got wrong in any of the notebook's edge cases — the
// unsmoothed user side, the smoothing at the first level only, the quarter
// of the population likelihood for a value never used — moves some of these
// numbers, so this is the test that says the port is a port.
//
// Also held: a first sign-in is not scored, and a familiar sign-in scores
// far below an unfamiliar one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const riskModel = require('../risk/risk_model');

const log = require('bunyan').createLogger({ name: 'risk_model',
  level: process.env.LOG_LEVEL || 'info' });

// userid, address, ASN, country, user agent, browser, OS, device — the
// notebook's column order.
const ROWS = [
  ['u07', '192.0.2.2', 64496, 'AU', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u00', '198.51.100.4', 64499, 'FR', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u06', '198.51.100.4', 64499, 'FR', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-e', 'Chrome 139', 'Android 15', 'mobile'],
  ['u03', '192.0.2.4', 64496, 'AU', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u07', '192.0.2.2', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u03', '192.0.2.6', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u01', '192.0.2.1', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u07', '192.0.2.4', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u04', '198.51.100.1', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u07', '192.0.2.2', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u00', '198.51.100.4', 64499, 'FR', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u02', '192.0.2.1', 64496, 'AU', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u02', '192.0.2.3', 64496, 'AU', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u01', '192.0.2.2', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u03', '192.0.2.6', 64496, 'AU', 'ua-e', 'Chrome 139', 'Android 15', 'mobile'],
  ['u04', '198.51.100.2', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-d', 'Firefox 142', 'Linux', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u07', '192.0.2.2', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u03', '192.0.2.6', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u00', '198.51.100.4', 64499, 'FR', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u01', '192.0.2.2', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u00', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u06', '192.0.2.4', 64496, 'AU', 'ua-d', 'Firefox 142', 'Linux', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u00', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u02', '198.51.100.3', 64497, 'DE', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u06', '192.0.2.6', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '198.51.100.4', 64499, 'FR', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u03', '198.51.100.2', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u00', '198.51.100.4', 64499, 'FR', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u01', '192.0.2.4', 64496, 'AU', 'ua-e', 'Chrome 139', 'Android 15', 'mobile'],
  ['u03', '192.0.2.4', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u00', '198.51.100.4', 64499, 'FR', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '192.0.2.3', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u02', '192.0.2.4', 64496, 'AU', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u01', '192.0.2.2', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u06', '198.51.100.1', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-d', 'Firefox 142', 'Linux', 'desktop'],
  ['u03', '192.0.2.1', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u03', '192.0.2.6', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u03', '192.0.2.4', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u07', '198.51.100.3', 64497, 'DE', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u00', '198.51.100.4', 64499, 'FR', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u06', '192.0.2.6', 64496, 'AU', 'ua-d', 'Firefox 142', 'Linux', 'desktop'],
  ['u06', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u07', '192.0.2.2', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u05', '198.51.100.4', 64499, 'FR', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u00', '198.51.100.4', 64499, 'FR', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u07', '192.0.2.2', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u04', '198.51.100.3', 64497, 'DE', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u01', '192.0.2.2', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u05', '192.0.2.3', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u04', '192.0.2.5', 64498, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u07', '198.51.100.1', 64497, 'DE', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u06', '192.0.2.5', 64498, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
  ['u03', '192.0.2.6', 64496, 'AU', 'ua-b', 'Chrome 140', 'macOS 15', 'desktop'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u02', '198.51.100.2', 64497, 'DE', 'ua-c', 'Safari 18', 'iOS 18', 'mobile'],
  ['u07', '192.0.2.2', 64496, 'AU', 'ua-a', 'Chrome 140', 'Windows 10', 'desktop'],
];

// [index into ROWS, the notebook's score for that sign-in]
const EXPECTED = [
  [4, 0.04622383838953852],
  [6, 1.2983015657772725],
  [7, 0.6879021712311397],
  [9, 1.1862745098039218],
  [10, 4.0555555555555545],
  [11, 0.028465965859957955],
  [12, 0.04923815251538413],
  [13, 0.0583368436229122],
  [15, 0.3440067745922331],
  [16, 0.06372638639827313],
  [17, 0.019203577584132908],
  [19, 0.11102958296741866],
  [20, 0.5714285714285715],
  [21, 0.04526530322944351],
  [22, 0.6832222112060292],
  [23, 0.058905493473462134],
  [24, 0.5532572492624107],
  [25, 0.6522539738177472],
  [26, 5.00396455364869],
  [27, 0.3109780455946423],
  [28, 0.15410957561440902],
  [29, 0.6807534685562309],
  [30, 0.07350419288229024],
  [31, 0.11141619827866156],
  [32, 0.4211685563187607],
  [33, 0.0902990802501566],
  [34, 0.0726404604726192],
  [35, 0.06188308041094303],
  [36, 0.05793983928023243],
  [37, 0.35654489788829724],
  [38, 0.0730150380128042],
  [39, 4.130318799847825],
  [40, 7.8800620390001255],
  [41, 0.8729260535382986],
  [42, 0.357554351852468],
  [43, 0.10504309604071722],
  [44, 2.1346153846153846],
  [45, 0.07735460506845412],
  [46, 0.76140304199334],
  [47, 0.10664704992920035],
  [48, 0.09773112628808238],
  [49, 1.0369739197062162],
  [50, 5.739050750221257],
  [51, 0.08828861119436889],
  [52, 4.699999999999999],
  [53, 0.5365166808163363],
  [54, 0.09941821113917121],
  [55, 0.08025487928797351],
  [56, 0.08134785725552343],
  [57, 1.7443225875106307],
  [58, 0.35990181580059444],
  [59, 0.42598635945140323],
  [60, 2.129150432382407],
  [61, 1.1576688686990084],
  [62, 0.6393350134480793],
  [63, 0.09483530659985548],
  [64, 0.24494805370022626],
  [65, 0.31768960648666555],
  [66, 0.3500924693984765],
  [67, 2.8505711796894904],
  [68, 0.09323096819182408],
  [69, 0.2018934732574574],
  [70, 0.32817948931701885],
  [71, 12.696202531645572],
  [72, 0.10199060506607584],
  [73, 0.09856025358418695],
  [74, 0.2200418638166194],
  [75, 0.3389493154835492],
  [76, 0.04870271329097831],
  [77, 0.09627670142315309],
  [78, 0.18795254267671646],
  [79, 0.11855175938174115],
  [80, 0.41895885874417405],
  [81, 0.10332007653783291],
  [82, 7.804999419428367],
  [83, 1.287711306380302],
  [84, 0.04433793944822252],
  [85, 0.3002018012570855],
  [86, 0.2839494651929995],
  [87, 0.041208217309284964],
  [88, 0.039916823801667445],
  [89, 0.18091337413717012],
];

// A row as the model reads it: this service's level names.
function attemptOf(row) {
  log.debug("Entering attemptOf().");
  log.debug("Leaving attemptOf().");
  return { user: row[0], ip: row[1], asn: String(row[2]), country: row[3],
           ua: row[4], browser: row[5], os: row[6], device: row[7] };
}

async function run(t) {
  log.debug("Entering run().");
  const attempts = ROWS.map(attemptOf);
  let worst = 0;
  let wrong = [];
  EXPECTED.forEach(function (pair) {
    const i = pair[0];
    const before = attempts.slice(0, i);
    const user = before.filter(function (a) {
      return a.user === attempts[i].user;
    });
    const got = riskModel.score(attempts[i],
      riskModel.historyOf(user),
      riskModel.historyOf(before, function (a) {
        return a.user;
      }));
    const error = Math.abs(got.score - pair[1]) / Math.abs(pair[1]);
    worst = Math.max(worst, error);
    if (!(error < 1e-9)) {
      wrong.push(i + ': ' + got.score + ' vs ' + pair[1]);
    }
  });
  t.check(wrong.length === 0,
          'every one of the notebook\'s ' + EXPECTED.length + ' scores on ' +
          'the synthetic history is reproduced (worst relative error ' +
          worst.toExponential(2) + ')', wrong.slice(0, 5).join('; '));
  const first = riskModel.score(attempts[0], riskModel.historyOf([]),
    riskModel.historyOf(attempts.slice(1), function (a) {
      return a.user;
    }));
  t.check(first.score === null && /first sign-in/.test(first.why),
          'a first sign-in is not scored, and says why',
          JSON.stringify(first));
  const familiar = { user: 'x', ip: '192.0.2.200', asn: '64496',
                     country: 'AU', ua: 'ua-x', browser: 'Chrome 140',
                     os: 'Windows 10', device: 'desktop' };
  const strange = { user: 'x', ip: '203.0.113.9', asn: '64511',
                    country: 'NZ', ua: 'ua-y', browser: 'Opera 1',
                    os: 'Haiku', device: 'tv' };
  const history = [];
  for (let i = 0; i < 10; i++) {
    history.push(familiar);
  }
  const population = history.concat(attempts);
  const userOf = function (a) {
    return a.user;
  };
  const low = riskModel.score(familiar, riskModel.historyOf(history),
                              riskModel.historyOf(population, userOf));
  const high = riskModel.score(strange, riskModel.historyOf(history),
                               riskModel.historyOf(population, userOf));
  t.check(low.score < 1 && high.score > 1 && high.score > low.score * 100,
          'a familiar sign-in scores below 1, one from a new network and a ' +
          'new device above it', low.score + ' vs ' + high.score);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_model',
  describe: 'the Freeman et al. port reproduces das-group/rba-algorithm\'s ' +
            'own scores on a synthetic history, does not score a first ' +
            'sign-in, and ranks a familiar sign-in far below a strange one',
  run: run
};
