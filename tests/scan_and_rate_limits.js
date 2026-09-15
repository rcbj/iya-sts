'use strict';
//
// File: scan_and_rate_limits.js
//
// ===========================================================================
// THREE BOUNDS THAT WERE MODULE CONSTANTS, AND ONE THAT WAS WRONG FOR ONE
// BUCKET (2026-09-12).
//
//   1. **THE PORTAL'S SIGNING-KEY LIMITER** passed a literal 5 to
//      `websecurity.attempt()`, which applies one number to BOTH buckets — so
//      everybody behind one NAT or proxy shared five key generations a window.
//      `attempt()` takes `{ identity, address }` now, and the portal passes
//      `pki.personSelfServicePerIdentity` and `…PerAddress`, both five by
//      default, so an unedited service behaves exactly as it did.
//   2. **`credentials.factorScanLimit`** — the second-factor roster's cap.
//   3. **`portal.applicationScanLimit`** — the applications page's cap, which
//      its own comment called "a guard and not a setting".
//   4. **`xacml.pipMaxDesignators`** — the PIP query's cap, beside the rate
//      that multiplies it.
//
// WHY IN PROCESS: every one of these is a bound that a request reaches only by
// exceeding it — five key generations from one address, five thousand people,
// a thousand applications, fifty designators — and the claim in each case is
// that the NUMBER is read from the setting, which a stub makes cheap and a run
// against a stack makes a load test.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const config = require('../common/config');
const websecurity = require('../common/websecurity');
const credentials = require('../common/credentials');
const xacml = require('../xacml/xacml');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'scan_and_rate_limits',
  level: process.env.LOG_LEVEL || 'info' });

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function fromAddress(address) {
  log.debug("Entering fromAddress().");
  log.debug("Leaving fromAddress().");
  return { headers: {}, socket: { remoteAddress: address } };
}

function run(t) {
  log.debug("Entering run().");
  websecurity.reset();

  // -----------------------------------------------------------------------
  t.log.info('=== 1. a limit per bucket ===');
  const what = 'scan-limits-probe';
  const office = '198.51.100.7';
  const limits = { identity: 2, address: 4 };
  t.check(websecurity.attempt(what, fromAddress(office), 'ann', limits).ok &&
          websecurity.attempt(what, fromAddress(office), 'ann', limits).ok,
          'one person gets their two');
  const third = websecurity.attempt(what, fromAddress(office), 'ann', limits);
  t.check(!third.ok && third.kind === 'identity' && third.limit === 2,
          'and the third is refused by the IDENTITY bucket, at its own number',
          JSON.stringify(third));
  t.check(websecurity.attempt(what, fromAddress(office), 'ben', limits).ok,
          'while somebody else behind the SAME address is not — which a ' +
          'single number for both buckets could not say without being five ' +
          'for a whole office');
  const bucketed = websecurity.attempt(what, fromAddress(office), 'cat',
                                       limits);
  t.check(!bucketed.ok && bucketed.kind === 'address' && bucketed.limit === 4,
          'and the address bucket refuses at ITS number, counting everybody',
          JSON.stringify(bucketed));
  websecurity.reset();
  const bare = [1, 2, 3].map(function () {
    return websecurity.attempt(what, fromAddress('203.0.113.9'), 'dee', 2).ok;
  });
  t.equal(bare.join(','), 'true,true,false',
          'a bare number still means both buckets, as every existing caller ' +
          'relies on');
  websecurity.reset();
  const partial = [1, 2, 3, 4, 5, 6].map(function () {
    return websecurity.attempt(what, fromAddress('203.0.113.10'), 'eve',
                               { address: 100 }).ok;
  });
  t.equal(partial.join(','), 'true,true,true,true,true,false',
          'and a bucket left out falls back to its shared setting — five per ' +
          'identity by default');
  websecurity.reset();

  const portalSource = fs.readFileSync(path.join(__dirname, '..', 'portal',
                                                 'portal.js'), 'utf8');
  t.check(/attempt(?:Shared)?\('portal-signing-key',\s*req,\s*username, \{\s*identity: config\.value\('pki\.personSelfServicePerIdentity'\),\s*address: config\.value\('pki\.personSelfServicePerAddress'\)/
            .test(portalSource),
          'the portal\'s signing-key door passes the two settings rather ' +
          'than the literal 5 — read as source, since reaching it means five ' +
          'RSA key generations');
  t.equal(config.value('pki.personSelfServicePerIdentity') + '/' +
          config.value('pki.personSelfServicePerAddress'), '5/5',
          'and both default to the five it was');

  // -----------------------------------------------------------------------
  t.log.info('=== 2. the second-factor roster\'s cap ===');
  t.equal(credentials.secondFactorHolders([]).limit, 5000,
          'the roster reads five thousand by default');
  withSettings({ 'credentials.factorScanLimit': 7 }, function () {
    t.equal(credentials.secondFactorHolders([]).limit, 7,
            'and credentials.factorScanLimit when it is set');
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 3. the applications page\'s cap ===');
  t.check(/const limit = scanLimit\(\);\s*const scanned = all\.slice\(0, limit\);/
            .test(portalSource) &&
          /config\.value\('portal\.applicationScanLimit'\)/.test(portalSource),
          'the portal slices the registry at portal.applicationScanLimit — ' +
          'the page needs a signed-in session and a registry past the cap to ' +
          'reach over HTTP');
  t.check(/esc\(String\(found\.limit\)\)/.test(portalSource),
          'and the sentence that says it stopped prints the number in force ' +
          'rather than the constant');

  // -----------------------------------------------------------------------
  t.log.info('=== 4. the PIP query\'s cap ===');
  t.equal(xacml.pipMaxDesignators(), 50, 'fifty designators by default');
  withSettings({ 'xacml.pipMaxDesignators': 3 }, function () {
    t.equal(xacml.pipMaxDesignators(), 3,
            'and xacml.pipMaxDesignators when set');
  });
  const xacmlSource = fs.readFileSync(path.join(__dirname, '..', 'xacml',
                                                'xacml.js'), 'utf8');
  t.check(/const most = pipMaxDesignators\(\);\s*if \(nodes\.length > most\)/
            .test(xacmlSource),
          'and the query handler compares against it, not against the ' +
          'constant');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scan_and_rate_limits',
  describe: 'a rate limit per bucket for the portal\'s signing-key door, and ' +
            'three scan caps read from their settings',
  run: run
};
