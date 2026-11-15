// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_pep_console.js
//
// ===========================================================================
// WHAT THE REMOTE PEPS TAB DRAWS ABOUT A PEP'S NOTIFY URL AND ITS LISTENERS
// (2026-11-14), held in node against `xacml/web_xacml.ts`, the renderer the
// console bundles. Two defects found on the 8081 demo:
//
//   N. THE NOTIFY COLUMN drew the service's whole sentence about an unusable
//      URL, and what the last nudge met, inline. It now draws a short status
//      — usable, unusable with a one-line reason, or not set — and the long
//      sentences in a `<details>`, collapsed, which needs no script.
//   L. THE LISTENER TAB drew a listener whose state the PEP never reported
//      as "listening". A missing report, or a state that is not one of the
//      four, reads "not reported"; an environment plain-HTTP listener with
//      no report reads as its default, off, labelled as the default; and a
//      reported `http-off` reads "off (PEP_HTTP=false)".
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'xacml_pep_console',
  level: process.env.LOG_LEVEL || 'info' });

// A row of `listenerRows` as the service answers it.
function envRow(id, protocol, enable, reported) {
  log.debug("Entering envRow(). " + id);
  log.debug("Leaving envRow().");
  return { id: id, source: 'environment', protocol: protocol,
           purpose: 'api', env: protocol === 'http' ? 'PEP_PORT'
             : 'PEP_HTTPS_PORT',
           enable: enable, defaultPort: protocol === 'http' ? 9090 : 9443,
           definition: null, reported: reported };
}

async function run(t) {
  log.debug("Entering run().");
  const XacmlPage = require('../xacml/web_xacml');
  const kit = require('../admin-ui/web_kit');
  const tr = kit.context({}, true).t;

  // -------------------------------------------------------------------------
  t.log.info('=== N. the notify column ===');
  // -------------------------------------------------------------------------
  const long = 'This notify URL is plain http, and a nudge is sent over ' +
    'https only: register the PEP\'s HTTPS notify URL, ' +
    'https://<host>:<PEP_HTTPS_PORT>/notify. Until then it converges by ' +
    'polling.';
  const plain = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'http://pep:9090/notify', notifyProblem: long,
    lastNotify: '2026-11-14T00:00:00.000Z — The nudge could not be ' +
      'delivered: a long sentence about a certificate.' });
  const shortPart = plain.split('<details')[0];
  t.check(shortPart.indexOf('plain http') >= 0 &&
          shortPart.indexOf('HTTPS only') >= 0 &&
          shortPart.indexOf('converges by polling') < 0,
          'N1. an http URL is "unusable" with a one-line reason, and the ' +
          'long sentence is not in the cell itself', shortPart);
  t.check(/<details class="sub"><summary>Details<\/summary>/.test(plain) &&
          plain.indexOf(' open') < 0 &&
          plain.split('<details')[1].indexOf('converges by polling') >= 0 &&
          plain.split('<details')[1].indexOf('a long sentence') >= 0,
          'N2. the long sentences are in a <details>, collapsed', plain);
  t.check(shortPart.indexOf('last nudge: not delivered') >= 0,
          'N3. the last nudge is two words in the cell', shortPart);
  const fine = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'https://pep:9443/notify', notifyProblem: null,
    lastNotify: '2026-11-14T00:00:00.000Z — The PEP answered 204.' });
  t.check(fine.indexOf('usable') >= 0 && fine.indexOf('unusable') < 0 &&
          fine.indexOf('last nudge: delivered') >= 0 &&
          fine.indexOf('<details') >= 0,
          'N4. an https URL is "usable", its last delivery said briefly',
          fine);
  const quiet = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'https://pep:9443/notify', notifyProblem: null });
  t.check(quiet.indexOf('<details') < 0,
          'N5. with nothing long to say there is no <details>', quiet);
  const host = XacmlPage.pepNotify(tr, {
    effectiveNotifyUrl: 'https://pep:9443/notify',
    notifyProblem: 'The host "pep" is not in xacml.pepNotifyAllowedHosts ' +
      '(other.test).' });
  t.check(host.split('<details')[0].indexOf('AllowedHosts') >= 0,
          'N6. a host off the allowlist says so in one line', host);
  const none = XacmlPage.pepNotify(tr, {});
  t.check(none.indexOf('never nudged') >= 0 && none.indexOf('<details') < 0,
          'N7. no notify URL is "none"', none);

  // -------------------------------------------------------------------------
  t.log.info('=== L. the listener tab\'s state cell ===');
  // -------------------------------------------------------------------------
  const words = XacmlPage.listenerWords(tr);
  const unreported = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP', null));
  t.check(unreported.indexOf('listening') < 0 &&
          unreported.indexOf('not reported') >= 0 &&
          unreported.indexOf('PEP_HTTP') >= 0,
          'L1. an unreported plain-HTTP listener is "off" by its default and ' +
          '"not reported", never "listening"', unreported);
  const nullState = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP', { state: null, reason: null }));
  t.check(nullState.indexOf('listening') < 0 &&
          nullState.indexOf('not reported') >= 0,
          'L2. a report whose state is null is "not reported"', nullState);
  const httpsNull = XacmlPage.listenerState(tr, words,
    envRow('api-https', 'https', '', { state: 'bogus' }));
  t.check(httpsNull.indexOf('listening') < 0 &&
          httpsNull.indexOf('not reported') >= 0 &&
          httpsNull.indexOf('by default') < 0,
          'L3. an unknown state on the HTTPS listener is "not reported", ' +
          'with no plain-HTTP default', httpsNull);
  const off = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP',
           { state: 'off', reason: 'http-off', port: 9090 }));
  t.check(off.indexOf('listening') < 0 &&
          off.indexOf('PEP_HTTP=false') >= 0,
          'L4. a reported http-off reads "off (PEP_HTTP=false)"', off);
  const crl = XacmlPage.listenerState(tr, words,
    envRow('api-http', 'http', 'PEP_HTTP',
           { state: 'listening', reason: 'crl-only', port: 9090 }));
  t.check(crl.indexOf('listening') >= 0 && crl.indexOf('CRLs only') >= 0,
          'L5. the CRL-only listener reads "listening — CRLs only"', crl);
  const on = XacmlPage.listenerState(tr, words,
    envRow('api-https', 'https', '',
           { state: 'listening', reason: 'none', port: 9443 }));
  t.check(on.indexOf('listening') >= 0 && on.indexOf('not reported') < 0,
          'L6. a reported listening listener reads "listening"', on);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xacml_pep_console',
  describe: 'The Remote PEPs tab: the notify column\'s short status with the ' +
            'long sentences collapsed, and a listener state never drawn as ' +
            'listening unless the PEP reported it',
  run: run
};
