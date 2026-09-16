'use strict';
//
// File: webauthn_addresses.js
//
// ===========================================================================
// THE ORIGIN AND THE RP ID A SECURITY-KEY CEREMONY IS HELD TO (2026-09-12).
//
// Both were derived from the address the REQUEST arrived at, and one of them
// silently replaced a configured value with it:
//
//   * the ORIGIN a clientDataJSON must carry was `originOf(baseUrlOf(req))` and
//     nothing else could say it — `webauthn.allowedOrigins` now, empty meaning
//     exactly that derivation, which `global.publicBaseUrl` already pins;
//   * a configured `webauthn.rpId` that did not fit the request's host FELL
//     BACK to that host and logged why — right for a mock reached under three
//     container names, and in product mode a ceremony scoped to whatever Host a
//     request carried. It is refused there now, by `rpIdProblem()`.
//
// `tests/webauthn_policy.js` holds the suffix rule itself and is not repeated
// here; what is here is the two new decisions and that the portal's ceremony
// asks the same functions the sign-in screen does.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS: `tests/webauthn_policy.js`'s reason. The origin and the RP ID
// only ever appear inside a ceremony a browser performs, and the product-mode
// half needs a mode no stack runs.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const config = require('../common/config');
const authn = require('../authn/authn');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'webauthn_addresses',
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

// A credential whose clientDataJSON names `origin` — all `expectedOriginFor()`
// reads of it.
function credentialFrom(origin) {
  log.debug("Entering credentialFrom().");
  log.debug("Leaving credentialFrom().");
  return { response: { clientDataJSON: Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge: 'x', origin: origin
  })).toString('base64url') } };
}

function run(t) {
  log.debug("Entering run().");
  const base = 'https://sts.example.com:8443/realm/acme';

  // -----------------------------------------------------------------------
  t.log.info('=== 1. the expected origin ===');
  t.equal(authn.expectedOriginFor(base, credentialFrom('https://evil.example')),
          'https://sts.example.com:8443',
          'unset, the origin is DERIVED from the base as it always was — and ' +
          'what the browser claims does not change it');
  withSettings({ 'webauthn.allowedOrigins':
                   'https://login.example.com, https://sso.example.com/' },
    function () {
      t.equal(authn.expectedOriginFor(base,
                                      credentialFrom(
                                          'https://sso.example.com')),
              'https://sso.example.com',
              'set, an origin ON THE LIST is the one the verifier expects — ' +
              'and a trailing slash in the setting is not part of an origin');
      t.equal(authn.expectedOriginFor(base,
                                      credentialFrom(
                                          'https://sts.example.com:8443')),
              'https://login.example.com',
              'while the origin the REQUEST arrived at is not accepted just ' +
              'for being the request\'s — the list is the whole answer, and ' +
              'a value off it is answered with the list\'s first so the ' +
              'verifier refuses it in its own words');
      t.equal(authn.expectedOriginFor(base,
                                      credentialFrom('https://evil.example')),
              'https://login.example.com',
              'and neither is an origin nobody listed');
      t.equal(authn.expectedOriginFor(base,
                                      { response: { clientDataJSON: '%%%' } }),
              'https://login.example.com',
              'and client data that will not decode is left to the verifier ' +
              'to refuse, rather than throwing here');
    });

  // -----------------------------------------------------------------------
  t.log.info('=== 2. an RP ID that does not fit ===');
  withSettings({ 'webauthn.rpId': 'attacker.example' }, function () {
    t.equal(authn.rpIdProblem(base), '',
            'DEVELOPMENT mode keeps the fallback — no refusal, the host is ' +
            'used and the log says why');
    t.equal(authn.rpIdOf(base), 'sts.example.com', 'as rpIdOf() reports');
    withSettings({ 'global.mode': 'product' }, function () {
      const problem = authn.rpIdProblem(base);
      t.check(/webauthn\.rpId/.test(problem) &&
              /global\.publicBaseUrl/.test(problem),
              'PRODUCT mode REFUSES the ceremony, naming the setting and the ' +
              'fix',
              problem);
    });
  });
  withSettings({ 'webauthn.rpId': 'example.com', 'global.mode': 'product' },
    function () {
      t.equal(authn.rpIdProblem(base), '',
              'while a value that IS a registrable suffix of the host is no ' +
              'problem in product mode either');
      t.check(authn.rpIdProblem('https://notexample.com') !== '',
              'and a host that ends in the RP ID as a STRING but not at a ' +
              'label boundary is refused — `endsWith()` alone is the mistake');
    });
  withSettings({ 'global.mode': 'product' }, function () {
    t.equal(authn.rpIdProblem(base), '',
            'and with no RP ID configured there is nothing to refuse — the ' +
            'host is the RP ID, which global.publicBaseUrl pins');
  });

  // -----------------------------------------------------------------------
  t.log.info('=== 3. both ceremonies ask the same functions ===');
  const root = path.join(__dirname, '..');
  const authnSource = fs.readFileSync(path.join(root, 'authn', 'authn.ts'),
                                      'utf8');
  const portalSource = fs.readFileSync(path.join(root, 'portal', 'portal.js'),
                                       'utf8');
  // `this.` since the module became a class (#50).
  t.check(/const expectedOrigin = (?:this\.)?expectedOriginFor\(base, credential\);/
            .test(authnSource) &&
          /const rpRefusal = (?:this\.)?rpIdProblem\(base\);/.test(
            authnSource),
          'the sign-in screen\'s verification asks expectedOriginFor() and ' +
          'rpIdProblem() — read as source, because the only other evidence ' +
          'is a ceremony a browser performs');
  t.check(/origin: authn\.expectedOriginFor\(base, credential\)/.test(
      portalSource) &&
          /authn\.rpIdProblem\(base\)/.test(portalSource) &&
          !/origin: authn\.originOf\(base\)/.test(portalSource),
          'and /portal/keys asks the SAME two, so the two ceremonies cannot ' +
          'accept different origins');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'webauthn_addresses',
  describe: 'webauthn.allowedOrigins as the whole list where it is set, and ' +
            'an RP ID that does not fit refused in product mode rather than ' +
            'replaced by the request\'s host',
  run: run
};
