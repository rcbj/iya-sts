'use strict';
//
// File: breached_passwords.js
//
// ===========================================================================
// A PASSWORD KNOWN FROM A DATA BREACH IS REFUSED (#62 P6, 2026-09-22), in
// process, with the Pwned Passwords range API STUBBED — nothing here dials
// the internet, and the "breached" password is one this file makes up and
// lists in its own fake answer.
//
//   A. K-ANONYMITY: only the five-character SHA-1 prefix is asked for; the
//      suffix is matched here; a range is asked for once and then cached.
//   B. THE RULE: in product mode, a screened password that is listed is
//      refused (STS-AUTHN-0222); a screened one that is not is set; a
//      padding decoy (count 0) is not a breach.
//   C. NOTHING DECIDED WITHOUT AN ANSWER: an API that does not answer, and a
//      door that did not screen, both set the password.
//   D. DEVELOPMENT MODE screens nothing; `risk.breachCheck` off screens
//      nothing.
//   E. A GENERATED password is not asked about.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const stsCrypto = require('../common/crypto');
const credentials = require('../common/credentials');
const breached = require('../common/breached_passwords');
const federationHttp = require('../federation/federation_http');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'breached_passwords',
  level: process.env.LOG_LEVEL || 'info' });

// Made up here, and "breached" only because the stub below says so.
const BREACHED = 'Correct-Horse-Battery-9';
const CLEAN = 'Unlisted-Passphrase-731';
const DECOY = 'Padding-Decoy-Passw0rd';

async function run(t) {
  log.debug("Entering run().");
  breached.forget();
  const asked = [];
  const bad = stsCrypto.pwnedPasswordDigest(BREACHED);
  const decoy = stsCrypto.pwnedPasswordDigest(DECOY);
  let answering = true;
  const original = federationHttp.fetchPublished;
  federationHttp.fetchPublished = function (url) {
    asked.push(String(url));
    if (!answering) {
      return Promise.resolve({ ok: false, status: 0, body: Buffer.alloc(0),
                               why: 'the test says no' });
    }
    const prefix = String(url).slice(-5);
    const lines = ['0000000000000000000000000000000000A:3'];
    if (prefix === bad.slice(0, 5)) {
      lines.push(bad.slice(5) + ':42');
    }
    if (prefix === decoy.slice(0, 5)) {
      lines.push(decoy.slice(5) + ':0');
    }
    return Promise.resolve({ ok: true, status: 200,
                             body: Buffer.from(lines.join('\r\n')) });
  };
  config.setOverride('global.mode', 'product');
  config.setOverride('risk.breachCheck', 'on');
  try {
    ldap.createUser('bp-carol', { invent: false });

    // --- A. k-anonymity ----------------------------------------------------
    const first = await breached.screen(BREACHED);
    const again = await breached.screen(BREACHED);
    t.check(first.checked && first.breached && first.count === 42 &&
            asked.length === 1 &&
            asked[0] === String(config.value('risk.breachApiUrl')) +
                         bad.slice(0, 5),
            'A1. only the five-character prefix is sent, the suffix is ' +
            'matched here, and the second screen is answered from the cache',
            JSON.stringify({ asked: asked, first: first, again: again }));
    t.check(asked.every(function (url) {
      return url.indexOf(bad.slice(5)) < 0 && url.indexOf(BREACHED) < 0;
    }), 'A2. neither the password nor the rest of its digest is ever sent');

    // --- B. the rule ---------------------------------------------------------
    const refused = credentials.setPassword('bp-carol', BREACHED);
    t.check(!refused.ok && refused.reason === 'breached',
            'B1. a screened, breached password is refused in product mode ' +
            '(STS-AUTHN-0222)', JSON.stringify(refused));
    await breached.screen(CLEAN);
    t.check(credentials.setPassword('bp-carol', CLEAN).ok,
            'B2. a screened password that is not listed is set');
    const padded = await breached.screen(DECOY);
    t.check(padded.checked && !padded.breached,
            'B3. a padding decoy, listed with a count of 0, is not a breach',
            JSON.stringify(padded));

    // --- C. nothing decided without an answer ------------------------------
    breached.forget();
    answering = false;
    const unanswered = await breached.screen('Another-Passphrase-512');
    t.check(!unanswered.checked &&
            credentials.setPassword('bp-carol', 'Another-Passphrase-512').ok,
            'C1. an API that does not answer decides nothing: the password ' +
            'is set', JSON.stringify(unanswered));
    answering = true;
    t.check(credentials.setPassword('bp-carol', 'Never-Screened-Pass-88').ok,
            'C2. a door that did not screen sets the password too — and is ' +
            'logged (STS-AUTHN-0223) so it is found');

    // --- D. off --------------------------------------------------------------
    config.setOverride('risk.breachCheck', 'off');
    const off = await breached.screen(BREACHED);
    config.setOverride('risk.breachCheck', 'on');
    config.setOverride('global.mode', 'development');
    const dev = await breached.screen(BREACHED);
    config.setOverride('global.mode', 'product');
    t.check(!off.checked && !dev.checked,
            'D1. risk.breachCheck off, and development mode, screen nothing');

    // --- E. generated --------------------------------------------------------
    await breached.screen(BREACHED);
    t.check(credentials.setPassword('bp-carol', BREACHED,
                                    { generated: true }).ok,
            'E1. a password the service generated is not asked about');
  } finally {
    federationHttp.fetchPublished = original;
    config.clearOverride('global.mode');
    config.clearOverride('risk.breachCheck');
    breached.forget();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'breached_passwords',
  describe: 'a password known from a data breach refused (#62 P6): only a ' +
            'five-character SHA-1 prefix sent to the Pwned Passwords range ' +
            'API (stubbed), refused in product mode, set when unanswered or ' +
            'unscreened, nothing screened in development or when off, and a ' +
            'generated password not asked about',
  run: run
};
