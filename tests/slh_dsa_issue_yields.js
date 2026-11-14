// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: slh_dsa_issue_yields.js
//
// ===========================================================================
// THE CERTIFICATE PATH'S SLH-DSA DOES NOT STOP ITS THREAD (#1464).
//
// `pqc_x509.generateKeyPair()` and `sign()` were `async` and called the
// synchronous primitives, so a hierarchy built with an `s` parameter set
// stopped its thread for seconds per key, and a store transaction that thread
// had open kept its locks throughout. This holds that the event loop turns
// while each runs, and that what comes out is still a working key pair.
// ===========================================================================

delete process.env.CONFIG_FILE;

const pqx = require('../common/crypto_impl/pqc_x509');

const log = require('bunyan').createLogger({ name: 'slh_dsa_issue_yields',
  level: process.env.LOG_LEVEL || 'info' });

const ALG = 'SLH-DSA-SHAKE-128s';

// How many times the event loop turned while `work` ran.
async function turnsDuring(work) {
  log.debug("Entering turnsDuring().");
  let turns = 0;
  let running = true;
  const spin = function () {
    if (running) {
      turns += 1;
      setImmediate(spin);
    }
  };
  setImmediate(spin);
  const value = await work();
  running = false;
  log.debug("Leaving turnsDuring(). " + turns);
  return { value: value, turns: turns };
}

async function run(t) {
  log.debug("Entering run().");
  const made = await turnsDuring(function () {
    return pqx.generateKeyPair(ALG);
  });
  t.check(made.turns > 0, 'the event loop turns while the key is generated',
          made.turns + ' turn(s)');
  const pair = made.value;
  const message = Buffer.from('a certificate to be signed');
  const signed = await turnsDuring(function () {
    return pqx.sign(ALG, message, pair.priv);
  });
  t.check(signed.turns > 0, 'the event loop turns while it signs',
          signed.turns + ' turn(s)');
  t.check(await pqx.verify(ALG, signed.value, message, pair.pub),
          'the signature verifies against the generated key');
  t.check(!await pqx.verify(ALG, signed.value, Buffer.from('other'), pair.pub),
          'and not over another message');
  t.equal(Buffer.from(pqx.publicFromPrivate(ALG, pair.priv)).toString('hex'),
          Buffer.from(pair.pub).toString('hex'),
          'the private key is in the form the rest of the path reads');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'slh_dsa_issue_yields',
  describe: 'generating and signing SLH-DSA on the certificate path lets ' +
            'the event loop turn',
  run: run
};
