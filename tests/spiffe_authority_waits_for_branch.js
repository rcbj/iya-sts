// ---------------------------------------------------------------------------
// File: spiffe_authority_waits_for_branch.js
//
// A REALM'S SPIFFE START WAITS FOR THE BRANCH ANOTHER NODE IS WRITING, rather
// than building a self-signed X.509 authority of its own (2026-09-24).
//
// In `cluster`, the node that did not create a realm learns of it from the
// change log and binds the realm's SPIFFE sockets at once, a few hundred
// milliseconds before the realm's certificate authority branch reaches it.
// `SpiffeCa.buildTrustMaterial()` found no SPIFFE Issuing CA, built a
// self-signed authority, and node A's Broker endpoint presented certificates
// no bundle publishes: `sts_spiffe_broker` was refused `self-signed
// certificate in certificate chain`. `awaitSpiffeIssuer()` pulls the realm's
// row from the store on every look and waits a bounded time. This drives it
// with the PKI and the keystore stubbed, and checks the call site reads it
// before the self-signed fallback.
// ---------------------------------------------------------------------------
'use strict';

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'spiffe_authority_waits_for_branch',
  level: process.env.LOG_LEVEL || 'info' });

const spiffeCa = require('../spiffe/spiffe_ca');

function caWith(describeIssuer, refreshPki) {
  log.debug("Entering caWith().");
  const deps = Object.assign({}, spiffeCa.SpiffeCa.defaultDeps());
  deps.pki = Object.assign(Object.create(deps.pki), {
    describeIssuer: describeIssuer
  });
  deps.loadKeystore = function () {
    log.debug("Entering loadKeystore().");
    log.debug("Leaving loadKeystore().");
    return { refreshPki: refreshPki };
  };
  log.debug("Leaving caWith().");
  return new spiffeCa.SpiffeCa(deps);
}

async function run(t) {
  log.debug("Entering run().");
  // The wait's timers are unref()'d, as a service's should be; nothing else
  // holds this process open.
  const keepAlive = setInterval(function () {}, 1000);
  try {
    // 1. ALREADY HERE: answered at once, after one pull.
    let pulls = 0;
    let ca = caWith(function (id, useCase) {
      return useCase === 'spiffe' ? { subject: 'CN=SPIFFE Issuing CA' } : null;
    }, function () {
      pulls += 1;
      return Promise.resolve();
    });
    let began = Date.now();
    t.equal(await ca.awaitSpiffeIssuer('r1'), true,
            'a realm whose SPIFFE Issuing CA is held is answered true');
    t.check(Date.now() - began < 200 && pulls === 1,
            'at once, after pulling its row once',
            (Date.now() - began) + 'ms, ' + pulls + ' pull(s)');

    // 2. ARRIVING FROM THE STORE: the pull is what brings it.
    let stored = false;
    let arrived = false;
    pulls = 0;
    setTimeout(function () {
      stored = true;
    }, 700).unref();
    ca = caWith(function () {
      return arrived ? { subject: 'CN=SPIFFE Issuing CA' } : null;
    }, function () {
      pulls += 1;
      if (stored) {
        arrived = true;
      }
      return Promise.resolve();
    });
    began = Date.now();
    const settled = await ca.awaitSpiffeIssuer('r2');
    const waited = Date.now() - began;
    t.equal(settled, true,
            'a branch another node writes a moment later is waited for, not ' +
            'replaced by a self-signed authority');
    t.check(waited >= 650 && waited < 5000 && pulls >= 2,
            'and the wait ends on the pull that finds it — not before, and ' +
            'not at the bound', waited + 'ms, ' + pulls + ' pull(s)');
  } finally {
    clearInterval(keepAlive);
  }

  // 3. THE CALL SITE: the wait comes before the self-signed fallback.
  const source = fs.readFileSync(path.join(__dirname, '..', 'spiffe',
                                           'spiffe_ca.ts'), 'utf8');
  t.check(/\n\s*if \(pki\.hasRoot\(\) && await this\.awaitSpiffeIssuer\(id\)\) \{[\s\S]*makeX509Authority\(/
            .test(source),
          'buildTrustMaterial() waits for the branch, where a Root exists, ' +
          'BEFORE it builds a self-signed X.509 authority');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_authority_waits_for_branch',
  describe: 'a realm\'s SPIFFE start waits for the certificate authority ' +
            'branch another node is still writing, rather than building a ' +
            'self-signed authority no bundle publishes',
  run: run
};
