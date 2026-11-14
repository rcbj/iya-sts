// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: certificate_trust_no_such_realm.js
//
// ===========================================================================
// THE VALIDATION DOOR FAILS CLOSED FOR A REALM THAT DOES NOT EXIST (#1147).
//
// A realm the door could not resolve was answered about the ambient realm, so
// a certificate could be judged by somebody else's policy and counted against
// them. Refused now, with paranoid mode reading as in force; and the default
// realm, a real realm by id and a realm record still resolve.
// ===========================================================================

delete process.env.CONFIG_FILE;

const door = require('../common/certificate_trust');
const realms = require('../common/realms');

const log = require('bunyan').createLogger({
  name: 'certificate_trust_no_such_realm',
  level: process.env.LOG_LEVEL || 'info' });

const GONE = 'no-such-realm-' + Date.now().toString(36);
const CODE = 'STS-PKI-0271';
const LEAF = { leaf: 'not a certificate' };

async function run(t) {
  log.debug("Entering run().");
  const before = door.counters('default')['jose-signer'].assessed;
  const sync = door.assessSync('jose-signer', LEAF, { realmId: GONE });
  t.check(sync.ok === false && sync.code === CODE,
          'the synchronous door refuses a realm that does not exist',
          JSON.stringify(sync));
  const later = await door.assess('jose-signer', LEAF, { realmId: GONE });
  t.check(later.ok === false && later.code === CODE,
          'the asynchronous door refuses it too', JSON.stringify(later));
  t.check(door.counters('default')['jose-signer'].assessed === before,
          'and neither is counted against the ambient realm');
  t.check(door.inForce(GONE).inForce === true,
          'paranoid mode reads as in force for it',
          JSON.stringify(door.inForce(GONE)));
  t.check(door.rowOn('jose-signer', GONE) === true, 'every row reads as on');
  t.check(door.applies('jose-signer', GONE) === true, 'so the check applies');
  t.equal(door.counters(GONE)['jose-signer'].assessed, 0,
          'its counters are empty, not the ambient realm\'s');
  t.equal(door.lastAudit(GONE).assessedAt, 0, 'and it has no audit');

  const made = realms.create({ id: GONE, name: GONE });
  t.check(made.ok, 'a realm of that name can then be made');
  try {
    const byId = door.assessSync('jose-signer', LEAF, { realmId: GONE });
    t.check(byId.code !== CODE, 'once it exists its id resolves', byId.code);
    const byRecord = door.counters(made.realm)['jose-signer'].assessed;
    t.equal(byRecord, door.counters(GONE)['jose-signer'].assessed,
            'and a realm record names the same realm as its id');
    const fromInside = realms.run(made.realm, function () {
      return door.inForce('default').decidedBy;
    });
    t.check(fromInside !== 'no such realm',
            'the default realm resolves from inside another', fromInside);
  } finally {
    realms.remove(GONE);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'certificate_trust_no_such_realm',
  describe: 'the certificate validation door refuses a realm that does not ' +
            'exist rather than answering about the ambient one',
  run: run
};
