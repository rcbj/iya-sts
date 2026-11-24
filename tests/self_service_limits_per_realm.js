// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: self_service_limits_per_realm.js
//
// ---------------------------------------------------------------------------
// THE SELF-SERVICE ISSUANCE LIMITS ARE COUNTED PER REALM (#2093).
//
// `pki.personSelfServicePerIdentity` and `…PerAddress` are realm settings,
// but the three doors that read them (the SSH user CA, the signing keys,
// the ACME and SCEP credentials) counted in buckets keyed by the door and
// the address or username alone, so one realm's issuances spent another's
// budget: `sts_ssh_user_ca.js` spent four of the runner's five and the next
// job's first issuance, in a DIFFERENT realm, was refused 429. And a
// username is unique only inside a realm, so two people called alice in two
// realms shared one identity budget.
//
//   A. through the account API's SSH door with the real limiter: an
//      address's budget spent in one realm is refused there and still
//      whole in another; the same username in two realms is two budgets;
//   B. the three doors name the realm in the door they count under, read
//      as source.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const log = require('bunyan').createLogger({
  name: 'self_service_limits_per_realm',
  level: process.env.LOG_LEVEL || 'info'
});

function contextWith(limits) {
  log.debug('Entering contextWith().');
  const errorCodes = require('../common/error_codes');
  const ctx = {
    websecurity: require('../common/websecurity'),
    errorCodes: errorCodes,
    config: { value: function (key) {
      if (key === 'pki.personSelfServicePerIdentity') {
        return limits.identity;
      }
      if (key === 'pki.personSelfServicePerAddress') {
        return limits.address;
      }
      return undefined;
    } },
    refuse: function (res, status, code) {
      return { status: status, code: code };
    },
    json: function (res, status) {
      return { status: status };
    },
    audit: { record: function () {} }
  };
  log.debug('Leaving contextWith().');
  return ctx;
}

function sshDoor() {
  log.debug('Entering sshDoor().');
  const provider = require('../account-api/ssh_user_ca');
  const door = new provider.AccountSshUserCa({
    log: log,
    sshUserCa: {
      issue: async function () {
        return { ok: true, line: 'ssh-ed25519-cert-v01 x' };
      }
    }
  });
  log.debug('Leaving sshDoor().');
  return door;
}

async function issue(door, ctx, realm, username, address) {
  log.debug('Entering issue().');
  const req = { headers: {}, socket: { remoteAddress: address } };
  const answer = await door.issue(ctx, req, {},
    { username: username, sub: 'urn:uuid:' + username, realm: realm },
    { publicKey: 'ssh-ed25519 AAAA', principals: [username] });
  log.debug('Leaving issue().');
  return answer.status;
}

async function byAddress(t) {
  log.debug('Entering byAddress().');
  const websecurity = require('../common/websecurity');
  websecurity.reset();
  const door = sshDoor();
  const ctx = contextWith({ identity: 100, address: 2 });
  const runner = '198.51.100.21';
  const first = [await issue(door, ctx, 'realm-a', 'ann', runner),
                 await issue(door, ctx, 'realm-a', 'ben', runner),
                 await issue(door, ctx, 'realm-a', 'cat', runner)];
  t.equal(first.join(','), '200,200,429',
          'A1. one address spends its two in realm-a and the third is 429');
  const other = [await issue(door, ctx, 'realm-b', 'dee', runner),
                 await issue(door, ctx, 'realm-b', 'eve', runner)];
  t.equal(other.join(','), '200,200',
          'A2. and the same address still has realm-b\'s two: realm-a\'s ' +
          'issuances spent nothing of it');
  websecurity.reset();
  log.debug('Leaving byAddress().');
}

async function byIdentity(t) {
  log.debug('Entering byIdentity().');
  const websecurity = require('../common/websecurity');
  websecurity.reset();
  const door = sshDoor();
  const ctx = contextWith({ identity: 1, address: 100 });
  const a = [await issue(door, ctx, 'realm-a', 'alice', '203.0.113.31'),
             await issue(door, ctx, 'realm-a', 'alice', '203.0.113.32')];
  t.equal(a.join(','), '200,429',
          'A3. alice in realm-a has one issuance a window');
  t.equal(await issue(door, ctx, 'realm-b', 'alice', '203.0.113.33'), 200,
          'A4. and alice in realm-b, another person, has her own');
  websecurity.reset();
  log.debug('Leaving byIdentity().');
}

function bySource(t) {
  log.debug('Entering bySource().');
  const read = function (rel) {
    return fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
  };
  const doors = [
    ['account-api/ssh_user_ca.ts', 'portal-ssh-user-ca'],
    ['portal/account_signing_key.ts', 'portal-signing-key'],
    ['portal/portal_certificates.ts', 'portal-enrollment']
  ];
  doors.forEach(function (one) {
    const source = read(one[0]);
    const named = new RegExp("attemptShared\\(\\s*'" + one[1] +
                             "@' \\+ caller\\.realm,");
    t.check(named.test(source) &&
            source.indexOf("'" + one[1] + "', req") < 0,
            'B. ' + one[0] + ' counts under "' + one[1] + '@<realm>"');
  });
  log.debug('Leaving bySource().');
}

async function run(t) {
  log.debug('Entering run().');
  await byAddress(t);
  await byIdentity(t);
  bySource(t);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'self_service_limits_per_realm',
  describe: 'the self-service issuance limits are counted per realm (#2093)',
  run: run
};
