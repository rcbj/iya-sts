// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cluster_autocreate_subject.js
//
// ===========================================================================
// A SIGN-IN'S ENTRY GETS A RANDOM entryUUID ON A CLUSTERED NODE TOO, AND A
// NAMESAKE NEVER GETS THE DELETED PERSON'S (2026-11-16, #1612's rule).
//
// From 2026-09-14 (#46) until 2026-11-16 an entry `autoCreateUser()` made on a
// clustered node (a cluster mode, or a dispatched request-worker pool) took the
// seed's version 5 value over the realm and the DN, so that two nodes racing
// to create one name's entry created the same subject. A person deleted and
// signing in again under the name there got the deleted person's
// `entryUUID` — their `sub`, and every store keyed by it. rcbj's rule since
// #1612 is that a namesake inherits nothing, and the race is covered without
// the derived value: the losing node's value is kept as an alias by
// `mergeCreateRace()`. This file holds:
//
//   A. a single node and a clustered node both give a sign-in's entry a
//      RANDOM (version 4) value;
//   B. on a clustered node, created, deleted and created again under the
//      same name: a DIFFERENT value, so a different subject;
//   C. two creates of one entry in two processes within the race window keep
//      both values (the lower primary, the other an alias), so the race #46
//      was about still yields one subject both nodes' tokens resolve to; a
//      RE-CREATE long after is not merged;
//   D. an entry that already carries a name-derived value (one created under
//      #46's rule) keeps it through an overwrite: an existing person's
//      subject does not change.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
// The mode is RESOLVED ONCE per process (`cluster.mode()` answers what the gate
// resolved), so a file that started persistence earlier in this process decided
// it — reset around each half, which is what a new process would see.
const cluster = require('../cluster/cluster');

const log = require('bunyan').createLogger({
  name: 'cluster_autocreate_subject', level: process.env.LOG_LEVEL || 'info' });

// Every setting clusteredNode() reads, named here so a file that ran earlier in
// this process cannot decide the answer (a leftover worker count did).
const VARIED = ['STS_CLUSTER_MODE', 'STS_PERSISTENCE_MODE', 'STS_MODE',
                'STS_WORKERS_REQUEST_COUNT', 'STS_WORKERS_DISPATCH',
                'STS_PERSISTENCE_MINTED'];

function versionOf(uuid) {
  log.debug("Entering versionOf().");
  log.debug("Leaving versionOf().");
  return String(uuid || '').charAt(14);
}

function run(t) {
  log.debug("Entering run().");
  const saved = {};
  VARIED.forEach(function (name) {
    saved[name] = process.env[name];
  });
  try {
    realms.run(realms.DEFAULT_REALM, function () {
      process.env.STS_MODE = 'development';
      process.env.STS_PERSISTENCE_MODE = 'memory';
      process.env.STS_WORKERS_REQUEST_COUNT = '0';
      process.env.STS_WORKERS_DISPATCH = '';
      process.env.STS_PERSISTENCE_MINTED = 'true';
      delete process.env.STS_CLUSTER_MODE;
      cluster.reset();
      const single = ldap.autoCreateUser({ key: 'cfsolo' + Date.now(),
                                           protocol: 'oauth2' });
      t.check(single && versionOf(ldap.entryUuidOf(single)) === '4',
              'A. ON A SINGLE NODE a sign-in\'s entry keeps a RANDOM entryUUID ' +
              '(version 4), so a person deleted and re-created under one name ' +
              'is a new subject', single && ldap.entryUuidOf(single));

      process.env.STS_CLUSTER_MODE = 'active-passive';
      process.env.STS_PERSISTENCE_MODE = 'postgres';
      cluster.reset();
      const name = 'cfracer' + Date.now();
      const clustered = ldap.autoCreateUser({ key: name, protocol: 'oauth2' });
      const first = clustered && ldap.entryUuidOf(clustered);
      t.check(versionOf(first) === '4',
              'A. ON A CLUSTERED NODE it is RANDOM too (version 4), no ' +
              'longer name-derived', first);

      const gone = ldap.deletePerson(clustered && clustered.dn,
                                     { door: 'cluster_autocreate_subject' });
      const again = gone && gone.ok &&
        ldap.autoCreateUser({ key: name, protocol: 'oauth2' });
      const second = again && ldap.entryUuidOf(again);
      t.check(!!second && second !== first && versionOf(second) === '4',
              'B. on a clustered node, a person deleted and signing in again ' +
              'under the same name gets a NEW entryUUID, so a new subject',
              JSON.stringify({ deleted: gone, first: first,
                               second: second }));

      const at = function (uuid, created, aliases) {
        const attributes = { uid: ['racer'], entryuuid: [uuid] };
        if (aliases) {
          attributes.stsentryuuidalias = aliases;
        }
        return { dn: 'uid=racer,ou=users,dc=example,dc=com',
                 attributes: attributes, createdAt: created };
      };
      const LOW = '11111111-1111-4111-8111-111111111111';
      const HIGH = '99999999-9999-4999-8999-999999999999';
      const raced = ldap.mergeCreateRace(at(HIGH, '20261116120000Z'),
                                         at(LOW, '20261116120010Z'));
      t.check(!!raced && raced.uuid === LOW &&
              raced.aliases.join(',') === HIGH,
              'C1. two creates of one entry in two processes keep both ' +
              'values: the lower primary and the other an alias, so the ' +
              'losing node\'s tokens still name the entry',
              JSON.stringify(raced));
      const recreated = ldap.mergeCreateRace(at(HIGH, '20261116120000Z'),
                                             at(LOW, '20261116130000Z'));
      t.check(recreated === null,
              'C2. a re-create an hour later is not merged, so a deleted ' +
              'person\'s value is never aliased onto a namesake',
              JSON.stringify(recreated));

      // D. An entry carrying a name-derived value, as one created under
      // #46's rule is stored, then overwritten by an ordinary whole-entry
      // write (SCIM's replace).
      const legacyName = 'cflegacy' + Date.now();
      const legacy = ldap.autoCreateUser({ key: legacyName,
                                          protocol: 'oauth2' });
      const derived = '5a5a5a5a-5a5a-5a5a-9a5a-5a5a5a5a5a5a';
      const key = ldap.normalizeDn(legacy.dn);
      ldap.entries.get(key).attributes.entryuuid = [derived];
      const rewrite = {};
      Object.keys(legacy.attributes).forEach(function (attr) {
        rewrite[attr] = legacy.attributes[attr];
      });
      rewrite.description = ['rewritten'];
      const written = ldap.writePerson(legacy.dn, rewrite);
      const kept = ldap.entryUuidOf(ldap.entries.get(key));
      t.check(kept === derived,
              'D. an existing entry whose entryUUID was name-derived keeps ' +
              'it, so an existing person\'s subject does not change',
              JSON.stringify({ written: written && written.ok, kept: kept }));
    });
  } finally {
    cluster.reset();
    VARIED.forEach(function (name) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_autocreate_subject',
  describe: 'a sign-in\'s directory entry gets a random entryUUID on a ' +
            'single node and a clustered one, and a namesake never gets the ' +
            'deleted person\'s',
  run: run
};
