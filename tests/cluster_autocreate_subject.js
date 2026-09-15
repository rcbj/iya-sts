'use strict';
//
// File: cluster_autocreate_subject.js
//
// ===========================================================================
// A SIGN-IN'S ENTRY ON A CLUSTERED NODE HAS A NAME-DERIVED entryUUID
// (2026-09-14, #46; rcbj's choice).
//
// `autoCreateUser()` runs synchronously inside every protocol's credential
// check, so two nodes seeing one name's first sign-in at the same moment both
// create `uid=<name>,ou=users` and cannot claim it first. With a random
// `entryUUID` each, the directory merge keeps one entry and the other node's
// tokens carry a `sub` that names nobody. With a value derived from the realm
// and the DN — the seed's version 5 UUID — both nodes create the SAME entry.
//
// The rule is narrowed to where the race exists: a clustered node. A single
// node keeps random values, which is the account-recycling protection
// `ldap_server.js`'s entryUUID block records. The version nibble is what tells
// the two apart, and it is what this asserts.
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
              'ON A SINGLE NODE a sign-in\'s entry keeps a RANDOM entryUUID ' +
              '(version 4), so a person deleted and re-created under one name ' +
              'is a new subject', single && ldap.entryUuidOf(single));

      process.env.STS_CLUSTER_MODE = 'active-passive';
      process.env.STS_PERSISTENCE_MODE = 'postgres';
      cluster.reset();
      const clustered = ldap.autoCreateUser({ key: 'cfracer' + Date.now(),
                                              protocol: 'oauth2' });
      t.check(clustered && versionOf(ldap.entryUuidOf(clustered)) === '5',
              'ON A CLUSTERED NODE it is NAME-DERIVED (version 5), so two ' +
              'nodes creating one name\'s entry at once create the same ' +
              'subject', clustered && ldap.entryUuidOf(clustered));
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
  describe: 'a sign-in\'s directory entry gets a name-derived entryUUID on a ' +
            'clustered node and a random one on a single node',
  run: run
};
