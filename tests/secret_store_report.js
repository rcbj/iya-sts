'use strict';
//
// File: tests/secret_store_report.js
//
// ===========================================================================
// THE `/admin/secrets` CONTRACTS THAT NEED NO SECRET STORE (2026-09-12).
//
// `npm test` has no OpenBao, no AWS and no Azure and must not need one. What
// this file holds is everything about that page decided by THIS REPOSITORY
// rather than by somebody else's store — and the most important of it is a
// REFUSAL rather than a behaviour.
//
// **THE ONE THING THIS PAGE COULD GET CATASTROPHICALLY WRONG IS PRINTING A
// SECRET**, and that is what sections A and B are for. A key-encryption key
// drawn once on a console is a key that has to be rotated, and rotating it
// means everything sealed under it is gone — so the deny-list guard is
// asserted directly, against objects shaped like the ones the providers
// actually answer, rather than trusted because every probe currently picks its
// fields by name.
//
// It is `tests/database_metrics.js`'s argument for the page next door, made
// again for a page whose failure mode is worse.
//
// ---------------------------------------------------------------------------
// IT DELETES THE SECRET-STORE ENVIRONMENT FOR `database_metrics.js`'s REASON.
//
// Both launchers run the suite once per mode and export each mode's
// environment into the runner, which hands `process.env` to every in-process
// job — and the `dispatch` mode's environment points this service's
// key-encryption key at the compose stack's OpenBao. This file asserts what
// the DEFAULTS say, so it removes what is overriding them rather than writing
// the defaults back over them.
// ===========================================================================

delete process.env.STS_KEYS_KEK_PROVIDER;
delete process.env.STS_KEYS_KEK_VAULT;
delete process.env.STS_KEYS_KEK_REF;
delete process.env.STS_KEYS_KEK_FIELD;
delete process.env.STS_KEYS_VAULT_CLIENT_CERT;
delete process.env.STS_KEYS_VAULT_CLIENT_KEY;
delete process.env.STS_KEYS_VAULT_CA_CERT;
delete process.env.STS_DATABASE_PASSWORD_PROVIDER;
delete process.env.STS_DATABASE_PASSWORD_REF;

const fs = require('fs');
const os = require('os');
const path = require('path');

const secrets = require('../common/secrets');
const secretsAdmin = require('../admin-ui/secrets_admin');

// **THE ENVIRONMENT LAYER AND NOT `config.setOverride()`**, which is the same
// trap `tests/database_password.js` documents beside it: every setting this
// file moves is RESTART-ONLY — the key is read once, before the listener binds
// — so `setOverride()` refuses it and a test that used it would silently
// assert against the defaults. `config.value()` resolves the environment on
// every call.
const VARS = ['STS_KEYS_KEK_PROVIDER', 'STS_KEYS_KEK_FILE', 'STS_KEYS_KEK_REF',
              'STS_KEYS_KEK_FIELD', 'STS_DATABASE_PASSWORD_PROVIDER',
              'STS_DATABASE_PASSWORD_REF', 'STS_DATABASE_PASSWORD_FIELD'];

function withEnvironment(values, fn) {
  const before = {};
  VARS.forEach(function (name) { before[name] = process.env[name]; });
  VARS.forEach(function (name) { delete process.env[name]; });
  Object.keys(values).forEach(function (name) {
    process.env[name] = values[name];
  });
  return Promise.resolve()
    .then(fn)
    .finally(function () {
      VARS.forEach(function (name) {
        if (before[name] === undefined) {
          delete process.env[name];
        } else {
          process.env[name] = before[name];
        }
      });
    });
}

// The member names a probe's answer must never carry out of `secrets.js`.
// **SHAPED LIKE THE REAL ANSWERS**, which is the point: `auth/token/
// lookup-self` really does put the token in `id`, a kv-v2 read really does
// nest it under `data.data`, and `GetSecretValue` really does answer
// `SecretString`. A guard tested against invented shapes is a guard tested
// against nothing.
const REAL_SHAPES = [
  { what: 'a Vault token lookup',
    value: { data: { id: 'hvs.THE-TOKEN', display_name: 'cert-sts',
                     policies: ['default', 'sts-read'] } },
    mustNotContain: ['hvs.THE-TOKEN'] },
  { what: 'a kv version 2 read',
    value: { data: { data: { kek: 'BASE64-KEY', databasePassword: 'hunter2' },
                     metadata: { version: 2 } } },
    mustNotContain: ['BASE64-KEY', 'hunter2'] },
  { what: 'an AWS GetSecretValue reply',
    value: { ARN: 'arn:aws:secretsmanager:eu-west-2:1:secret:sts',
             SecretString: '{"kek":"BASE64-KEY"}' },
    mustNotContain: ['BASE64-KEY'] },
  { what: 'a cert login',
    value: { auth: { client_token: 'hvs.THE-TOKEN', policies: ['sts-read'] } },
    mustNotContain: ['hvs.THE-TOKEN'] },
  { what: 'a GCP payload',
    value: { name: 'projects/p/secrets/s/versions/3',
             payload: { data: 'BASE64-KEY' } },
    mustNotContain: ['BASE64-KEY'] }
];

async function run(t) {
  t.log.info('=== A. the guard deletes what a provider would otherwise leak ===');

  t.check(secrets.NEVER_REPORTED.length >= 10,
          'the deny list is published and is not empty',
          secrets.NEVER_REPORTED.length + ' member name(s)');

  REAL_SHAPES.forEach(function (shape) {
    const scrubbed = JSON.stringify(secrets.scrub(shape.value));
    shape.mustNotContain.forEach(function (leak) {
      t.check(scrubbed.indexOf(leak) < 0,
              'scrub() removes the secret from ' + shape.what,
              scrubbed);
    });
  });

  // **THE HALF THAT MATTERS AS MUCH: IT MUST NOT DELETE EVERYTHING.** A guard
  // that answered `{}` would pass every assertion above and make the page
  // useless, which is not hypothetical — the `mounts` probe DID answer `{}`
  // on its first run against a real store, because it named its members
  // `secret` and `auth` and both are on this list. That is the rule the
  // probes follow now: a probe names its OWN members and never echoes a
  // provider's.
  const kept = secrets.scrub({ sealed: false, version: '2.6.2',
                               policies: ['default'], nested: { ttl: 3600 } });
  t.equal(kept.version, '2.6.2', 'and it keeps everything not on the list');
  t.equal(kept.nested.ttl, 3600, 'including nested members');
  t.equal(JSON.stringify(kept.policies), '["default"]', 'and arrays');

  t.check(secrets.NEVER_REPORTED.indexOf('id') >= 0,
          '`id` is on the list, which is the one that catches ' +
          'auth/token/lookup-self — the single most plausible way a live ' +
          'credential ends up on this page');

  t.log.info('=== B. nothing in a real report is a secret ===');

  // A file holding BOTH secrets, which is the arrangement the compose stack
  // uses and the one where a leak would be worst.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-secret-report-'));
  const file = path.join(dir, 'shared.json');
  fs.writeFileSync(file, JSON.stringify({ kek: 'THE-KEY-MATERIAL',
                                          databasePassword: 'THE-PASSWORD' }),
                   { mode: 0o600 });

  try {
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: file,
      STS_KEYS_KEK_FIELD: 'kek',
      STS_DATABASE_PASSWORD_PROVIDER: 'file'
    }, async function () {
      // READ BOTH FIRST, so the ledger has something in it and the process is
      // in the state where a leak would actually be possible.
      await secrets.readKek();
      await secrets.readDatabasePassword();

      const report = await secretsAdmin.secretsView();
      const serialised = JSON.stringify(report);

      t.check(serialised.indexOf('THE-KEY-MATERIAL') < 0,
              'THE KEY IS NOT IN THE REPORT, with the key read and held by ' +
              'this process');
      t.check(serialised.indexOf('THE-PASSWORD') < 0,
              'and neither is the database password');

      t.log.info('=== C. the ledger says whether this process actually read ===');

      const kek = report.secrets.filter(function (one) {
        return one.secret === 'kek';
      })[0];
      t.check(!!kek, 'the key-encryption key is a row on the report');
      t.check(!!kek.lastRead && kek.lastRead.ok,
              'and the ledger records that this process read it. That is the ' +
              'fact no settings page can carry: a development-mode service ' +
              'never asks for the key, so a broken configuration and a ' +
              'working one look identical until the mode changes');
      t.check(JSON.stringify(kek.lastRead).indexOf('THE-KEY-MATERIAL') < 0,
              'and the ledger row holds no value');

      const password = report.secrets.filter(function (one) {
        return one.secret === 'database-password';
      })[0];
      t.check(password.shared,
              'the database password reports that it is SHARING the key\'s ' +
              'location, which is the one fact an operator cannot work out ' +
              'from the settings: an empty location row means *wherever the ' +
              'key is*, and a page drawing the empty row would report that ' +
              'nothing is configured');

      t.log.info('=== D. two secrets in one place are ONE store ===');

      t.equal(report.stores.length, 1,
              'both secrets are in one file, so there is one store row. ' +
              'Asking the same store twice whether it is sealed would be ' +
              'this page inventing a disagreement it then has to draw');
      t.equal(report.stores[0].secrets.length, 2,
              'and it names both secrets it holds');
      t.equal(report.secrets[0].probes.length, 1,
              'each secret still gets its own field probe, because the file ' +
              'provider declares its scope per MEMBER — two secrets taking ' +
              'two members out of one file are two questions');

      t.log.info('=== E. a failed read is recorded, not swallowed ===');

      process.env.STS_KEYS_KEK_FILE = path.join(dir, 'not-there');
      let threw = false;
      try {
        await secrets.readKek();
      } catch (e) {
        // EXPECTED. A missing key file is a throw in product mode and is the
        // thing this section is about; what matters is what was written down
        // on the way past.
        threw = true;
      }
      t.check(threw, 'a missing key file still throws, which is what product ' +
                     'mode refuses to start on');
      const after = secrets.readLedger(secrets.KEK);
      t.check(!after.ok, 'and the ledger now records the FAILURE');
      t.check(/ENOENT|could not be read/.test(after.error || ''),
              'with the reason, which is the row an operator most needs and ' +
              'the one a service that did not start cannot show anybody',
              after.error);
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  t.log.info('=== F. every provider has probes, and the page has a note ' +
             'for every secret ===');

  // **BOTH WAYS ROUND, AND NEITHER IS AN ERROR ANYWHERE ELSE** — which is
  // `pki_authoring.js`'s field-table argument and `database_metrics.js`'s
  // section B, one layer out. A provider with no probe table draws a store
  // block with nothing in it and reads as a feature that broke; a probe table
  // for a provider that does not exist is code nothing can reach.
  secrets.PROVIDER_IDS.forEach(function (id) {
    const table = secrets.PROBES[id];
    t.check(!!table, 'the "' + id + '" provider has a probe table');
    t.check(!!table && typeof table.store === 'function' &&
            typeof table.secret === 'function' &&
            typeof table.scope === 'function',
            'and it has all three of store(), secret() and scope(). The ' +
            'scope is the PROVIDER\'s to declare because the report cannot ' +
            'know what a probe\'s answer depends on — the file one is per ' +
            'member and every other is per stored object');
  });
  Object.keys(secrets.PROBES).forEach(function (id) {
    t.check(secrets.PROVIDER_IDS.indexOf(id) >= 0,
            'the "' + id + '" probe table names a provider that exists');
  });

  const notes = secretsAdmin.secretNotes();
  secrets.SECRETS.forEach(function (spec) {
    const note = notes[spec.id];
    t.check(!!note, 'the "' + spec.id + '" secret has a note on the page. ' +
            'A secret with none is drawn with no explanation of what it is ' +
            'for or what breaks without it, which is what a reader arriving ' +
            'because something will not start came for');
    t.check(!!note && !!note.heading && !!note.what && !!note.without &&
            !!note.rotating,
            'and the note is complete');
  });
  Object.keys(notes).forEach(function (id) {
    t.check(secrets.SECRETS.some(function (spec) { return spec.id === id; }),
            'the "' + id + '" note describes a secret that exists. One for a ' +
            'secret that does not is prose about nothing');
  });

  t.log.info('=== G. the KV metadata path is derived and not configured ===');

  // The one string rewrite in the Vault probe, asserted directly because it
  // is the only piece of that provider's behaviour reachable with no store.
  const report2 = await secretsAdmin.secretsView();
  t.check(report2.timeoutMs >= 250,
          'the probe bound is read from keys.storeProbeTimeoutMs',
          report2.timeoutMs + 'ms');
  t.check(Array.isArray(report2.failed),
          'and `failed` is a list rather than a count, so a client can say ' +
          'WHICH probe did not answer');
}

module.exports = {
  name: 'secret_store_report',
  describe: 'The /admin/secrets contracts that need no secret store: the ' +
            'deny-list guard against the real shapes a Vault token lookup, a ' +
            'kv-v2 read, a GetSecretValue and a cert login actually have — ' +
            'and that it does NOT delete everything, which is the mistake ' +
            'that was measured; that a report built with both secrets read ' +
            'and held carries neither value; that the ledger records a ' +
            'successful read AND a failed one; that two secrets in one place ' +
            'are one store; and that every provider has a probe table and ' +
            'every secret a note, both ways round',
  run: run
};
