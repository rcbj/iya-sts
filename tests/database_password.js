'use strict';
//
// File: database_password.js
//
// ===========================================================================
// THE DATABASE PASSWORD OUT OF A SECRET STORE, AND INTO THE CONNECTION STRING
// (2026-09-12).
//
// `persistence.databaseUrl` carries a password in plain text. That is right
// for a throwaway database of mock identities and is not a deployment, so the
// password can now be read from the five places the key-encryption key already
// comes from — a mounted file, AWS Secrets Manager, Google Secret Manager,
// Azure Key Vault or HashiCorp Vault — and, by default, out of the SAME file
// or secret.
//
// Four claims, and each is breakable by an innocent edit:
//
//   1. **ONE PLACE CAN HOLD BOTH SECRETS**, told apart by a field. That is the
//      whole reason the feature is usable: a deployment already mounts one
//      file and should not have to mount a second.
//   2. **A SHARED LOCATION THAT IS NOT JSON IS REFUSED.** This is the
//      important one. What is in a plain key file is the KEY, and returning it
//      as a password would send this service's master key to a database
//      server as a credential — in the clear, on the wire — with a failed
//      connection as the only symptom.
//   3. **THE PASSWORD REACHES THE CONNECTION STRING INTACT**, whatever is in
//      it. `URL.password =` percent-encodes some characters and not others,
//      and `pg` runs `decodeURIComponent()` over what it finds, so the
//      obvious spelling mangles a password containing `%` and throws on some.
//   4. **NOTHING IS CONFIGURED BY DEFAULT AND NOTHING CHANGES.** `none` means
//      the connection string is dialled exactly as written.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS `tests/CLAUDE.md`'s FIRST QUESTION.
//
// Every claim above needs to CHOOSE HOW THE PROCESS WAS STARTED — which
// provider, which file, which field — and three of them are about a value that
// must never leave this process. There is no endpoint that reports a password
// and there must not be one, so an over-HTTP job could only assert that a
// service which was given a correct password connected, which is also what it
// does when the password was in the URL all along.
//
// **THE SECOND IMPLEMENTATION IS `pg`'s OWN PARSER**, and claim 3 is asserted
// against it rather than against this repository's idea of a URL:
// `ConnectionParameters` is the code that will really read the string at
// runtime, so a round-trip through it is the arrangement
// `tests/webauthn_cross_impl.js` describes — two implementations meeting,
// where one of them is the one that matters.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const secrets = require('../common/secrets');
const persistence = require('../persistence/persistence');
// `pg`'s own connection-string reader — a DEPENDENCY of this package rather
// than a transitive one, so requiring it here is not reaching into somebody
// else's tree.
const ConnectionParameters = require('pg/lib/connection-parameters.js');

// The settings this file moves. All four are RESTART-ONLY — the pool is opened
// before the listener binds — so `config.setOverride()` would refuse them and a
// test that used it would silently assert against the defaults. The
// environment layer is what `config.value()` resolves on every call.
const VARS = ['STS_KEYS_KEK_PROVIDER', 'STS_KEYS_KEK_FILE', 'STS_KEYS_KEK_REF',
              'STS_KEYS_KEK_FIELD', 'STS_DATABASE_PASSWORD_PROVIDER',
              'STS_DATABASE_PASSWORD_REF', 'STS_DATABASE_PASSWORD_FIELD',
              'STS_DATABASE_URL',
              // How a secret reaches its store, and the cert auth mount
              // (2026-09-12) — sections K and L.
              'STS_KEYS_KEK_VAULT', 'STS_KEYS_KEK_REGION', 'STS_KEYS_KEK_TOKEN',
              'STS_DATABASE_PASSWORD_VAULT', 'STS_DATABASE_PASSWORD_REGION',
              'STS_DATABASE_PASSWORD_TOKEN', 'STS_KEYS_VAULT_CERT_AUTH_MOUNT'];

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

// The password `pg` will really use, out of a string this module produced.
function passwordPgSees(url) {
  return new ConnectionParameters({ connectionString: url }).password;
}

async function run(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dbpw-'));
  const shared = path.join(dir, 'shared.json');
  const rawKey = path.join(dir, 'kek');
  const own = path.join(dir, 'db-password');
  const kek = nodeCrypto.randomBytes(32).toString('base64');
  fs.writeFileSync(shared, JSON.stringify({ kek: kek,
                                            databasePassword: 'sh4red-p@ss' }),
                   { mode: 0o600 });
  fs.writeFileSync(rawKey, kek, { mode: 0o600 });
  fs.writeFileSync(own, 'just-the-password\n', { mode: 0o600 });

  try {
    // ---------------------------------------------------------------------
    // A. NOTHING CONFIGURED, NOTHING CHANGED.
    // ---------------------------------------------------------------------
    await withEnvironment({
      STS_DATABASE_URL: 'postgres://sts:in-the-url@localhost:5432/sts'
    }, async function () {
      t.equal(await secrets.readDatabasePassword(), null,
              'A. with no provider configured the password is not read at ' +
              'all — `none` is the default, and a deployment that never ' +
              'asked for this must not have a secret store dialled at ' +
              'startup');
      t.equal(await persistence.resolveDatabaseUrl(),
              'postgres://sts:in-the-url@localhost:5432/sts',
              'and the connection string is handed to the driver byte for ' +
              'byte as it was written');
      t.equal(secrets.describeDatabasePassword().configured, false,
              'and the report says so rather than naming a provider nobody ' +
              'chose');
    });

    // ---------------------------------------------------------------------
    // B. ONE FILE, TWO SECRETS.
    // ---------------------------------------------------------------------
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: shared,
      STS_KEYS_KEK_FIELD: 'kek',
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts?sslmode=require'
    }, async function () {
      t.equal(await secrets.readKek(), kek,
              'B. the key-encryption key comes out of the shared file by its ' +
              'own field');
      t.equal(await secrets.readDatabasePassword(), 'sh4red-p@ss',
              'and the database password comes out of the SAME file by ' +
              'ITS field — which is the arrangement this feature exists for: ' +
              'a deployment mounts one file and does not have to invent a ' +
              'second');
      const report = secrets.describeDatabasePassword();
      t.check(report.shared,
              'the report says the two are sharing a location, which is the ' +
              'one fact an operator cannot work out from the settings — the ' +
              'location row is EMPTY in that case, and a page printing the ' +
              'row would report that nothing is configured');
      t.check(JSON.stringify(report).indexOf('sh4red-p@ss') < 0,
              'and it says WHERE and never WHAT: no password anywhere in the ' +
              'report', JSON.stringify(report).slice(0, 120));

      const url = await persistence.resolveDatabaseUrl();
      t.equal(passwordPgSees(url), 'sh4red-p@ss',
              'and the password `pg` will really use, out of the string this ' +
              'service hands it, is the one the store held');
      t.check(url.indexOf('sslmode=require') >= 0,
              'with everything else in the string untouched — the injection ' +
              'is one field and not a rewrite', url);
    });

    // ---------------------------------------------------------------------
    // C. THE REFUSAL THIS FILE EXISTS FOR.
    // ---------------------------------------------------------------------
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey,
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts'
    }, async function () {
      let refusal = '';
      try {
        await secrets.readDatabasePassword();
      } catch (e) {
        refusal = e.message;
      }
      t.check(refusal,
              'C. **A SHARED LOCATION HOLDING SOMETHING THAT IS NOT JSON IS ' +
              'REFUSED.** What is in a plain key file is the KEY, and handing ' +
              'it over as a database password would send this service\'s ' +
              'master key to a database server as a credential — in the ' +
              'clear, on the wire, with a failed connection as the only ' +
              'symptom');
      t.check(/rather than a password|key/.test(refusal),
              'and the sentence says WHY rather than reporting a parse that ' +
              'failed', refusal.slice(0, 140));
      let startFailed = '';
      try {
        await persistence.resolveDatabaseUrl();
      } catch (e) {
        startFailed = e.message;
      }
      t.check(startFailed,
              'and it reaches the caller, so a service configured this way ' +
              'does not start — `persistence.start()` treats it as a store ' +
              'that cannot be opened, which is the one failure in this ' +
              'service that is fatal by design');
    });

    // ---------------------------------------------------------------------
    // D. A SECRET OF ITS OWN IS TAKEN WHOLE.
    // ---------------------------------------------------------------------
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey,
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_PASSWORD_REF: own,
      STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts'
    }, async function () {
      t.equal(await secrets.readDatabasePassword(), 'just-the-password',
              'D. a location of its OWN holding a bare password is taken ' +
              'whole — the field is what tells two secrets apart inside one ' +
              'value, and there is only one thing in this one');
      t.equal(secrets.describeDatabasePassword().shared, false,
              'and the report stops calling it shared');
      t.equal(passwordPgSees(await persistence.resolveDatabaseUrl()),
              'just-the-password',
              'and the trailing newline `echo` wrote into that file is gone ' +
              'by the time `pg` reads it — a password with one on the end ' +
              'fails to authenticate with a message about the password being ' +
              'wrong, which sends somebody to look at the wrong end');
    });

    // ---------------------------------------------------------------------
    // E. A JSON OBJECT WITHOUT THE FIELD.
    // ---------------------------------------------------------------------
    const wrongShape = path.join(dir, 'wrong-shape.json');
    fs.writeFileSync(wrongShape,
                     JSON.stringify({ username: 'sts_app', password: 'p' }),
                     { mode: 0o600 });
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey,
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_PASSWORD_REF: wrongShape,
      STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts'
    }, async function () {
      let refusal = '';
      try {
        await secrets.readDatabasePassword();
      } catch (e) {
        refusal = e.message;
      }
      t.check(/username, password/.test(refusal),
              'E. a JSON object with no member of that name is refused with ' +
              'the keys it DOES hold — which is the mistake everybody makes ' +
              'once, because AWS Secrets Manager writes a database ' +
              'credential as {username, password}', refusal.slice(0, 160));
    });
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey,
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_PASSWORD_REF: wrongShape,
      STS_DATABASE_PASSWORD_FIELD: 'password',
      STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts'
    }, async function () {
      t.equal(await secrets.readDatabasePassword(), 'p',
              'and naming the field is the whole fix, which is what that ' +
              'sentence tells somebody to do');
    });

    // ---------------------------------------------------------------------
    // F. THE PASSWORD REACHES `pg` INTACT, WHATEVER IS IN IT.
    //
    // Every character here has broken a connection string somewhere: `%` is
    // what `URL.password =` leaves alone and `decodeURIComponent` then trips
    // over, `@` and `:` and `/` are the userinfo delimiters, `+` is a space in
    // some readings, and the rest are RFC 3986's reserved set.
    // ---------------------------------------------------------------------
    const nasty = ['simple', 'p@ss:w/ord', '100%sure', '%&+= #?', 'ünïcödé',
                   'a"b\'c', 'back\\slash', ':@/?#[]!$&()*+,;=',
                   'trailing ', ' leading'];
    for (const password of nasty) {
      const secretFile = path.join(dir, 'nasty.json');
      fs.writeFileSync(secretFile, JSON.stringify({ databasePassword: password }),
                       { mode: 0o600 });
      await withEnvironment({
        STS_KEYS_KEK_PROVIDER: 'file',
        STS_KEYS_KEK_FILE: rawKey,
        STS_DATABASE_PASSWORD_PROVIDER: 'file',
        STS_DATABASE_PASSWORD_REF: secretFile,
        STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts?sslmode=require'
      }, async function () {
        const url = await persistence.resolveDatabaseUrl();
        t.equal(passwordPgSees(url), password.trim(),
                'F. `pg` reads back exactly what the store held, for a ' +
                'password containing ' + JSON.stringify(password) +
                ' — trimmed, because `echo secret > file` writes a newline ' +
                'and a password with one on the end fails to authenticate ' +
                'with a message about the password being wrong');
      });
    }

    // ---------------------------------------------------------------------
    // G. A PASSWORD ALREADY IN THE URL IS REPLACED, AND H. A STRING THAT IS
    //    NOT A URL IS REFUSED.
    // ---------------------------------------------------------------------
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey,
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_PASSWORD_REF: own,
      STS_DATABASE_URL: 'postgres://sts_app:left-over@db.example:5432/sts'
    }, async function () {
      t.equal(passwordPgSees(await persistence.resolveDatabaseUrl()),
              'just-the-password',
              'G. a password left in the connection string is REPLACED by ' +
              'the configured one. Two passwords for one connection is a ' +
              'question with no good answer, and the provider is the one ' +
              'somebody chose deliberately');
    });
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey,
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_PASSWORD_REF: own,
      STS_DATABASE_URL: 'host=db.example port=5432 dbname=sts user=sts_app'
    }, async function () {
      let refusal = '';
      try {
        await persistence.resolveDatabaseUrl();
      } catch (e) {
        refusal = e.message;
      }
      t.check(/keyword\/value|not a URL/.test(refusal),
              'H. libpq\'s keyword/value form is REFUSED rather than dialled ' +
              'without the password somebody configured — `pg` accepts that ' +
              'shape and this cannot edit one safely, so the honest answer ' +
              'is to say so', refusal.slice(0, 160));
    });

    // ---------------------------------------------------------------------
    // I. AN EMPTY SECRET IS NOT A PASSWORD.
    // ---------------------------------------------------------------------
    const empty = path.join(dir, 'empty');
    fs.writeFileSync(empty, '   \n', { mode: 0o600 });
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey,
      STS_DATABASE_PASSWORD_PROVIDER: 'file',
      STS_DATABASE_PASSWORD_REF: empty,
      STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts'
    }, async function () {
      let refusal = '';
      try {
        await secrets.readDatabasePassword();
      } catch (e) {
        refusal = e.message;
      }
      t.check(/empty/.test(refusal),
              'I. a secret that reads empty is refused by name rather than ' +
              'dialled with an empty password, which fails at the database ' +
              'as "authentication failed" and sends somebody to look at the ' +
              'wrong end', refusal.slice(0, 140));
    });

    // ---------------------------------------------------------------------
    // J. THE KEK'S OWN PATH IS UNCHANGED.
    // ---------------------------------------------------------------------
    await withEnvironment({
      STS_KEYS_KEK_PROVIDER: 'file',
      STS_KEYS_KEK_FILE: rawKey
    }, async function () {
      t.equal(await secrets.readKek(), kek,
              'J. a key file holding raw bytes and no field named still ' +
              'reads WHOLE — which is every deployment that existed before ' +
              'there was a second secret, and the compatibility this design ' +
              'turns on');
      t.equal(secrets.describe().provider, 'file',
              'and the key\'s own report is the shape it always was');
    });

    // ---------------------------------------------------------------------
    // K. HOW A SECRET REACHES ITS STORE: THE KEY'S BY DEFAULT, ITS OWN WHERE
    //    IT NAMES ONE (2026-09-12).
    //
    // The endpoint, the region and the token were the key's rows and nothing
    // else, so a database credential kept in a different Vault, region or Key
    // Vault could not be configured at all. The shared store must stay the
    // default — that is the arrangement this file's first claim is about — so
    // the empty case is asserted before the override.
    // ---------------------------------------------------------------------
    await withEnvironment({
      STS_KEYS_KEK_VAULT: 'https://kek-vault.example:8200',
      STS_KEYS_KEK_REGION: 'eu-west-1',
      STS_KEYS_KEK_TOKEN: 'kek-token'
    }, async function () {
      ['vault', 'region', 'token'].forEach(function (which) {
        t.equal(secrets.reachOf(secrets.DATABASE_PASSWORD, which),
                secrets.reachOf(secrets.KEK, which),
                'K. with nothing of its own, the database password reaches ' +
                'the KEY\'s store for `' + which + '` — the shared store is ' +
                'still the default');
      });
    });
    await withEnvironment({
      STS_KEYS_KEK_VAULT: 'https://kek-vault.example:8200',
      STS_KEYS_KEK_REGION: 'eu-west-1',
      STS_KEYS_KEK_TOKEN: 'kek-token',
      STS_DATABASE_PASSWORD_VAULT: 'https://db-vault.example:8200',
      STS_DATABASE_PASSWORD_REGION: 'us-east-2',
      STS_DATABASE_PASSWORD_TOKEN: 'db-token',
      STS_DATABASE_PASSWORD_PROVIDER: 'vault',
      STS_DATABASE_PASSWORD_REF: 'secret/data/db'
    }, async function () {
      t.equal(secrets.reachOf(secrets.DATABASE_PASSWORD, 'vault'),
              'https://db-vault.example:8200',
              'K. naming an endpoint of its own, the database password is ' +
              'read from THAT Vault');
      t.equal(secrets.reachOf(secrets.DATABASE_PASSWORD, 'region'), 'us-east-2',
              'and that region');
      t.equal(secrets.reachOf(secrets.DATABASE_PASSWORD, 'token'), 'db-token',
              'and with that token');
      t.equal(secrets.reachOf(secrets.KEK, 'vault'),
              'https://kek-vault.example:8200',
              'while the KEY is untouched — an override on one secret is not ' +
              'a change to the other');
      const described = secrets.describeDatabasePassword();
      t.equal(described.where && described.where.endpoint,
              'https://db-vault.example:8200',
              'and /admin/secrets names the endpoint the read really goes to',
              JSON.stringify(described.where));
      t.check(JSON.stringify(described).indexOf('db-token') < 0 &&
              JSON.stringify(described).indexOf('kek-token') < 0,
              'without either token in the report — its presence and never ' +
              'its value');
    });

    // ---------------------------------------------------------------------
    // L. THE CERT AUTH MOUNT IS A SETTING, AND IT GOES INTO A REQUEST LINE.
    // ---------------------------------------------------------------------
    await withEnvironment({}, async function () {
      t.equal(secrets.certAuthMount(), 'cert',
              'L. unset, the certificate login goes to auth/cert, as it ' +
              'always did');
    });
    await withEnvironment({ STS_KEYS_VAULT_CERT_AUTH_MOUNT: '/tls-clients/' },
      async function () {
        t.equal(secrets.certAuthMount(), 'tls-clients',
                'L. a store that enabled the method elsewhere is logged in ' +
                'to there, with the slashes the CLI prints forgiven');
      });
    for (const hostile of ['../sys/raw', 'cert?x=1', 'cert login']) {
      await withEnvironment({ STS_KEYS_VAULT_CERT_AUTH_MOUNT: hostile },
        async function () {
          let refused = '';
          try {
            secrets.certAuthMount();
          } catch (e) {
            refused = e.message;
          }
          t.check(/keys\.vaultCertAuthMount/.test(refused),
                  'L. "' + hostile + '" is REFUSED by name rather than put ' +
                  'into a request line', refused.slice(0, 120));
        });
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = {
  name: 'database_password',
  describe: 'the database password out of the same secret store as the ' +
            'key-encryption key, and into the connection string: one place ' +
            'for both, the refusal that stops a key being sent as a ' +
            'password, and a round-trip through pg\'s own parser',
  run: run
};
