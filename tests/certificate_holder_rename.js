'use strict';
//
// File: certificate_holder_rename.js
//
// A PERSON'S CERTIFICATE FOLLOWS THEIR ENTRY, NOT THEIR NAME (2026-09-14).
//
// A TLS client certificate and an enrolled one name a person as they were
// CALLED at issuance — the CN, the `urn:sts:person:` subjectAltName, the
// register's slot and the issued record's identifier. Before the holder's
// `urn:uuid:` subject was recorded beside them, renaming alice to alicia left
// her certificate naming nobody, and deleting alicia and creating a new alice
// handed the old certificate to the new person — the account-recycling hole a
// stable subject exists to close, arriving through the one credential that
// carries a name in its own bytes.
//
// Asserted, for a `tls-client` certificate and an ACME-enrolled one:
//   1. the identity gate names the holder;
//   2. after a rename it names the RENAMED person, and RFC 8705's still-held
//      question and the enrollment lookup both still find the certificate;
//   3. after the renamed person is deleted and somebody new is created under
//      the old name, the certificate is refused (`HOLDER_GONE`).
//
// In a CHILD PROCESS, because it loads the stack for the directory's subject
// resolver and builds a certificate authority, both of which are process state
// `run.js` shares with every other file.
//

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_CERT_HOLDER_RENAME_CHILD';
const MARK = 'CERT-HOLDER-CHILD ';

const log = require('bunyan').createLogger({ name: 'certificate_holder_rename',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function asInput(pem, chain) {
  log.debug("Entering asInput().");
  log.debug("Leaving asInput().");
  return { leaf: new nodeCrypto.X509Certificate(pem).raw,
           chain: (chain || []).map(function (one) {
             return new nodeCrypto.X509Certificate(one).raw;
           }),
           verified: true };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const realms = require(ROOT + '/common/realms');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const core = require(ROOT + '/common/cert_enrollment');
  const keyMaterial = require(ROOT + '/common/vendored/key_material');
  const x509 = require(ROOT + '/common/vendored/x509');
  const tlsClient = require(ROOT + '/common/tls_client_certificates');

  await keystore.start();
  await pki.start({ realmIds: [''],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  await pki.ensureScope(realms.currentId());

  const rename = function (from, to) {
    log.debug("Entering rename().");
    const found = ldap.objectFor(from);
    const r = ldap.performOperation('modifyDN', {
      dn: found.entry.dn, boundDn: '', channel: 'ldaps',
      newRdn: 'uid=' + to, newSuperior: '', deleteOldRdn: true });
    log.debug("Leaving rename().");
    return r;
  };
  const recreateUnderOldName = function (current, old) {
    log.debug("Entering recreateUnderOldName().");
    ldap.deletePerson(ldap.objectFor(current).entry.dn);
    ldap.createUser(old, { invent: false });
    log.debug("Leaving recreateUnderOldName().");
  };

  // -------------------------------------------------------------------------
  // A. A TLS CLIENT CERTIFICATE
  // -------------------------------------------------------------------------
  ldap.createUser('chr-alice', { invent: false });
  const made = await tlsClient.issue(undefined, { username: 'chr-alice',
    label: 'laptop', keyAlg: 'ec-p256' });
  t.check(made.ok, 'A0. a TLS client certificate is issued',
          JSON.stringify(made.errors || ''));
  const input = asInput(made.issued.certificatePem, made.issued.chainPem);
  let seen = tlsClient.identityOf(input);
  t.check(seen.accepted && seen.username === 'chr-alice',
          'A1. the gate names its holder', JSON.stringify(seen));
  rename('chr-alice', 'chr-alicia');
  seen = tlsClient.identityOf(input);
  t.check(seen.accepted && seen.username === 'chr-alicia' &&
          seen.certifiedName === 'chr-alice',
          'A2. after a RENAME it names the renamed person, and says what the ' +
          'certificate calls them', JSON.stringify(seen));
  t.check(tlsClient.stillHeld(seen),
          'A3. and RFC 8705\'s still-held question still finds it');
  recreateUnderOldName('chr-alicia', 'chr-alice');
  seen = tlsClient.identityOf(input);
  t.check(!seen.accepted && seen.error === 'HOLDER_GONE',
          'A4. once that person is deleted, the certificate is REFUSED — ' +
          'not handed to somebody new under the old name',
          JSON.stringify(seen));

  // -------------------------------------------------------------------------
  // B. AN ENROLLED CERTIFICATE
  // -------------------------------------------------------------------------
  ldap.createUser('chr-bob', { invent: false });
  const pair = await keyMaterial.generateKeyPair('ec-p256');
  const csr = await x509.certificationRequest({
    subject: 'CN=chr-bob', publicKeyPem: pair.publicPem,
    privateKeyPem: pair.privatePem, subjectAltName: [] });
  const enrolled = await core.issue({
    family: 'acme', profile: 'tls-client',
    principal: { kind: 'person', id: 'chr-bob', admin: false,
                 hasEntry: true, via: 'test' },
    target: { kind: 'person', id: 'chr-bob' },
    publicKeyPem: pair.publicPem, csrDer: Buffer.from(csr.der),
    requested: {}, via: 'test' });
  t.check(enrolled.ok, 'B0. a certificate is enrolled over ACME',
          JSON.stringify(enrolled.errors || ''));
  const enrolledInput = asInput(enrolled.record.certificatePem,
                                enrolled.record.chainPem || []);
  seen = tlsClient.identityOf(enrolledInput);
  t.check(seen.accepted && seen.username === 'chr-bob',
          'B1. the gate names its holder', JSON.stringify(seen));
  rename('chr-bob', 'chr-bobby');
  seen = tlsClient.identityOf(enrolledInput);
  const found = core.findEnrolled(enrolled.record.serialHex, 'acme');
  t.check(seen.accepted && seen.username === 'chr-bobby' &&
          found && found.entry.id === 'chr-bobby' && tlsClient.stillHeld(seen),
          'B2. after a RENAME the gate, the enrollment lookup and the ' +
          'still-held question all find the renamed person',
          JSON.stringify({ seen: seen, found: found && found.entry }));
  recreateUnderOldName('chr-bobby', 'chr-bob');
  seen = tlsClient.identityOf(enrolledInput);
  t.check(!seen.accepted && seen.error === 'HOLDER_GONE' &&
          !core.findEnrolled(enrolled.record.serialHex, 'acme'),
          'B3. once that person is deleted, neither the gate nor the lookup ' +
          'gives the certificate to the new person under the old name',
          JSON.stringify(seen));
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  const got = spawnChild();
  if (got.error) {
    log.debug("Leaving run(). The child failed.");
    throw new Error(got.error);
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'certificate_holder_rename',
  describe: 'A person\'s TLS client and enrolled certificates follow their ' +
            'entry through a rename, and are refused to somebody re-created ' +
            'under the old name',
  run: run
};
