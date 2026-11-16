// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: deleted_certificates.js
//
// ===========================================================================
// A DELETED HOLDER'S CERTIFICATES ARE REVOKED AND LEAVE ITS NAME (2026-11-16).
//
// rcbj's rule on #1612/#1613: a person or an application deleted and made
// again under the same name inherits NOTHING. Seen on a running service: a
// person's TLS client certificate, revoked, then the person deleted with
// `/admin-api/users/delete` and made again — and `/admin-api/users` listed
// the old certificate on the new entry, because the certificate register
// (`tls_client_certificates.js`) finds a holder by the name in its slot.
// `forgetDeletedHolder()` is what every delete door now reaches. Asserted:
//
//   A. A PERSON DELETED BY THE MANAGEMENT API'S DOOR (`usersAction()`'s
//      `delete`) with a TLS client certificate, a message-signing
//      certificate and an ACME-enrolled one, all valid: each is REVOKED
//      `cessationOfOperation`; made again under the name, the new person is
//      listed none of them (either purpose), the identity gate refuses the
//      old TLS one (`HOLDER_GONE`) and RFC 8705's still-held question says
//      no; the old serials are on the authority's revocation list, in the
//      signed CRL, and still issued here (OCSP knows them); a certificate
//      the new person is issued is the one they are listed.
//   B. THE CASE SEEN: a certificate the person revoked themselves
//      (`keyCompromise`) and deleted over SCIM's door (`deletePerson()` by
//      the SCIM id): the namesake is listed nothing, and the revocation
//      keeps its first reason and date.
//   C. AN LDAP DELETE reaches the same function.
//   D. A RE-HOMING IS NOT A DELETE: `moved` leaves the certificate valid —
//      and the namesake is still not listed it, because the listing reads
//      the holder by subject (what a delete before this change left behind).
//   E. AN APPLICATION deleted and registered again under its identifier is
//      listed none of its old TLS client certificates, which are revoked.
//   F. The two codes are in the table.
//
// In a CHILD PROCESS, for `certificate_holder_rename.js`'s reason: it loads
// the stack and builds a certificate authority, process state `run.js`
// shares with every other file.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_DELETED_CERTIFICATES_CHILD';
const MARK = 'DELETED-CERTS-CHILD ';

const log = require('bunyan').createLogger({ name: 'deleted_certificates',
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

// The serials a signed CRL lists, normalised.
function crlSerials(der) {
  log.debug("Entering crlSerials().");
  const from = { paths: [ROOT + '/common'] };
  const asn1js = require(require.resolve('asn1js', from));
  const pkijs = require(require.resolve('pkijs', from));
  const bytes = new Uint8Array(der).buffer;
  const crl = new pkijs.CertificateRevocationList({
    schema: asn1js.fromBER(bytes).result });
  const out = (crl.revokedCertificates || []).map(function (one) {
    const block = one.userCertificate.valueBlock;
    return Buffer.from(block.valueHexView || block.valueHex)
      .toString('hex').replace(/^0+/, '');
  });
  log.debug("Leaving crlSerials(). " + out.length);
  return out;
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
  const keyMaterial = require(ROOT + '/common/crypto_impl/key_material');
  const x509 = require(ROOT + '/common/crypto_impl/x509');
  const tlsClient = require(ROOT + '/common/tls_client_certificates');
  const revocation = require(ROOT + '/common/pki_revocation');
  const applications = require(ROOT + '/common/applications');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const errorCodes = require(ROOT + '/common/error_codes');

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
  const scope = realms.currentId();
  await pki.ensureScope(scope);
  const normal = revocation.normalSerial;
  const dnOf = function (name) {
    log.debug("Entering dnOf().");
    const found = ldap.objectFor(name);
    log.debug("Leaving dnOf().");
    return found && found.entry ? found.entry.dn : '';
  };
  const listed = function (name, purpose) {
    log.debug("Entering listed().");
    log.debug("Leaving listed().");
    return tlsClient.listFor(undefined, name, 'person', purpose)
      .map(function (one) {
        return normal(one.serialHex);
      });
  };
  const revokedFor = function (ca, serial) {
    log.debug("Entering revokedFor().");
    log.debug("Leaving revokedFor().");
    return revocation.isRevoked(scope, ca, serial);
  };
  const issueTls = function (name, purpose) {
    log.debug("Entering issueTls().");
    log.debug("Leaving issueTls().");
    return tlsClient.issue(undefined, { username: name, label: 'laptop',
                                        keyAlg: 'ec-p256',
                                        purpose: purpose });
  };

  // -------------------------------------------------------------------------
  // A. THE MANAGEMENT API'S DOOR, THREE REGISTERS
  // -------------------------------------------------------------------------
  const ALICE = 'dc-alice';
  ldap.createUser(ALICE, { invent: false });
  const tls = await issueTls(ALICE);
  const signing = await issueTls(ALICE, 'message-signing');
  const pair = await keyMaterial.generateKeyPair('ec-p256');
  const csr = await x509.certificationRequest({
    subject: 'CN=' + ALICE, publicKeyPem: pair.publicPem,
    privateKeyPem: pair.privatePem, subjectAltName: [] });
  const enrolled = await core.issue({
    family: 'acme', profile: 'tls-client',
    principal: { kind: 'person', id: ALICE, admin: false,
                 hasEntry: true, via: 'test' },
    target: { kind: 'person', id: ALICE },
    publicKeyPem: pair.publicPem, csrDer: Buffer.from(csr.der),
    requested: {}, via: 'test' });
  t.check(tls.ok && signing.ok && enrolled.ok,
          'A0. a TLS client, a message-signing and an ACME certificate are ' +
          'issued to the person',
          JSON.stringify([tls.errors, signing.errors, enrolled.errors]));
  const tlsSerial = normal(tls.issued.serialHex);
  const signingSerial = normal(signing.issued.serialHex);
  const acmeSerial = normal(enrolled.record.serialHex);
  t.check(listed(ALICE).indexOf(tlsSerial) >= 0 &&
          listed(ALICE, 'message-signing').indexOf(signingSerial) >= 0,
          'A1. the person is listed both');
  const input = asInput(tls.issued.certificatePem, tls.issued.chainPem);
  const gone = adminActions.usersAction({ action: 'delete', user: ALICE },
                                        { actor: 'test', via: 'test' });
  t.check(gone && gone.ok && !dnOf(ALICE),
          'A2. the person is deleted through usersAction()\'s delete',
          JSON.stringify(gone));
  const reasons = [revokedFor('tls-client', tlsSerial),
                   revokedFor('message-signing', signingSerial),
                   revokedFor('acme', acmeSerial)];
  t.check(reasons.every(function (one) {
    return one && one.reason === 'cessationOfOperation';
  }), 'A3. all three were REVOKED cessationOfOperation by the delete',
          JSON.stringify(reasons));
  ldap.createUser(ALICE, { invent: false });
  t.check(listed(ALICE).length === 0 &&
          listed(ALICE, 'message-signing').length === 0,
          'A4. made again under the name, the new person is listed none of ' +
          'them', JSON.stringify([listed(ALICE),
                                  listed(ALICE, 'message-signing')]));
  const seen = tlsClient.identityOf(input);
  t.check(!seen.accepted && seen.error === 'HOLDER_GONE',
          'A5. the identity gate refuses the old TLS client certificate',
          JSON.stringify(seen));
  t.check(!tlsClient.stillHeld({ accepted: true, kind: 'person',
                                 username: ALICE, realm: scope,
                                 serialHex: tlsSerial,
                                 authority: { ca: 'tls-client' } }),
          'A6. and RFC 8705\'s still-held question does not find it under ' +
          'the name');
  t.check(revocation.issuedHere(scope, 'tls-client', tlsSerial) &&
          revocation.issuedHere(scope, 'message-signing', signingSerial),
          'A7. the old serials are still known as issued here (OCSP does not ' +
          'answer `unknown`)');
  const crl = await revocation.buildCrl(scope, 'tls-client');
  let onCrl = [];
  try {
    onCrl = crl && crl.ok ? crlSerials(crl.der) : [];
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.message) || e));
    onCrl = ['unreadable: ' + ((e && e.message) || e)];
  }
  t.check(onCrl.indexOf(tlsSerial) >= 0,
          'A8. the old TLS serial is on the signed CRL',
          JSON.stringify({ ok: crl && crl.ok, serials: onCrl }));
  const fresh = await issueTls(ALICE);
  t.check(fresh.ok && JSON.stringify(listed(ALICE)) ===
          JSON.stringify([normal(fresh.issued.serialHex)]),
          'A9. a certificate the new person is issued is the only one they ' +
          'are listed', JSON.stringify(listed(ALICE)));
  const record = pki.issuedKeyPairsFor(scope, 'tls-client')
    .filter(function (one) {
      return normal(one.serialHex) === tlsSerial;
    })[0];
  t.check(!!record && record.subjectKind === 'deleted-person' &&
          /^urn:uuid:/.test(String(record.identifier)) &&
          String(record.identifier).indexOf(ALICE) < 0,
          'A10. the old record is kept in the issued register under the ' +
          'deleted entry\'s subject, naming no name', JSON.stringify(record));

  // -------------------------------------------------------------------------
  // B. REVOKED FIRST, THEN DELETED OVER SCIM'S DOOR (the case seen)
  // -------------------------------------------------------------------------
  const BOB = 'dc-bob';
  ldap.createUser(BOB, { invent: false });
  const bobs = await issueTls(BOB);
  const bobSerial = normal(bobs.issued.serialHex);
  const own = tlsClient.revoke(undefined, BOB, bobs.issued.serialHex,
                               'keyCompromise');
  const before = revokedFor('tls-client', bobSerial);
  const scimId = String(helpers.subjectForName(BOB) || '')
    .replace(/^urn:uuid:/, '') || dnOf(BOB);
  const scimGone = ldap.deletePerson(scimId);
  ldap.createUser(BOB, { invent: false });
  const after = revokedFor('tls-client', bobSerial);
  t.check(own.ok && scimGone.ok && listed(BOB).length === 0,
          'B1. a revoked certificate is not listed for the namesake after a ' +
          'SCIM delete', JSON.stringify({ own: own.ok, scim: scimGone,
                                          listed: listed(BOB) }));
  t.check(!!before && !!after && after.reason === 'keyCompromise' &&
          after.revokedAt === before.revokedAt,
          'B2. the revocation keeps its first reason and date',
          JSON.stringify({ before: before, after: after }));

  // -------------------------------------------------------------------------
  // C. AN LDAP DELETE
  // -------------------------------------------------------------------------
  const CAROL = 'dc-carol';
  ldap.createUser(CAROL, { invent: false });
  const carols = await issueTls(CAROL);
  await Promise.resolve(ldap.performOperation('del',
    { dn: dnOf(CAROL), boundDn: '', channel: 'ldaps' }));
  ldap.createUser(CAROL, { invent: false });
  const carolRevoked = revokedFor('tls-client', carols.issued.serialHex);
  t.check(listed(CAROL).length === 0 && !!carolRevoked &&
          carolRevoked.reason === 'cessationOfOperation',
          'C1. an LDAP delete revokes and detaches the same way',
          JSON.stringify({ listed: listed(CAROL), revoked: carolRevoked }));

  // -------------------------------------------------------------------------
  // D. A RE-HOMING IS NOT A DELETE
  // -------------------------------------------------------------------------
  const DAN = 'dc-dan';
  ldap.createUser(DAN, { invent: false });
  const dans = await issueTls(DAN);
  const moved = ldap.deletePerson(dnOf(DAN), { door: 'a re-homing',
                                               moved: true });
  t.check(moved.ok && !revokedFor('tls-client', dans.issued.serialHex),
          'D1. a re-homing leaves the certificate valid', JSON.stringify(moved));
  ldap.createUser(DAN, { invent: false });
  t.check(listed(DAN).length === 0,
          'D2. and a namesake here is still not listed it: the listing ' +
          'reads the holder by subject', JSON.stringify(listed(DAN)));

  // -------------------------------------------------------------------------
  // E. AN APPLICATION
  // -------------------------------------------------------------------------
  const APP = 'dc-app';
  const madeApp = applications.createApplication({ identifier: APP,
    protocols: ['oauth2'], fields: { oauthClientId: APP } });
  const appCert = await tlsClient.issue(undefined, { kind: 'application',
    application: APP, label: 'svc', keyAlg: 'ec-p256' });
  const appGone = applications.deleteApplication(APP);
  applications.createApplication({ identifier: APP,
    protocols: ['oauth2'], fields: { oauthClientId: APP } });
  const appListed = tlsClient.listFor(undefined, APP, 'application');
  const appRevoked = appCert.ok
    ? revokedFor('tls-client', appCert.issued.serialHex) : null;
  t.check(madeApp && appCert.ok && appGone.ok && appListed.length === 0 &&
          !!appRevoked && appRevoked.reason === 'cessationOfOperation',
          'E1. an application registered again under its identifier is ' +
          'listed none of the deleted one\'s certificates, which are revoked',
          JSON.stringify({ issued: appCert.errors || '', gone: appGone,
                           listed: appListed.length, revoked: appRevoked }));

  // -------------------------------------------------------------------------
  // F. THE CODES
  // -------------------------------------------------------------------------
  t.check(['STS-PKI-0279', 'STS-PKI-0280'].every(function (code) {
    return !!errorCodes.describe(code);
  }), 'F1. STS-PKI-0279 and STS-PKI-0280 are in the table');
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
  name: 'deleted_certificates',
  describe: 'A deleted person\'s or application\'s certificates are revoked ' +
            'and detached from its name, so a namesake inherits none of them',
  run: run
};
