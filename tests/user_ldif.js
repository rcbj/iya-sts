// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/user_ldif.js
//
// ===========================================================================
// A PERSON EXPORTED TO, AND IMPORTED FROM, AN LDIF FILE (2026-11-14), the
// application page's #546 pattern on a person's page (`ldap/person_ldif.ts`).
//
//   A. EXPORT: `export-ldif` writes one RFC 2849 record — the entry's DN, its
//      object classes and the attributes a create takes, and none of what the
//      service recorded, no `entryUUID`, no group membership. WITHOUT the box
//      no credential attribute is in it and the header names what was left
//      out; WITH it every kind the entry holds is in it — the password's
//      stored hash, the authenticator app, a passkey and its user handle, the
//      recovery codes, an app password and a stored certificate — and the
//      header says UNENCRYPTED. A person nobody holds is STS-LDAP-0214.
//   B. IMPORT, INTO ANOTHER REALM: the person is created there with a new
//      subject; the same password verifies against the stored hash, the same
//      TOTP secret is held, the passkey and the recovery code and the app
//      password and the certificate come with them; no Kerberos key.
//   C. THE REFUSALS, each with its code and nothing created: an existing
//      username (0218, the existing person unchanged), an application's file
//      at the person door (0217) and a person's at the application door
//      (STS-REG-0348), a recorded attribute and an entryUUID (0219), a clear
//      password (0220), a passkey user handle already held in the realm
//      (0220), a file of two records (0216).
//   D. THE AUDIT: an export and an import each write a row naming
//      attributes and never a value.
//   E. THE ANSWER MEETS ITS CLOSED MODEL, both operations, and the model is
//      closed.
//   F. THE CONSOLE TAB: the two forms for a writer, and the reason for a
//      reader without Admin Write; and Admin Read is refused at the
//      management API's door (the operations ask admin:write).
//
// In a child process, with the whole stack, because it creates realms and
// writes the directory for the rest of the process.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'user_ldif',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.UL_ROOT;
  const OUT = process.env.UL_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const nodeCrypto = require('crypto');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const applications = require(ROOT + '/common/applications');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const errorCodes = require(ROOT + '/common/error_codes');
    const credentials = require(ROOT + '/common/credentials');
    const totp = require(ROOT + '/common/totp');
    const stsCrypto = require(ROOT + '/common/crypto');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const RUN = process.pid + '-' + nodeCrypto.randomBytes(3).toString('hex');
    const P = 'ldifperson' + RUN.replace(/[^a-z0-9]/gi, '');
    const PW = 'Ldif-Password-' + RUN + '-x9!';
    const CTX = { via: 'api', actor: 'ldif-tester' };
    const act = async function (body) {
      const reply = actions.usersAction(body, CTX);
      return reply && reply.then ? await reply : reply;
    };
    const unfold = function (ldif) {
      return String(ldif || '').replace(/\r?\n /g, '');
    };
    const codeOf = function (reply) {
      return reply && errorCodes.codeOf(reply);
    };
    const attrLines = function (text) {
      return unfold(text).split('\n').filter(function (line) {
        return line && line.charAt(0) !== '#';
      }).map(function (line) {
        return line.split(':')[0].toLowerCase();
      });
    };
    const CREDENTIAL_NAMES = ['userpassword', 'ststotpcredential',
      'stswebauthncredential', 'stswebauthnuserhandle', 'stsbackupcodes',
      'stsapppassword', 'usercertificate;binary', 'usercertificate',
      'hobapublickey', 'stscibausercode', 'stswebauthnpqcuserhandle'];

    // --- the person, with one of each kind of credential --------------------
    const made = await act({ action: 'create', username: P, invent: 'no',
      attributes: { cn: 'LDIF Person', sn: 'Person', givenName: 'LDIF',
                    mail: P + '@example.com', title: 'Engineer' },
      credential: 'password', password: PW });
    note(made && made.ok, '0. the person is created with a password',
         JSON.stringify(made && made.errors));
    const begun = credentials.beginTotpEnrolment(P);
    const confirmed = begun && begun.ok
      ? credentials.confirmTotpEnrolment(P, totp.codeAt(begun.secret))
      : null;
    note(confirmed && confirmed.ok, '0. an authenticator app is enrolled',
         JSON.stringify(confirmed && confirmed.errors));
    const codes = credentials.beginBackupCodes(P);
    const kept = codes && codes.ok
      ? credentials.confirmBackupCodes(P, codes.handle) : null;
    note(kept && kept.ok, '0. recovery codes are issued',
         JSON.stringify(kept && kept.errors));
    const appPassword = credentials.createAppPassword(P, { name: 'mail',
                                                           doors: ['ldap'] });
    note(appPassword && appPassword.ok, '0. an app password is made',
         JSON.stringify(appPassword && appPassword.errors));
    const keyPair = nodeCrypto.generateKeyPairSync('ec',
      { namedCurve: 'P-256' });
    const CRED_ID = 'ldif-cred-' + RUN;
    const HANDLE = Buffer.from('ldif-handle-' + RUN).toString('base64');
    const dn = ldap.locateEntry(P).stored.dn;
    ldap.writeImportedCredentials(dn, {
      stswebauthncredential: [JSON.stringify({ credentialId: CRED_ID,
        publicKeyJwk: keyPair.publicKey.export({ format: 'jwk' }),
        label: 'ldif key', signCount: 0 })],
      stswebauthnuserhandle: [HANDLE] });
    note(credentials.keysOf(P).length === 1,
         '0. a passkey and its user handle are held');
    const cert = stsCrypto.selfSignedRsaCertificate({ commonName: P });
    const stored = await act({ action: 'add-certificate', user: P,
                               certificate: cert.certPem });
    note(stored && stored.ok, '0. a certificate is stored on the entry',
         JSON.stringify(stored && stored.errors));
    const hashBefore = String((ldap.locateEntry(P).stored.attributes
      .userpassword || [])[0] || '');

    // --- A. export -----------------------------------------------------------
    const plain = await act({ action: 'export-ldif', user: P });
    const text = (plain && plain.ldif) || '';
    const names = attrLines(text);
    note(plain && plain.ok && /^dn: uid=/m.test(text) &&
         /ou=users/i.test(text) && names.indexOf('uid') >= 0,
         'A1. export-ldif writes the entry\'s DN and its uid',
         JSON.stringify(plain && (plain.errors || plain.attributes)));
    note(/^title: Engineer$/m.test(text) && /^givenName: LDIF$/m.test(text),
         'A2. with the attributes a create takes', text.slice(0, 500));
    note(names.indexOf('entryuuid') < 0 && names.indexOf('authnmethod') < 0 &&
         names.indexOf('createtimestamp') < 0 &&
         names.indexOf('memberof') < 0,
         'A3. and nothing recorded, no entryUUID, no membership',
         names.join(','));
    const leaked = names.filter(function (one) {
      return CREDENTIAL_NAMES.indexOf(one) >= 0;
    });
    note(leaked.length === 0 && unfold(text).indexOf(hashBefore) < 0 &&
         unfold(text).indexOf(begun.secret) < 0 &&
         (plain.leftOut || []).indexOf('userPassword') >= 0 &&
         /userPassword/.test(text.split('\n').filter(function (line) {
           return line.charAt(0) === '#';
         }).join('\n')),
         'A4. WITHOUT the box no credential attribute is in it, and the ' +
         'header names what was left out', leaked.join(',') + ' ' +
         JSON.stringify(plain && plain.leftOut));
    const file = plain && plain.files && plain.files[0];
    note(file && /\.ldif$/.test(file.name) &&
         Buffer.from(file.base64, 'base64').toString('utf8') === text,
         'A5. the answer carries the file to save',
         JSON.stringify(file && file.name));
    const full = await act({ action: 'export-ldif', user: P,
                             credentials: 'on' });
    const fullText = (full && full.ldif) || '';
    const fullNames = attrLines(fullText);
    const kinds = ['userpassword', 'ststotpcredential',
                   'stswebauthncredential', 'stswebauthnuserhandle',
                   'stsbackupcodes', 'stsapppassword',
                   'usercertificate;binary'];
    const missing = kinds.filter(function (one) {
      return fullNames.indexOf(one) < 0;
    });
    note(full && full.ok && full.credentials === true && !missing.length &&
         unfold(fullText).indexOf(hashBefore) >= 0 &&
         unfold(fullText).indexOf(begun.secret) >= 0 &&
         /UNENCRYPTED/.test(fullText),
         'A6. WITH the box each kind the entry holds is in it, the TOTP ' +
         'secret opened, and the header says UNENCRYPTED',
         'missing ' + missing.join(',') + ' ' +
         JSON.stringify(full && full.errors));
    note(fullNames.indexOf('stskrb5keys') < 0 &&
         fullNames.indexOf('stskrb5keyinfo') < 0,
         'A7. and no Kerberos key, even then');
    const nobody = await act({ action: 'export-ldif', user: P + 'nobody' });
    note(nobody && nobody.ok === false && codeOf(nobody) === 'STS-LDAP-0214',
         'A8. a person nobody holds is STS-LDAP-0214', JSON.stringify(nobody));

    // --- D. the export's audit rows -----------------------------------------
    const exportRows = audit.list().filter(function (row) {
      return row.action === 'user.export' && row.target === P;
    });
    note(exportRows.length === 2 && exportRows.every(function (row) {
      const json = JSON.stringify(row);
      return json.indexOf(hashBefore) < 0 && json.indexOf(begun.secret) < 0;
    }), 'D1. each export is audited, never with a value',
         exportRows.length + ' row(s)');

    // --- C. a refusal in the source realm: the user handle -------------------
    const renamed = fullText.split(P).join(P + 'b');
    const clash = await act({ action: 'import-ldif',
      ldif: renamed.replace(/^usercertificate;binary.*$/gmi, '') });
    note(clash && clash.ok === false && codeOf(clash) === 'STS-LDAP-0220' &&
         !ldap.locateEntry(P + 'b').stored,
         'C1. a passkey user handle held in this realm already is refused, ' +
         'and nobody is created', JSON.stringify(clash));
    const before = JSON.stringify(ldap.locateEntry(P).stored.attributes);
    const again = await act({ action: 'import-ldif', ldif: fullText });
    note(again && again.ok === false && codeOf(again) === 'STS-LDAP-0218' &&
         JSON.stringify(ldap.locateEntry(P).stored.attributes) === before,
         'C2. an existing username is refused and the person is unchanged',
         JSON.stringify(again));

    // --- B. import, into another realm --------------------------------------
    const REALM = 'ldifu' + process.pid;
    realms.create({ id: REALM, name: 'Person LDIF import' });
    try {
      await realms.run(realms.get(REALM), async function () {
        note(!ldap.locateEntry(P).stored,
             'B0. the person is not in the other realm yet');
        const imported = await act({ action: 'import-ldif',
                                     file: { name: 'p.ldif',
                                             text: fullText } });
        note(imported && imported.ok === true && imported.changed === true &&
             imported.kerberosKeys === false,
             'B1. the file imports into another realm',
             JSON.stringify(imported && (imported.errors || imported.ok)));
        const entry = ldap.locateEntry(P).stored || { attributes: {} };
        const attrs = entry.attributes;
        note(String((attrs.title || [])[0]) === 'Engineer' &&
             String((attrs.mail || [])[0]) === P + '@example.com',
             'B2. with the attributes the file carried',
             JSON.stringify(Object.keys(attrs)));
        const hashAfter = String((attrs.userpassword || [])[0] || '');
        note(hashAfter === hashBefore && stsCrypto.verifySecret(PW, hashAfter),
             'B3. the same password verifies against the stored hash');
        const record = credentials.totpOf(P);
        note(record && record.secret === begun.secret,
             'B4. the same authenticator secret is held');
        note(credentials.keysOf(P).some(function (one) {
          return one.credentialId === CRED_ID;
        }) && String((attrs.stswebauthnuserhandle || [])[0]) === HANDLE,
             'B5. the same passkey and its user handle are held');
        const spent = await credentials.verifyBackupCodeAsync(P,
                                                              codes.codes[0]);
        note(spent && spent.ok, 'B6. a recovery code works there',
             JSON.stringify(spent));
        note(credentials.appPasswordsOf(P).passwords.length === 1 &&
             [].concat(attrs['usercertificate;binary'] || []).length === 1,
             'B7. with the app password and the stored certificate',
             JSON.stringify(credentials.appPasswordsOf(P)) + ' ' +
             JSON.stringify(Object.keys(attrs)));
        note(!attrs.stskrb5keys,
             'B8. and no Kerberos key: a hash gives back no password');
        const uuidThere = String((attrs.entryuuid || [])[0] || '');
        note(uuidThere && fullText.indexOf(uuidThere) < 0,
             'B9. a new subject was minted');
        const importRows = audit.list().filter(function (row) {
          return row.action === 'user.import' && row.target === P;
        });
        note(importRows.length === 1 &&
             JSON.stringify(importRows[0]).indexOf(hashBefore) < 0,
             'D2. the import is audited in the realm it made the person in, ' +
             'never with a value', importRows.length + ' row(s)');

        // --- C. the other refusals -------------------------------------------
        const other = text.split(P).join(P + 'c');
        const tried = function (reply, code, what) {
          note(reply && reply.ok === false && codeOf(reply) === code &&
               !ldap.locateEntry(P + 'c').stored,
               what + ' (' + code + '), and nobody is created',
               JSON.stringify(reply));
        };
        tried(await act({ action: 'import-ldif',
          ldif: other.replace(/\n*$/, '\nauthnMethod: pwd\n') }),
          'STS-LDAP-0219', 'C3. a recorded attribute is refused');
        tried(await act({ action: 'import-ldif',
          ldif: other.replace(/\n*$/, '\nentryUUID: ' +
                              nodeCrypto.randomUUID() + '\n') }),
          'STS-LDAP-0219', 'C4. an entryUUID is refused');
        tried(await act({ action: 'import-ldif',
          ldif: other.replace(/\n*$/, '\nuserPassword: clear-text\n') }),
          'STS-LDAP-0220', 'C5. a clear password is refused');
        tried(await act({ action: 'import-ldif',
          ldif: other + '\n\n' + other.split(P + 'c').join(P + 'd') }),
          'STS-LDAP-0216', 'C6. a file of two records is refused');
        const APP = 'ldif-app-' + RUN;
        applications.createApplication({ identifier: APP,
          protocols: ['oauth2'], fields: { oauthClientId: APP } });
        const appFile = actions.applicationsAction({ action: 'export-ldif',
          application: APP }, [], {});
        tried(await act({ action: 'import-ldif',
                          ldif: (appFile && appFile.ldif) || '' }),
          'STS-LDAP-0217', 'C7. an application\'s file is refused at the ' +
          'person door');
        const atApps = actions.applicationsAction({ action: 'import-ldif',
          ldif: other }, [], {});
        note(atApps && atApps.ok === false &&
             codeOf(atApps) === 'STS-REG-0348',
             'C8. and a person\'s file at the application door',
             JSON.stringify(atApps));

        // --- E. the answers against their closed models --------------------
        const document = require(ROOT + '/common/model_tables')
          .file('openapi.management.json');
        const Ajv = require('ajv');
        const modelOf = function (pathName) {
          const op = document.paths[pathName] && document.paths[pathName].post;
          return op ? new Ajv({ strict: false, allErrors: true }).compile({
            allOf: [op.responses['200'].content['application/json'].schema],
            components: document.components }) : null;
        };
        const exportModel = modelOf('/admin-api/users/export-ldif');
        const importModel = modelOf('/admin-api/users/import-ldif');
        note(exportModel && exportModel(JSON.parse(JSON.stringify(full))) &&
             exportModel(JSON.parse(JSON.stringify(plain))),
             'E1. both exports meet exportUserLdif\'s model',
             JSON.stringify(exportModel && exportModel.errors));
        note(importModel &&
             importModel(JSON.parse(JSON.stringify(imported))),
             'E2. the import meets importUserLdif\'s model',
             JSON.stringify(importModel && importModel.errors));
        note(exportModel && !exportModel(Object.assign({ stray: 1 }, full)) &&
             importModel && !importModel(Object.assign({ stray: 1 },
                                                       imported)),
             'E3. and both models are closed');
      });

      // --- F. the console, and the door -------------------------------------
      const page = require(ROOT + '/admin-ui/web_users');
      const kit = require(ROOT + '/admin-ui/web_kit');
      const tr = kit.context({}, true).t;
      const writer = page.userLdifSection(tr, P, { write: true }, '');
      note(/name="action" value="export-ldif"/.test(writer) &&
           /name="credentials"/.test(writer) &&
           /name="action" value="import-ldif"/.test(writer) &&
           /type="file"/.test(writer) && /UNENCRYPTED|unencrypted/
             .test(writer),
           'F1. a writer is drawn both forms, the box saying unencrypted',
           writer.slice(0, 300));
      const reader = page.userLdifSection(tr, P, { write: false }, '');
      note(!/<form/.test(reader) && /Admin Write/.test(reader),
           'F2. a reader without Admin Write is told why and given no form',
           reader);
      const spec = document_ops();
      note(spec.every(function (one) {
        return one && one.security && JSON.stringify(one.security)
          .indexOf('admin:write') >= 0 &&
          JSON.stringify(one.security).indexOf('admin:read') < 0;
      }) && spec.length === 2,
           'F3. both operations ask admin:write, so Admin Read is refused',
           JSON.stringify(spec.map(function (one) {
             return one && one.security;
           })));
    } finally {
      realms.remove(REALM);
    }

    function document_ops() {
      const document = require(ROOT + '/common/model_tables')
        .file('openapi.management.json');
      return ['/admin-api/users/export-ldif',
              '/admin-api/users/import-ldif'].map(function (one) {
        return document.paths[one] && document.paths[one].post;
      });
    }

    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'user-ldif-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', UL_ROOT: ROOT, UL_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'user_ldif',
  describe: 'a person exported to LDIF without and with their credentials, ' +
            'imported into another realm signing in with the same password, ' +
            'TOTP, passkey and recovery code, the refusals (an existing ' +
            'username, an application\'s file, a recorded attribute, an ' +
            'entryUUID, a clear password, a held user handle, two records), ' +
            'the audit rows, the closed models and the console tab',
  run: run
};
