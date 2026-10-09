// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_ldif.js
//
// ===========================================================================
// AN APPLICATION EXPORTED TO, AND IMPORTED FROM, AN LDIF FILE (#546).
//
//   A. EXPORT: `export-ldif` writes one RFC 2849 record — the entry's DN,
//      its object classes and the attributes an administrator can declare,
//      and none of what this registry derived (appFirstSeen). Without the
//      option no credential is in it, and the header names what was left
//      out; with it the client secret is in it IN THE CLEAR, and the header
//      says so. An application nobody recorded is STS-REG-0345.
//   B. IMPORT: the file read back into ANOTHER realm makes the same
//      application there, its client secret authenticating. The same
//      identifier again is STS-REG-0349, a derived attribute STS-REG-0350,
//      an attribute this registry has no row for STS-REG-0351, and a file
//      that is not one LDIF record STS-REG-0347.
//   C. THE AUDIT: an export and an import each write a row naming the
//      attributes and never a value.
//   D. SEALED AT REST: where the key-encryption key persists, a secret
//      exported in the clear and imported is sealed again on the entry.
//
// In a child process, with the whole stack, because D changes the keystore
// and the mode for the rest of the process.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'application_ldif',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.AL_ROOT;
  const OUT = process.env.AL_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const applications = require(ROOT + '/common/applications');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const config = require(ROOT + '/common/config');
    const errorCodes = require(ROOT + '/common/error_codes');
    const clientAuth = require(ROOT + '/oauth-oidc/client_auth');
    const RUN = process.pid + '-' +
      require('crypto').randomBytes(3).toString('hex');
    const APP = 'ldif-app-' + RUN;
    const SECRET = 'ldif-secret-0123456789abcdef-' + RUN;
    const act = async function (body) {
      const reply = actions.applicationsAction(body, [], {});
      return reply && reply.then ? await reply : reply;
    };
    // RFC 2849 folds a line at 76 columns, so a value is searched for in
    // the unfolded text.
    const unfold = function (ldif) {
      return String(ldif || '').replace(/\r?\n /g, '');
    };
    const codeOf = function (reply) {
      return reply && errorCodes.codeOf(reply);
    };

    applications.createApplication({ identifier: APP, name: 'LDIF probe',
      protocols: ['oauth2'],
      fields: { oauthClientId: APP, oauthClientSecret: SECRET,
                oauthRedirectUri: 'https://ldif.example.com/cb',
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });

    // --- A. export ----------------------------------------------------------
    const plain = await act({ action: 'export-ldif', application: APP });
    const text = (plain && plain.ldif) || '';
    note(plain && plain.ok && /^dn: cn=/m.test(text) &&
         /ou=applications/i.test(text) && text.indexOf(APP) >= 0,
         'A1. export-ldif writes the entry\'s DN and identifier',
         JSON.stringify(plain && (plain.errors || plain.attributes)));
    note(/^oauthRedirectUri: https:\/\/ldif\.example\.com\/cb$/m.test(text) &&
         /^oauthTokenEndpointAuthMethod: client_secret_basic$/m.test(text),
         'A2. with every declared attribute it holds');
    note(!/^appFirstSeen:/mi.test(text) && !/^appLastSeen:/mi.test(text),
         'A3. and none this registry derived', text.slice(0, 600));
    note(unfold(text).indexOf(SECRET) < 0 &&
         !/^oauthClientSecret:/mi.test(text) &&
         (plain.leftOut || []).indexOf('oauthClientSecret') >= 0 &&
         /oauthClientSecret/.test(text.split('\n').filter(function (line) {
           return line.charAt(0) === '#';
         }).join('\n')),
         'A4. WITHOUT the option no credential is in it, and the header ' +
         'names what was left out', JSON.stringify(plain && plain.leftOut));
    const file = plain && plain.files && plain.files[0];
    note(file && /\.ldif$/.test(file.name) &&
         Buffer.from(file.base64, 'base64').toString('utf8') === text,
         'A5. the answer carries the file to save',
         JSON.stringify(file && file.name));
    const full = await act({ action: 'export-ldif', application: APP,
                             credentials: 'on' });
    const fullText = (full && full.ldif) || '';
    note(full && full.ok && full.credentials === true &&
         unfold(fullText).indexOf(SECRET) >= 0 &&
         /UNENCRYPTED|unencrypted|in the clear/.test(fullText),
         'A6. WITH the option the client secret is in it in the clear, ' +
         'and the header says so',
         JSON.stringify(full && (full.errors || full.credentials)));
    const nobody = await act({ action: 'export-ldif',
                               application: APP + '-nobody' });
    note(nobody && nobody.ok === false && codeOf(nobody) === 'STS-REG-0345',
         'A7. an application nobody recorded is STS-REG-0345',
         JSON.stringify(nobody));

    // --- C. the export's audit row ------------------------------------------
    const exportRows = audit.list().filter(function (row) {
      return row.action === 'application.export' && row.target === APP;
    });
    note(exportRows.length === 2 && exportRows.every(function (row) {
      return JSON.stringify(row).indexOf(SECRET) < 0;
    }), 'C1. each export is audited, never with a value',
         exportRows.length + ' row(s)');

    // --- B. import, into another realm --------------------------------------
    const REALM = 'ldifimp' + process.pid;
    realms.create({ id: REALM, name: 'LDIF import' });
    try {
      await realms.run(realms.get(REALM), async function () {
        note(!applications.get(APP),
             'B0. the application is not in the other realm yet');
        const imported = await act({ action: 'import-ldif',
                                     file: { name: 'x.ldif',
                                             text: fullText } });
        note(imported && imported.ok === true && imported.changed === true,
             'B1. the file imports into another realm',
             JSON.stringify(imported && (imported.errors || imported.ok)));
        const copy = applications.clientConfigOf(APP) || {};
        note(copy.client_secret === SECRET &&
             [].concat(copy.redirect_uris || []).indexOf(
               'https://ldif.example.com/cb') >= 0,
             'B2. with its declared attributes and its client secret',
             JSON.stringify(Object.keys(copy)));
        const auth = await clientAuth.verify({
          method: 'client_secret_basic', clientId: APP,
          presentedSecret: SECRET });
        note(auth && auth.ok, 'B3. and the secret authenticates there',
             JSON.stringify(auth));

        const again = await act({ action: 'import-ldif', ldif: fullText });
        note(again && again.ok === false && codeOf(again) === 'STS-REG-0349',
             'B5. the same identifier again is refused, never overwritten',
             JSON.stringify(again));
        const other = fullText.split(APP).join(APP + '-b');
        const derived = await act({ action: 'import-ldif',
          ldif: other.replace(/\n*$/, '\nappFirstSeen: 20260101000000Z\n') });
        note(derived && derived.ok === false &&
             codeOf(derived) === 'STS-REG-0350' &&
             !applications.get(APP + '-b'),
             'B6. a derived attribute is refused, and nothing is made',
             JSON.stringify(derived));
        const unknown = await act({ action: 'import-ldif',
          ldif: other.replace(/\n*$/, '\nnoSuchAttribute: x\n') });
        note(unknown && unknown.ok === false &&
             codeOf(unknown) === 'STS-REG-0351' &&
             !applications.get(APP + '-b'),
             'B7. so is an attribute this registry has no row for',
             JSON.stringify(unknown));
        const two = await act({ action: 'import-ldif',
          ldif: other + '\n\n' + other.split(APP + '-b').join(APP + '-c') });
        note(two && two.ok === false && codeOf(two) === 'STS-REG-0347',
             'B8. so is a file of two records', JSON.stringify(two));
        const junk = await act({ action: 'import-ldif',
                                 ldif: 'not an ldif file at all' });
        note(junk && junk.ok === false &&
             ['STS-REG-0347', 'STS-REG-0348'].indexOf(codeOf(junk)) >= 0,
             'B9. and one that is not LDIF', JSON.stringify(junk));
        const person = await act({ action: 'import-ldif',
          ldif: 'dn: uid=x,ou=people,dc=example,dc=com\nuid: x\n' });
        note(person && person.ok === false &&
             codeOf(person) === 'STS-REG-0348',
             'B10. and an entry that is not an application',
             JSON.stringify(person));
        const importRows = audit.list().filter(function (row) {
          return row.action === 'application.import' && row.target === APP;
        });
        note(importRows.length === 1 &&
             JSON.stringify(importRows[0]).indexOf(SECRET) < 0,
             'C2. the import is audited in the realm it made the ' +
             'application in, never with a value',
             importRows.length + ' row(s)');
      });

      // --- D. sealed at rest ------------------------------------------------
      const keystore = require(ROOT + '/common/keystore');
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-ldif-seal-'));
      fs.writeFileSync(path.join(dir, 'kek'),
        require('crypto').randomBytes(32).toString('base64'),
        { encoding: 'utf8', mode: 0o600 });
      config.setOverride('global.mode', 'product');
      process.env.STS_KEYS_SOURCE = 'persisted';
      process.env.STS_KEYS_KEK_PROVIDER = 'file';
      process.env.STS_KEYS_KEK_FILE = path.join(dir, 'kek');
      keystore.reset();
      keystore.setStore({
        loadKeys: function () { return Promise.resolve([]); },
        saveKeys: function () { return Promise.resolve(); },
        deleteKeys: function () { return Promise.resolve(); }
      });
      await keystore.start();
      note(keystore.persists(), 'D0. the key-encryption key now persists');
      const SEALED = 'ldif-sealed-' + RUN;
      const SS = 'ldif-sealed-secret-0123456789abcdef-' + RUN;
      applications.createApplication({ identifier: SEALED,
        protocols: ['oauth2'],
        fields: { oauthClientId: SEALED, oauthClientSecret: SS,
                  oauthRedirectUri: 'https://ldif.example.com/cb' } });
      const storedOf = function (id) {
        return [].concat(((applications.get(id) || {}).attributes || {})
          .oauthClientSecret || []);
      };
      note(storedOf(SEALED).length === 1 &&
           applications.isSealed(storedOf(SEALED)[0]),
           'D1. the source\'s secret is sealed on its entry');
      const sealedOut = await act({ action: 'export-ldif',
                                    application: SEALED,
                                    credentials: true });
      const sealedText = (sealedOut && sealedOut.ldif) || '';
      note(sealedOut && sealedOut.ok && unfold(sealedText).indexOf(SS) >= 0,
           'D2. exported WITH credentials it is opened, in the clear',
           JSON.stringify(sealedOut && sealedOut.errors));
      await realms.run(realms.get(REALM), async function () {
        const back = await act({ action: 'import-ldif', ldif: sealedText });
        note(back && back.ok, 'D3. and imported into the other realm',
             JSON.stringify(back && back.errors));
        const held = storedOf(SEALED);
        note(held.length === 1 && applications.isSealed(held[0]) &&
             held[0].indexOf(SS) < 0,
             'D4. where it is SEALED again on the entry',
             String(held[0] || '').slice(0, 16));
        note((applications.clientConfigOf(SEALED) || {}).client_secret === SS,
             'D5. and opened for the reader');
      });
      delete process.env.STS_KEYS_SOURCE;
      delete process.env.STS_KEYS_KEK_PROVIDER;
      delete process.env.STS_KEYS_KEK_FILE;
      keystore.reset();
      config.clearOverride('global.mode');
      fs.rmSync(dir, { recursive: true, force: true });
    } finally {
      realms.remove(REALM);
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
  const out = path.join(os.tmpdir(), 'application-ldif-' + process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', AL_ROOT: ROOT, AL_OUT: out }),
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
  name: 'application_ldif',
  describe: 'an application exported to LDIF without and with its ' +
            'credentials, imported into another realm, the refusals ' +
            '(an existing identifier, a derived or unknown attribute, not ' +
            'one record), the audit rows, and a secret sealed again at rest',
  run: run
};
