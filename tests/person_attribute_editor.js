'use strict';

// ===========================================================================
// tests/person_attribute_editor.js — WHAT AN ADMINISTRATOR MAY CHANGE ON A
// PERSON'S ENTRY, ONE ATTRIBUTE AT A TIME (#228, 2026-09-26).
//
// `ldap/person_editor.ts` and its three doors: `set-attribute`,
// `add-attribute` and `remove-attribute` through `usersAction()` (which the
// console's /admin/users and POST /admin-api/users/{action} both call), the
// `attributeEditor` in the person's view, and the section on their page.
//
// In a CHILD PROCESS, for `admin_bootstrap.js`'s reason: it loads the whole
// protocol stack and creates people in the default realm.
//
// The claims:
//
//   1. The list is the person schema and the credential catalogue less what
//      is managed: `title`, `telephoneNumber`, `manager`, `schacDateOfBirth`,
//      `c` and `employeeStatus` are on it; `userPassword`, `jpegPhoto`,
//      `userPKCS12`, `uid` and `mail` are withheld with a reason; `memberOf`
//      and `stsTotpCredential` are on neither.
//   2. set / add / remove do what they say, and write only that attribute:
//      the entryUUID, the password hash and every other value are untouched.
//   3. Every refusal carries its code: no person named (ADMIN-0518), nobody
//      there (LDAP-0102), a withheld or unknown attribute (0103), the entry's
//      own naming attribute (0104), an add to a single-valued attribute or a
//      bad mode (0105), a bad value (0106), a duplicate (0107), an absent
//      value (0108), emptying cn or sn (0109).
//   4. The shaped values: a country code is checked and upper-cased, a date
//      checked and stored YYYYMMDD, a language range, an http(s) labeledURI,
//      a DN's shape, and no control character or over-long value anywhere.
//   5. The account observer is told of an edit with the before and after, as
//      it is of a SCIM or LDAP write.
//   6. The person's view publishes `attributeEditor`, and the page draws the
//      section.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'person_attribute_editor',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.PAE_ROOT;
  const OUT = process.env.PAE_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const credentials = require(ROOT + '/common/credentials');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const editor = require(ROOT + '/ldap/person_editor');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const admin = require(ROOT + '/admin-ui/admin');

    await realms.run(realms.DEFAULT_REALM, async function () {
      const ctx = { via: 'api', actor: 'tester' };
      const act = function (action, user, attribute, value) {
        return actions.usersAction({ action: action, user: user,
                                     attribute: attribute, value: value },
                                   ctx);
      };
      const codeOf = function (result) {
        return errorCodes.codeOf(result) || '';
      };
      const refusedWith = function (result, code, what) {
        note(result && result.ok === false && codeOf(result) === code, what,
             JSON.stringify(result) + ' ' + codeOf(result));
      };
      const entryOf = function (name) {
        return ldap.readPerson(ldap.usersDn().replace(/^/, 'uid=' + name +
                                                          ','));
      };
      const valuesOf = function (name, attribute) {
        const entry = entryOf(name);
        // Canonically spelt by readPerson(), so found in any case.
        const map = (entry && entry.attributes) || {};
        const found = Object.keys(map).filter(function (k) {
          return k.toLowerCase() === String(attribute).toLowerCase();
        })[0];
        const held = found === undefined ? undefined : map[found];
        return Array.isArray(held) ? held.map(String)
                                   : (held === undefined ? [] : [held]);
      };

      // ====================================================================
      // 1. THE LIST
      // ====================================================================
      const editable = editor.editableAttributes().map(function (row) {
        return row.name;
      });
      const withheld = editor.withheldAttributes();
      const withheldNames = withheld.map(function (row) {
        return row.name;
      });
      ['title', 'telephoneNumber', 'manager', 'schacDateOfBirth', 'c',
       'employeeStatus', 'cn', 'sn', 'displayName'].forEach(function (name) {
        note(editable.indexOf(name) >= 0, '1. ' + name + ' is editable',
             editable.join(','));
      });
      ['userPassword', 'jpegPhoto', 'userPKCS12', 'uid', 'mail']
        .forEach(function (name) {
          const row = withheld.filter(function (one) {
            return one.name === name;
          })[0];
          note(editable.indexOf(name) < 0 && row && row.why.length > 20,
               '1. ' + name + ' is withheld, with a reason',
               JSON.stringify(row));
        });
      ['memberOf', 'stsTotpCredential', 'federationLink']
        .forEach(function (name) {
          note(editable.indexOf(name) < 0 && withheldNames.indexOf(name) < 0,
               '1. ' + name + ' is on neither list');
        });
      note(editor.available(), '1. the directory filled the editor\'s slot');

      // ====================================================================
      // 2. SET, ADD, REMOVE — and nothing else moves
      // ====================================================================
      const made = ldap.createUser('pae-alice', {});
      note(made && made.ok !== false, '2. a person is created',
           JSON.stringify(made));
      credentials.setPassword('pae-alice', 'Pae-Pass-123!');
      const before = entryOf('pae-alice');
      const snapshot = JSON.stringify(before.attributes || before);
      const uuidBefore = valuesOf('pae-alice', 'entryuuid').join();
      const hashBefore = valuesOf('pae-alice', 'userpassword').join();

      let result = act('set-attribute', 'pae-alice', 'title',
                       'Principal Engineer');
      note(result.ok && valuesOf('pae-alice', 'title').join() ===
             'Principal Engineer',
           '2. set-attribute replaces the value', JSON.stringify(result));
      result = act('set-attribute', 'pae-alice', 'title', 'Staff Engineer');
      note(result.ok && valuesOf('pae-alice', 'title').join() ===
             'Staff Engineer',
           '2. a second set replaces rather than adds',
           valuesOf('pae-alice', 'title').join('|'));
      result = act('add-attribute', 'pae-alice', 'telephoneNumber',
                   '+1 555 0100');
      result = act('add-attribute', 'pae-alice', 'telephonenumber',
                   '+1 555 0101');
      note(result.ok && result.attribute === 'telephoneNumber' &&
             valuesOf('pae-alice', 'telephonenumber').length === 2 &&
             valuesOf('pae-alice', 'telephonenumber')
               .indexOf('+1 555 0100') >= 0 &&
             valuesOf('pae-alice', 'telephonenumber')
               .indexOf('+1 555 0101') >= 0,
           '2. add-attribute appends, and the name is matched in any case',
           valuesOf('pae-alice', 'telephonenumber').join('|'));
      result = act('remove-attribute', 'pae-alice', 'telephoneNumber',
                   '+1 555 0100');
      note(result.ok && valuesOf('pae-alice', 'telephonenumber').join() ===
             '+1 555 0101',
           '2. remove-attribute takes off the one value',
           valuesOf('pae-alice', 'telephonenumber').join('|'));
      result = act('set-attribute', 'pae-alice', 'title', '');
      note(result.ok && valuesOf('pae-alice', 'title').length === 0,
           '2. an empty set removes the attribute');
      note(valuesOf('pae-alice', 'entryuuid').join() === uuidBefore &&
             valuesOf('pae-alice', 'userpassword').join() === hashBefore &&
             !!hashBefore,
           '2. the entryUUID and the password hash are untouched');
      const after = entryOf('pae-alice');
      const untouched = Object.keys(JSON.parse(snapshot)).filter(function (k) {
        return ['title', 'telephonenumber', 'modifytimestamp']
          .indexOf(k.toLowerCase()) < 0;
      }).every(function (k) {
        return JSON.stringify((after.attributes || after)[k]) ===
               JSON.stringify(JSON.parse(snapshot)[k]);
      });
      note(untouched, '2. every other attribute is exactly as it was');

      // ====================================================================
      // 3. EVERY REFUSAL, CODED
      // ====================================================================
      refusedWith(act('set-attribute', '', 'title', 'x'), 'STS-ADMIN-0518',
                  '3. no person named is STS-ADMIN-0518');
      refusedWith(act('set-attribute', 'pae-nobody', 'title', 'x'),
                  'STS-LDAP-0102', '3. nobody there is STS-LDAP-0102');
      ['userPassword', 'mail', 'uid', 'jpegPhoto', 'memberOf',
       'stsTotpCredential'].forEach(function (name) {
        refusedWith(act('set-attribute', 'pae-alice', name, 'x'),
                    'STS-LDAP-0103', '3. ' + name + ' is STS-LDAP-0103');
      });
      refusedWith(act('add-attribute', 'pae-alice', 'displayName', 'Al'),
                  'STS-LDAP-0105',
                  '3. an add to a single-valued attribute is STS-LDAP-0105');
      refusedWith(editor.update('pae-alice', { attribute: 'title',
                                               mode: 'replace', value: 'x' }),
                  'STS-LDAP-0105', '3. a mode that is not one is ' +
                  'STS-LDAP-0105');
      refusedWith(act('add-attribute', 'pae-alice', 'telephoneNumber', ''),
                  'STS-LDAP-0106', '3. an add of nothing is STS-LDAP-0106');
      refusedWith(act('add-attribute', 'pae-alice', 'telephoneNumber',
                      '+1 555 0101'),
                  'STS-LDAP-0107', '3. a duplicate add is STS-LDAP-0107');
      refusedWith(act('add-attribute', 'pae-alice', 'telephoneNumber',
                      '+1 555 0101'.toUpperCase()),
                  'STS-LDAP-0107', '3. and a duplicate is found in any case');
      refusedWith(act('remove-attribute', 'pae-alice', 'telephoneNumber',
                      '+1 555 9999'),
                  'STS-LDAP-0108', '3. removing a value not held is ' +
                  'STS-LDAP-0108');
      refusedWith(act('set-attribute', 'pae-alice', 'cn', ''),
                  'STS-LDAP-0109', '3. emptying cn is STS-LDAP-0109');
      const sn = valuesOf('pae-alice', 'sn');
      if (sn.length === 1) {
        refusedWith(act('remove-attribute', 'pae-alice', 'sn', sn[0]),
                    'STS-LDAP-0109', '3. removing the last sn is ' +
                    'STS-LDAP-0109');
      } else {
        note(false, '3. the fixture has one sn to remove', sn.join('|'));
      }
      // The entry's own name: a person filed under cn=, as a client
      // certificate's sign-in files them.
      const carlDn = 'cn=pae-carl,' + ldap.usersDn();
      const wrote = ldap.writePerson(carlDn, {
        objectClass: ['top', 'person', 'organizationalPerson',
                      'inetOrgPerson'],
        cn: ['pae-carl'], sn: ['Carlsson'] });
      note(wrote && wrote.ok, '3. a person named by cn is written',
           JSON.stringify(wrote));
      refusedWith(editor.update(carlDn, { attribute: 'cn', mode: 'set',
                                          value: 'somebody else' }),
                  'STS-LDAP-0104', '3. that entry\'s cn is STS-LDAP-0104');
      const carlView = editor.editorFor(carlDn);
      const carlCn = carlView && carlView.attributes.filter(function (row) {
        return row.name === 'cn';
      })[0];
      note(carlCn && carlCn.editable === false &&
             /names|named/.test(carlCn.why),
           '3. and the editor says so for that entry',
           JSON.stringify(carlCn));
      const aliceCn = (editor.editorFor('pae-alice') || { attributes: [] })
        .attributes.filter(function (row) {
          return row.name === 'cn';
        })[0];
      note(aliceCn && aliceCn.editable === true,
           '3. while a uid-named person\'s cn is editable');

      // ====================================================================
      // 4. THE SHAPED VALUES
      // ====================================================================
      const shaped = [
        ['c', 'Sweden', false], ['c', 'XX', false], ['c', 'se', 'SE'],
        ['schacCountryOfCitizenship', 'dk', 'DK'],
        ['schacDateOfBirth', '1990-02-30', false],
        ['schacDateOfBirth', '1990-02-28', '19900228'],
        ['schacDateOfBirth', '19900301', '19900301'],
        ['preferredLanguage', 'en_GB!', false],
        ['preferredLanguage', 'da, en-gb;q=0.8', 'da, en-gb;q=0.8'],
        ['labeledURI', 'javascript:alert(1)', false],
        ['labeledURI', 'ftp://example.org/', false],
        ['labeledURI', 'https://example.org/ Home page',
         'https://example.org/ Home page'],
        ['manager', 'Bob in accounts', false],
        ['manager', 'uid=bob,ou=users,dc=example,dc=com',
         'uid=bob,ou=users,dc=example,dc=com'],
        ['description', 'two\nlines', false],
        ['description', 'x'.repeat(1025), false],
        ['description', 'x'.repeat(1024), 'x'.repeat(1024)]
      ];
      shaped.forEach(function (row) {
        const answer = act('set-attribute', 'pae-alice', row[0], row[1]);
        const label = '4. ' + row[0] + ' "' + String(row[1]).slice(0, 30) +
                      '"';
        if (row[2] === false) {
          refusedWith(answer, 'STS-LDAP-0106', label + ' is refused');
        } else {
          note(answer.ok &&
                 valuesOf('pae-alice', row[0].toLowerCase()).join() === row[2],
               label + ' is stored as "' + String(row[2]).slice(0, 30) + '"',
               JSON.stringify(answer).slice(0, 300));
        }
      });

      // ====================================================================
      // 5. THE ACCOUNT OBSERVER
      // ====================================================================
      const seen = [];
      ldap.setAccountObserver(function (event) {
        seen.push(event);
      });
      act('set-attribute', 'pae-alice', 'title', 'Observed');
      const event = seen.filter(function (one) {
        return one.kind === 'updated' && one.username === 'pae-alice';
      })[0];
      note(event &&
             String((event.after.title || [])[0]) === 'Observed' &&
             !(event.before.title || []).length,
           '5. the account observer is told, with the before and after',
           JSON.stringify(event && { before: event.before.title,
                                     after: event.after.title }));

      // ====================================================================
      // 6. THE VIEW AND THE PAGE
      // ====================================================================
      const req = { query: { user: 'pae-alice' }, headers: {}, cookies: {},
                    method: 'GET', path: '/admin/users', url: '/admin/users' };
      const view = adminViews.userDetailJson(req, 'pae-alice');
      const json = view && (typeof view.json === 'function' ? view.json()
                                                           : view.json);
      const published = json && json.attributeEditor;
      const titleRow = published && published.attributes.filter(function (r) {
        return r.name === 'title';
      })[0];
      note(titleRow && titleRow.values.join() === 'Observed' &&
             Array.isArray(published.withheld) &&
             /^uid=pae-alice,/.test(published.dn),
           '6. the person\'s JSON publishes attributeEditor with the values',
           JSON.stringify(titleRow));
      const page = admin.usersView(req, undefined);
      const inner = String((page && page.inner) || '');
      note(/id="attributes"/.test(inner) &&
             (/value="set-attribute"/.test(inner) ||
              /needs <strong>Admin Write<\/strong>/.test(inner)),
           '6. the person\'s page draws the attribute section');
      note(/value="set-attribute"/.test(inner)
             ? /<option value="title">/.test(inner) &&
               !/<option value="userPassword">/.test(inner) &&
               !/<option value="mail">/.test(inner)
             : true,
           '6. and its selects offer title and never userPassword or mail');
    });

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
  const out = path.join(os.tmpdir(), 'person-attribute-editor-' +
                        process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|ADMIN_|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', PAE_ROOT: ROOT,
                                  PAE_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
               String(result.stderr || '').slice(-800))) {
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
  name: 'person attribute editor',
  describe: 'set, add and remove one of a person\'s attributes from the ' +
            'console and /admin-api: what is editable, what is withheld, ' +
            'every refusal and its code, the shaped values, the account ' +
            'observer, and the view and page',
  run: run
};
