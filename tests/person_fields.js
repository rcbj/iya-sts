// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/person_fields.js — A PERSON'S PAGE AS TABS, AND THEIR ATTRIBUTES AS A
// TYPED FIELD GRID (rcbj, 2026-10-01).
//
// The application page's model for a person: seven tabs, the Attributes tab
// one sub-tab per group of `ldap/person_editor.ts`'s FIELD_GROUPS with its
// own Save (`update-fields`, which `POST /admin-api/users/update-fields`
// calls too), and `/admin/users/new` drawing the same fields.
//
// In a CHILD PROCESS, for `person_attribute_editor.js`'s reason: it loads the
// whole protocol stack and creates people in the default realm.
//
// The claims:
//
//   A. Every editable attribute is in exactly one group and has an example.
//   B. update-fields brings each attribute to the values given — a single
//      value set or cleared, a list added to and taken from — and refuses
//      with its code: an empty list box (ADMIN-0834), nothing named (0838),
//      a refused value or attribute (0839, after saving the rest).
//   C. The form's body: `field.<name>.<n>` boxes and `present`, a field
//      present and absent cleared.
//   D. A create takes the grid's attributes, a list included, and holds them
//      to the editor's rules (a bad country code refused, STS-LDAP-0106).
//   E. The page: seven tabs in order, the Credentials and Attributes
//      sub-tabs, each group a form posting to /admin/users/edit with its own
//      Save and `present`, an example as each box's placeholder, the
//      address form on Contact, and the one-attribute forms on Directory
//      entry.
//   F. A redraw ("+") keeps the posted boxes and adds an empty one.
//   G. /admin/users/new draws the simplified view and the advanced one, and
//      its JSON publishes the grid.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'person_fields',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.PF_ROOT;
  const OUT = process.env.PF_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const editor = require(ROOT + '/ldap/person_editor');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const adminViews = require(ROOT + '/admin-core/admin_views');
    const admin = require(ROOT + '/admin-ui/admin');

    await realms.run(realms.DEFAULT_REALM, async function () {
      const ctx = { via: 'api', actor: 'tester' };
      const codeOf = function (result) {
        return errorCodes.codeOf(result) || '';
      };
      const valuesOf = function (name, attribute) {
        const row = editor.editorFor(name).attributes.filter(function (one) {
          return one.name.toLowerCase() === attribute.toLowerCase();
        })[0];
        return row ? row.values.map(String) : null;
      };
      const update = function (user, fields, extra) {
        return actions.usersAction(Object.assign({ action: 'update-fields',
          user: user, fields: fields }, extra || {}), ctx);
      };

      // ====================================================================
      // A. THE CATALOGUE
      // ====================================================================
      const groups = editor.FIELD_GROUPS.map(function (g) { return g.id; });
      const rows = editor.editableAttributes();
      const ungrouped = rows.filter(function (row) {
        return groups.indexOf(row.group) < 0;
      });
      note(rows.length > 30 && !ungrouped.length,
           'A. every editable attribute is in one of the groups',
           JSON.stringify(ungrouped.map(function (r) { return r.name; })));
      const twice = [];
      const named = {};
      editor.FIELD_GROUPS.forEach(function (g) {
        g.attributes.forEach(function (a) {
          const k = a.toLowerCase();
          if (named[k]) {
            twice.push(a);
          }
          named[k] = g.id;
        });
      });
      note(!twice.length, 'A. no attribute is named by two groups',
           twice.join(','));
      const noExample = rows.filter(function (row) {
        return !row.example;
      }).map(function (row) { return row.name; });
      note(!noExample.length, 'A. every editable attribute has an example',
           noExample.join(','));
      note(rows.filter(function (row) { return row.simple; }).length >= 8,
           'A. the simplified view offers the usual names and contacts');

      // ====================================================================
      // B. UPDATE-FIELDS
      // ====================================================================
      const made = ldap.createUser('pf-alice', {});
      note(made && made.ok !== false, 'B. a person is created',
           JSON.stringify(made));
      const first = update('pf-alice', { title: 'Engineer',
        mobile: ['+1 555 0101', '+1 555 0102'], c: 'se' });
      note(first.ok && first.changed.length === 3 &&
             valuesOf('pf-alice', 'title').join() === 'Engineer' &&
             valuesOf('pf-alice', 'mobile').join() ===
               '+1 555 0101,+1 555 0102' &&
             valuesOf('pf-alice', 'c').join() === 'SE',
           'B. a single value is set, a list written, a country upper-cased',
           JSON.stringify(first));
      const second = update('pf-alice', { title: '',
        mobile: ['+1 555 0102', '+1 555 0103'] });
      note(second.ok && valuesOf('pf-alice', 'title').length === 0 &&
             valuesOf('pf-alice', 'mobile').join() ===
               '+1 555 0102,+1 555 0103',
           'B. an empty single value clears it, a list is added to and ' +
           'taken from', JSON.stringify(second));
      const same = update('pf-alice', { mobile: ['+1 555 0103',
                                                 '+1 555 0102'] });
      note(same.ok && same.changed.length === 0,
           'B. the same values in another order change nothing',
           JSON.stringify(same));
      const cn = update('pf-alice', { cn: ['Alice Renamed'] });
      note(cn.ok && valuesOf('pf-alice', 'cn').join() === 'Alice Renamed',
           'B. a required list (cn) moves from one value to another',
           JSON.stringify(cn));
      const partial = update('pf-alice', { c: 'zz', title: 'Lead' });
      note(partial.ok === false && codeOf(partial) === 'STS-ADMIN-0839' &&
             partial.changed.join() === 'title' &&
             valuesOf('pf-alice', 'title').join() === 'Lead' &&
             valuesOf('pf-alice', 'c').join() === 'SE',
           'B. a refused value is reported and the rest saved (0839)',
           JSON.stringify(partial) + ' ' + codeOf(partial));
      const withheld = update('pf-alice', { memberOf: 'cn=x' });
      note(withheld.ok === false && codeOf(withheld) === 'STS-ADMIN-0839' &&
             /memberOf/.test(withheld.errors.join(' ')),
           'B. an attribute the editor does not change is refused by name',
           JSON.stringify(withheld));
      const single = update('pf-alice', { displayName: ['One', 'Two'] });
      note(single.ok === false && /holds one value/.test(
             single.errors.join(' ')),
           'B. two values for a single-valued attribute are refused',
           JSON.stringify(single));
      const nothing = actions.usersAction({ action: 'update-fields',
                                            user: 'pf-alice' }, ctx);
      note(nothing.ok === false && codeOf(nothing) === 'STS-ADMIN-0838',
           'B. nothing named is refused (0838)', codeOf(nothing));
      const emptyBox = actions.usersAction({ action: 'update-fields',
        user: 'pf-alice', present: 'mobile', 'field.mobile.0': '' }, ctx);
      note(emptyBox.ok === false && codeOf(emptyBox) === 'STS-ADMIN-0834',
           'B. an empty list box is refused (0834)', codeOf(emptyBox));
      const nobody = update('pf-nobody', { title: 'x' });
      note(nobody.ok === false && codeOf(nobody) === 'STS-LDAP-0102',
           'B. a person who is not there is refused (LDAP-0102)',
           codeOf(nobody));

      // ====================================================================
      // C. THE FORM'S BODY
      // ====================================================================
      const form = actions.usersAction({ action: 'update-fields',
        user: 'pf-alice', present: 'mobile title pager',
        'field.mobile.0': '+1 555 0200', 'field.pager': '+1 555 0300' },
        ctx);
      note(form.ok && valuesOf('pf-alice', 'mobile').join() ===
             '+1 555 0200' &&
             valuesOf('pf-alice', 'pager').join() === '+1 555 0300' &&
             valuesOf('pf-alice', 'title').length === 0,
           'C. boxes and present: a list replaced, a field present and ' +
           'absent cleared', JSON.stringify(form));

      // ====================================================================
      // D. A CREATE TAKES THE GRID'S ATTRIBUTES
      // ====================================================================
      const created = actions.usersAction({ action: 'create',
        username: 'pf-bob', credential: 'none', invent: 'no',
        attributes: { title: 'Analyst', mobile: ['+1 555 0400',
                                                 '+1 555 0401'],
                      c: 'de' } }, ctx);
      note(created.ok && valuesOf('pf-bob', 'title').join() === 'Analyst' &&
             valuesOf('pf-bob', 'mobile').length === 2 &&
             valuesOf('pf-bob', 'c').join() === 'DE',
           'D. a create writes an editor attribute, a list and a shaped value',
           JSON.stringify(created));
      const refused = actions.usersAction({ action: 'create',
        username: 'pf-carol', credential: 'none', invent: 'no',
        attributes: { c: 'zz' } }, ctx);
      note(refused.ok === false && codeOf(refused) === 'STS-LDAP-0106' &&
             !editor.editorFor('pf-carol'),
           'D. a value the editor refuses refuses the create (LDAP-0106)',
           JSON.stringify(refused) + ' ' + codeOf(refused));

      // ====================================================================
      // E. THE PAGE
      // ====================================================================
      const req = { query: { user: 'pf-alice' }, headers: {}, cookies: {},
                    method: 'GET', path: '/admin/users', url: '/admin/users' };
      const inner = String((admin.usersView(req, undefined) || {}).inner || '');
      // GNAP grants (#432 phase 7) joined after Federation links.
      const tabs = ['utab-overview', 'utab-activity', 'utab-attributes',
                    'utab-credentials', 'utab-federation', 'utab-gnap',
                    'utab-entry', 'utab-signout'];
      const at = tabs.map(function (id) {
        return inner.indexOf('<section class="tabpanel' +
          (id === 'utab-overview' ? ' first' : '') + '" id="' + id + '">');
      });
      const inOrder = at.every(function (n, i) {
        return n >= 0 && (!i || n > at[i - 1]);
      });
      note(inOrder &&
             /<nav class="tabbar" aria-label="Sections of this page">/.test(
               inner),
           'E. eight tabs, in order', JSON.stringify(at));
      ['ucred-factors', 'ucred-password', 'ucred-keys']
        .forEach(function (id) {
          note(inner.indexOf('id="' + id + '"') > at[3] &&
                 inner.indexOf('id="' + id + '"') < at[4],
               'E. the Credentials tab holds the ' + id + ' sub-tab');
        });
      const writable = /action="\/admin\/users\/edit#ufg-name"/.test(inner);
      if (writable) {
        ['name', 'contact', 'organization', 'address', 'identity']
          .forEach(function (g) {
            const formAt = inner.indexOf('action="/admin/users/edit#ufg-' +
                                         g + '"');
            note(formAt > inner.indexOf('id="ufg-' + g + '"') &&
                   formAt > at[2] && formAt < at[3],
                 'E. the ' + g + ' group is a form on the Attributes tab');
          });
        note(/name="field\.title"[^>]*placeholder="e\.g\. Principal Engineer"/
               .test(inner),
             'E. a box carries its example as the placeholder');
        note(/name="field\.mobile\.0" value="\+1 555 0200"/.test(inner) &&
               /name="grow" value="mobile"/.test(inner),
             'E. a list is drawn one box per value, with +');
        note(/name="present" value="[^"]*\btitle\b/.test(inner) &&
               />Save organization<\/button>/.test(inner),
             'E. each group form names its fields and has its own Save');
        const mail = inner.indexOf('value="set-mail"');
        note(mail > inner.indexOf('id="ufg-contact"') &&
               mail < inner.indexOf('id="ufg-organization"'),
             'E. the address form is on the Contact sub-tab');
        note(inner.indexOf('value="set-attribute"') > at[5] &&
               inner.indexOf('value="set-attribute"') < at[6],
             'E. the one-attribute forms are on the Directory entry tab');
      } else {
        note(/needs <strong>Admin Write<\/strong>/.test(inner),
             'E. read only: the Attributes tab says what writing needs');
      }

      // ====================================================================
      // F. A REDRAW KEEPS THE BOXES
      // ====================================================================
      const redrawn = admin.userDetailPage(req, 'pf-alice', undefined, {
        draft: { present: 'mobile', 'field.mobile.0': '+1 555 0999',
                 grow: 'mobile' } });
      const again = String((redrawn && redrawn.inner) || '');
      note(!writable || (/name="field\.mobile\.0" value="\+1 555 0999"/
             .test(again) && /name="field\.mobile\.1" value=""/.test(again)),
           'F. "+" redraws the posted box and an empty one');

      // ====================================================================
      // G. THE NEW-USER FORM
      // ====================================================================
      const fresh = { query: {}, headers: {}, cookies: {}, method: 'GET',
                      path: '/admin/users/new', url: '/admin/users/new' };
      const simple = String(admin.newUserPage(fresh).inner || '');
      note(/name="field\.cn\.0" value=""/.test(simple) &&
             /name="field\.mail"/.test(simple) &&
             !/name="field\.carLicense/.test(simple) &&
             /name="switchview" value="advanced"/.test(simple),
           'G. the simplified view offers the names and the address',
           (simple.match(/name="field\.[A-Za-z.0-9]+"/g) || []).join(' ') +
           ' | ' + simple.slice(0, 300));
      const advanced = String(admin.newUserPage(fresh, { view: 'advanced' })
        .inner || '');
      note(/name="field\.carLicense\.0"/.test(advanced) &&
             /name="field\.x121Address\.0"/.test(advanced) &&
             /name="grow" value="mobile"/.test(advanced),
           'G. the advanced view offers every field');
      const switched = String(admin.newUserPage(fresh, { view: 'advanced',
        draft: { view: 'simple', switchview: 'advanced',
                 'field.cn.0': 'Kept Name' } }).inner || '');
      note(/name="field\.cn\.0" value="Kept Name"/.test(switched) &&
             /name="field\.carLicense\.0" value=""/.test(switched),
           'G. switching view keeps what was typed and gives a new list ' +
           'field a box');
      const json = adminViews.newUserJson(fresh);
      note(json.gridFields && json.gridFields.length === rows.length &&
             json.fieldGroups.length === editor.FIELD_GROUPS.length,
           'G. GET /admin-api/users/new publishes the grid',
           json.gridFields && json.gridFields.length);
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
  const out = path.join(os.tmpdir(), 'person-fields-' +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', PF_ROOT: ROOT,
                                  PF_OUT: out }),
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
  name: 'person fields',
  describe: 'a person\'s page as tabs and their attributes as a typed field ' +
            'grid: the catalogue, update-fields and its refusals, a create ' +
            'taking the grid, the tabbed page, a redraw, and the new-user ' +
            'form\'s two views',
  run: run
};
