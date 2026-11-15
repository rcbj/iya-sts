// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: roles_subject_names.js
//
// ===========================================================================
// A ROLE IS HELD THE SAME WHETHER A PERSON IS NAMED BY USERNAME OR BY SUBJECT
// (2026-11-14).
//
// Found on 8081: a remote PEP asked `POST /xacml/pip` about a person named by
// their `sub`, `urn:uuid:<entryUUID>`. `common/roles.js` found the roles they
// held through a GROUP (the directory's `groupsOfUser()` looks a subject up)
// and missed the ones they held DIRECTLY, because `roleMemberUser` holds
// usernames and was compared against the subject string — so
// `/admin-api/xacml/decide` answered Permit for `pepdemo3` and Deny for the
// same person's `urn:uuid:`.
//
//   S1. a direct member holds the role by username and by subject, and both
//       answer the same, through `rolesOf()`, `claimFor()` and
//       `role_permissions.configuredRolesOf()` (the PIP's path);
//   S2. a group member holds it by both forms;
//   S3. a subject that names nobody keeps today's behaviour: it holds
//       nothing, and a role naming that literal string still matches it;
//   S4. an application, or a principal across a Kerberos trust, named by a
//       person's subject is never resolved to that person.
//
// In a child process: it installs its own subject resolver, which
// `helpers.js` offers no way to put back.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'roles_subject_names',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.RSN_OUT;
  const ROOT = process.env.RSN_ROOT;
  try {
    const helpers = require(ROOT + '/common/helpers');
    const roles = require(ROOT + '/common/roles');
    const rolePermissions = require(ROOT + '/common/role_permissions');
    // Invented fixtures, after the 8081 demo's people: pepdemo3 holds the
    // role directly, pepdemo1 through a group.
    const people = {
      pepdemo3: 'urn:uuid:18a3336b-0000-4000-8000-000000000003',
      pepdemo1: 'urn:uuid:18a3336b-0000-4000-8000-000000000001'
    };
    const NOBODY = 'urn:uuid:18a3336b-0000-4000-8000-0000000000ff';
    // The directory's `groupsOfUser()` answers for a username and for a
    // subject alike, as `ldap/ldap_server.js`'s does.
    const groupsByName = { pepdemo1: ['pep-group'] };
    // Installed again before each question: `role_permissions` reaches the
    // console roster, which loads the real directory lazily, and that fills
    // both slots with its own.
    const install = function () {
      helpers.setSubjectResolver({
        subjectFor: function (name) {
          return people[name] || '';
        },
        nameFor: function (sub) {
          const key = String(sub).toLowerCase();
          return Object.keys(people).find(function (k) {
            return people[k] === key;
          }) || '';
        }
      });
      roles.setDirectory({
        allRoles: function () {
          return [
            { name: 'pep-demo-users', dn: 'cn=pep-demo-users,ou=roles',
              attributes: { roleName: ['pep-demo-users'],
                            roleMemberUser: ['pepdemo3'] } },
            { name: 'pep-group-users', dn: 'cn=pep-group-users,ou=roles',
              attributes: { roleName: ['pep-group-users'],
                            roleMemberGroup: ['pep-group'] } },
            { name: 'literal-subject', dn: 'cn=literal-subject,ou=roles',
              attributes: { roleName: ['literal-subject'],
                            roleMemberUser: [NOBODY] } }
          ];
        },
        groupsOfUser: function (name) {
          const filed = helpers.nameForSubject(name) || name;
          return groupsByName[filed] || [];
        }
      });
    };
    install();
    const held = function (kind, name) {
      return roles.rolesOf({ kind: kind, name: name, authenticated: true })
        .filter(function (one) {
          return !roles.isBuiltIn(one);
        }).sort().join(',');
    };

    // S1.
    const byName = held('user', 'pepdemo3');
    const bySub = held('user', people.pepdemo3);
    note(byName === 'pep-demo-users' && bySub === byName,
         'S1. a direct member holds the role by username and by urn:uuid ' +
         'subject alike', JSON.stringify({ byName: byName, bySub: bySub }));
    const upper = held('user', people.pepdemo3.toUpperCase()
      .replace('URN:UUID:', 'urn:uuid:'));
    note(upper === byName,
         'S1. and the subject matches however its hex was typed', upper);
    const claim = roles.claimFor({ kind: 'user', name: people.pepdemo3,
                                   authenticated: true });
    note(claim && JSON.stringify(claim.roles) === '["pep-demo-users"]',
         'S1. the roles claim for the subject carries the direct role',
         JSON.stringify(claim));
    // S2.
    const groupByName = held('user', 'pepdemo1');
    const groupBySub = held('user', people.pepdemo1);
    note(groupByName === 'pep-group-users' && groupBySub === groupByName,
         'S2. a group member holds the role by username and by subject',
         JSON.stringify({ byName: groupByName, bySub: groupBySub }));

    // S3.
    note(held('user', 'urn:uuid:18a3336b-0000-4000-8000-0000000000ee') === '',
         'S3. a subject that names nobody holds no configured role');
    note(held('user', NOBODY) === 'literal-subject',
         'S3. and a role naming the literal subject string still matches it',
         held('user', NOBODY));

    // S4.
    note(held('application', people.pepdemo3) === '',
         'S4. an application named by a person\'s subject holds none of ' +
         'that person\'s roles', held('application', people.pepdemo3));
    const across = roles.rolesOf({ kind: 'user', name: people.pepdemo3,
                                   authenticated: true, crossRealm: true,
                                   sids: [] });
    note(across.length === 0,
         'S4. nor does a principal across a Kerberos trust spelt as one ' +
         '(#430: it has no entry here)', across.join(','));
    // S1, through the PIP's path, last: see `install()`.
    const ours = ['pep-demo-users', 'pep-group-users', 'literal-subject'];
    const pip = function (name) {
      install();
      return rolePermissions.configuredRolesOf({
        kind: 'user', name: name, authenticated: true })
        .filter(function (one) {
          return ours.indexOf(one) >= 0;
        }).sort().join(',');
    };
    const pipByName = pip('pepdemo3');
    const pipBySub = pip(people.pepdemo3);
    note(pipByName === 'pep-demo-users' && pipBySub === pipByName,
         'S1. role_permissions.configuredRolesOf(), what the PIP\'s role ' +
         'designator asks, answers the same for both forms',
         JSON.stringify({ byName: pipByName, bySub: pipBySub }));
    const pipGroup = pip(people.pepdemo1);
    note(pipGroup === 'pep-group-users' && pip('pepdemo1') === pipGroup,
         'S2. and the same for a group member', pipGroup);
  } catch (e) {
    note(false, 'the child ran to the end', (e && e.stack) || e);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-rsn-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { RSN_OUT: out, RSN_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings) && findings.length > 0,
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'roles_subject_names',
  describe: 'a role is held the same whether a person is named by username ' +
            'or by urn:uuid subject',
  run: run
};
