// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_group_authority.js
//
// ===========================================================================
// A PARTNER'S TOKEN NEVER BUYS A GROUP THAT GRANTS SOMETHING (#358).
//
// `fedProvisionGroups` turns each group name in a partner's assertion into a
// membership, creating the group when it does not exist. The review of #691
// found the hole: a token naming a group that does not exist YET, but whose
// NAME already stands for something here — a console roster, a role's member
// group, an owner — had it created and the person put in it. Provisioning
// must never create, or add anybody to, such a group
// (`ldap/ldap_server.js`'s `federatedGroupAuthority()`), and the refusal is
// `STS-FED-0164` with an audit row of its own.
//
// Asserted, in the default realm of a fresh child process, through
// `federation.applyFederatedGroups()` and through `FederationSp`'s own
// `provisionGroups()` (which writes the audit row):
//
//   1. a plain new name is created, marked with the relationship and joined
//      — the control, so the refusals below are not a switch that is off;
//   2. the console rosters (`admin.readGroup`, `admin.writeGroup`) and the
//      two group-derived roles' groups (`roles.remotePepGroup`,
//      `roles.xacmlUserGroup`) are refused `grants`, whether or not they
//      exist, and none is created;
//   3. a name a configured role names as a member group, which does NOT
//      exist, is refused and not created;
//   4. a group named as the owner of another group is refused (#607: an
//      owner group administers what it owns);
//   5. a name an XACML policy names as an attribute value is refused;
//   6. a group this relationship created, which a role LATER names, is no
//      longer joined;
//   7. through provisionGroups(): a `federation.group-ignored` audit row
//      with `STS-FED-0164` for a granting name, `STS-FED-0161` for an
//      ordinary collision, and the person in neither group.
//
// WHY A CHILD PROCESS: it loads the whole protocol stack.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'federation_group_authority',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.FGA_ROOT;
  const OUT = process.env.FGA_OUT;
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const roles = require(ROOT + '/common/roles');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const federation = require(ROOT + '/federation/federation');
    const xacmlStore = require(ROOT + '/xacml/xacml_store');
    const sp = require(ROOT + '/federation/federation_sp');

    const REL = 'fga-partner';
    const WHO = 'fga-person';
    const made = ldap.createUser(WHO, {});
    note(made && made.ok !== false, '0. the person exists',
         JSON.stringify(made && (made.errors || made.why)));

    function exists(name) {
      return !!ldap.readGroupEntry(ldap.groupDnFor(name));
    }
    function memberOf(name, who) {
      const groups = ldap.groupsOfUser(who || WHO).groups || [];
      return groups.some(function (one) {
        return String(one.cn || '').toLowerCase() === name.toLowerCase();
      });
    }
    function apply(names, who) {
      return federation.applyFederatedGroups(REL, who || WHO, names) || {};
    }
    function reasonOf(result, name) {
      const hit = (result.ignored || []).filter(function (one) {
        return one.name === name;
      })[0];
      return hit ? hit.reason : '';
    }

    // 1. The control.
    let r = apply(['fga-engineers']);
    const entry = ldap.readGroupEntry(ldap.groupDnFor('fga-engineers'));
    const attrs = (entry && entry.attributes) || {};
    const mark = attrs.federationRelationship ||
                 attrs.federationrelationship || [];
    note((r.created || []).indexOf('fga-engineers') >= 0 &&
         memberOf('fga-engineers') && mark.indexOf(REL) >= 0,
         '1. a plain new group from the token is created, marked and joined',
         JSON.stringify(r) + ' mark=' + JSON.stringify(mark));

    // 2. The four settings.
    const settingNames = ['admin.readGroup', 'admin.writeGroup',
                          'roles.remotePepGroup', 'roles.xacmlUserGroup']
      .map(function (key) {
        return String(config.value(key) || '').trim();
      }).filter(Boolean);
    const before = {};
    settingNames.forEach(function (name) {
      before[name] = exists(name);
    });
    r = apply(settingNames);
    const settingBad = settingNames.filter(function (name) {
      return reasonOf(r, name) !== 'grants' || memberOf(name) ||
             (!before[name] && exists(name));
    });
    note(settingNames.length === 4 && settingBad.length === 0 &&
         (r.joined || []).length === 0 && (r.created || []).length === 0,
         '2. the console rosters and the REMOTE_PEPS / XACML_USER groups are ' +
         'refused "grants" and none is created or joined',
         JSON.stringify(settingNames) + ' bad=' + JSON.stringify(settingBad) +
         ' ' + JSON.stringify(r));

    // 3. A role's member group that does not exist yet.
    const wrote = roles.write('fga-approver',
                              { users: [], groups: ['fga-approvers'] });
    r = apply(['fga-approvers']);
    note(wrote && wrote.ok && reasonOf(r, 'fga-approvers') === 'grants' &&
         !exists('fga-approvers') && !memberOf('fga-approvers'),
         '3. a name a role names as its member group is refused and NOT ' +
         'created, although no such group exists yet',
         JSON.stringify(wrote) + ' ' + JSON.stringify(r));

    // 4. An owner group.
    const owners = ldap.createGroup('fga-owners', { members: [] });
    const owned = ldap.createGroup('fga-owned', { members: [] });
    const owning = ldap.addGroupOwner('fga-owned', 'fga-owners');
    r = apply(['fga-owners']);
    note(owners.ok && owned.ok && owning && owning.ok &&
         reasonOf(r, 'fga-owners') === 'grants' && !memberOf('fga-owners'),
         '4. a group named as the owner of another group is refused',
         JSON.stringify(owning) + ' ' + JSON.stringify(r));

    // 5. A group an XACML policy names.
    let policyCase = 'none named';
    const policyGroup = 'fga-policy-group';
    const wroteRow = (function () {
      const document =
        '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
        'PolicyId="urn:sts:test:fga" Version="1.0" ' +
        'RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-' +
        'algorithm:deny-overrides"><Target/>' +
        '<Rule RuleId="fga" Effect="Permit"><Target><AnyOf><AllOf>' +
        '<Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-' +
        'equal"><AttributeValue DataType="http://www.w3.org/2001/' +
        'XMLSchema#string">' + policyGroup + '</AttributeValue>' +
        '<AttributeDesignator Category="urn:oasis:names:tc:xacml:1.0:' +
        'subject-category:access-subject" AttributeId="urn:sts:xacml:' +
        'group" DataType="http://www.w3.org/2001/XMLSchema#string" ' +
        'MustBePresent="false"/></Match></AllOf></AnyOf></Target>' +
        '</Rule></Policy>';
      try {
        return xacmlStore.write('fga-policy', document,
                                { enabled: false });
      } catch (e) {
        return { ok: false, why: (e && e.message) || String(e) };
      }
    })();
    if (wroteRow && wroteRow.ok !== false) {
      r = apply([policyGroup]);
      policyCase = reasonOf(r, policyGroup);
    }
    note(wroteRow && wroteRow.ok !== false &&
         policyCase === 'grants' && !exists(policyGroup),
         '5. a name an XACML policy names as an attribute value is refused',
         JSON.stringify(wroteRow) + ' ' + policyCase);

    // 6. A group this relationship made, later named by a role. A second
    // person asserted through the same relationship is not added to it.
    const OTHER = 'fga-other';
    ldap.createUser(OTHER, {});
    r = apply(['fga-later-group']);
    const madeLater = (r.created || []).indexOf('fga-later-group') >= 0 &&
                      memberOf('fga-later-group');
    const laterRole = roles.write('fga-later',
                                  { users: [], groups: ['fga-later-group'] });
    r = apply(['fga-later-group'], OTHER);
    note(madeLater && laterRole && laterRole.ok &&
         reasonOf(r, 'fga-later-group') === 'grants' &&
         !memberOf('fga-later-group', OTHER),
         '6. a group the relationship created is not joined once a role ' +
         'names it',
         'first=' + madeLater + ' ' + JSON.stringify(r));

    // 7. The audit rows, through FederationSp's own provisionGroups().
    const FederationSp = sp.FederationSp;
    const instance = new FederationSp(FederationSp.defaultDeps());
    ldap.createGroup('fga-collision', { members: [] });
    const writeGroup = String(config.value('admin.writeGroup') || '');
    const start = audit.list().length;
    instance.provisionGroups(
      { fedId: REL, fedProvisionGroups: 'TRUE' }, WHO,
      { flat: { groups: [writeGroup, 'fga-collision'] } },
      { subject: 'partner-subject' });
    const rows = audit.list().filter(function (event) {
      return event.action === 'federation.group-ignored';
    });
    const granting = rows.filter(function (event) {
      return event.errorCode === 'STS-FED-0164' &&
             event.detail && event.detail.group === writeGroup;
    });
    const collision = rows.filter(function (event) {
      return event.errorCode === 'STS-FED-0161' &&
             event.detail && event.detail.group === 'fga-collision';
    });
    note(granting.length >= 1 && collision.length >= 1 &&
         !memberOf(writeGroup) && !memberOf('fga-collision'),
         '7. provisionGroups() audits a granting group STS-FED-0164 and a ' +
         'collision STS-FED-0161, and joins neither',
         'audit grew ' + (audit.list().length - start) + ' granting=' +
         granting.length + ' collision=' + collision.length);

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'federation-group-authority-' +
                        process.pid + '-' +
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
                         { LOG_LEVEL: 'fatal', FGA_ROOT: ROOT, FGA_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), 'the child process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-1200))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'federation_group_authority',
  describe: 'fedProvisionGroups never creates, or adds anybody to, a group ' +
            'that grants something by being held — the console rosters, ' +
            'the REMOTE_PEPS and XACML_USER groups, a role\'s member group, ' +
            'an owner group, a group a policy names — and audits it ' +
            'STS-FED-0164',
  run: run
};
