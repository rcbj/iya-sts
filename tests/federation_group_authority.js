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
// AND IN A WINDOWED DIRECTORY (#1306), where the entries that make a name
// grant need not be held by this process — section W, a second child
// loading `ldap/ldap_server.js` as a windowed request worker, its window
// given `tests/directory_window.js`'s stand-in bridge, whose `byAttribute`
// is answered here through the codec's own halves (`keyArgs()` on the
// question, `indexOf()` on each row), as the store answers it:
//
//   W0. the codec keys each value of the six granting attributes as
//       `grantinggroup`, trimmed and lower-cased, a DN in its normalised
//       form as well, and `keyArgs()` takes the question;
//   W1. a plain name is created and joined with the store answering
//       nothing (the control);
//   W2. a service account under `ou=users` that this process does not
//       hold, whose `stsServiceAccountOwner` names a group, makes that
//       name refused `grants` and not created;
//   W3. a group row only the store has — another process's write, not yet
//       pulled here — whose `owner` names a group by a DN written in
//       another case and spacing, makes that name refused, by its DN;
//   W4. the questions were `byAttribute` on `grantinggroup` and nothing
//       paged `ou=users`: no walk of the people;
//   W5. a store that cannot answer refuses the name (`its registers could
//       not be read`) and creates nothing.
//
// The other half of #1306, the attribute policy's `STS-FED-0158` reaching
// the page from "a directory in another process", is not asserted here
// because no such process exists: `federation/CLAUDE.md` says why, and
// `tests/federation_subject_policy.js` 1m-0 holds the page.
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
    async function apply(names, who) {
      return (await federation.applyFederatedGroups(REL, who || WHO,
                                                    names)) || {};
    }
    function reasonOf(result, name) {
      const hit = (result.ignored || []).filter(function (one) {
        return one.name === name;
      })[0];
      return hit ? hit.reason : '';
    }

    // 1. The control.
    let r = await apply(['fga-engineers']);
    const entry = ldap.readGroupEntry(ldap.groupDnFor('fga-engineers'));
    const attrs = (entry && entry.attributes) || {};
    const mark = attrs.federationRelationship ||
                 attrs.federationrelationship || [];
    note((r.created || []).indexOf('fga-engineers') >= 0 &&
         memberOf('fga-engineers') && mark.indexOf(REL) >= 0,
         '1. a plain new group from the token is created, marked and joined',
         JSON.stringify(r) + ' mark=' + JSON.stringify(mark));

    // 2. The five settings.
    const settingNames = ['admin.readGroup', 'admin.writeGroup',
                          'roles.remotePepGroup', 'roles.xacmlUserGroup',
                          'roles.authzenPepGroup']
      .map(function (key) {
        return String(config.value(key) || '').trim();
      }).filter(Boolean);
    const before = {};
    settingNames.forEach(function (name) {
      before[name] = exists(name);
    });
    r = await apply(settingNames);
    const settingBad = settingNames.filter(function (name) {
      return reasonOf(r, name) !== 'grants' || memberOf(name) ||
             (!before[name] && exists(name));
    });
    note(settingNames.length === 5 && settingBad.length === 0 &&
         (r.joined || []).length === 0 && (r.created || []).length === 0,
         '2. the console rosters and the REMOTE_PEPS / XACML_USER / ' +
         'AUTHZEN_PEPS groups are ' +
         'refused "grants" and none is created or joined',
         JSON.stringify(settingNames) + ' bad=' + JSON.stringify(settingBad) +
         ' ' + JSON.stringify(r));

    // 3. A role's member group that does not exist yet.
    const wrote = roles.write('fga-approver',
                              { users: [], groups: ['fga-approvers'] });
    r = await apply(['fga-approvers']);
    note(wrote && wrote.ok && reasonOf(r, 'fga-approvers') === 'grants' &&
         !exists('fga-approvers') && !memberOf('fga-approvers'),
         '3. a name a role names as its member group is refused and NOT ' +
         'created, although no such group exists yet',
         JSON.stringify(wrote) + ' ' + JSON.stringify(r));

    // 4. An owner group.
    const owners = ldap.createGroup('fga-owners', { members: [] });
    const owned = ldap.createGroup('fga-owned', { members: [] });
    const owning = ldap.addGroupOwner('fga-owned', 'fga-owners');
    r = await apply(['fga-owners']);
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
      r = await apply([policyGroup]);
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
    r = await apply(['fga-later-group']);
    const madeLater = (r.created || []).indexOf('fga-later-group') >= 0 &&
                      memberOf('fga-later-group');
    const laterRole = roles.write('fga-later',
                                  { users: [], groups: ['fga-later-group'] });
    r = await apply(['fga-later-group'], OTHER);
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
    await instance.provisionGroups(
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

// W. The windowed child (#1306). See the header.
function windowedChildMain() {
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
    const codec = require(ROOT + '/persistence/directory_codec');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const federation = require(ROOT + '/federation/federation');
    const queries = require(ROOT + '/persistence/directory_queries');
    const fakeBridge = require(ROOT + '/tests/directory_window').fakeBridge;
    const dwRow = require(ROOT + '/tests/directory_window').row;

    // W0. The codec's key.
    const keys = codec.grantingGroupKeysOf({
      stsServiceAccountOwner: ['  Ops-Team '],
      owner: ['CN=Admins, OU=Groups, DC=Example, DC=Com'],
      description: ['not-granting'] });
    const asked = codec.keyArgs('byAttribute',
                                ['default', 'grantinggroup', 'ops-team', 1]);
    note(keys.indexOf('ops-team') >= 0 &&
         keys.indexOf('cn=admins,ou=groups,dc=example,dc=com') >= 0 &&
         keys.indexOf('not-granting') < 0 &&
         codec.VALUE_INDEXED.indexOf('grantinggroup') >= 0 &&
         asked[2] && asked[2].key ===
           codec.lookupOf('attr:grantinggroup', 'ops-team'),
         'W0. the codec keys the granting attributes as grantinggroup, ' +
         'trimmed and lower-cased, a DN normalised too, and keyArgs() ' +
         'takes the question', JSON.stringify(keys));

    const w = ldap.directoryWindow;
    if (!w) {
      note(false, 'W. the child holds its directory as a window');
      fs.writeFileSync(OUT, JSON.stringify(findings));
      process.exit(0);
    }
    const users = ldap.usersDn().toLowerCase();
    const groups = ldap.groupDnFor('x').toLowerCase().replace(/^cn=x,/, '');
    const rows = new Map();
    const svcDn = 'uid=fgw-svc,' + users;
    rows.set('default\n' + svcDn, dwRow('default', svcDn, {
      uid: ['fgw-svc'], objectclass: ['inetOrgPerson'],
      stsserviceaccountowner: [' FGW-Svc-Owners '] }));
    const remoteDn = 'cn=fgw-remote-owned,' + groups;
    const remoteOwnerDn = 'CN=FGW-Remote-Owners, ' +
      groups.split(',').map(function (part) {
        return part.toUpperCase();
      }).join(', ');
    rows.set('default\n' + remoteDn, dwRow('default', remoteDn, {
      cn: ['fgw-remote-owned'], objectclass: ['groupOfNames'],
      owner: [remoteOwnerDn] }));
    const bridge = fakeBridge(rows);
    const plain = bridge.query;
    let failing = false;
    // `byAttribute` as the store answers it: the question keyed by the
    // codec, each row's `value_keys` made by the codec.
    bridge.query = function (name, args) {
      if (name === 'byAttribute') {
        bridge.asked.push(name + ':' + args[1]);
        if (failing) {
          throw new Error('the store is away');
        }
        const keyed = codec.keyArgs(name, args);
        const want = keyed[2].key;
        return Array.from(rows.values()).filter(function (r) {
          return r.realm === args[0] &&
                 codec.indexOf(r.attrs).valueKeys.indexOf(want) >= 0;
        }).slice(0, Number(args[3]) || 1).map(function (r) {
          return queries.rowOf(JSON.parse(JSON.stringify(r)));
        });
      }
      return plain(name, args);
    };
    w.attach(bridge);

    const REL = 'fgw-partner';
    const WHO = 'fgw-person';
    const made = ldap.createUser(WHO, {});
    note(made && made.ok !== false, 'W. the person exists',
         JSON.stringify(made && (made.errors || made.why)));
    function exists(name) {
      return !!ldap.readGroupEntry(ldap.groupDnFor(name));
    }
    function reasonOf(result, name) {
      const hit = (result.ignored || []).filter(function (one) {
        return one.name === name;
      })[0];
      return hit ? hit.reason + (hit.detail ? ': ' + hit.detail : '') : '';
    }
    async function apply(names) {
      return (await federation.applyFederatedGroups(REL, WHO, names)) || {};
    }

    // W1. The control.
    bridge.asked.length = 0;
    let r = await apply(['fgw-plain']);
    note((r.created || []).indexOf('fgw-plain') >= 0 &&
         (r.joined || []).indexOf('fgw-plain') >= 0 && exists('fgw-plain'),
         'W1. a plain name is created and joined with the store answering ' +
         'nothing', JSON.stringify(r));

    // W2. A service account the window does not hold.
    const heldBefore = w.peekIn('default', svcDn);
    r = await apply(['fgw-svc-owners']);
    note(!heldBefore && /^grants: stsserviceaccountowner of /i.test(
           reasonOf(r, 'fgw-svc-owners')) && !exists('fgw-svc-owners'),
         'W2. a name only a service account this process does not hold ' +
         'names, by stsServiceAccountOwner, is refused and not created',
         'held=' + !!heldBefore + ' ' + JSON.stringify(r));

    // W3. A group row only the store has.
    const residentBefore = w.peekIn('default', remoteDn);
    r = await apply(['fgw-remote-owners']);
    note(!residentBefore && /^grants: owner of /i.test(
           reasonOf(r, 'fgw-remote-owners')) && !exists('fgw-remote-owners'),
         'W3. a name another process\'s group row names as its owner, by ' +
         'a DN in another case and spacing, is refused, though this ' +
         'process has not applied the row',
         'held=' + !!residentBefore + ' ' + JSON.stringify(r));

    // W4. What was asked.
    const pagedPeople = bridge.asked.filter(function (one) {
      return one === 'page' || one === 'withAttribute' ||
             one === 'namesUnder';
    });
    note(bridge.asked.indexOf('byAttribute:grantinggroup') >= 0 &&
         pagedPeople.length === 0,
         'W4. the questions were byAttribute on grantinggroup, and nothing ' +
         'paged the people', JSON.stringify(bridge.asked));

    // W5. A store that cannot answer.
    failing = true;
    r = await apply(['fgw-unanswered']);
    failing = false;
    note(/^grants: its registers could not be read/.test(
           reasonOf(r, 'fgw-unanswered')) && !exists('fgw-unanswered'),
         'W5. a store that cannot answer refuses the name and creates ' +
         'nothing', JSON.stringify(r));
    r = await apply(['fgw-after']);
    note((r.created || []).indexOf('fgw-after') >= 0,
         'W5b. and once it answers again a plain name is created',
         JSON.stringify(r));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the windowed child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inChild(t, main, label, extra) {
  log.debug("Entering inChild(). " + label);
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
    ['-e', '(' + main.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', FGA_ROOT: ROOT, FGA_OUT: out },
                         extra || {}),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), 'the ' + label + ' child reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-1200))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving inChild().");
}

function run(t) {
  log.debug("Entering run().");
  inChild(t, childMain, 'whole-directory');
  inChild(t, windowedChildMain, 'windowed', {
    STS_REQUEST_WORKER: '1', LDAP_WORKER_DIRECTORY: 'postgres-lru',
    STS_PERSISTENCE_MODE: 'postgres', LDAP_WORKER_CACHE_ENTRIES: '100' });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'federation_group_authority',
  describe: 'fedProvisionGroups never creates, or adds anybody to, a group ' +
            'that grants something by being held — the console rosters, ' +
            'the REMOTE_PEPS and XACML_USER groups, a role\'s member group, ' +
            'an owner group, a group a policy names — and audits it ' +
            'STS-FED-0164; in a windowed directory the store is asked ' +
            '(#1306)',
  run: run
};
