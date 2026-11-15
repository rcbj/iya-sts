// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: service_account_orphan_owner.js
//
// ===========================================================================
// A SERVICE ACCOUNT WHOSE LAST OWNER IS DELETED IS GIVEN THE REALM'S
// ADMINISTRATOR (rcbj, 2026-11-15).
//
// rcbj: "if the last owner is deleted, then the realm admin account should
// be added as the owner." #1813 holds that an account that has an owner
// always keeps one at every door that WRITES the owners
// (`service_account_irreversible.js`); deleting the owner's own entry was
// the one way left to strand it. `ldap/ldap_server.js`'s
// rewriteOwnerReferences() — the cleanup every person and group delete
// reaches (#1613, `deleted_references.js`) — now names the realm's Admin
// Write group, else its bootstrap administrator (#1760's choice), in the
// same write that takes the deleted DN off. Held here, each in a throwaway
// realm:
//
//   A. the last owner, a person, deleted: `cn=<admin.writeGroup>` owns the
//      account, though the bootstrap administrator exists too; an
//      `owner-removed` row and an `owner-added` row (actor `system`)
//      naming both DNs;
//   B. the last owner IS the Admin Write group, deleted: the bootstrap
//      administrator owns it;
//   C. one of two owners deleted: the other alone, nothing added, no
//      `owner-added` row;
//   D. neither the group nor the administrator: the account names no owner,
//      STS-SVCACCT-0068 is logged, and an administrator's add-owner then
//      repairs it; and the account is never its own heir (the bootstrap
//      administrator itself a service account);
//   E. an account that named no owner before (requireOwner off) is
//      unchanged by an unrelated delete;
//   F. THE DOORS: an LDAP delete of a person and of a group (the handler
//      every LDAP DelRequest reaches), and SCIM's `DELETE /Users/{id}` and
//      `DELETE /Groups/{id}` over HTTP in a child process (the stack loaded
//      fresh, scim_model_wire.js's arrangement), each ending with the Admin
//      Write group owning the account; and neither the console nor
//      `/admin-api` has a person or group delete of its own (its every act
//      is an `/admin-api` operation, and the route table has none), so
//      those are every door.
// ===========================================================================
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const realms = require('../common/realms');
const config = require('../common/config');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
const serviceAccounts = require('../common/service_accounts');
const policy = require('../common/service_account_policy');
const bootstrapName = require('../common/bootstrap_name');
const ldap = require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({
  name: 'service_account_orphan_owner',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + require('crypto').randomBytes(3).toString('hex');
}

async function withRealm(t, stem, fn) {
  log.debug('Entering withRealm(). ' + stem);
  const id = realmId(stem);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withRealm(). Not created.');
    return undefined;
  }
  try {
    log.debug('Leaving withRealm().');
    return await realms.run(made.realm, function () {
      return fn(made.realm);
    });
  } finally {
    // Every other file in the run asserts only the default realm is left.
    realms.remove(id);
  }
}

function key(dn) {
  log.debug('Entering key().');
  log.debug('Leaving key().');
  return String(dn || '').trim().toLowerCase().replace(/\s*,\s*/g, ',');
}

function personDn(name) {
  log.debug('Entering personDn().');
  const entry = ldap.existingUserEntry(name);
  log.debug('Leaving personDn().');
  return entry ? entry.dn : '';
}

function person(name) {
  log.debug('Entering person().');
  if (!personDn(name)) {
    ldap.createUser(name, { invent: false, attributes: {} });
  }
  log.debug('Leaving person().');
  return personDn(name);
}

function writeGroupName() {
  log.debug('Entering writeGroupName().');
  log.debug('Leaving writeGroupName().');
  return String(config.value('admin.writeGroup') || '');
}

function groupDn(name) {
  log.debug('Entering groupDn().');
  const found = ldap.readGroupEntry(ldap.groupDnFor(name));
  log.debug('Leaving groupDn().');
  return found && found.dn ? found.dn : '';
}

function group(name) {
  log.debug('Entering group().');
  if (!groupDn(name)) {
    ldap.createGroup(name, { members: [] });
  }
  log.debug('Leaving group().');
  return groupDn(name);
}

// The realm's Admin Write group, made where the realm has none.
function adminWrite() {
  log.debug('Entering adminWrite().');
  log.debug('Leaving adminWrite().');
  return group(writeGroupName());
}

function ownerDns(name) {
  log.debug('Entering ownerDns().');
  const facts = serviceAccounts.of(name);
  log.debug('Leaving ownerDns().');
  return facts ? facts.owners.map(function (one) {
    return key(one.dn);
  }) : [];
}

// A service account named `name`, owned by `owners` (names or DNs).
function account(t, label, name, owners) {
  log.debug('Entering account(). ' + name);
  person(name);
  const set = serviceAccounts.set(name, { serviceAccount: true,
                                          owners: owners });
  t.check(set && set.ok && ownerDns(name).length === owners.length,
          'precondition (' + label + '): ' + name + ' is a service ' +
          'account with ' + owners.length + ' owner(s)', JSON.stringify(set));
  log.debug('Leaving account().');
  return set;
}

function rowsOf(action, since, target) {
  log.debug('Entering rowsOf(). ' + action);
  const rows = audit.list().filter(function (row) {
    return row.action === action && Number(row.at) >= since &&
           (!target || key(row.target) === key(target));
  });
  log.debug('Leaving rowsOf(). ' + rows.length);
  return rows;
}

// The service's own warn lines, caught at bunyan's prototype as
// minted_persistence.js does, while `fn` runs.
async function warnings(fn) {
  log.debug('Entering warnings().');
  const proto = require('bunyan').createLogger({ name: 'probe' })
    .constructor.prototype;
  const own = proto.warn;
  const logged = [];
  proto.warn = function (msg) {
    logged.push(String(msg));
    return own.apply(this, arguments);
  };
  try {
    await fn();
  } finally {
    proto.warn = own;
  }
  log.debug('Leaving warnings(). ' + logged.length);
  return logged.filter(function (line) {
    return !/^\s*[✓✗]/.test(line);
  });
}

// One LDAP operation as the socket would hand it to the directory.
async function ldapOp(operation, fields) {
  log.debug('Entering ldapOp(). ' + operation);
  const out = await Promise.resolve(ldap.performOperation(operation,
    Object.assign({ boundDn: 'cn=oo-test', channel: 'ldaps' }, fields)));
  log.debug('Leaving ldapOp().');
  return out || {};
}

async function aPerson(t) {
  log.debug('Entering aPerson().');
  t.log.info('=== A. the last owner, a person, deleted ===');
  await withRealm(t, 'svc-orphan-a', function () {
    const write = adminWrite();
    // The bootstrap administrator exists too, so the ORDER is what is held.
    person(bootstrapName.current());
    const ownerDn = person('oo-a-owner');
    account(t, 'A', 'oo-a-sa', ['oo-a-owner']);
    const accountDn = personDn('oo-a-sa');
    const since = Date.now();
    const gone = ldap.deletePerson(ownerDn, { door: 'the test' });
    t.check(gone && gone.ok !== false, 'A0. the owner is deleted',
            JSON.stringify(gone));
    const now = ownerDns('oo-a-sa');
    t.check(now.length === 1 && now[0] === key(write),
            'A1. the realm\'s Admin Write group owns the account now',
            JSON.stringify(now));
    t.check(serviceAccounts.isServiceAccountName('oo-a-sa'),
            'A2. it is still a service account');
    const added = rowsOf('admin.service-account.owner-added', since,
                         accountDn);
    const detail = (added[0] || {}).detail || {};
    const summary = String((added[0] || {}).summary || '').toLowerCase();
    t.check(added.length === 1 && added[0].actor === 'system' &&
            key(detail.owner) === key(write) &&
            key(detail.deletedOwner) === key(ownerDn) &&
            summary.indexOf(key(write)) >= 0 &&
            summary.indexOf(key(ownerDn)) >= 0,
            'A3. one owner-added row, actor system, naming the new owner ' +
            'and the deleted one', JSON.stringify(added));
    t.check(rowsOf('admin.service-account.owner-removed', since,
                   accountDn).length === 1,
            'A4. and the removal has its own row');
  });
  log.debug('Leaving aPerson().');
}

async function theWriteGroup(t) {
  log.debug('Entering theWriteGroup().');
  t.log.info('=== B. the last owner is the Admin Write group ===');
  await withRealm(t, 'svc-orphan-b', function () {
    const write = adminWrite();
    const boot = person(bootstrapName.current());
    account(t, 'B', 'oo-b-sa', [write]);
    const since = Date.now();
    const gone = ldap.deleteGroupEntry(write);
    t.check(gone && gone.ok, 'B0. the Admin Write group is deleted',
            JSON.stringify(gone));
    const now = ownerDns('oo-b-sa');
    t.check(!!boot && now.length === 1 && now[0] === key(boot),
            'B1. the bootstrap administrator owns the account now, not the ' +
            'deleted group', JSON.stringify([boot, now]));
    const added = rowsOf('admin.service-account.owner-added', since,
                         personDn('oo-b-sa'));
    t.check(added.length === 1 && added[0].actor === 'system',
            'B2. one owner-added row, actor system', JSON.stringify(added));
  });
  log.debug('Leaving theWriteGroup().');
}

async function aCoOwner(t) {
  log.debug('Entering aCoOwner().');
  t.log.info('=== C. one of two owners deleted ===');
  await withRealm(t, 'svc-orphan-c', function () {
    adminWrite();
    const one = person('oo-c-one');
    const other = person('oo-c-other');
    account(t, 'C', 'oo-c-sa', ['oo-c-one', 'oo-c-other']);
    const since = Date.now();
    ldap.deletePerson(one, { door: 'the test' });
    const now = ownerDns('oo-c-sa');
    t.check(now.length === 1 && now[0] === key(other),
            'C1. the other owner alone, nothing added', JSON.stringify(now));
    t.check(rowsOf('admin.service-account.owner-added', since).length === 0,
            'C2. and no owner-added row');
  });
  log.debug('Leaving aCoOwner().');
}

async function noAdministrator(t) {
  log.debug('Entering noAdministrator().');
  t.log.info('=== D. neither the group nor the administrator ===');
  await withRealm(t, 'svc-orphan-d', async function () {
    const write = groupDn(writeGroupName());
    if (write) {
      ldap.deleteGroupEntry(write);
    }
    const boot = personDn(bootstrapName.current());
    if (boot) {
      ldap.deletePerson(boot, { door: 'the test' });
    }
    t.check(!groupDn(writeGroupName()) &&
            !personDn(bootstrapName.current()),
            'precondition (D): the realm has neither an Admin Write group ' +
            'nor a bootstrap administrator', JSON.stringify([write, boot]));
    const ownerDn = person('oo-d-owner');
    account(t, 'D', 'oo-d-sa', ['oo-d-owner']);
    const since = Date.now();
    const lines = await warnings(function () {
      return ldap.deletePerson(ownerDn, { door: 'the test' });
    });
    t.check(ownerDns('oo-d-sa').length === 0 &&
            serviceAccounts.isServiceAccountName('oo-d-sa'),
            'D1. the account is left a service account with no owner',
            JSON.stringify(ownerDns('oo-d-sa')));
    t.check(lines.some(function (line) {
      return line.indexOf(errorCodes.tag('STS-SVCACCT-0068')) >= 0 &&
             line.indexOf('oo-d-sa') >= 0;
    }), 'D2. STS-SVCACCT-0068 is logged for it', JSON.stringify(lines));
    t.check(rowsOf('admin.service-account.owner-added', since).length === 0,
            'D3. and no owner-added row');
    person('oo-d-new');
    const repaired = adminActions.usersAction({
      action: 'add-service-account-owner', user: 'oo-d-sa',
      owner: 'oo-d-new' }, { via: 'api', actor: '', admin: null });
    t.check(repaired && repaired.ok &&
            ownerDns('oo-d-sa')[0] === key(personDn('oo-d-new')),
            'D4. an administrator adding an owner repairs it',
            JSON.stringify(repaired));
  });
  log.debug('Leaving noAdministrator().');
}

// The account itself is never its own heir: the bootstrap administrator
// made a service account, in a realm with no Admin Write group.
async function notItsOwnHeir(t) {
  log.debug('Entering notItsOwnHeir().');
  t.log.info('=== D. the account is never its own owner ===');
  await withRealm(t, 'svc-orphan-h', async function () {
    const write = groupDn(writeGroupName());
    if (write) {
      ldap.deleteGroupEntry(write);
    }
    const boot = bootstrapName.current();
    person(boot);
    const ownerDn = person('oo-h-owner');
    account(t, 'D5', boot, ['oo-h-owner']);
    ldap.deletePerson(ownerDn, { door: 'the test' });
    t.check(ownerDns(boot).length === 0,
            'D5. the bootstrap administrator, itself the account, is not ' +
            'made its own owner', JSON.stringify(ownerDns(boot)));
  });
  log.debug('Leaving notItsOwnHeir().');
}

async function neverOwned(t) {
  log.debug('Entering neverOwned().');
  t.log.info('=== E. an account that named no owner ===');
  await withRealm(t, 'svc-orphan-e', function () {
    adminWrite();
    policy.save('default', Object.assign({}, policy.DEFAULTS,
                                         { requireOwner: false }));
    try {
      person('oo-e-sa');
      const made = serviceAccounts.set('oo-e-sa', { serviceAccount: true,
                                                    owners: '' });
      const bystander = person('oo-e-bystander');
      ldap.deletePerson(bystander, { door: 'the test' });
      t.check(made && made.ok && ownerDns('oo-e-sa').length === 0,
              'E1. an account made with no owner still names none after a ' +
              'delete', JSON.stringify([made, ownerDns('oo-e-sa')]));
    } finally {
      policy.reset('default');
    }
  });
  log.debug('Leaving neverOwned().');
}

async function overLdap(t) {
  log.debug('Entering overLdap().');
  t.log.info('=== F. an LDAP delete, of a person and of a group ===');
  await withRealm(t, 'svc-orphan-f', async function () {
    const write = adminWrite();
    const ownerDn = person('oo-f-owner');
    const owners = group('oo-f-owners');
    account(t, 'F', 'oo-f-sa1', ['oo-f-owner']);
    account(t, 'F', 'oo-f-sa2', [owners]);
    const one = await ldapOp('del', { dn: ownerDn });
    const two = await ldapOp('del', { dn: owners });
    t.check(one.ok !== false && !one.error && !personDn('oo-f-owner'),
            'F0. the LDAP deletes succeed', JSON.stringify([one, two]));
    t.check(ownerDns('oo-f-sa1').join() === key(write),
            'F1. an LDAP delete of the last owner, a person: the Admin ' +
            'Write group owns the account', JSON.stringify(
              ownerDns('oo-f-sa1')));
    t.check(two.ok !== false && !two.error &&
            ownerDns('oo-f-sa2').join() === key(write),
            'F2. an LDAP delete of the last owner, a group: the same',
            JSON.stringify(ownerDns('oo-f-sa2')));
  });
  log.debug('Leaving overLdap().');
}

// THE CHILD'S WHOLE PROGRAM, serialised with toString() and run by
// `node -e` — it may use nothing from this file's scope and (root
// CLAUDE.md, Code style) is exempt from the Entering/Leaving rule; it
// carries its errors on the record it writes.
function childMain() {
  const ROOT = process.env.OO_ROOT;
  const OUT = process.env.OO_OUT;
  const http = require('http');
  const record = { problems: [], steps: {} };

  function request(port, method, urlPath, headers) {
    return new Promise(function (resolve) {
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        res.resume();
        res.on('end', function () {
          resolve(res.statusCode);
        });
      });
      req.on('error', function (e) {
        resolve('error: ' + e.message);
      });
      req.end();
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const serviceAccounts = require(ROOT + '/common/service_accounts');
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    await realms.run(realms.DEFAULT_REALM, async function () {
      const uuidOf = function (stored) {
        const at = (stored && stored.attributes) || {};
        return String((at.entryuuid || at.entryUUID || [''])[0]);
      };
      const owners = function (name) {
        const facts = serviceAccounts.of(name);
        return facts ? facts.owners.map(function (one) {
          return one.dn.toLowerCase();
        }) : [];
      };
      const writeName = String(config.value('admin.writeGroup') || '');
      if (!ldap.readGroupEntry(ldap.groupDnFor(writeName))) {
        ldap.createGroup(writeName, { members: [] });
      }
      const write = ldap.readGroupEntry(ldap.groupDnFor(writeName));
      record.writeDn = write ? String(write.dn).toLowerCase() : '';
      ['oo-scim-client', 'oo-scim-owner', 'oo-scim-sa1', 'oo-scim-sa2']
        .forEach(function (name) {
          ldap.createUser(name, { invent: false, attributes: {} });
        });
      ldap.createGroup('oo-scim-owners', { members: [] });
      const groupEntry = ldap.readGroupEntry(ldap.groupDnFor(
        'oo-scim-owners'));
      record.steps.made = [
        serviceAccounts.set('oo-scim-sa1', { serviceAccount: true,
                                             owners: ['oo-scim-owner'] }).ok,
        serviceAccounts.set('oo-scim-sa2', { serviceAccount: true,
                                             owners: [groupEntry.dn] }).ok];
      const auth = { authorization: 'Basic ' +
        Buffer.from('oo-scim-client:whatever').toString('base64') };
      record.steps.user = await request(port, 'DELETE', '/scim/v2/Users/' +
        uuidOf(ldap.existingUserEntry('oo-scim-owner')), auth);
      record.steps.group = await request(port, 'DELETE', '/scim/v2/Groups/' +
        uuidOf(ldap.getEntry ? ldap.getEntry(groupEntry.dn) : groupEntry),
        auth);
      record.steps.ownerGone = !ldap.existingUserEntry('oo-scim-owner');
      record.sa1 = owners('oo-scim-sa1');
      record.sa2 = owners('oo-scim-sa2');
    });
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push(String(e && e.stack));
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

function overScim(t) {
  log.debug('Entering overScim().');
  t.log.info('=== F. SCIM DELETE /Users and /Groups, over HTTP ===');
  const out = path.join(os.tmpdir(), 'svc-orphan-owner-' + process.pid +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (name) {
    if (!/^(STS_|SCIM_|OAUTH2_|LDAP_|CONFIG_FILE$)/.test(name)) {
      clean[name] = process.env[name];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', OO_ROOT: ROOT,
                                  OO_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug('Caught in overScim(): ' + ((e && e.message) || e));
    record = null;
  }
  if (!t.check(!!record && record.problems.length === 0,
               'F3. the SCIM child ran to the end',
               record ? record.problems.join('\n')
                 : 'exit ' + result.status + ' ' +
                   String(result.stderr || '').slice(-800))) {
    log.debug('Leaving overScim(). No record.');
    return;
  }
  t.check(record.steps.user === 204 && record.steps.ownerGone &&
          record.sa1.join() === record.writeDn && !!record.writeDn,
          'F4. SCIM DELETE /Users of the last owner: the Admin Write ' +
          'group owns the account', JSON.stringify(record));
  t.check(record.steps.group === 204 &&
          record.sa2.join() === record.writeDn,
          'F5. SCIM DELETE /Groups of the last owner: the same',
          JSON.stringify(record));
  log.debug('Leaving overScim().');
}

// Neither the console nor /admin-api deletes a person or a group: the
// console's every act is an /admin-api operation, and the API's route table
// (generated from `models/api/*.tsp`) has no such operation, so the LDAP
// delete and SCIM above are every door to the cleanup.
function noOtherDoor(t) {
  log.debug('Entering noOtherDoor().');
  const table = fs.readFileSync(path.join(ROOT, 'types',
                                          'api.generated.d.ts'), 'utf8');
  const paths = (table.match(/"\/admin-api\/(users|groups)[^"]*"/g) || []);
  const deletes = paths.filter(function (one) {
    return /delete|remove-(user|person|group)"|\/(users|groups)\/forget"/
      .test(one);
  });
  t.check(paths.length > 0 && deletes.length === 0,
          'F6. /admin-api (and so the console) has no person or group ' +
          'delete of its own', JSON.stringify(deletes));
  log.debug('Leaving noOtherDoor().');
}

async function run(t) {
  log.debug('Entering run().');
  await aPerson(t);
  await theWriteGroup(t);
  await aCoOwner(t);
  await noAdministrator(t);
  await notItsOwnHeir(t);
  await neverOwned(t);
  await overLdap(t);
  overScim(t);
  noOtherDoor(t);
  t.check(errorCodes.CODES.some(function (one) {
    return one.code === 'STS-SVCACCT-0068';
  }), 'G1. STS-SVCACCT-0068 is in the table');
  log.debug('Leaving run().');
}

module.exports = {
  name: 'service_account_orphan_owner',
  describe: 'a service account whose last owner is deleted is owned by ' +
            'the realm\'s Admin Write group, else its bootstrap ' +
            'administrator, by every door that deletes a person or a ' +
            'group; with neither it names none and STS-SVCACCT-0068 is ' +
            'logged (rcbj, 2026-11-15)',
  run: run
};
